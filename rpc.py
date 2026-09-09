import logging
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass

from .xdr import XdrDecodeError, XdrReader, XdrWriter

logger = logging.getLogger(__name__)

MSG_CALL = 0
MSG_REPLY = 1

MSG_ACCEPTED = 0
MSG_DENIED = 1

SUCCESS = 0
PROG_UNAVAIL = 1
PROG_MISMATCH = 2
PROC_UNAVAIL = 3
GARBAGE_ARGS = 4
SYSTEM_ERR = 5

RPC_MISMATCH = 0
AUTH_ERROR = 1

AUTH_TOOWEAK = 5

AUTH_NONE = 0
AUTH_SYS = 1

MAX_RECORD_SIZE = 4 * 1024 * 1024

Handler = Callable[[XdrReader, XdrWriter, 'ClientCred'], None]


class RpcProcError(Exception):
    def __init__(self, accept_stat: int):
        self.accept_stat = accept_stat


@dataclass
class ClientCred:
    flavor: int
    uid: int | None = None
    gid: int | None = None
    peer: tuple[str, int] | None = None


def _parse_opaque_auth(reader: XdrReader) -> tuple[int, bytes]:
    flavor = reader.u32()
    body = reader.opaque_var(400)
    return flavor, body


def _parse_cred(flavor: int, body: bytes) -> ClientCred:
    if flavor != AUTH_SYS:
        return ClientCred(flavor=flavor)
    r = XdrReader(body)
    r.u32()  # stamp
    r.string(255)  # machinename
    uid = r.u32()
    gid = r.u32()
    r.array_u32(16)  # gids
    return ClientCred(flavor=flavor, uid=uid, gid=gid)


def _write_opaque_auth_none(w: XdrWriter):
    w.u32(AUTH_NONE)
    w.opaque_var(b'')


ACCEPT_POLL_INTERVAL = 0.5


class RpcServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.programs: dict[tuple[int, int], dict[int, Handler]] = {}
        self._listen_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._conns: set[socket.socket] = set()
        self._conns_lock = threading.Lock()
        self._conn_threads: list[threading.Thread] = []
        self._stopping = threading.Event()

    def register_program(self, prog: int, vers: int, procs: dict[int, Handler]):
        self.programs[(prog, vers)] = procs

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(16)
        sock.settimeout(ACCEPT_POLL_INTERVAL)
        self._listen_sock = sock

        self._accept_thread = threading.Thread(
            target=self._accept_loop, name='nfs-rpc-accept'
        )
        self._accept_thread.start()

    def stop(self):
        self._stopping.set()

        if self._listen_sock is not None:
            try:
                self._listen_sock.close()
            except OSError:
                pass

        with self._conns_lock:
            conns = list(self._conns)
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        if self._accept_thread is not None:
            self._accept_thread.join()
        for t in self._conn_threads:
            t.join()

    def _accept_loop(self):
        assert self._listen_sock is not None
        while not self._stopping.is_set():
            try:
                conn, _addr = self._listen_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            with self._conns_lock:
                self._conns.add(conn)

            t = threading.Thread(
                target=self._connection_loop, args=(conn,), name='nfs-rpc-conn'
            )
            self._conn_threads.append(t)
            t.start()

    def _connection_loop(self, conn: socket.socket):
        write_lock = threading.Lock()
        worker_threads: list[threading.Thread] = []
        try:
            while True:
                message = self._read_record(conn)
                if message is None:
                    break

                t = threading.Thread(
                    target=self._handle_message,
                    args=(conn, write_lock, message),
                    name='nfs-rpc-worker',
                )
                worker_threads.append(t)
                t.start()
        finally:
            with self._conns_lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass
            for t in worker_threads:
                t.join()

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes | None:
        chunks = []
        remaining = n
        while remaining > 0:
            try:
                chunk = conn.recv(remaining)
            except OSError:
                return None
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b''.join(chunks)

    def _read_record(self, conn: socket.socket) -> bytes | None:
        fragments = bytearray()
        while True:
            header = self._recv_exact(conn, 4)
            if header is None:
                return None
            (marker,) = struct.unpack('>I', header)
            last = bool(marker & 0x80000000)
            length = marker & 0x7FFFFFFF

            if len(fragments) + length > MAX_RECORD_SIZE:
                logger.warning('NFS RPC record too large, closing connection')
                return None

            fragment = self._recv_exact(conn, length)
            if fragment is None:
                return None
            fragments += fragment

            if last:
                return bytes(fragments)

    def _send_message(
        self, conn: socket.socket, write_lock: threading.Lock, payload: bytes
    ):
        header = struct.pack('>I', len(payload) | 0x80000000)
        with write_lock:
            try:
                conn.sendall(header + payload)
            except OSError:
                pass

    def _handle_message(
        self, conn: socket.socket, write_lock: threading.Lock, message: bytes
    ):
        try:
            reader = XdrReader(message)
            xid = reader.u32()
            mtype = reader.u32()
            if mtype != MSG_CALL:
                return

            rpcvers = reader.u32()
            prog = reader.u32()
            vers = reader.u32()
            proc = reader.u32()
            cred_flavor, cred_body = _parse_opaque_auth(reader)
            _verf_flavor, _verf_body = _parse_opaque_auth(reader)

            if rpcvers != 2:
                self._send_message(
                    conn,
                    write_lock,
                    self._build_rejected_reply_rpc_mismatch(xid, 2, 2),
                )
                return

            if cred_flavor not in (AUTH_NONE, AUTH_SYS):
                self._send_message(
                    conn,
                    write_lock,
                    self._build_rejected_reply_auth(xid, AUTH_TOOWEAK),
                )
                return

            cred = _parse_cred(cred_flavor, cred_body)
            try:
                cred.peer = conn.getpeername()
            except OSError:
                pass

            procs = self.programs.get((prog, vers))
            if procs is None:
                versions = [v for (p, v) in self.programs if p == prog]
                if versions:
                    self._send_message(
                        conn,
                        write_lock,
                        self._build_accepted_reply(
                            xid,
                            PROG_MISMATCH,
                            struct.pack('>II', min(versions), max(versions)),
                        ),
                    )
                else:
                    self._send_message(
                        conn,
                        write_lock,
                        self._build_accepted_reply(xid, PROG_UNAVAIL),
                    )
                return

            handler = procs.get(proc)
            if handler is None:
                self._send_message(
                    conn,
                    write_lock,
                    self._build_accepted_reply(xid, PROC_UNAVAIL),
                )
                return

            result_writer = XdrWriter()
            try:
                handler(reader, result_writer, cred)
            except XdrDecodeError:
                self._send_message(
                    conn,
                    write_lock,
                    self._build_accepted_reply(xid, GARBAGE_ARGS),
                )
                return
            except RpcProcError as e:
                self._send_message(
                    conn,
                    write_lock,
                    self._build_accepted_reply(xid, e.accept_stat),
                )
                return
            except Exception:
                logger.exception('NFS RPC handler failed')
                self._send_message(
                    conn,
                    write_lock,
                    self._build_accepted_reply(xid, SYSTEM_ERR),
                )
                return

            self._send_message(
                conn,
                write_lock,
                self._build_accepted_reply(
                    xid, SUCCESS, result_writer.to_bytes()
                ),
            )
        except XdrDecodeError:
            pass
        except OSError:
            pass

    def _build_accepted_reply(
        self, xid: int, accept_stat: int, extra: bytes = b''
    ) -> bytes:
        w = XdrWriter()
        w.u32(xid)
        w.u32(MSG_REPLY)
        w.u32(MSG_ACCEPTED)
        _write_opaque_auth_none(w)
        w.u32(accept_stat)
        w.raw(extra)
        return w.to_bytes()

    def _build_rejected_reply_rpc_mismatch(
        self, xid: int, low: int, high: int
    ) -> bytes:
        w = XdrWriter()
        w.u32(xid)
        w.u32(MSG_REPLY)
        w.u32(MSG_DENIED)
        w.u32(RPC_MISMATCH)
        w.u32(low)
        w.u32(high)
        return w.to_bytes()

    def _build_rejected_reply_auth(self, xid: int, auth_stat: int) -> bytes:
        w = XdrWriter()
        w.u32(xid)
        w.u32(MSG_REPLY)
        w.u32(MSG_DENIED)
        w.u32(AUTH_ERROR)
        w.u32(auth_stat)
        return w.to_bytes()
