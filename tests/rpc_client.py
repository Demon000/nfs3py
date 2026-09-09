import os
import socket
import struct


def pad(n: int) -> int:
    return (-n) % 4


def u32(v: int) -> bytes:
    return struct.pack('>I', v & 0xFFFFFFFF)


def u64(v: int) -> bytes:
    return struct.pack('>Q', v & 0xFFFFFFFFFFFFFFFF)


def opaque(data: bytes) -> bytes:
    return u32(len(data)) + data + b'\x00' * pad(len(data))


def string(s: str) -> bytes:
    return opaque(os.fsencode(s))


def sattr3_unset() -> bytes:
    return u32(0) * 6


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def u32(self) -> int:
        (v,) = struct.unpack_from('>I', self.data, self.pos)
        self.pos += 4
        return v

    def u64(self) -> int:
        (v,) = struct.unpack_from('>Q', self.data, self.pos)
        self.pos += 8
        return v

    def bool(self) -> bool:
        return self.u32() != 0

    def opaque_fixed(self, n: int) -> bytes:
        d = self.data[self.pos : self.pos + n]
        self.pos += n + pad(n)
        return d

    def opaque(self) -> bytes:
        n = self.u32()
        d = self.data[self.pos : self.pos + n]
        self.pos += n + pad(n)
        return d

    def string(self) -> str:
        return os.fsdecode(self.opaque())

    def skip_fattr3(self):
        for _ in range(21):
            self.u32()

    def skip_post_op_attr(self):
        if self.bool():
            self.skip_fattr3()

    def skip_wcc_data(self):
        if self.bool():
            self.u64()
            self.u32()
            self.u32()
            self.u32()
            self.u32()
        self.skip_post_op_attr()


class RpcError(Exception):
    def __init__(self, accept_stat: int):
        self.accept_stat = accept_stat
        super().__init__(f'RPC accept_stat={accept_stat}')


class RpcClient:
    def __init__(self, host: str, port: int, timeout: float = 5):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._xid = 1

    def close(self):
        self.sock.close()

    def call(self, prog: int, vers: int, proc: int, args: bytes) -> Reader:
        xid = self._xid
        self._xid += 1

        cred = u32(0) + opaque(b'')
        verf = u32(0) + opaque(b'')
        body = (
            u32(xid)
            + u32(0)
            + u32(2)
            + u32(prog)
            + u32(vers)
            + u32(proc)
            + cred
            + verf
            + args
        )
        header = struct.pack('>I', len(body) | 0x80000000)
        self.sock.sendall(header + body)

        message = self._read_record()
        r = Reader(message)
        if r.u32() != xid:
            raise AssertionError('xid mismatch')
        if r.u32() != 1:
            raise AssertionError('not a reply')
        if r.u32() != 0:
            raise AssertionError('MSG_DENIED')
        r.u32()
        r.opaque()
        accept_stat = r.u32()
        if accept_stat != 0:
            raise RpcError(accept_stat)
        return r

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('connection closed')
            buf += chunk
        return bytes(buf)

    def _read_record(self) -> bytes:
        fragments = bytearray()
        while True:
            (marker,) = struct.unpack('>I', self._recv_exact(4))
            last = bool(marker & 0x80000000)
            length = marker & 0x7FFFFFFF
            fragments += self._recv_exact(length)
            if last:
                return bytes(fragments)
