from collections.abc import Callable

from . import mount_proto, nfs_proto
from .const import MOUNT_PROGRAM, MOUNT_V3, NFS_PROGRAM, NFS_V3
from .fs import Filesystem
from .rpc import RpcServer


class NfsServer:
    def __init__(self, nfs_config, resolve: Callable[[str], str]):
        self.fs = Filesystem(list(nfs_config.mounts), resolve)

        host = resolve(nfs_config.server_ip)
        port = int(resolve(nfs_config.server_port))
        self._rpc = RpcServer(host, port)
        self._rpc.register_program(
            MOUNT_PROGRAM, MOUNT_V3, mount_proto.build_handlers(self.fs)
        )
        self._rpc.register_program(
            NFS_PROGRAM, NFS_V3, nfs_proto.build_handlers(self.fs)
        )

    def start(self):
        self._rpc.start()

    def stop(self):
        self._rpc.stop()
        self.fs.close_all_open_files()
