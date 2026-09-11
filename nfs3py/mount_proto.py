from .const import (
    MNT3_OK,
    MNT3ERR_NOENT,
    NfsError,
)
from .fs import Filesystem
from .rpc import AUTH_SYS, ClientCred, Handler
from .xdr import XdrReader, XdrWriter


def build_handlers(fs: Filesystem) -> dict[int, Handler]:
    def null(args: XdrReader, res: XdrWriter, cred: ClientCred):
        pass

    def mnt(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dirpath = args.string(1024)
        try:
            fh = fs.mount_root_fh(dirpath)
        except NfsError:
            res.u32(MNT3ERR_NOENT)
            return

        host = cred.peer[0] if cred.peer else '*'
        fs.mount_list.append((host, dirpath))

        res.u32(MNT3_OK)
        res.opaque_var(fh)
        res.array_u32([AUTH_SYS])

    def dump(args: XdrReader, res: XdrWriter, cred: ClientCred):
        for host, dirpath in fs.mount_list:
            res.bool(True)
            res.string(host)
            res.string(dirpath)
        res.bool(False)

    def umnt(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dirpath = args.string(1024)
        fs.mount_list = [(h, d) for h, d in fs.mount_list if d != dirpath]

    def umntall(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fs.mount_list = []

    def export(args: XdrReader, res: XdrWriter, cred: ClientCred):
        for dirpath in fs.refresh_exports():
            res.bool(True)
            res.string(dirpath)
            res.bool(False)
        res.bool(False)

    return {
        0: null,
        1: mnt,
        2: dump,
        3: umnt,
        4: umntall,
        5: export,
    }
