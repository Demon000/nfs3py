import os
import stat as statmod
import time

from .const import (
    DONT_CHANGE,
    EXCLUSIVE,
    FSF3_CANSETTIME,
    FSF3_LINK,
    FSF3_SYMLINK,
    NF3BLK,
    NF3CHR,
    NF3FIFO,
    NF3SOCK,
    NFS3_FHSIZE,
    NFS3_OK,
    NFS3ERR_BADTYPE,
    NFS3ERR_INVAL,
    NFS3ERR_NOT_SYNC,
    SET_TO_CLIENT_TIME,
    SET_TO_SERVER_TIME,
    UNSTABLE,
    NfsError,
)
from .fs import Filesystem, fattr3_dict, wcc_attr_dict
from .rpc import ClientCred, Handler
from .xdr import XdrReader, XdrWriter

ACCESS3_READ = 0x0001
ACCESS3_LOOKUP = 0x0002
ACCESS3_MODIFY = 0x0004
ACCESS3_EXTEND = 0x0008
ACCESS3_DELETE = 0x0010
ACCESS3_EXECUTE = 0x0020


def _write_nfstime3(w: XdrWriter, t: tuple[int, int]):
    w.u32(t[0])
    w.u32(t[1])


def _write_fattr3(w: XdrWriter, a: dict):
    w.u32(a['type'])
    w.u32(a['mode'])
    w.u32(a['nlink'])
    w.u32(a['uid'])
    w.u32(a['gid'])
    w.u64(a['size'])
    w.u64(a['used'])
    w.u32(a['rdev1'])
    w.u32(a['rdev2'])
    w.u64(a['fsid'])
    w.u64(a['fileid'])
    _write_nfstime3(w, a['atime'])
    _write_nfstime3(w, a['mtime'])
    _write_nfstime3(w, a['ctime'])


def _write_post_op_attr(w: XdrWriter, st):
    if st is None:
        w.bool(False)
        return
    w.bool(True)
    _write_fattr3(w, fattr3_dict(st))


def _write_wcc_data(w: XdrWriter, pre_st, post_st):
    if pre_st is None:
        w.bool(False)
    else:
        w.bool(True)
        wa = wcc_attr_dict(pre_st)
        w.u64(wa['size'])
        _write_nfstime3(w, wa['mtime'])
        _write_nfstime3(w, wa['ctime'])
    _write_post_op_attr(w, post_st)


def _write_post_op_fh3(w: XdrWriter, fh):
    if fh is None:
        w.bool(False)
        return
    w.bool(True)
    w.opaque_var(fh)


def _read_sattr3(args: XdrReader) -> dict:
    mode = args.u32() if args.bool() else None
    uid = args.u32() if args.bool() else None
    gid = args.u32() if args.bool() else None
    size = args.u64() if args.bool() else None

    atime_how = args.u32()
    atime = (
        (args.u32(), args.u32()) if atime_how == SET_TO_CLIENT_TIME else None
    )

    mtime_how = args.u32()
    mtime = (
        (args.u32(), args.u32()) if mtime_how == SET_TO_CLIENT_TIME else None
    )

    return {
        'mode': mode,
        'uid': uid,
        'gid': gid,
        'size': size,
        'atime_how': atime_how,
        'atime': atime,
        'mtime_how': mtime_how,
        'mtime': mtime,
    }


def _time_how_to_ns(how: int, value: tuple[int, int] | None) -> int | None:
    if how == DONT_CHANGE:
        return None
    if how == SET_TO_SERVER_TIME:
        return time.time_ns()
    if how == SET_TO_CLIENT_TIME and value is not None:
        return value[0] * 1_000_000_000 + value[1]
    return None


def _apply_sattr3(fs: Filesystem, path, sattr: dict):
    fs.setattr(
        path,
        sattr['mode'],
        sattr['uid'],
        sattr['gid'],
        sattr['size'],
        _time_how_to_ns(sattr['atime_how'], sattr['atime']),
        _time_how_to_ns(sattr['mtime_how'], sattr['mtime']),
    )


def _compute_cookieverf(dir_st) -> bytes:
    return (dir_st.st_mtime_ns & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')


def _cred_owner(cred: ClientCred) -> tuple[int, int] | None:
    if cred.uid is None or cred.gid is None:
        return None
    return cred.uid, cred.gid


def build_handlers(fs: Filesystem) -> dict[int, Handler]:
    def null(args: XdrReader, res: XdrWriter, cred: ClientCred):
        pass

    def getattr_(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            res.u32(NFS3_OK)
            _write_fattr3(res, fattr3_dict(st))
        except NfsError as e:
            res.u32(e.status)

    def setattr_(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)
        sattr = _read_sattr3(args)
        guard_ctime = (args.u32(), args.u32()) if args.bool() else None

        pre = None
        try:
            _root, path = fs.resolve_fh(fh)
            pre = fs.stat(path)
            if guard_ctime is not None:
                cur = (
                    pre.st_ctime_ns // 1_000_000_000,
                    pre.st_ctime_ns % 1_000_000_000,
                )
                if cur != guard_ctime:
                    raise NfsError(NFS3ERR_NOT_SYNC)
            _apply_sattr3(fs, path, sattr)
            post = fs.stat(path)
            res.u32(NFS3_OK)
            _write_wcc_data(res, pre, post)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def lookup(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()

        dir_attrs = None
        try:
            _root, dir_path = fs.resolve_fh(dir_fh)
            dir_attrs = fs.stat(dir_path)
            fh, _child_path, _root2, child_attrs = fs.lookup(
                dir_fh, name, dir_st=dir_attrs
            )
            res.u32(NFS3_OK)
            res.opaque_var(fh)
            _write_post_op_attr(res, child_attrs)
            _write_post_op_attr(res, dir_attrs)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, dir_attrs)

    def access(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)
        requested = args.u32()

        st = None
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            granted = 0
            if requested & ACCESS3_READ and fs.access_ok(path, os.R_OK):
                granted |= ACCESS3_READ
            if requested & ACCESS3_LOOKUP and fs.access_ok(path, os.X_OK):
                granted |= ACCESS3_LOOKUP
            if requested & ACCESS3_MODIFY and fs.access_ok(path, os.W_OK):
                granted |= ACCESS3_MODIFY
            if requested & ACCESS3_EXTEND and fs.access_ok(path, os.W_OK):
                granted |= ACCESS3_EXTEND
            if requested & ACCESS3_DELETE and fs.access_ok(path, os.W_OK):
                granted |= ACCESS3_DELETE
            if requested & ACCESS3_EXECUTE and fs.access_ok(path, os.X_OK):
                granted |= ACCESS3_EXECUTE
            res.u32(NFS3_OK)
            _write_post_op_attr(res, st)
            res.u32(granted)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)

    def readlink(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)

        st = None
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            target = fs.readlink(path)
            res.u32(NFS3_OK)
            _write_post_op_attr(res, st)
            res.string(target)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)

    def read(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)
        offset = args.u64()
        count = args.u32()

        st = None
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            data, eof = fs.read(path, offset, count)
            res.u32(NFS3_OK)
            _write_post_op_attr(res, fs.stat(path))
            res.u32(len(data))
            res.bool(eof)
            res.opaque_var(data)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)

    def write(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)
        offset = args.u64()
        count = args.u32()
        stable = args.u32()
        data = args.opaque_var()

        pre = None
        try:
            _root, path = fs.resolve_fh(fh)
            pre = fs.stat(path)
            fs.write(path, offset, data[:count], stable=(stable != UNSTABLE))
            post = fs.stat(path)
            res.u32(NFS3_OK)
            _write_wcc_data(res, pre, post)
            res.u32(min(count, len(data)))
            res.u32(stable)
            res.opaque_fixed(fs.writeverf(), 8)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def create(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()
        mode = args.u32()
        sattr = None
        verf = None
        if mode != EXCLUSIVE:
            sattr = _read_sattr3(args)
        else:
            verf = args.opaque_fixed(8)
        del verf

        pre = None
        try:
            root, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            path = fs.create(
                dir_path,
                name,
                exclusive=(mode == EXCLUSIVE),
                owner=_cred_owner(cred),
            )
            if sattr is not None:
                _apply_sattr3(fs, path, sattr)
            fh = fs.fh_for_known_path(root, path)
            post_obj = fs.stat(path)
            post_dir = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_post_op_fh3(res, fh)
            _write_post_op_attr(res, post_obj)
            _write_wcc_data(res, pre, post_dir)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def mkdir(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()
        sattr = _read_sattr3(args)

        pre = None
        try:
            root, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            path = fs.mkdir(dir_path, name, owner=_cred_owner(cred))
            _apply_sattr3(fs, path, sattr)
            fh = fs.fh_for_known_path(root, path)
            post_obj = fs.stat(path)
            post_dir = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_post_op_fh3(res, fh)
            _write_post_op_attr(res, post_obj)
            _write_wcc_data(res, pre, post_dir)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def symlink(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()
        sattr = _read_sattr3(args)
        target = args.string()

        pre = None
        try:
            root, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            path = fs.symlink(dir_path, name, target, owner=_cred_owner(cred))
            _apply_sattr3(fs, path, sattr)
            fh = fs.fh_for_known_path(root, path)
            post_obj = fs.stat(path)
            post_dir = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_post_op_fh3(res, fh)
            _write_post_op_attr(res, post_obj)
            _write_wcc_data(res, pre, post_dir)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def mknod(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()
        ftype = args.u32()

        sattr = None
        device = 0
        if ftype in (NF3CHR, NF3BLK):
            sattr = _read_sattr3(args)
            spec1 = args.u32()
            spec2 = args.u32()
            device = os.makedev(spec1, spec2)
        elif ftype in (NF3SOCK, NF3FIFO):
            sattr = _read_sattr3(args)

        pre = None
        try:
            if ftype == NF3CHR:
                base_mode = statmod.S_IFCHR
            elif ftype == NF3BLK:
                base_mode = statmod.S_IFBLK
            elif ftype == NF3SOCK:
                base_mode = statmod.S_IFSOCK
            elif ftype == NF3FIFO:
                base_mode = statmod.S_IFIFO
            else:
                raise NfsError(NFS3ERR_BADTYPE)

            root, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            perm = (
                sattr['mode'] if sattr and sattr['mode'] is not None else 0o644
            )
            path = fs.mknod(
                dir_path,
                name,
                base_mode | perm,
                device,
                owner=_cred_owner(cred),
            )
            if sattr is not None:
                sattr_no_mode = dict(sattr)
                sattr_no_mode['mode'] = None
                _apply_sattr3(fs, path, sattr_no_mode)
            fh = fs.fh_for_known_path(root, path)
            post_obj = fs.stat(path)
            post_dir = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_post_op_fh3(res, fh)
            _write_post_op_attr(res, post_obj)
            _write_wcc_data(res, pre, post_dir)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def remove(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()

        pre = None
        try:
            _root, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            fs.remove(dir_path, name)
            post = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_wcc_data(res, pre, post)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def rmdir(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()

        pre = None
        try:
            _root, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            fs.rmdir(dir_path, name)
            post = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_wcc_data(res, pre, post)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    def rename(args: XdrReader, res: XdrWriter, cred: ClientCred):
        from_dir_fh = args.opaque_var(NFS3_FHSIZE)
        from_name = args.string()
        to_dir_fh = args.opaque_var(NFS3_FHSIZE)
        to_name = args.string()

        pre_from = None
        pre_to = None
        try:
            _root1, from_dir = fs.resolve_fh(from_dir_fh)
            _root2, to_dir = fs.resolve_fh(to_dir_fh)
            pre_from = fs.stat(from_dir)
            pre_to = fs.stat(to_dir)
            fs.rename(from_dir, from_name, to_dir, to_name)
            post_from = fs.stat(from_dir)
            post_to = fs.stat(to_dir)
            res.u32(NFS3_OK)
            _write_wcc_data(res, pre_from, post_from)
            _write_wcc_data(res, pre_to, post_to)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre_from, None)
            _write_wcc_data(res, pre_to, None)

    def link(args: XdrReader, res: XdrWriter, cred: ClientCred):
        file_fh = args.opaque_var(NFS3_FHSIZE)
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        name = args.string()

        st = None
        pre = None
        try:
            _root1, target_path = fs.resolve_fh(file_fh)
            _root2, dir_path = fs.resolve_fh(dir_fh)
            pre = fs.stat(dir_path)
            fs.link(target_path, dir_path, name)
            st = fs.stat(target_path)
            post = fs.stat(dir_path)
            res.u32(NFS3_OK)
            _write_post_op_attr(res, st)
            _write_wcc_data(res, pre, post)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)
            _write_wcc_data(res, pre, None)

    def readdir(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        cookie = args.u64()
        _cookieverf = args.opaque_fixed(8)
        count = args.u32()

        dir_attrs = None
        try:
            root, dir_path = fs.resolve_fh(dir_fh)
            dir_attrs = fs.stat(dir_path)
            scanned = fs.scandir_sorted(dir_path)
            names = ['.', '..'] + [e.name for e in scanned]
            inode_by_name = {e.name: e.inode() for e in scanned}

            verf = _compute_cookieverf(dir_attrs)
            if (
                cookie != 0
                and _cookieverf != b'\x00' * 8
                and _cookieverf != verf
            ):
                raise NfsError(NFS3ERR_INVAL)
            if cookie > len(names):
                raise NfsError(NFS3ERR_INVAL)

            parent_path = dir_path.parent if dir_path != root else root

            out = []
            used = 0
            idx = cookie
            while idx < len(names):
                name = names[idx]
                if name == '.':
                    fileid = dir_attrs.st_ino
                elif name == '..':
                    fileid = fs.stat(parent_path).st_ino
                else:
                    fileid = inode_by_name[name]
                entry_size = 8 + 4 + len(name.encode()) + 4 + 8 + 12
                if out and used + entry_size > count:
                    break
                out.append((fileid, name, idx + 1))
                used += entry_size
                idx += 1
            eof = idx >= len(names)

            res.u32(NFS3_OK)
            _write_post_op_attr(res, dir_attrs)
            res.opaque_fixed(verf, 8)
            for fileid, name, entry_cookie in out:
                res.bool(True)
                res.u64(fileid)
                res.string(name)
                res.u64(entry_cookie)
            res.bool(False)
            res.bool(eof)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, dir_attrs)

    def readdirplus(args: XdrReader, res: XdrWriter, cred: ClientCred):
        dir_fh = args.opaque_var(NFS3_FHSIZE)
        cookie = args.u64()
        _cookieverf = args.opaque_fixed(8)
        _dircount = args.u32()
        maxcount = args.u32()

        dir_attrs = None
        try:
            root, dir_path = fs.resolve_fh(dir_fh)
            dir_attrs = fs.stat(dir_path)
            scanned = fs.scandir_sorted(dir_path)
            names = ['.', '..'] + [e.name for e in scanned]

            verf = _compute_cookieverf(dir_attrs)
            if (
                cookie != 0
                and _cookieverf != b'\x00' * 8
                and _cookieverf != verf
            ):
                raise NfsError(NFS3ERR_INVAL)
            if cookie > len(names):
                raise NfsError(NFS3ERR_INVAL)

            parent_path = dir_path.parent if dir_path != root else root

            out = []
            used = 0
            idx = cookie
            while idx < len(names):
                name = names[idx]
                if name == '.':
                    entry_path = dir_path
                elif name == '..':
                    entry_path = parent_path
                else:
                    entry_path = dir_path / name
                entry_st = fs.stat(entry_path)
                entry_fh = fs.fh_for_known_path(root, entry_path)
                entry_size = (
                    8 + 4 + len(name.encode()) + 4 + 96 + NFS3_FHSIZE + 16
                )
                if out and used + entry_size > maxcount:
                    break
                out.append((entry_st.st_ino, name, idx + 1, entry_st, entry_fh))
                used += entry_size
                idx += 1
            eof = idx >= len(names)

            res.u32(NFS3_OK)
            _write_post_op_attr(res, dir_attrs)
            res.opaque_fixed(verf, 8)
            for fileid, name, entry_cookie, entry_st, entry_fh in out:
                res.bool(True)
                res.u64(fileid)
                res.string(name)
                res.u64(entry_cookie)
                _write_post_op_attr(res, entry_st)
                _write_post_op_fh3(res, entry_fh)
            res.bool(False)
            res.bool(eof)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, dir_attrs)

    def fsstat(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)

        st = None
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            vfs = fs.statvfs(path)
            res.u32(NFS3_OK)
            _write_post_op_attr(res, st)
            res.u64(vfs.f_blocks * vfs.f_frsize)
            res.u64(vfs.f_bfree * vfs.f_frsize)
            res.u64(vfs.f_bavail * vfs.f_frsize)
            res.u64(vfs.f_files)
            res.u64(vfs.f_ffree)
            res.u64(vfs.f_favail)
            res.u32(0)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)

    def fsinfo(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)

        st = None
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            res.u32(NFS3_OK)
            _write_post_op_attr(res, st)
            res.u32(1024 * 1024)
            res.u32(64 * 1024)
            res.u32(4096)
            res.u32(1024 * 1024)
            res.u32(64 * 1024)
            res.u32(4096)
            res.u32(8192)
            res.u64((1 << 63) - 1)
            _write_nfstime3(res, (0, 1))
            res.u32(FSF3_LINK | FSF3_SYMLINK | FSF3_CANSETTIME)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)

    def pathconf(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)

        st = None
        try:
            _root, path = fs.resolve_fh(fh)
            st = fs.stat(path)
            try:
                linkmax = os.pathconf(path, 'PC_LINK_MAX')
            except OSError:
                linkmax = 32000
            try:
                name_max = os.pathconf(path, 'PC_NAME_MAX')
            except OSError:
                name_max = 255
            res.u32(NFS3_OK)
            _write_post_op_attr(res, st)
            res.u32(linkmax)
            res.u32(name_max)
            res.bool(True)
            res.bool(True)
            res.bool(False)
            res.bool(True)
        except NfsError as e:
            res.u32(e.status)
            _write_post_op_attr(res, st)

    def commit(args: XdrReader, res: XdrWriter, cred: ClientCred):
        fh = args.opaque_var(NFS3_FHSIZE)
        _offset = args.u64()
        _count = args.u32()

        pre = None
        try:
            _root, path = fs.resolve_fh(fh)
            pre = fs.stat(path)
            fs.commit(path)
            res.u32(NFS3_OK)
            _write_wcc_data(res, pre, pre)
            res.opaque_fixed(fs.writeverf(), 8)
        except NfsError as e:
            res.u32(e.status)
            _write_wcc_data(res, pre, None)

    return {
        0: null,
        1: getattr_,
        2: setattr_,
        3: lookup,
        4: access,
        5: readlink,
        6: read,
        7: write,
        8: create,
        9: mkdir,
        10: symlink,
        11: mknod,
        12: remove,
        13: rmdir,
        14: rename,
        15: link,
        16: readdir,
        17: readdirplus,
        18: fsstat,
        19: fsinfo,
        20: pathconf,
        21: commit,
    }
