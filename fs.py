import os
import stat as statmod
import struct
import threading
from collections.abc import Callable
from pathlib import Path

from .const import (
    NF3BLK,
    NF3CHR,
    NF3DIR,
    NF3FIFO,
    NF3LNK,
    NF3REG,
    NF3SOCK,
    NFS3ERR_ACCES,
    NFS3ERR_EXIST,
    NFS3ERR_IO,
    NFS3ERR_ISDIR,
    NFS3ERR_NOENT,
    NFS3ERR_NOTDIR,
    NFS3ERR_NOTEMPTY,
    NFS3ERR_PERM,
    NFS3ERR_STALE,
    NfsError,
)

_FTYPE_BY_ST_MODE = (
    (statmod.S_ISREG, NF3REG),
    (statmod.S_ISDIR, NF3DIR),
    (statmod.S_ISLNK, NF3LNK),
    (statmod.S_ISCHR, NF3CHR),
    (statmod.S_ISBLK, NF3BLK),
    (statmod.S_ISFIFO, NF3FIFO),
    (statmod.S_ISSOCK, NF3SOCK),
)


def ftype_for_stat(st: os.stat_result) -> int:
    for check, ftype in _FTYPE_BY_ST_MODE:
        if check(st.st_mode):
            return ftype
    return NF3REG


def raise_for_oserror(e: OSError):
    if isinstance(e, FileNotFoundError):
        raise NfsError(NFS3ERR_NOENT) from e
    if isinstance(e, PermissionError):
        raise NfsError(NFS3ERR_ACCES) from e
    if isinstance(e, FileExistsError):
        raise NfsError(NFS3ERR_EXIST) from e
    if isinstance(e, IsADirectoryError):
        raise NfsError(NFS3ERR_ISDIR) from e
    if isinstance(e, NotADirectoryError):
        raise NfsError(NFS3ERR_NOTDIR) from e
    if isinstance(e, OSError) and e.errno == 39:  # ENOTEMPTY
        raise NfsError(NFS3ERR_NOTEMPTY) from e
    raise NfsError(NFS3ERR_IO) from e


OWNER_XATTR_NAME = 'user.nfs3_owner'


def read_owner_xattr(path) -> tuple[int, int] | None:
    try:
        raw = os.getxattr(path, OWNER_XATTR_NAME, follow_symlinks=False)
    except OSError:
        return None
    try:
        uid_s, gid_s = raw.decode().split(':')
        return int(uid_s), int(gid_s)
    except ValueError:
        return None


def write_owner_xattr(path, uid: int, gid: int):
    try:
        os.setxattr(
            path,
            OWNER_XATTR_NAME,
            f'{uid}:{gid}'.encode(),
            follow_symlinks=False,
        )
    except OSError:
        pass


class _MappedStat:
    """Wraps a real os.stat_result, overriding st_uid/st_gid with the
    virtual ownership recorded in the file's user.nfs3_owner xattr, if
    present. Lets every attribute-reporting call site keep reading
    .st_uid/.st_gid exactly as if this were a real stat_result."""

    __slots__ = ('_st', 'st_gid', 'st_uid')

    def __init__(self, st: os.stat_result, uid: int, gid: int):
        self._st = st
        self.st_uid = uid
        self.st_gid = gid

    def __getattr__(self, name):
        return getattr(self._st, name)


def fattr3_dict(st: os.stat_result) -> dict:
    return {
        'type': ftype_for_stat(st),
        'mode': st.st_mode & 0o7777,
        'nlink': st.st_nlink,
        'uid': st.st_uid,
        'gid': st.st_gid,
        'size': st.st_size,
        'used': st.st_blocks * 512 if hasattr(st, 'st_blocks') else st.st_size,
        'rdev1': (st.st_rdev >> 8) & 0xFFFFFFFF
        if hasattr(st, 'st_rdev')
        else 0,
        'rdev2': st.st_rdev & 0xFF if hasattr(st, 'st_rdev') else 0,
        'fsid': st.st_dev & 0xFFFFFFFFFFFFFFFF,
        'fileid': st.st_ino & 0xFFFFFFFFFFFFFFFF,
        'atime': (
            st.st_atime_ns // 1_000_000_000,
            st.st_atime_ns % 1_000_000_000,
        ),
        'mtime': (
            st.st_mtime_ns // 1_000_000_000,
            st.st_mtime_ns % 1_000_000_000,
        ),
        'ctime': (
            st.st_ctime_ns // 1_000_000_000,
            st.st_ctime_ns % 1_000_000_000,
        ),
    }


def wcc_attr_dict(st: os.stat_result) -> dict:
    return {
        'size': st.st_size,
        'mtime': (
            st.st_mtime_ns // 1_000_000_000,
            st.st_mtime_ns % 1_000_000_000,
        ),
        'ctime': (
            st.st_ctime_ns // 1_000_000_000,
            st.st_ctime_ns % 1_000_000_000,
        ),
    }


def _vpath_join(vpath: str, name: str) -> str:
    return vpath.rstrip('/') + '/' + name


def _vpath_dirname(vpath: str) -> str:
    parent = vpath.rstrip('/').rsplit('/', 1)[0]
    return parent if parent else '/'


class VirtualPath:
    """A path as the NFS client sees it, lazily resolved to a real
    filesystem path on every use so grafted sub-mounts (see
    Filesystem.resolve_real_path) and ${arg} changes stay live."""

    __slots__ = ('_fs', 'export_root', 'vpath')

    def __init__(self, fs: 'Filesystem', export_root: str, vpath: str):
        self._fs = fs
        self.export_root = export_root
        self.vpath = vpath

    def __fspath__(self) -> str:
        return str(self._fs.resolve_real_path(self.vpath))

    def __truediv__(self, name: str) -> 'VirtualPath':
        return VirtualPath(
            self._fs, self.export_root, _vpath_join(self.vpath, name)
        )

    def __eq__(self, other) -> bool:
        if isinstance(other, VirtualPath):
            return self.vpath == other.vpath
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.vpath)

    def __repr__(self) -> str:
        return f'VirtualPath({self.vpath!r})'

    @property
    def parent(self) -> 'VirtualPath':
        if self.vpath == self.export_root:
            return self
        parent_vpath = _vpath_dirname(self.vpath)
        if not (
            parent_vpath == self.export_root
            or parent_vpath.startswith(self.export_root + '/')
        ):
            parent_vpath = self.export_root
        return VirtualPath(self._fs, self.export_root, parent_vpath)


class _GraftDirEntry:
    """Stands in for an os.DirEntry when listing a directory that a graft
    is mounted under but which has no corresponding real on-disk entry -
    e.g. a virtual root/pyrotux graft when the real exported rootfs has
    no root/pyrotux of its own. Only .name/.inode() are ever read off
    scandir_sorted()'s results, so duck-typing just those two is enough
    for grafts to show up in READDIR/READDIRPLUS, not just direct
    LOOKUP-by-name."""

    __slots__ = ('_ino', 'name')

    def __init__(self, name: str, ino: int):
        self.name = name
        self._ino = ino

    def inode(self) -> int:
        return self._ino


class Filesystem:
    def __init__(
        self, mounts: list[tuple[str, str]], resolve: Callable[[str], str]
    ):
        self._mounts_cfg = mounts
        self._resolve = resolve
        self._fh_to_entry: dict[bytes, VirtualPath] = {}
        self._lock = threading.RLock()
        self._writeverf = os.urandom(8)
        self.mount_list: list[tuple[str, str]] = []

    def writeverf(self) -> bytes:
        return self._writeverf

    def refresh_exports(self) -> dict[str, Path]:
        exports = {}
        for dst_file_path, src_file_path in self._mounts_cfg:
            real = self._resolve(dst_file_path)
            virt = self._resolve(src_file_path)
            if not real or not virt:
                continue
            exports.setdefault(virt, Path(real).resolve())
        return exports

    def resolve_real_path(self, vpath: str) -> Path:
        vpath = vpath.rstrip('/') or '/'
        for dst_file_path, src_file_path in self._mounts_cfg:
            real = self._resolve(dst_file_path)
            virt = self._resolve(src_file_path)
            if not real or not virt:
                continue
            virt = virt.rstrip('/') or '/'

            if vpath == virt:
                rel = ''
            elif vpath.startswith(virt + '/'):
                rel = vpath[len(virt) + 1 :]
            else:
                continue

            real_path = Path(real).resolve()
            return real_path.joinpath(rel) if rel else real_path
        raise NfsError(NFS3ERR_NOENT)

    def stat(self, path) -> os.stat_result:
        try:
            st = os.lstat(path)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')
        if statmod.S_ISLNK(st.st_mode):
            # Linux doesn't support user.* xattrs on symlinks at all, so
            # read_owner_xattr() would always miss here - skip the doomed
            # syscall. Harmless: the kernel never consults a symlink's own
            # ownership when following it, only the target's.
            return st
        owner = read_owner_xattr(path)
        if owner is not None:
            return _MappedStat(st, owner[0], owner[1])
        return st

    def _register(
        self, path: VirtualPath, st: os.stat_result | None = None
    ) -> bytes:
        if st is None:
            st = self.stat(path)
        fh = struct.pack(
            '>QQ',
            st.st_dev & 0xFFFFFFFFFFFFFFFF,
            st.st_ino & 0xFFFFFFFFFFFFFFFF,
        )
        with self._lock:
            self._fh_to_entry[fh] = path
        return fh

    def mount_root_fh(self, dirpath: str) -> bytes:
        exports = self.refresh_exports()
        if dirpath not in exports:
            raise NfsError(NFS3ERR_NOENT)
        return self._register(VirtualPath(self, dirpath, dirpath))

    def resolve_fh(self, fh: bytes) -> tuple[VirtualPath, VirtualPath]:
        with self._lock:
            entry = self._fh_to_entry.get(fh)
        if entry is None:
            raise NfsError(NFS3ERR_STALE)
        return VirtualPath(self, entry.export_root, entry.export_root), entry

    def fh_for_known_path(self, root, path: VirtualPath) -> bytes:
        del root
        return self._register(path)

    def lookup(
        self,
        dir_fh: bytes,
        name: str,
        dir_st: os.stat_result | None = None,
    ) -> tuple[bytes, VirtualPath, VirtualPath, os.stat_result]:
        root, dir_path = self.resolve_fh(dir_fh)
        self._validate_lookup_name(name)

        if dir_st is None:
            dir_st = self.stat(dir_path)
        if not statmod.S_ISDIR(dir_st.st_mode):
            # Without this, "looking up" a child of e.g. a symlink's own
            # fh would silently string-concatenate a vpath instead of
            # failing - which a real NFS client never actually does (it
            # follows symlinks itself, via READLINK + re-resolving from
            # the target), but is easy to get wrong by hand when testing.
            raise NfsError(NFS3ERR_NOTDIR)

        if name == '.':
            child = dir_path
        elif name == '..':
            child = dir_path.parent
        else:
            child = dir_path / name

        child_st = self.stat(child)
        fh = self._register(child, st=child_st)
        return fh, child, root, child_st

    def _validate_lookup_name(self, name: str):
        if (
            not name
            or os.sep in name
            or (os.altsep and os.altsep in name)
            or '\x00' in name
        ):
            raise NfsError(NFS3ERR_ACCES)

    def validate_create_name(self, name: str):
        self._validate_lookup_name(name)
        if name in ('.', '..'):
            raise NfsError(NFS3ERR_EXIST)

    def _graft_child_names(self, vpath: str) -> list[str]:
        names = []
        for _dst_file_path, src_file_path in self._mounts_cfg:
            virt = self._resolve(src_file_path)
            if virt and _vpath_dirname(virt) == vpath:
                names.append(virt.rsplit('/', 1)[-1])
        return names

    def scandir_sorted(self, dir_path: VirtualPath) -> list:
        try:
            with os.scandir(dir_path) as it:
                entries = list(it)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')

        real_names = {e.name for e in entries}
        for name in self._graft_child_names(dir_path.vpath):
            # A graft mounted directly under this directory has no real
            # on-disk entry of its own here - LOOKUP resolves it fine via
            # resolve_real_path(), but a plain scandir() never would.
            if name not in real_names:
                child = dir_path / name
                entries.append(_GraftDirEntry(name, self.stat(child).st_ino))

        entries.sort(key=lambda e: e.name)
        return entries

    def register_dir_entry(
        self, root, dir_path: VirtualPath, name: str
    ) -> bytes:
        del root
        return self._register(dir_path / name)

    def read(self, path, offset: int, count: int) -> tuple[bytes, bool]:
        try:
            with open(path, 'rb') as f:
                f.seek(offset)
                data = f.read(count)
            size = self.stat(path).st_size
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')
        eof = offset + len(data) >= size
        return data, eof

    def write(self, path, offset: int, data: bytes, stable: bool):
        try:
            with open(path, 'r+b') as f:
                f.seek(offset)
                f.write(data)
                if stable:
                    f.flush()
                    os.fsync(f.fileno())
        except OSError as e:
            raise_for_oserror(e)

    def commit(self, path):
        try:
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as e:
            raise_for_oserror(e)

    def create(
        self,
        dir_path: VirtualPath,
        name: str,
        exclusive: bool,
        owner: tuple[int, int] | None = None,
    ) -> VirtualPath:
        self.validate_create_name(name)
        target = dir_path / name
        flags = os.O_WRONLY | os.O_CREAT
        flags |= os.O_EXCL if exclusive else os.O_TRUNC
        try:
            fd = os.open(target, flags, 0o644)
            os.close(fd)
        except OSError as e:
            raise_for_oserror(e)
        if owner is not None:
            write_owner_xattr(target, *owner)
        return target

    def mkdir(
        self,
        dir_path: VirtualPath,
        name: str,
        owner: tuple[int, int] | None = None,
    ) -> VirtualPath:
        self.validate_create_name(name)
        target = dir_path / name
        try:
            os.mkdir(target, 0o755)
        except OSError as e:
            raise_for_oserror(e)
        if owner is not None:
            write_owner_xattr(target, *owner)
        return target

    def remove(self, dir_path: VirtualPath, name: str):
        self.validate_create_name(name)
        target = dir_path / name
        try:
            if statmod.S_ISDIR(self.stat(target).st_mode):
                raise NfsError(NFS3ERR_ISDIR)
            os.unlink(target)
        except OSError as e:
            raise_for_oserror(e)
        self._forget(target)

    def rmdir(self, dir_path: VirtualPath, name: str):
        self.validate_create_name(name)
        target = dir_path / name
        try:
            os.rmdir(target)
        except OSError as e:
            raise_for_oserror(e)
        self._forget(target)

    def _forget(self, path: VirtualPath):
        with self._lock:
            stale = [fh for fh, p in self._fh_to_entry.items() if p == path]
            for fh in stale:
                del self._fh_to_entry[fh]

    def rename(
        self,
        from_dir: VirtualPath,
        from_name: str,
        to_dir: VirtualPath,
        to_name: str,
    ):
        self.validate_create_name(from_name)
        self.validate_create_name(to_name)
        old_path = from_dir / from_name
        new_path = to_dir / to_name
        try:
            os.rename(old_path, new_path)
        except OSError as e:
            raise_for_oserror(e)

        with self._lock:
            old_prefix = old_path.vpath + '/'
            new_prefix = new_path.vpath + '/'
            for fh, entry in list(self._fh_to_entry.items()):
                if entry.vpath == old_path.vpath:
                    self._fh_to_entry[fh] = VirtualPath(
                        self, entry.export_root, new_path.vpath
                    )
                elif entry.vpath.startswith(old_prefix):
                    self._fh_to_entry[fh] = VirtualPath(
                        self,
                        entry.export_root,
                        new_prefix + entry.vpath[len(old_prefix) :],
                    )

    def symlink(
        self,
        dir_path: VirtualPath,
        name: str,
        target: str,
        owner: tuple[int, int] | None = None,
    ) -> VirtualPath:
        self.validate_create_name(name)
        link_path = dir_path / name
        try:
            os.symlink(target, link_path)
        except OSError as e:
            raise_for_oserror(e)
        # Symlinks can't hold user.* xattrs at all (see stat()), so unlike
        # create/mkdir/mknod there's no owner-tagging call to make here.
        del owner
        return link_path

    def readlink(self, path) -> str:
        try:
            return os.readlink(path)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')

    def link(self, target_path, dir_path: VirtualPath, name: str):
        self.validate_create_name(name)
        link_path = dir_path / name
        try:
            os.link(target_path, link_path)
        except OSError as e:
            raise_for_oserror(e)

    def mknod(
        self,
        dir_path: VirtualPath,
        name: str,
        mode: int,
        device: int = 0,
        owner: tuple[int, int] | None = None,
    ):
        self.validate_create_name(name)
        target = dir_path / name
        try:
            os.mknod(target, mode, device)
        except PermissionError as e:
            raise NfsError(NFS3ERR_PERM) from e
        except OSError as e:
            raise_for_oserror(e)
        if owner is not None:
            write_owner_xattr(target, *owner)
        return target

    def setattr(
        self,
        path,
        mode: int | None,
        uid: int | None,
        gid: int | None,
        size: int | None,
        atime_ns: int | None,
        mtime_ns: int | None,
    ):
        is_link = os.path.islink(path)
        try:
            # chmod/truncate always follow symlinks on Linux (there is no
            # lchmod), so applying them to a symlink would instead act on
            # whatever it points at - including a dangling/nonexistent
            # target, which real filesystems have no concept of "mode" or
            # "size" for anyway. Skip both for symlinks, matching how real
            # NFS servers treat these attributes as not meaningful there.
            if size is not None and not is_link:
                os.truncate(path, size)
            if mode is not None and not is_link:
                os.chmod(path, mode)
            if uid is not None or gid is not None:
                try:
                    os.chown(
                        path,
                        uid if uid is not None else -1,
                        gid if gid is not None else -1,
                        follow_symlinks=False,
                    )
                except PermissionError:
                    pass
                # The real chown above only actually lands when the
                # process has privilege to become the requested uid/gid
                # (root, or already that uid). Record the requested
                # ownership as reported (virtual) ownership regardless, so
                # SETATTR still "works" from the client's point of view
                # even when running unprivileged - see read_owner_xattr().
                # Symlinks can't hold user.* xattrs at all, so skip them
                # (matches stat()'s own skip for the same reason).
                if not is_link:
                    current = self.stat(path)
                    write_owner_xattr(
                        path,
                        uid if uid is not None else current.st_uid,
                        gid if gid is not None else current.st_gid,
                    )
            if atime_ns is not None or mtime_ns is not None:
                st = self.stat(path)
                a = atime_ns if atime_ns is not None else st.st_atime_ns
                m = mtime_ns if mtime_ns is not None else st.st_mtime_ns
                os.utime(path, ns=(a, m), follow_symlinks=False)
        except OSError as e:
            raise_for_oserror(e)

    def statvfs(self, path):
        try:
            return os.statvfs(path)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')

    def access_ok(self, path, mode: int) -> bool:
        return os.access(path, mode)
