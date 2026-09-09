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


class Filesystem:
    def __init__(
        self, mounts: list[tuple[str, str]], resolve: Callable[[str], str]
    ):
        self._mounts_cfg = mounts
        self._resolve = resolve
        self._fh_to_entry: dict[bytes, tuple[Path, Path]] = {}
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
            exports[virt] = Path(real).resolve()
        return exports

    def stat(self, path: Path) -> os.stat_result:
        try:
            return os.lstat(path)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')

    def _register(self, root: Path, path: Path) -> bytes:
        st = self.stat(path)
        fh = struct.pack(
            '>QQ',
            st.st_dev & 0xFFFFFFFFFFFFFFFF,
            st.st_ino & 0xFFFFFFFFFFFFFFFF,
        )
        with self._lock:
            self._fh_to_entry[fh] = (root, path)
        return fh

    def mount_root_fh(self, dirpath: str) -> bytes:
        exports = self.refresh_exports()
        real = exports.get(dirpath)
        if real is None:
            raise NfsError(NFS3ERR_NOENT)
        return self._register(real, real)

    def resolve_fh(self, fh: bytes) -> tuple[Path, Path]:
        with self._lock:
            entry = self._fh_to_entry.get(fh)
        if entry is None:
            raise NfsError(NFS3ERR_STALE)
        return entry

    def fh_for_known_path(self, root: Path, path: Path) -> bytes:
        return self._register(root, path)

    def lookup(self, dir_fh: bytes, name: str) -> tuple[bytes, Path, Path]:
        root, dir_path = self.resolve_fh(dir_fh)
        self._validate_lookup_name(name)

        if name == '.':
            child = dir_path
        elif name == '..':
            child = dir_path.parent if dir_path != root else root
            if not self._within_root(root, child):
                child = root
        else:
            child = dir_path / name

        self.stat(child)
        fh = self._register(root, child)
        return fh, child, root

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

    def _within_root(self, root: Path, path: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return path == root

    def scandir_sorted(self, dir_path: Path) -> list[os.DirEntry]:
        try:
            with os.scandir(dir_path) as it:
                entries = list(it)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')
        entries.sort(key=lambda e: e.name)
        return entries

    def register_dir_entry(
        self, root: Path, dir_path: Path, name: str
    ) -> bytes:
        return self._register(root, dir_path / name)

    def read(self, path: Path, offset: int, count: int) -> tuple[bytes, bool]:
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

    def write(self, path: Path, offset: int, data: bytes):
        try:
            with open(path, 'r+b') as f:
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            raise_for_oserror(e)

    def create(self, dir_path: Path, name: str, exclusive: bool) -> Path:
        self.validate_create_name(name)
        target = dir_path / name
        flags = os.O_WRONLY | os.O_CREAT
        flags |= os.O_EXCL if exclusive else os.O_TRUNC
        try:
            fd = os.open(target, flags, 0o644)
            os.close(fd)
        except OSError as e:
            raise_for_oserror(e)
        return target

    def mkdir(self, dir_path: Path, name: str) -> Path:
        self.validate_create_name(name)
        target = dir_path / name
        try:
            os.mkdir(target, 0o755)
        except OSError as e:
            raise_for_oserror(e)
        return target

    def remove(self, dir_path: Path, name: str):
        self.validate_create_name(name)
        target = dir_path / name
        try:
            if statmod.S_ISDIR(self.stat(target).st_mode):
                raise NfsError(NFS3ERR_ISDIR)
            os.unlink(target)
        except OSError as e:
            raise_for_oserror(e)
        self._forget(target)

    def rmdir(self, dir_path: Path, name: str):
        self.validate_create_name(name)
        target = dir_path / name
        try:
            os.rmdir(target)
        except OSError as e:
            raise_for_oserror(e)
        self._forget(target)

    def _forget(self, path: Path):
        with self._lock:
            stale = [
                fh for fh, (_r, p) in self._fh_to_entry.items() if p == path
            ]
            for fh in stale:
                del self._fh_to_entry[fh]

    def rename(
        self, from_dir: Path, from_name: str, to_dir: Path, to_name: str
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
            old_prefix = str(old_path) + os.sep
            new_prefix = str(new_path) + os.sep
            for fh, (root, path) in list(self._fh_to_entry.items()):
                path_str = str(path)
                if path_str == str(old_path):
                    self._fh_to_entry[fh] = (root, new_path)
                elif path_str.startswith(old_prefix):
                    self._fh_to_entry[fh] = (
                        root,
                        Path(new_prefix + path_str[len(old_prefix) :]),
                    )

    def symlink(self, dir_path: Path, name: str, target: str) -> Path:
        self.validate_create_name(name)
        link_path = dir_path / name
        try:
            os.symlink(target, link_path)
        except OSError as e:
            raise_for_oserror(e)
        return link_path

    def readlink(self, path: Path) -> str:
        try:
            return os.readlink(path)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')

    def link(self, target_path: Path, dir_path: Path, name: str):
        self.validate_create_name(name)
        link_path = dir_path / name
        try:
            os.link(target_path, link_path)
        except OSError as e:
            raise_for_oserror(e)

    def mknod(self, dir_path: Path, name: str, mode: int, device: int = 0):
        self.validate_create_name(name)
        target = dir_path / name
        try:
            os.mknod(target, mode, device)
        except PermissionError as e:
            raise NfsError(NFS3ERR_PERM) from e
        except OSError as e:
            raise_for_oserror(e)
        return target

    def setattr(
        self,
        path: Path,
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
            if atime_ns is not None or mtime_ns is not None:
                st = self.stat(path)
                a = atime_ns if atime_ns is not None else st.st_atime_ns
                m = mtime_ns if mtime_ns is not None else st.st_mtime_ns
                os.utime(path, ns=(a, m), follow_symlinks=False)
        except OSError as e:
            raise_for_oserror(e)

    def statvfs(self, path: Path):
        try:
            return os.statvfs(path)
        except OSError as e:
            raise_for_oserror(e)
            raise AssertionError('unreachable')

    def access_ok(self, path: Path, mode: int) -> bool:
        return os.access(path, mode)
