import os
import shutil
import socket
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from nfs3py.server import NfsServer

from .rpc_client import (
    RpcClient,
    RpcError,
    opaque,
    sattr3_unset,
    string,
    u32,
    u64,
)

NFS3_FHSIZE = 64

MOUNT_NULL, MOUNT_MNT = 0, 1

NULL = 0
GETATTR = 1
SETATTR = 2
LOOKUP = 3
ACCESS = 4
READLINK = 5
READ = 6
WRITE = 7
CREATE = 8
MKDIR = 9
SYMLINK = 10
REMOVE = 12
RMDIR = 13
RENAME = 14
LINK = 15
READDIR = 16
FSSTAT = 18
FSINFO = 19
PATHCONF = 20
COMMIT = 21


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _NfsConfig:
    def __init__(self, mounts, server_ip, server_port):
        self.mounts = mounts
        self.server_ip = server_ip
        self.server_port = server_port


class Nfs3ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='nfs3-test-')
        cls.export_dir = Path(cls.tmpdir) / 'export'
        cls.export_dir.mkdir()
        (cls.export_dir / 'greeting.txt').write_bytes(b'hello nfs3\n')
        (cls.export_dir / 'subdir').mkdir()

        cls.port = _free_port()
        config = _NfsConfig(
            mounts=[(str(cls.export_dir), '/export')],
            server_ip='127.0.0.1',
            server_port=str(cls.port),
        )
        cls.server = NfsServer(config, lambda s: s)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.client = RpcClient('127.0.0.1', self.port)
        self.addCleanup(self.client.close)
        r = self.client.call(100005, 3, MOUNT_MNT, string('/export'))
        self.assertEqual(r.u32(), 0)
        self.root_fh = r.opaque()

    def lookup(self, dir_fh, name):
        r = self.client.call(100003, 3, LOOKUP, opaque(dir_fh) + string(name))
        self.assertEqual(r.u32(), 0)
        fh = r.opaque()
        r.skip_post_op_attr()
        r.skip_post_op_attr()
        return fh

    def getattr(self, fh):
        r = self.client.call(100003, 3, GETATTR, opaque(fh))
        self.assertEqual(r.u32(), 0)
        return r

    def create(self, dir_fh, name):
        args = opaque(dir_fh) + string(name) + u32(0) + sattr3_unset()
        r = self.client.call(100003, 3, CREATE, args)
        self.assertEqual(r.u32(), 0)
        self.assertTrue(r.bool())
        return r.opaque()

    def mkdir(self, dir_fh, name):
        args = opaque(dir_fh) + string(name) + sattr3_unset()
        r = self.client.call(100003, 3, MKDIR, args)
        self.assertEqual(r.u32(), 0)
        self.assertTrue(r.bool())
        return r.opaque()

    def write(self, fh, offset, data):
        args = opaque(fh) + u64(offset) + u32(len(data)) + u32(2) + opaque(data)
        r = self.client.call(100003, 3, WRITE, args)
        self.assertEqual(r.u32(), 0)
        return r

    def read(self, fh, offset, count):
        args = opaque(fh) + u64(offset) + u32(count)
        r = self.client.call(100003, 3, READ, args)
        self.assertEqual(r.u32(), 0)
        r.skip_post_op_attr()
        r.u32()
        eof = r.bool()
        data = r.opaque()
        return data, eof

    def test_mount_null_and_nfs_null(self):
        self.client.call(100005, 3, MOUNT_NULL, b'')
        self.client.call(100003, 3, NULL, b'')

    def test_mount_unknown_export_fails(self):
        r = self.client.call(100005, 3, MOUNT_MNT, string('/no-such-export'))
        self.assertEqual(r.u32(), 2)  # MNT3ERR_NOENT

    def test_unknown_procedure_is_rpc_level_error(self):
        with self.assertRaises(RpcError):
            self.client.call(100003, 3, 99, b'')

    def test_getattr_root_is_directory(self):
        r = self.getattr(self.root_fh)
        ftype = r.u32()
        self.assertEqual(ftype, 2)

    def test_lookup_existing_file_and_read(self):
        fh = self.lookup(self.root_fh, 'greeting.txt')
        data, eof = self.read(fh, 0, 4096)
        self.assertEqual(data, b'hello nfs3\n')
        self.assertTrue(eof)

    def test_lookup_missing_file_fails(self):
        r = self.client.call(
            100003, 3, LOOKUP, opaque(self.root_fh) + string('nope.txt')
        )
        status = r.u32()
        self.assertEqual(status, 2)  # NFS3ERR_NOENT

    def test_dotdot_navigation(self):
        subdir_fh = self.lookup(self.root_fh, 'subdir')
        parent_fh = self.lookup(subdir_fh, '..')
        self.assertEqual(parent_fh, self.root_fh)

    def test_create_write_read(self):
        fh = self.create(self.root_fh, 'created.txt')
        self.write(fh, 0, b'written over nfs3')
        data, eof = self.read(fh, 0, 4096)
        self.assertEqual(data, b'written over nfs3')
        self.assertTrue(eof)

    def test_mkdir_and_readdir(self):
        self.mkdir(self.root_fh, 'newdir')
        args = opaque(self.root_fh) + u64(0) + b'\x00' * 8 + u32(4096)
        r = self.client.call(100003, 3, READDIR, args)
        self.assertEqual(r.u32(), 0)
        r.skip_post_op_attr()
        r.opaque_fixed(8)
        names = []
        while r.bool():
            r.u64()
            names.append(r.string())
            r.u64()
        self.assertTrue(r.bool())
        self.assertIn('newdir', names)
        self.assertIn('greeting.txt', names)
        self.assertIn('.', names)
        self.assertIn('..', names)

    def test_symlink_and_readlink(self):
        args = (
            opaque(self.root_fh)
            + string('mylink')
            + sattr3_unset()
            + string('/some/target')
        )
        r = self.client.call(100003, 3, SYMLINK, args)
        self.assertEqual(r.u32(), 0)

        link_fh = self.lookup(self.root_fh, 'mylink')
        r = self.getattr(link_fh)
        ftype = r.u32()
        self.assertEqual(ftype, 5)  # NF3LNK

        r = self.client.call(100003, 3, READLINK, opaque(link_fh))
        self.assertEqual(r.u32(), 0)
        r.skip_post_op_attr()
        self.assertEqual(r.string(), '/some/target')

    def test_symlink_with_mode_attr_to_dangling_target(self):
        # Real clients (e.g. libnfs) set mode.set_it=True with a mode value
        # on SYMLINK's attributes. chmod()/truncate() follow symlinks by
        # default, so naively applying that mode would try to modify
        # whatever the (possibly nonexistent) target points at instead of
        # the symlink itself.
        mode_set_777 = u32(1) + u32(0o777) + u32(0) * 5
        args = (
            opaque(self.root_fh)
            + string('danglelink')
            + mode_set_777
            + string('/nonexistent/target')
        )
        r = self.client.call(100003, 3, SYMLINK, args)
        self.assertEqual(r.u32(), 0)

        link_fh = self.lookup(self.root_fh, 'danglelink')
        r = self.getattr(link_fh)
        ftype = r.u32()
        self.assertEqual(ftype, 5)  # NF3LNK

    def test_link_creates_second_name_same_handle(self):
        target_fh = self.create(self.root_fh, 'linktarget.txt')
        args = opaque(target_fh) + opaque(self.root_fh) + string('linkname.txt')
        r = self.client.call(100003, 3, LINK, args)
        self.assertEqual(r.u32(), 0)

        r = self.getattr(target_fh)
        r.u32()
        r.u32()
        nlink = r.u32()
        self.assertEqual(nlink, 2)

        other_fh = self.lookup(self.root_fh, 'linkname.txt')
        self.assertEqual(other_fh, target_fh)

    def test_rename_preserves_handle_identity(self):
        fh = self.create(self.root_fh, 'before.txt')
        self.write(fh, 0, b'payload')

        args = (
            opaque(self.root_fh)
            + string('before.txt')
            + opaque(self.root_fh)
            + string('after.txt')
        )
        r = self.client.call(100003, 3, RENAME, args)
        self.assertEqual(r.u32(), 0)

        data, _eof = self.read(fh, 0, 4096)
        self.assertEqual(data, b'payload')

        renamed_fh = self.lookup(self.root_fh, 'after.txt')
        self.assertEqual(renamed_fh, fh)

    def test_remove_then_stale_handle(self):
        fh = self.create(self.root_fh, 'toremove.txt')
        args = opaque(self.root_fh) + string('toremove.txt')
        r = self.client.call(100003, 3, REMOVE, args)
        self.assertEqual(r.u32(), 0)

        r = self.client.call(100003, 3, GETATTR, opaque(fh))
        status = r.u32()
        self.assertEqual(status, 70)  # NFS3ERR_STALE

    def test_rmdir(self):
        self.mkdir(self.root_fh, 'emptydir')
        args = opaque(self.root_fh) + string('emptydir')
        r = self.client.call(100003, 3, RMDIR, args)
        self.assertEqual(r.u32(), 0)

        r = self.client.call(
            100003, 3, LOOKUP, opaque(self.root_fh) + string('emptydir')
        )
        self.assertEqual(r.u32(), 2)  # NFS3ERR_NOENT

    def test_access_rejects_path_traversal_component(self):
        args = opaque(self.root_fh) + string('../etc/passwd')
        r = self.client.call(100003, 3, LOOKUP, args)
        status = r.u32()
        self.assertEqual(status, 13)  # NFS3ERR_ACCES

    def test_fsstat_fsinfo_pathconf(self):
        for proc in (FSSTAT, FSINFO, PATHCONF):
            r = self.client.call(100003, 3, proc, opaque(self.root_fh))
            self.assertEqual(r.u32(), 0)

    def test_commit(self):
        fh = self.create(self.root_fh, 'commit.txt')
        self.write(fh, 0, b'data')
        args = opaque(fh) + u64(0) + u32(4)
        r = self.client.call(100003, 3, COMMIT, args)
        self.assertEqual(r.u32(), 0)

    def test_write_and_read_succeed_after_chmod_zero_on_same_handle(self):
        # Mirrors cthon04's special/op_chmod.c: create, chmod(0), then
        # write/read through the handle obtained at create time. A fresh
        # per-RPC open() would see the now-zero mode and fail with EACCES
        # - fds are pre-warmed at CREATE time specifically so this still
        # works, matching local open()-time permission semantics.
        fh = self.create(self.root_fh, 'chmod_then_write.txt')

        args = (
            opaque(fh)
            + u32(1)
            + u32(0)  # mode set to 0
            + u32(0)  # uid not set
            + u32(0)  # gid not set
            + u32(0)  # size not set
            + u32(0)  # atime DONT_CHANGE
            + u32(0)  # mtime DONT_CHANGE
            + u32(0)  # sattrguard3.check
        )
        r = self.client.call(100003, 3, SETATTR, args)
        self.assertEqual(r.u32(), 0)

        self.write(fh, 0, b'written after chmod 0')
        data, _eof = self.read(fh, 0, 4096)
        self.assertEqual(data, b'written after chmod 0')


class GraftedMountTestCase(unittest.TestCase):
    """A second real directory grafted onto a sub-path of an export -
    e.g. serving a separately-built kernel modules tree at lib/modules
    inside an exported rootfs without copying it in."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='nfs3-graft-test-')
        cls.export_dir = Path(cls.tmpdir) / 'export'
        cls.graft_dir = Path(cls.tmpdir) / 'graft'
        (cls.export_dir / 'lib').mkdir(parents=True)
        cls.graft_dir.mkdir()
        (cls.export_dir / 'lib' / 'libc.so.fake').write_bytes(b'from export\n')
        (cls.graft_dir / 'foo.ko').write_bytes(b'from graft\n')

        cls.port = _free_port()
        config = _NfsConfig(
            # graft listed before the broader export it nests under -
            # first match in list order wins, same precedence rule as
            # TFTP's dyn_file_func.
            mounts=[
                (str(cls.graft_dir), '/export/lib/modules'),
                (str(cls.export_dir), '/export'),
            ],
            server_ip='127.0.0.1',
            server_port=str(cls.port),
        )
        cls.server = NfsServer(config, lambda s: s)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.client = RpcClient('127.0.0.1', self.port)
        self.addCleanup(self.client.close)
        r = self.client.call(100005, 3, MOUNT_MNT, string('/export'))
        self.assertEqual(r.u32(), 0)
        self.root_fh = r.opaque()

    def lookup(self, dir_fh, name):
        r = self.client.call(100003, 3, LOOKUP, opaque(dir_fh) + string(name))
        self.assertEqual(r.u32(), 0)
        fh = r.opaque()
        r.skip_post_op_attr()
        r.skip_post_op_attr()
        return fh

    def read(self, fh):
        args = opaque(fh) + u64(0) + u32(4096)
        r = self.client.call(100003, 3, READ, args)
        self.assertEqual(r.u32(), 0)
        r.skip_post_op_attr()
        r.u32()
        r.bool()
        return r.opaque()

    def test_lookup_reaches_grafted_real_directory(self):
        lib_fh = self.lookup(self.root_fh, 'lib')
        modules_fh = self.lookup(lib_fh, 'modules')
        foo_fh = self.lookup(modules_fh, 'foo.ko')
        self.assertEqual(self.read(foo_fh), b'from graft\n')

    def test_readdir_of_parent_includes_graft_entry(self):
        # 'modules' has no real on-disk entry under export_dir/lib - only
        # LOOKUP-by-name resolves it via resolve_real_path(). A plain
        # READDIR of the parent must still list it, or anything that
        # discovers files by listing (ls, find, depmod) would silently
        # miss the whole grafted tree.
        lib_fh = self.lookup(self.root_fh, 'lib')
        args = opaque(lib_fh) + u64(0) + b'\x00' * 8 + u32(4096)
        r = self.client.call(100003, 3, READDIR, args)
        self.assertEqual(r.u32(), 0)
        r.skip_post_op_attr()
        r.opaque_fixed(8)
        names = []
        while r.bool():
            r.u64()
            names.append(r.string())
            r.u64()
        self.assertTrue(r.bool())
        self.assertIn('modules', names)
        self.assertIn('libc.so.fake', names)

    def test_graft_does_not_shadow_sibling_files(self):
        lib_fh = self.lookup(self.root_fh, 'lib')
        libc_fh = self.lookup(lib_fh, 'libc.so.fake')
        self.assertEqual(self.read(libc_fh), b'from export\n')

    def test_dotdot_from_graft_returns_to_export_lib(self):
        lib_fh = self.lookup(self.root_fh, 'lib')
        modules_fh = self.lookup(lib_fh, 'modules')
        back_fh = self.lookup(modules_fh, '..')
        self.assertEqual(back_fh, lib_fh)

    def test_write_inside_graft_lands_on_graft_disk_not_export(self):
        lib_fh = self.lookup(self.root_fh, 'lib')
        modules_fh = self.lookup(lib_fh, 'modules')
        args = opaque(modules_fh) + string('bar.ko') + u32(0) + sattr3_unset()
        r = self.client.call(100003, 3, CREATE, args)
        self.assertEqual(r.u32(), 0)

        self.assertTrue((self.graft_dir / 'bar.ko').exists())
        self.assertFalse(
            (self.export_dir / 'lib' / 'modules' / 'bar.ko').exists()
        )


class OwnershipMappingTestCase(unittest.TestCase):
    """Lets the server report ownership (e.g. root-owned system files)
    that differs from the real host uid/gid it's actually running as -
    needed because the server runs unprivileged, so a real chown to an
    arbitrary uid always fails, and files genuinely owned by another user
    on the host are otherwise unreadable to it."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='nfs3-owner-test-')
        cls.export_dir = Path(cls.tmpdir) / 'export'
        cls.export_dir.mkdir()
        (cls.export_dir / 'tagged.txt').write_bytes(b'x')
        os.setxattr(
            cls.export_dir / 'tagged.txt',
            'user.nfs3_owner',
            b'1234:5678',
            follow_symlinks=False,
        )

        cls.port = _free_port()
        config = _NfsConfig(
            mounts=[(str(cls.export_dir), '/export')],
            server_ip='127.0.0.1',
            server_port=str(cls.port),
        )
        cls.server = NfsServer(config, lambda s: s)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.client = RpcClient('127.0.0.1', self.port)
        self.addCleanup(self.client.close)
        r = self.client.call(100005, 3, MOUNT_MNT, string('/export'))
        self.assertEqual(r.u32(), 0)
        self.root_fh = r.opaque()

    def lookup(self, client, dir_fh, name):
        r = client.call(100003, 3, LOOKUP, opaque(dir_fh) + string(name))
        self.assertEqual(r.u32(), 0)
        fh = r.opaque()
        r.skip_post_op_attr()
        r.skip_post_op_attr()
        return fh

    def getattr_owner(self, client, fh):
        r = client.call(100003, 3, GETATTR, opaque(fh))
        self.assertEqual(r.u32(), 0)
        r.u32()  # type
        r.u32()  # mode
        r.u32()  # nlink
        uid = r.u32()
        gid = r.u32()
        return uid, gid

    def test_getattr_reports_xattr_tagged_owner_not_real_owner(self):
        fh = self.lookup(self.client, self.root_fh, 'tagged.txt')
        uid, gid = self.getattr_owner(self.client, fh)
        self.assertEqual((uid, gid), (1234, 5678))
        self.assertNotEqual((uid, gid), (os.getuid(), os.getgid()))

    @unittest.skipIf(os.getuid() == 0, 'meaningless when run as root')
    def test_setattr_owner_change_is_reported_without_needing_real_chown(
        self,
    ):
        fh = self.lookup(self.client, self.root_fh, 'tagged.txt')
        args = (
            opaque(fh)
            + u32(0)  # mode not set
            + u32(1)
            + u32(4242)  # uid set
            + u32(1)
            + u32(4343)  # gid set
            + u32(0)  # size not set
            + u32(0)  # atime DONT_CHANGE
            + u32(0)  # mtime DONT_CHANGE
            + u32(0)  # sattrguard3.check: no ctime guard
        )
        r = self.client.call(100003, 3, SETATTR, args)
        self.assertEqual(r.u32(), 0)

        uid, gid = self.getattr_owner(self.client, fh)
        self.assertEqual((uid, gid), (4242, 4343))

        real_st = os.stat(self.export_dir / 'tagged.txt')
        self.assertEqual(real_st.st_uid, os.getuid())
        self.assertNotEqual(real_st.st_uid, 4242)

    @unittest.skipIf(os.getuid() == 0, 'meaningless when run as root')
    def test_create_tags_new_file_with_claimed_auth_sys_owner(self):
        privileged_client = RpcClient(
            '127.0.0.1', self.port, auth_uid=0, auth_gid=0
        )
        self.addCleanup(privileged_client.close)
        r = privileged_client.call(100005, 3, MOUNT_MNT, string('/export'))
        self.assertEqual(r.u32(), 0)
        root_fh = r.opaque()

        args = (
            opaque(root_fh)
            + string('created_as_root.txt')
            + u32(0)
            + sattr3_unset()
        )
        r = privileged_client.call(100003, 3, CREATE, args)
        self.assertEqual(r.u32(), 0)

        fh = self.lookup(privileged_client, root_fh, 'created_as_root.txt')
        uid, gid = self.getattr_owner(privileged_client, fh)
        self.assertEqual((uid, gid), (0, 0))

        real_st = os.stat(self.export_dir / 'created_as_root.txt')
        self.assertNotEqual(real_st.st_uid, 0)
        self.assertEqual(real_st.st_uid, os.getuid())


UNSTABLE, DATA_SYNC, FILE_SYNC = 0, 1, 2


class WriteStabilityTestCase(unittest.TestCase):
    """UNSTABLE writes must not fsync on every RPC (that's the whole
    point of the stability flag - it lets a client batch many writes and
    force durability once via COMMIT), but a stable WRITE or a COMMIT
    still must."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='nfs3-stability-test-')
        cls.export_dir = Path(cls.tmpdir) / 'export'
        cls.export_dir.mkdir()
        (cls.export_dir / 'f.txt').write_bytes(b'0123456789')

        cls.port = _free_port()
        config = _NfsConfig(
            mounts=[(str(cls.export_dir), '/export')],
            server_ip='127.0.0.1',
            server_port=str(cls.port),
        )
        cls.server = NfsServer(config, lambda s: s)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.client = RpcClient('127.0.0.1', self.port)
        self.addCleanup(self.client.close)
        r = self.client.call(100005, 3, MOUNT_MNT, string('/export'))
        self.assertEqual(r.u32(), 0)
        self.root_fh = r.opaque()
        r = self.client.call(
            100003, 3, LOOKUP, opaque(self.root_fh) + string('f.txt')
        )
        self.assertEqual(r.u32(), 0)
        self.fh = r.opaque()
        r.skip_post_op_attr()
        r.skip_post_op_attr()

    def write(self, stable, data=b'x'):
        args = (
            opaque(self.fh)
            + u64(0)
            + u32(len(data))
            + u32(stable)
            + opaque(data)
        )
        r = self.client.call(100003, 3, WRITE, args)
        self.assertEqual(r.u32(), 0)
        r.skip_wcc_data()
        r.u32()
        return r.u32()  # committed

    def test_unstable_write_does_not_fsync(self):
        with unittest.mock.patch('nfs3py.fs.os.fsync') as fsync:
            committed = self.write(UNSTABLE)
        fsync.assert_not_called()
        self.assertEqual(committed, UNSTABLE)

    def test_file_sync_write_fsyncs(self):
        with unittest.mock.patch('nfs3py.fs.os.fsync') as fsync:
            committed = self.write(FILE_SYNC)
        fsync.assert_called_once()
        self.assertEqual(committed, FILE_SYNC)

    def test_commit_fsyncs(self):
        with unittest.mock.patch('nfs3py.fs.os.fsync') as fsync:
            args = opaque(self.fh) + u64(0) + u32(0)
            r = self.client.call(100003, 3, COMMIT, args)
            self.assertEqual(r.u32(), 0)
        fsync.assert_called_once()


if __name__ == '__main__':
    unittest.main()
