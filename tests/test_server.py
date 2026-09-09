import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from nfs3_server.server import NfsServer

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


if __name__ == '__main__':
    unittest.main()
