# nfs3py

An NFSv3 server, written in plain Python with no dependencies. It runs as
a normal unprivileged process on a single TCP port you choose. The MOUNT
protocol shares that same port, so nothing needs a portmapper or a
privileged bind. ONC RPC, XDR, and NFSv3 itself (all 22 procedures, full
read/write) are implemented directly from RFC 5531, RFC 4506, and
RFC 1813.

Import `NfsServer` and start/stop it from inside another process. One
example: serving a live directory over NFS for the duration of some
other task.

## Usage

```python
from dataclasses import dataclass
from nfs3py.server import NfsServer


@dataclass
class NfsConfig:
    mounts: list[tuple[str, str]]  # (real_dir, exported_path) pairs
    server_ip: str
    server_port: str


config = NfsConfig(
    mounts=[('/srv/my-rootfs', '/srv/my-rootfs')],
    server_ip='0.0.0.0',
    server_port='2049',
)

# `resolve` is called on every config string (mounts, server_ip,
# server_port) right before it's used, so a host application can thread
# live template substitution (${arg}-style) through it. Pass the
# identity function if you don't need that.
server = NfsServer(config, resolve=lambda s: s)
server.start()
...
server.stop()
```

Clients must mount with explicit `port=`/`mountport=` options, e.g.:

```
mount -t nfs -o vers=3,proto=tcp,port=2049,mountport=2049,nolock \
    127.0.0.1:/srv/my-rootfs /mnt
```

### Grafting a second real directory into an export

`mounts` entries are matched by longest prefix, first match in list order
wins. That lets a second directory sit at a sub-path of a broader
export without copying anything in, e.g. serving a separately-built tree
at `lib/modules` inside an already-exported rootfs:

```python
mounts = [
    ('/build/output/lib/modules', '/srv/my-rootfs/lib/modules'),
    ('/srv/my-rootfs', '/srv/my-rootfs'),
]
```

The graft entry must be listed before the broader export it nests under.

### Reporting ownership the server can't actually have

The server runs unprivileged, so it can't `chown` files to arbitrary
uids, and it can't read files only readable by another real user (e.g.
`/etc/shadow`, SSH host keys). Linux checks permissions against the
real process uid, regardless of what an NFS client's `AUTH_SYS`
credentials claim.

`nfs3py.migrate_ownership` is a one-time, offline tool that tags each
file's current (uid, gid) into a `user.nfs3_owner` xattr, then `chown`s it
to the uid the server will actually run as. The live server reads that
xattr when answering GETATTR/SETATTR, so NFS clients still see the
original ownership even though the real on-disk owner (irrelevant to
anything but this host's own permission checks) has changed:

```
sudo python3 -m nfs3py.migrate_ownership /srv/my-rootfs --uid 1000 --gid 1000
```

## Known limitations

`SETATTR`'s mode change on an already-open file descriptor isn't
reflected for reads/writes still in flight on that fd, since there's no
server-side open-file cache. That's the one Connectathon (`cthon04`)
`special` suite case (`op_chmod`) that doesn't pass; `basic` and
`general` pass in full.

File handles live in an in-memory table scoped to one server process.
Restarting the server invalidates every outstanding handle (clients see
`ESTALE`), same as most non-persistent NFS server setups.

## Testing

```
python3 -m unittest nfs3py.tests.test_server
```

The Connectathon (`cthon04`) suite can also be run against the server via
[`fuse-nfs`](https://github.com/sahlberg/fuse-nfs)/`libnfs`, entirely
without root (`mount(2)` for NFS is blocked in unprivileged user
namespaces, but a FUSE bridge isn't).

## License

MIT
