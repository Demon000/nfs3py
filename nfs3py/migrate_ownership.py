"""One-time, offline preparation for exporting a real-permissions rootfs
through nfs3py without running the server itself privileged.

nfs3py always runs as whatever unprivileged OS user starts it, and Linux
enforces file permission checks against that real process uid regardless
of what the NFS client claims - so root-owned, owner-only files
(/etc/shadow, SSH host keys, ...) are unreadable to it, breaking anything
that needs them (login, sshd, ...).

This script fixes that once, offline, rather than needing the live server
to run privileged: for every file under the given tree, it records the
*real* current (uid, gid) into a user.nfs3_owner xattr, then chows the
file to the target user (default: whoever invoked sudo, not root - see
_default_target_id()). The live server reads that xattr when answering
GETATTR/SETATTR (see fs.py), so NFS clients still see the original
ownership - only the on-disk owner (irrelevant to anything but local
permission checks on this host) changes.

Idempotent: the tag and the chown are checked independently, so re-running
only does whichever part (if any) a given entry still needs - safe to
re-run after adding files, or after an interrupted/partial previous run.

Usage (needs to run as root, or as whoever already owns every file under
the tree - typically neither is true for a real rootfs, hence sudo):
    sudo python3 -m nfs3py.migrate_ownership /srv/nfs/some-rootfs
    sudo python3 -m nfs3py.migrate_ownership /srv/nfs/some-rootfs --uid 1000 --gid 1000
"""

import argparse
import os
import stat
import sys
from collections import Counter

from .fs import read_owner_xattr, write_owner_xattr


def _default_target_id() -> tuple[int, int] | None:
    # Under `sudo`, os.getuid()/os.getgid() report root (this process's
    # own real ids), not the invoking user - sudo instead sets SUDO_UID/
    # SUDO_GID for exactly this purpose. Fall back to the real ids only
    # when not running under sudo (e.g. an actual root login).
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    if sudo_uid is not None and sudo_gid is not None:
        return int(sudo_uid), int(sudo_gid)
    if os.getuid() != 0:
        return os.getuid(), os.getgid()
    return None


def _migrate_one(path: str, uid: int, gid: int) -> str:
    try:
        st = os.lstat(path)
    except OSError as e:
        print(f'skip {path}: {e}', file=sys.stderr)
        return 'error'

    if stat.S_ISLNK(st.st_mode):
        # Linux doesn't support user.* xattrs on symlinks at all - skip
        # the doomed syscalls entirely rather than attempting and
        # reporting a "failure" for something that can never work.
        # Harmless: the kernel never consults a symlink's own ownership
        # when following it, only the target's.
        return 'symlink'

    changed = False

    if read_owner_xattr(path) is None:
        write_owner_xattr(path, st.st_uid, st.st_gid)
        if read_owner_xattr(path) is None:
            print(
                f'warning: xattr did not stick on {path}'
                ' (filesystem may not support user xattrs here)'
                ' - leaving ownership untouched',
                file=sys.stderr,
            )
            return 'error'
        changed = True

    if st.st_uid != uid or st.st_gid != gid:
        try:
            os.chown(path, uid, gid, follow_symlinks=False)
            changed = True
        except OSError as e:
            print(f'chown failed for {path}: {e}', file=sys.stderr)
            return 'error'

    return 'changed' if changed else 'unchanged'


def migrate(root: str, uid: int, gid: int) -> Counter:
    counts: Counter = Counter()

    # os.walk() only yields root's *contents*, never root itself.
    entries = [root]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        entries.extend(
            os.path.join(dirpath, name) for name in dirnames + filenames
        )

    for path in entries:
        counts[_migrate_one(path, uid, gid)] += 1

    return counts


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('root', help='export directory to migrate')
    parser.add_argument('--uid', type=int, help='target uid')
    parser.add_argument('--gid', type=int, help='target gid')
    args = parser.parse_args()

    if args.uid is None or args.gid is None:
        default = _default_target_id()
        if default is None:
            parser.error(
                'running as root with no SUDO_UID/SUDO_GID in the '
                'environment and no --uid/--gid given - refusing to '
                'guess (defaulting to root would silently no-op, since '
                'root-owned files are already root-owned)'
            )
        args.uid = args.uid if args.uid is not None else default[0]
        args.gid = args.gid if args.gid is not None else default[1]

    print(f'migrating {args.root} to {args.uid}:{args.gid}')
    counts = migrate(args.root, args.uid, args.gid)
    print(
        f'{counts["changed"]} entries changed, '
        f'{counts["unchanged"]} already correct, '
        f'{counts["symlink"]} symlinks skipped, '
        f'{counts["error"]} errors'
    )


if __name__ == '__main__':
    main()
