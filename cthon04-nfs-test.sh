#!/bin/bash

SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

CACHE_DIR="$SCRIPT_DIR/.cache/nfs-tests"
CTHON04_DIR="$CACHE_DIR/cthon04"
FUSE_NFS_DIR="$CACHE_DIR/fuse-nfs"
FUSE_NFS_BIN="$FUSE_NFS_DIR/fuse/fuse-nfs"

# export/mnt are the live, actively-written filesystem the test suite churns
# through - they must NOT live inside the (editor-watched) repo tree. Since
# inotify doesn't propagate through a FUSE-over-NFS mount, an IDE/indexer
# recursively watching a repo that contains the mount falls back to polling
# it, and with fuse-nfs's caching disabled below (needed for accurate
# results) every poll becomes a full uncached RPC round trip - a busy loop
# that isn't fuse-nfs's or the server's fault, just bad mount placement.
RUN_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/nfs3py-cthon04-test"
EXPORT_DIR="$RUN_DIR/export"
MOUNT_DIR="$RUN_DIR/mnt"
PORT=20490

print_usage() {
	echo "usage: $0 [-c]"
	echo "runs the connectathon (cthon04) NFS test suite against nfs3py,"
	echo "through fuse-nfs (libnfs), entirely without root."
	echo "options:"
	echo "	-c: clean the cached/built cthon04 and fuse-nfs trees and rebuild"
	exit 1
}

while [[ $# -gt 0 ]]; do
	case $1 in
	-c)
		rm -rf "$CACHE_DIR"
		shift
		;;
	-h|--help)
		print_usage
		;;
	*)
		print_usage
		;;
	esac
done

for tool in git gcc autoreconf automake libtoolize fusermount3; do
	if ! command -v "$tool" >/dev/null; then
		echo "missing required tool: $tool"
		exit 1
	fi
done
if ! pkg-config --exists fuse3; then
	echo "missing fuse3 pkg-config (libfuse3 development headers)"
	exit 1
fi
if ! pkg-config --exists libnfs; then
	echo "missing libnfs pkg-config (libnfs development headers)"
	exit 1
fi

mkdir -p "$CACHE_DIR"

if [ ! -d "$CTHON04_DIR" ]; then
	git clone --depth 1 https://github.com/phdeniel/cthon04.git "$CTHON04_DIR"
fi

if [ ! -d "$FUSE_NFS_DIR" ]; then
	git clone --depth 1 https://github.com/sahlberg/fuse-nfs.git "$FUSE_NFS_DIR"
fi

# Modern GCC (14+) hard-errors on implicit function declarations that this
# 2003-era codebase relies on; -std=gnu89 plus a few -Wno-* flags restore
# the old permissive behavior.
if ! grep -q 'std=gnu89' "$CTHON04_DIR/tests.init"; then
	sed -i \
		's/^CFLAGS=`echo -DLINUX -DHAVE_SOCKLEN_T -DGLIBC=22 -DMMAP -DSTDARG`$/CFLAGS=`echo -DLINUX -DHAVE_SOCKLEN_T -DGLIBC=22 -DMMAP -DSTDARG -std=gnu89 -Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion -Wno-return-mismatch -Wno-incompatible-pointer-types`/' \
		"$CTHON04_DIR/tests.init"
fi

if [ ! -x "$FUSE_NFS_BIN" ]; then
	(
		cd "$FUSE_NFS_DIR"
		./setup.sh
		./configure
		make -j"$(nproc)"
	)
fi

(
	cd "$CTHON04_DIR"
	make domount getopt
	cd basic && make
	cd ../general && make
	cd ../special && make
)

rm -rf "$EXPORT_DIR" "$MOUNT_DIR"
mkdir -p "$EXPORT_DIR" "$MOUNT_DIR"

PYTHONPATH="$SCRIPT_DIR" python3 -m nfs3py \
	--mount "$EXPORT_DIR:/export" \
	--host 127.0.0.1 \
	--port "$PORT" &
SERVER_PID=$!

cleanup() {
	fusermount3 -u "$MOUNT_DIR" 2>/dev/null
	kill "$SERVER_PID" 2>/dev/null
	wait "$SERVER_PID" 2>/dev/null
	rm -rf "$RUN_DIR"
}
trap cleanup EXIT

sleep 1

# -E/-T/-N/-C 0 disable fuse-nfs's attribute/entry caching: with it on, a
# stat() immediately after another client op (e.g. link()'s nlink check in
# cthon04's basic/test7) can read back a stale cached value instead of
# round-tripping to the server, producing false failures.
"$FUSE_NFS_BIN" \
	-n "nfs://127.0.0.1/export?version=3&nfsport=$PORT&mountport=$PORT" \
	-m "$MOUNT_DIR" \
	-E 0 -T 0 -N 0 -C 0
sleep 1

if ! mountpoint -q "$MOUNT_DIR"; then
	echo "fuse-nfs failed to mount"
	exit 1
fi

FAILED=0

export NFSTESTDIR="$MOUNT_DIR/cthon_test"
for suite in basic general special; do
	echo "=== $suite ==="
	rm -rf "$NFSTESTDIR"
	(cd "$CTHON04_DIR/$suite" && sh runtests -f)
	if [ $? -ne 0 ]; then
		echo "$suite: FAILED"
		FAILED=1
	fi
done

exit $FAILED
