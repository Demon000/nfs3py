import argparse
import threading
from dataclasses import dataclass

from .server import NfsServer


@dataclass
class _Config:
    mounts: list[tuple[str, str]]
    server_ip: str
    server_port: str


def _mount_arg(value: str) -> tuple[str, str]:
    if ':' not in value:
        raise argparse.ArgumentTypeError(
            f'expected REAL_DIR:EXPORTED_PATH, got {value!r}'
        )
    real, virt = value.split(':', 1)
    return real, virt


def main():
    parser = argparse.ArgumentParser(
        prog='nfs3py',
        description='Serve one or more directories over NFSv3, unprivileged.',
    )
    parser.add_argument(
        '--mount',
        metavar='REAL_DIR:EXPORTED_PATH',
        type=_mount_arg,
        action='append',
        required=True,
        help='real directory to export at the given path; repeatable. '
        'Earlier --mount entries take precedence over later, overlapping '
        'ones (e.g. to graft a directory under a broader export).',
    )
    parser.add_argument(
        '--host', default='0.0.0.0', help='listen address (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port', default='2049', help='listen TCP port (default: 2049)'
    )
    args = parser.parse_args()

    config = _Config(
        mounts=args.mount, server_ip=args.host, server_port=args.port
    )
    server = NfsServer(config, resolve=lambda s: s)
    server.start()

    print(f'nfs3py listening on {args.host}:{args.port}')
    for real, virt in args.mount:
        print(f'  {virt} -> {real}')
    print(
        'Mount with: mount -t nfs -o '
        f'vers=3,proto=tcp,port={args.port},mountport={args.port},nolock '
        f'{args.host}:<EXPORTED_PATH> /mnt'
    )

    stop_event = threading.Event()
    try:
        stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == '__main__':
    main()
