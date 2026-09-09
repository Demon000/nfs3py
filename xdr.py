import os
import struct
from collections.abc import Iterable


class XdrDecodeError(Exception):
    pass


class XdrWriter:
    def __init__(self):
        self.buf = bytearray()

    def to_bytes(self) -> bytes:
        return bytes(self.buf)

    def raw(self, data: bytes):
        self.buf += data

    def u32(self, value: int):
        self.buf += struct.pack('>I', value & 0xFFFFFFFF)

    def i32(self, value: int):
        self.buf += struct.pack('>i', value)

    def u64(self, value: int):
        self.buf += struct.pack('>Q', value & 0xFFFFFFFFFFFFFFFF)

    def bool(self, value: bool):
        self.u32(1 if value else 0)

    def _pad(self, n: int):
        r = (-n) % 4
        if r:
            self.buf += b'\x00' * r

    def opaque_fixed(self, data: bytes, n: int):
        if len(data) != n:
            raise ValueError(f'expected {n} bytes, got {len(data)}')
        self.buf += data
        self._pad(n)

    def opaque_var(self, data: bytes):
        self.u32(len(data))
        self.buf += data
        self._pad(len(data))

    def string(self, s: str):
        self.opaque_var(os.fsencode(s))

    def array_u32(self, items: Iterable[int]):
        items = list(items)
        self.u32(len(items))
        for item in items:
            self.u32(item)


class XdrReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def _need(self, n: int):
        if self.pos + n > len(self.data):
            raise XdrDecodeError('truncated XDR message')

    def u32(self) -> int:
        self._need(4)
        (v,) = struct.unpack_from('>I', self.data, self.pos)
        self.pos += 4
        return v

    def i32(self) -> int:
        self._need(4)
        (v,) = struct.unpack_from('>i', self.data, self.pos)
        self.pos += 4
        return v

    def u64(self) -> int:
        self._need(8)
        (v,) = struct.unpack_from('>Q', self.data, self.pos)
        self.pos += 8
        return v

    def bool(self) -> bool:
        return self.u32() != 0

    def _skip_pad(self, n: int):
        r = (-n) % 4
        if r:
            self._need(r)
            self.pos += r

    def opaque_fixed(self, n: int) -> bytes:
        self._need(n)
        data = self.data[self.pos : self.pos + n]
        self.pos += n
        self._skip_pad(n)
        return data

    def opaque_var(self, maxlen: int | None = None) -> bytes:
        n = self.u32()
        if maxlen is not None and n > maxlen:
            raise XdrDecodeError(f'opaque length {n} exceeds max {maxlen}')
        return self.opaque_fixed(n)

    def string(self, maxlen: int | None = None) -> str:
        return os.fsdecode(self.opaque_var(maxlen))

    def array_u32(self, maxlen: int | None = None) -> list[int]:
        n = self.u32()
        if maxlen is not None and n > maxlen:
            raise XdrDecodeError(f'array length {n} exceeds max {maxlen}')
        return [self.u32() for _ in range(n)]
