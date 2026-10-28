"""Pure-Python recognition of firmware wrappers and filesystems that binwalk can miss.

Nothing here runs a subprocess. ``unpack`` uses these helpers as a fallback when binwalk
extracts no filesystem: strip a vendor header (uImage, TRX), decompress a stream, then
look for filesystem magic with enough validation to keep random data from matching.
"""

from __future__ import annotations

import lzma
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any

UIMAGE_MAGIC = 0x27051956
UIMAGE_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
UIMAGE_TYPE = {
    1: "standalone",
    2: "kernel",
    3: "ramdisk",
    4: "multi",
    5: "firmware",
    8: "script",
    14: "filesystem",
}
UIMAGE_ARCH = {2: "arm", 5: "mips", 6: "mips64", 7: "ppc", 22: "arm64"}
UIMAGE_OS = {5: "linux", 17: "u-boot"}
MAX_STREAM = 256 << 20


@dataclass(frozen=True)
class Wrapper:
    kind: str  # uimage or trx
    offset: int
    payload_offset: int
    payload_len: int
    info: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        bits = ", ".join(f"{k}={v}" for k, v in self.info.items() if v not in ("", None))
        return f"{self.kind} header at 0x{self.offset:x}: {bits}"


@dataclass(frozen=True)
class FsHit:
    fs: str  # squashfs, cramfs, cpio, jffs2, ubi
    offset: int
    length: int | None  # None = unknown, carve to the end of the layer


def parse_uimage(data: bytes, off: int = 0) -> Wrapper | None:
    if len(data) < off + 64 or struct.unpack_from(">I", data, off)[0] != UIMAGE_MAGIC:
        return None
    magic, hcrc, ts, size, load, entry, dcrc, os_, arch, typ, comp = struct.unpack_from(
        ">7I4B", data, off
    )
    hdr = bytearray(data[off : off + 64])
    hdr[4:8] = b"\0\0\0\0"
    payload = data[off + 64 : off + 64 + size]
    name = data[off + 32 : off + 64].split(b"\0", 1)[0].decode("ascii", "replace")
    if size == 0:
        return None
    return Wrapper(
        "uimage",
        off,
        off + 64,
        len(payload),
        {
            "name": name,
            "os": UIMAGE_OS.get(os_, os_),
            "arch": UIMAGE_ARCH.get(arch, arch),
            "type": UIMAGE_TYPE.get(typ, typ),
            "comp": UIMAGE_COMP.get(comp, comp),
            "load": f"0x{load:x}",
            "header_crc_ok": zlib.crc32(bytes(hdr)) & 0xFFFFFFFF == hcrc,
            "data_crc_ok": zlib.crc32(payload) & 0xFFFFFFFF == dcrc,
        },
    )


def parse_trx(data: bytes, off: int = 0) -> Wrapper | None:
    """Broadcom TRX: magic HDR0, length, crc32, flags+version, up to four partition offsets."""
    if len(data) < off + 32 or data[off : off + 4] != b"HDR0":
        return None
    length, crc, flags, version = struct.unpack_from("<IIHH", data, off + 4)
    offsets = [o for o in struct.unpack_from("<4I", data, off + 16) if o]
    if length < 28 or length > len(data) - off or version not in (1, 2):
        return None
    hdr = 28 if version == 1 else 32
    return Wrapper(
        "trx",
        off,
        off + hdr,
        length - hdr,
        {"version": version, "partitions": len(offsets), "offsets": ",".join(map(str, offsets))},
    )


def find_wrapper(data: bytes) -> Wrapper | None:
    """A vendor header at the start of the layer. Only offset 0 is trusted."""
    return parse_uimage(data) or parse_trx(data)


def decompress_at(data: bytes, off: int = 0) -> tuple[str, bytes] | None:
    """Try gzip, xz and lzma-alone at ``off``. Trailing garbage is tolerated."""
    head = data[off : off + 16]
    try:
        if head[:3] == b"\x1f\x8b\x08":
            d = zlib.decompressobj(31)
            out = d.decompress(data[off:], MAX_STREAM)
            return ("gzip", out) if out else None
        if head[:6] == b"\xfd7zXZ\x00":
            lz = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            out = lz.decompress(data[off:], MAX_STREAM)
            return ("xz", out) if out else None
        if head[:1] == b"\x5d" and head[1:3] == b"\x00\x00" and len(head) >= 13:
            size = struct.unpack_from("<Q", head, 5)[0]
            if size == 0xFFFFFFFFFFFFFFFF or 0 < size <= MAX_STREAM:
                lz = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
                out = lz.decompress(data[off:], MAX_STREAM)
                return ("lzma", out) if out else None
    except (zlib.error, lzma.LZMAError, ValueError):
        return None
    return None


def _squashfs(data: bytes) -> list[FsHit]:
    hits: list[FsHit] = []
    for magic, endian in ((b"hsqs", "<"), (b"sqsh", ">")):
        start = 0
        while (off := data.find(magic, start)) != -1:
            start = off + 4
            if off + 96 > len(data):
                continue
            block = struct.unpack_from(endian + "I", data, off + 12)[0]
            log = struct.unpack_from(endian + "H", data, off + 22)[0]
            major = struct.unpack_from(endian + "H", data, off + 28)[0]
            if major != 4 or block < 4096 or block > 1 << 20 or block != 1 << log:
                continue
            used = struct.unpack_from(endian + "Q", data, off + 40)[0]
            length = used if 96 < used <= len(data) - off else None
            hits.append(FsHit("squashfs", off, length))
    return hits


def _cramfs(data: bytes) -> list[FsHit]:
    hits: list[FsHit] = []
    for magic, endian in ((b"\x45\x3d\xcd\x28", "<"), (b"\x28\xcd\x3d\x45", ">")):
        start = 0
        while (off := data.find(magic, start)) != -1:
            start = off + 4
            if off + 76 > len(data) or data[off + 16 : off + 32] != b"Compressed ROMFS"[:16]:
                continue
            size = struct.unpack_from(endian + "I", data, off + 4)[0]
            hits.append(FsHit("cramfs", off, size if 76 <= size <= len(data) - off else None))
    return hits


CPIO_START = re.compile(rb"07070[12][0-9A-Fa-f]{104}")


def _cpio(data: bytes) -> list[FsHit]:
    hits: list[FsHit] = []
    pos = 0
    for m in CPIO_START.finditer(data):
        if m.start() < pos:
            continue
        end = data.find(b"TRAILER!!!", m.start())
        if end == -1:
            continue
        # the trailer entry has a name length of 11 and zero size, so it sits ~110 bytes on
        length = min(len(data) - m.start(), end - m.start() + 10 + 3 + 512)
        hits.append(FsHit("cpio", m.start(), length))
        pos = m.start() + length
    return hits


JFFS2_NODES = {0xE001, 0xE002, 0x2003, 0x2004, 0x2006, 0x2005, 0x2008}


def _jffs2(data: bytes) -> list[FsHit]:
    """JFFS2 magic is two bytes, so require a chain of three plausible node headers."""
    for magic, endian in ((b"\x85\x19", "<"), (b"\x19\x85", ">")):
        start, tried = 0, 0
        while (off := data.find(magic, start)) != -1 and tried < 4096:
            start, tried = off + 1, tried + 1
            pos, chain = off, 0
            while pos + 12 <= len(data) and data[pos : pos + 2] == magic:
                ntype, total = struct.unpack_from(endian + "HI", data, pos + 2)
                if ntype not in JFFS2_NODES or total < 12 or total > 1 << 20:
                    break
                chain += 1
                pos += (total + 3) & ~3
            if chain >= 3:
                return [FsHit("jffs2", off, None)]
    return []


def _ubi(data: bytes) -> list[FsHit]:
    start = 0
    while (off := data.find(b"UBI#", start)) != -1:
        start = off + 4
        if off + 64 > len(data) or data[off + 4] != 1:
            continue
        vid, data_off = struct.unpack_from(">II", data, off + 16)
        if vid in (512, 1024, 2048, 4096) and data_off >= vid:
            return [FsHit("ubi", off, None)]
    return []


def find_filesystems(data: bytes) -> list[FsHit]:
    """Filesystem candidates in one layer, validated beyond the bare magic."""
    hits = [*_squashfs(data), *_cramfs(data), *_cpio(data), *_jffs2(data), *_ubi(data)]
    return sorted(hits, key=lambda h: h.offset)
