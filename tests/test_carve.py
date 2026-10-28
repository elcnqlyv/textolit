import gzip
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from textolit import carve
from textolit.core.case import Case
from textolit.modules.ingest import Ingest
from textolit.modules.unpack import Unpack, _fallback_extract


def tree(tmp: Path) -> Path:
    root = tmp / "src"
    (root / "etc").mkdir(parents=True)
    (root / "etc/passwd").write_text("root::0:0:root:/root:/bin/sh\n")
    (root / "etc/wr.conf").write_text("x")
    (root / "etc/wr.conf").chmod(0o666)
    return root


def make_cpio(root: Path, out: Path) -> bytes:
    with out.open("wb") as fh:
        find = subprocess.run(["find", "."], cwd=root, capture_output=True, check=True)
        subprocess.run(
            ["cpio", "-o", "-H", "newc", "--quiet"],
            cwd=root,
            input=find.stdout,
            stdout=fh,
            check=True,
        )
    return out.read_bytes()


def uimage(payload: bytes, comp: int = 1, typ: int = 3) -> bytes:
    hdr = bytearray(
        struct.pack(
            ">7I4B32s",
            carve.UIMAGE_MAGIC,
            0,
            0,
            len(payload),
            0x80000000,
            0x80000000,
            zlib.crc32(payload) & 0xFFFFFFFF,
            5,
            5,
            typ,
            comp,
            b"initramfs",
        )
    )
    struct.pack_into(">I", hdr, 4, zlib.crc32(bytes(hdr)) & 0xFFFFFFFF)
    return bytes(hdr) + payload


def test_uimage_header_and_crcs() -> None:
    w = carve.parse_uimage(uimage(b"payload-bytes"))
    assert w and w.kind == "uimage" and w.payload_offset == 64 and w.payload_len == 13
    assert w.info["arch"] == "mips" and w.info["comp"] == "gzip" and w.info["name"] == "initramfs"
    assert w.info["header_crc_ok"] and w.info["data_crc_ok"]
    bad = bytearray(uimage(b"payload-bytes"))
    bad[-1] ^= 1
    assert carve.parse_uimage(bytes(bad)).info["data_crc_ok"] is False  # type: ignore[union-attr]
    assert carve.parse_uimage(b"\0" * 100) is None


def test_trx_header() -> None:
    body = b"A" * 100
    hdr = b"HDR0" + struct.pack("<IIHH4I", 28 + 4 + len(body), 0, 0, 2, 32, 0, 0, 0)
    w = carve.parse_trx(hdr + body)
    assert w and w.kind == "trx" and w.info["partitions"] == 1 and w.payload_offset == 32
    assert carve.parse_trx(b"HDR0" + b"\0" * 40) is None


def test_decompress_gzip_with_trailing_garbage() -> None:
    blob = gzip.compress(b"hello" * 100) + b"\xff" * 50
    assert carve.decompress_at(blob) == ("gzip", b"hello" * 100)
    assert carve.decompress_at(b"\x1f\x8b\x08 not really") is None


def test_random_data_has_no_filesystem() -> None:
    import os

    assert carve.find_filesystems(os.urandom(1 << 20)) == []


def test_cpio_and_cramfs_detected(tmp_path: Path) -> None:
    root = tree(tmp_path)
    cpio = make_cpio(root, tmp_path / "a.cpio")
    hits = carve.find_filesystems(b"\0" * 300 + cpio)
    assert [(h.fs, h.offset) for h in hits] == [("cpio", 300)]
    if shutil.which("mkfs.cramfs"):
        subprocess.run(["mkfs.cramfs", str(root), str(tmp_path / "a.cramfs")], check=True)
        cr = (tmp_path / "a.cramfs").read_bytes()
        got = carve.find_filesystems(b"\xaa" * 1000 + cr)
        assert [(h.fs, h.offset) for h in got] == [("cramfs", 1000)]


def test_fallback_extracts_cpio_inside_gzip_inside_uimage(tmp_path: Path) -> None:
    root = tree(tmp_path)
    cpio = make_cpio(root, tmp_path / "a.cpio")
    img = tmp_path / "fw.bin"
    img.write_bytes(uimage(gzip.compress(cpio)))
    case = Case.create(tmp_path / "c")
    dest = case.extract_dir / "image1"
    dest.mkdir(parents=True)
    notes, wrappers, unextracted = _fallback_extract(case, img, dest)
    assert wrappers and wrappers[0]["kind"] == "uimage" and not unextracted
    assert any("gzip stream" in n for n in notes)
    found = list(dest.glob("cpio-root-*/etc/passwd"))
    assert found and found[0].read_text().startswith("root::")
    assert (found[0].parent / "wr.conf").stat().st_mode & 0o777 == 0o666  # modes kept (umask 0)


@pytest.mark.skipif(not shutil.which("mkfs.cramfs") or not shutil.which("7z"), reason="no tools")
def test_fallback_extracts_cramfs(tmp_path: Path) -> None:
    root = tree(tmp_path)
    subprocess.run(["mkfs.cramfs", str(root), str(tmp_path / "a.cramfs")], check=True)
    img = tmp_path / "fw.bin"
    img.write_bytes(b"\x00" * 512 + (tmp_path / "a.cramfs").read_bytes())
    case = Case.create(tmp_path / "c")
    dest = case.extract_dir / "image1"
    dest.mkdir(parents=True)
    _notes, _w, unextracted = _fallback_extract(case, img, dest)
    assert not unextracted, unextracted
    assert list(dest.glob("cramfs-root-*/etc/passwd"))


def test_unpack_end_to_end_with_wrapper_and_report_of_unknown(tmp_path: Path) -> None:
    root = tree(tmp_path)
    cpio = make_cpio(root, tmp_path / "a.cpio")
    img = tmp_path / "fw.bin"
    img.write_bytes(uimage(gzip.compress(cpio)))
    case = Case.create(tmp_path / "c")
    Ingest().run(case, image=img)
    res = Unpack().run(case)
    assert res.data["fs_roots"], res.warnings
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x13\x37" * 5000)
    case2 = Case.create(tmp_path / "c2")
    Ingest().run(case2, image=junk)
    res2 = Unpack().run(case2)
    assert not res2.data["fs_roots"] and any("no filesystem recognised" in w for w in res2.warnings)
