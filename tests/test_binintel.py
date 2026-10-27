import shutil
from pathlib import Path

from textolit.modules.binintel import cve_hints, find_versions, parse_elf


def test_parse_real_elf() -> None:
    exe = shutil.which("ls")
    assert exe
    info = parse_elf(Path(exe).read_bytes())
    assert info is not None
    assert info.bits in (32, 64) and info.endian in ("little", "big")
    assert any(lib.startswith("libc") for lib in info.libs)


def test_parse_elf_rejects_garbage() -> None:
    assert parse_elf(b"not an elf") is None
    assert parse_elf(b"\x7fELF" + b"\x09" * 60) is None


def test_versions_and_hints() -> None:
    blob = (
        b"junk BusyBox v1.19.4 (2013) \x00 Dropbear sshd v2012.55 \x00 OpenSSL 1.0.1e 11 Feb 2013"
        b" \x00 Boa/0.94.13 \x00 lighttpd/1.4.28"
    )
    v = find_versions(blob)
    assert v == {
        "busybox": "1.19.4",
        "dropbear": "2012.55",
        "lighttpd": "1.4.28",
        "boa": "0.94.13",
        "openssl": "1.0.1e",
    }
    comps = {h["component"]: h for h in cve_hints(v)}
    assert "CVE-2014-0160" in comps["openssl"]["cves"]
    assert "CVE-2016-3116" in comps["dropbear"]["cves"]
    assert comps["boa"]["cves"] == []
    assert cve_hints({"openssl": "1.0.2k", "dropbear": "2019.78"}) == []


def test_module_records_binaries_and_findings(tmp_path: Path) -> None:
    from textolit.core.case import Case
    from textolit.core.ledger import add_artifact
    from textolit.modules.binintel import BinIntel
    from textolit.modules.fswalk import FsWalk

    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "usr/sbin").mkdir(parents=True)
    exe = shutil.which("ls")
    assert exe
    (root / "usr/sbin/httpd").write_bytes(Path(exe).read_bytes() + b"\0OpenSSL 1.0.1e 11 Feb\0")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    assert FsWalk().run(case).ok
    res = BinIntel().run(case)
    assert res.ok and res.data["hints"] == 1
    assert case.conn.execute("SELECT count(*) FROM binaries").fetchone()[0] == 1
    f = case.conn.execute("SELECT * FROM findings").fetchone()
    assert f["confidence"] == "low" and "CVE-2014-0160" in f["detail"]
    assert f["evidence_path"].endswith("usr/sbin/httpd")
