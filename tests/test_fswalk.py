import os
from pathlib import Path

from textolit.core.case import Case
from textolit.core.ledger import add_artifact
from textolit.modules.fswalk import FsWalk, is_interesting, sniff


def make_case(tmp: Path) -> Case:
    case = Case.create(tmp / "case")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc/init.d").mkdir(parents=True)
    (root / "www").mkdir()
    (root / "tmp").mkdir()
    (root / "etc/passwd").write_text("root::0:0::/root:/bin/sh\n")
    (root / "etc/init.d/rcS").write_text("#!/bin/sh\ntelnetd -p 23456 &\n")
    (root / "www/index.html").write_text("<html></html>")
    (root / "www/copy.html").write_text("<html></html>")
    (root / "bin").mkdir()
    (root / "bin/app").write_bytes(b"\x7fELF" + os.urandom(600))
    os.symlink("/etc/passwd", root / "www/pw")
    os.symlink("nowhere", root / "www/dangling")
    ww = root / "tmp/open.txt"
    ww.write_text("x")
    ww.chmod(0o666)
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    return case


def test_sniff_and_interesting() -> None:
    assert sniff(b"\x7fELF\x01", 5) == "elf"
    assert sniff(b"#!/bin/sh\n", 10) == "script"
    assert sniff(b"hello world\n", 12) == "text"
    assert sniff(b"", 0) == "empty"
    assert is_interesting("/etc/init.d/rcS") and is_interesting("/usr/lib/foo.pem")
    assert not is_interesting("/usr/lib/libc.so.6")


def test_fswalk_indexes(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    res = FsWalk().run(case)
    assert res.ok
    rows = {r["path"]: r for r in case.conn.execute("SELECT * FROM files")}
    assert rows["/etc/init.d/rcS"]["ftype"] == "script" and rows["/etc/init.d/rcS"]["interesting"]
    assert rows["/bin/app"]["ftype"] == "elf" and rows["/bin/app"]["entropy"] > 7
    assert rows["/www/pw"]["is_symlink"] == 1 and rows["/www/pw"]["link_target"] == "/etc/passwd"
    assert res.data["counts"]["world_writable"] == 1
    assert res.data["counts"]["dangling_symlinks"] == 1
    assert any("world writable" in w for w in res.warnings)
    # idempotent re-run
    FsWalk().run(case)
    assert case.conn.execute("SELECT count(*) FROM files").fetchone()[0] == len(rows)
