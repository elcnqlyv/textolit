"""Synthetic squashfs end-to-end: ingest -> unpack -> entropy -> report-ready ledger."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from textolit.core.case import Case
from textolit.modules.entropy import Entropy
from textolit.modules.ingest import Ingest
from textolit.modules.unpack import Unpack

pytestmark = pytest.mark.skipif(
    not (shutil.which("mksquashfs") and shutil.which("binwalk")),
    reason="needs mksquashfs and binwalk",
)


def build_firmware(tmp: Path) -> Path:
    root = tmp / "root"
    (root / "etc/init.d").mkdir(parents=True)
    (root / "www").mkdir()
    (root / "etc/passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    (root / "etc/init.d/rcS").write_text("#!/bin/sh\ntelnetd -p 23456 &\n")
    (root / "www/a.html").write_text("<html>same</html>")
    (root / "www/b.html").write_text("<html>same</html>")
    os.symlink("/etc/passwd", root / "www/pw")
    (root / "etc/open.conf").write_text("x")
    (root / "etc/open.conf").chmod(0o666)
    subprocess.run(
        ["mksquashfs", root, tmp / "fs.sqsh", "-quiet", "-noappend"],
        check=True,
        capture_output=True,
    )
    fw = tmp / "fw.bin"
    fw.write_bytes(os.urandom(4096) + (tmp / "fs.sqsh").read_bytes())
    return fw


def test_pipeline(tmp_path: Path) -> None:
    fw = build_firmware(tmp_path)
    case = Case.create(tmp_path / "case")
    assert Ingest().run(case, image=fw).ok

    res = Unpack().run(case)
    assert res.ok, res.errors
    assert any(r["type"] == "squashfs" for r in res.data["fs_roots"])
    extracted = list((case.root / res.data["extract_dir"]).rglob("rcS"))
    assert extracted and "23456" in extracted[0].read_text()
    assert res.data["files"] >= 4 and res.data["unique"] < res.data["files"]  # a.html == b.html

    # modes must survive extraction (umask would strip world-writable bits)
    from textolit.modules.fswalk import FsWalk

    assert FsWalk().run(case).ok
    mode = case.conn.execute("SELECT mode FROM files WHERE path='/etc/open.conf'").fetchone()[0]
    assert mode & 0o002, oct(mode)

    ent = Entropy().run(case)
    assert ent.ok
    classes = {r[0] for r in case.conn.execute("SELECT classification FROM regions")}
    assert "encrypted" in classes  # the random 4 KiB prefix

    assert case.conn.execute("SELECT count(*) FROM commands").fetchone()[0] >= 3
    kinds = {r[0] for r in case.conn.execute("SELECT kind FROM artifacts")}
    assert {"image", "extract_root", "fs_root:squashfs", "entropy_map"} <= kinds
