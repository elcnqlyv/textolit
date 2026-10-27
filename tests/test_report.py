import os
from pathlib import Path

from textolit.core.case import Case
from textolit.modules.entropy import Entropy
from textolit.modules.ingest import Ingest
from textolit.modules.report import Report


def test_report_markdown(tmp_path: Path) -> None:
    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(16384))
    case = Case.create(tmp_path / "c")
    Ingest().run(case, image=img)
    Entropy().run(case)
    res = Report().run(case)
    text = (case.root / res.data["path"]).read_text()
    assert "Textolit — firmware triage workbench" in text
    assert "encrypted" in text and "not a clean bill of health" in text
    assert "Command log" in text and "file -b" in text


def test_report_v2_sections(tmp_path: Path) -> None:
    from textolit.core.ledger import add_artifact, decide
    from textolit.modules.binintel import BinIntel
    from textolit.modules.fswalk import FsWalk
    from textolit.modules.missedfindings import MissedFindings
    from textolit.modules.netmap import NetMap

    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc/init.d").mkdir(parents=True)
    (root / "etc/init.d/rcS").write_text("#!/bin/sh\ntelnetd -p 23456 &\n")
    (root / "etc/passwd").write_text("root::0:0:root:/root:/bin/sh\n")
    (root / "etc/app.conf").write_text("user=admin\npassword=letmein\n")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    for mod in (FsWalk(), BinIntel(), NetMap(), MissedFindings()):
        mod.run(case)
    rej = case.conn.execute(
        "SELECT id FROM findings WHERE heuristic_id='creds.plaintext-password'"
    ).fetchone()
    assert rej is not None
    other = case.conn.execute(
        "SELECT id FROM findings WHERE heuristic_id='net.nonstandard-port'"
    ).fetchone()
    assert other is not None
    decide(case, rej[0], "rejected", "lab placeholder")
    text = Report().run(case)
    body = (case.root / text.data["path"]).read_text()
    assert "### I1 Weak, Guessable, or Hardcoded Passwords" in body
    assert "### I2 Insecure Network Services" in body
    assert "23456/tcp" in body and "NON" not in body.split("Listen-by-default")[0]
    assert "le*****" in body and "letmein" not in body  # secrets are masked
    assert "lab placeholder" in body  # rejection recorded in the report
    assert "leads pending review" in body


def test_report_masks_secrets_in_snippets(tmp_path: Path) -> None:
    from textolit.core.ledger import add_artifact
    from textolit.modules.fswalk import FsWalk
    from textolit.modules.missedfindings import MissedFindings

    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/app.conf").write_text("password=letmein\n")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    FsWalk().run(case)
    MissedFindings().run(case)
    body = (case.root / Report().run(case).data["path"]).read_text()
    assert "password=" in body and "letmein" not in body
