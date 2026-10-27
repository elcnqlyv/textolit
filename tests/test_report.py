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


def test_report_sprint3_sections(tmp_path: Path) -> None:
    import hashlib

    from textolit import crack
    from textolit.core.ledger import add_artifact
    from textolit.hashcat import Profile
    from textolit.modules.crypto import Crypto
    from textolit.modules.fswalk import FsWalk
    from textolit.modules.websurface import WebSurface

    fake = str(Path(__file__).parent / "fake_hashcat.py")
    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc").mkdir(parents=True)
    (root / "www/cgi-bin").mkdir(parents=True)
    md5 = hashlib.md5(b"admin").hexdigest()
    (root / "etc/shadow").write_text(f"admin:{md5}:0:0:::\n")  # raw md5 in a shadow-style file
    (root / "etc/app.conf").write_text('aes_key="00112233445566778899aabbccddeeff"\n')
    (root / "www/index.html").write_text(
        '<form action="/cgi-bin/login.cgi"><input type="password" value="hunter22"></form>'
        '<form action="/cgi-bin/up.cgi" enctype="multipart/form-data"><input type="file"></form>'
    )
    (root / "www/cgi-bin/login.cgi").write_text("#!/bin/sh\n")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    FsWalk().run(case)
    Crypto().run(case)
    WebSurface().run(case)
    crack.plan_tasks(case, Profile(binary=fake), masks=False)
    crack.run_next(case)
    body = (case.root / Report().run(case).data["path"]).read_text()
    assert "## Web surface (static)" in body and "/cgi-bin/up.cgi" in body
    assert "html-form-login" in body and "hunter22" not in body
    assert "## Crypto material" in body and "| admin | md5 | 0 | ad*** |" in body
    assert "00112233445566778899aabbccddeeff" not in body  # key strings are masked
    assert "### Crack queue" in body and "default IoT passwords" in body
    assert "Cracked password for 'admin'" in body


def test_report_rollup_and_appendix(tmp_path: Path) -> None:
    from textolit.core.ledger import add_finding, ensure_heuristic

    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(4096))
    case = Case.create(tmp_path / "c")
    Ingest().run(case, image=img)
    ensure_heuristic(case, "x.a", "t", "t", "high")
    for n, (conf, sev, tag) in enumerate(
        (("high", "high", "I1"), ("low", "medium", "I2"), ("low", "medium", "I2"))
    ):
        add_finding(
            case,
            heuristic_id="x.a",
            title=f"t-{conf}-{tag}-{sev}",
            evidence_path=f"p{n}",
            line=1 if conf == "high" else 2,
            confidence=conf,
            severity=sev,
            owasp_iot=tag,
        )
    body = (case.root / Report().run(case).data["path"]).read_text()
    assert (
        "## Summary" in body and "| high | 1 | 0 | 0 |" in body and "| medium | 0 | 0 | 2 |" in body
    )
    assert "| I2 | Insecure Network Services | 2 |" in body
    assert "## Evidence appendix" in body and "| image |" in body and "evidence links" in body
