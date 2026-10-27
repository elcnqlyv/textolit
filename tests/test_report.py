import os
from pathlib import Path

import pytest

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


def _case_with_accepted(tmp_path: Path) -> Case:
    from textolit.core.ledger import add_finding, decide, ensure_heuristic

    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(4096))
    case = Case.create(tmp_path / "c")
    Ingest().run(case, image=img)
    ensure_heuristic(case, "creds.empty-password-field", "creds", "t", "high")
    fid = add_finding(
        case,
        heuristic_id="creds.empty-password-field",
        title="Account with an empty password field",
        evidence_path="artifacts/x/etc/passwd",
        line=1,
        snippet="root::0:0",
        confidence="high",
        severity="high",
        cwe="CWE-258",
        owasp_iot="I1",
    )
    assert fid
    decide(case, fid, "accepted")
    return case


def test_report_all_formats(tmp_path: Path) -> None:
    import json

    case = _case_with_accepted(tmp_path)
    res = Report().run(case, formats=["all"])
    assert res.ok, res.errors
    names = sorted(Path(p).suffix for p in res.data["paths"])
    assert names == [".docx", ".json", ".md", ".pdf"]
    cve = next(p for p in res.data["paths"] if p.endswith(".json"))
    doc = json.loads((case.root / cve).read_text())
    assert doc["entries"][0]["cvss_v31"]["base_score"] == 9.8
    kinds = [r[0] for r in case.conn.execute("SELECT kind FROM artifacts WHERE kind='report'")]
    assert len(kinds) == 4


def test_report_missing_export_library(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    case = _case_with_accepted(tmp_path)
    monkeypatch.setitem(sys.modules, "docx", None)
    explicit = Report().run(case, formats=["md", "docx"])
    assert not explicit.ok and any("python-docx" in e for e in explicit.errors)
    assert explicit.data["paths"][0].endswith(".md")  # the other format is still written
    soft = Report().run(case, formats=["all"])
    assert soft.ok and any("python-docx" in w for w in soft.warnings)


def test_report_unknown_format_and_empty_cve_warning(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    assert not Report().run(case, formats=["rtf"]).ok
    res = Report().run(case, formats=["json"])
    assert res.ok and any("no entries" in w for w in res.warnings)


def test_report_includes_llm_notes_only_when_asked(tmp_path: Path) -> None:
    import json
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from llm_server import FakeLlm

    from textolit.llm_backends import LlmConfig, save_config
    from textolit.modules.llm import Llm

    case = _case_with_accepted(tmp_path)
    with FakeLlm() as srv:
        srv.reply = json.dumps(
            {
                "summary": "Root has no password.",
                "priorities": [{"finding": "F1", "reason": "empty field", "cites": ["F1", "E1"]}],
                "unverified": ["telnet may be on"],
            }
        )
        save_config(case, LlmConfig(model="m", base_url=srv.url))
        case.set_llm(True)
        assert Llm().run(case, task="triage").ok
    plain = (case.root / Report().run(case).data["path"]).read_text()
    assert "LLM-assisted notes" not in plain and "Root has no password." not in plain
    full = (case.root / Report().run(case, include_llm=True).data["path"]).read_text()
    assert "## LLM-assisted notes (unverified draft)" in full and "**Unverified.**" in full
    assert "- F1: empty field [F1, E1]" in full and "unverified: telnet may be on" in full
    assert "triage.txt" in full  # call log with prompt hash
