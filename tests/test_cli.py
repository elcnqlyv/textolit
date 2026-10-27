import os
from pathlib import Path

import pytest

from textolit.cli import main


def test_cli_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(9000))
    case = tmp_path / "case"
    assert main(["init", str(case), "--image", str(img)]) == 0
    assert main(["entropy", str(case), "--window", "2048"]) == 0
    assert main(["report", str(case)]) == 0
    assert main(["fswalk", str(case)]) == 1  # stub reports failure rather than silence
    assert main(["jobs", str(case)]) == 0
    out = capsys.readouterr().out
    assert "ingest" in out and "entropy" in out and "wrote reports/report-" in out


def test_cli_missing_case(tmp_path: Path) -> None:
    assert main(["entropy", str(tmp_path / "nope")]) == 2


def test_cli_sprint2_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from textolit.core.case import Case
    from textolit.core.ledger import add_artifact

    case_dir = tmp_path / "case"
    case = Case.create(case_dir)
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc/init.d").mkdir(parents=True)
    (root / "etc/init.d/rcS").write_text("#!/bin/sh\ntelnetd -p 23456 &\n")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    case.close()

    assert main(["fswalk", str(case_dir)]) == 0
    assert main(["netmap", str(case_dir)]) == 0
    out = capsys.readouterr().out
    assert "23456/tcp" in out and "NON" in out  # table row
    assert "missedfindings" in out  # sweep ran as a follow-up, not silently skipped
    assert main(["findings", str(case_dir)]) == 0
    listing = capsys.readouterr().out
    assert "leads pending review" in listing and "telnetd" in listing.lower()
    assert main(["decide", str(case_dir), "1", "reject", "--note", "lab fixture"]) == 0
    assert main(["decide", str(case_dir), "999", "reject"]) == 2


def test_cli_crack_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import hashlib

    from textolit.core.case import Case

    fake = str(Path(__file__).parent / "fake_hashcat.py")
    case_dir = tmp_path / "case"
    case = Case.create(case_dir)
    case.conn.execute(
        "INSERT INTO crypto_materials(kind,algo,value,source_path,hashcat_mode,username,"
        "source_line) VALUES ('hash','md5',?,'artifacts/etc/shadow',0,'admin',1)",
        (hashlib.md5(b"admin").hexdigest(),),
    )
    case.conn.commit()
    case.close()

    assert (
        main(
            ["crack", str(case_dir), "plan", "--hashcat", fake, "--gpu-budget", "90m", "--no-masks"]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "--runtime 5400" in out and "-w 2" in out and "1 tasks queued" in out
    assert (
        main(
            ["crack", str(case_dir), "plan", "--hashcat", fake, "--gpu-budget", "90m", "--no-masks"]
        )
        == 0
    )
    assert "nothing new to queue" in capsys.readouterr().out
    assert main(["crack", str(case_dir), "plan", "--gpu-budget", "soon"]) == 2
    assert main(["crack", str(case_dir), "run", "--hashcat", fake]) == 0
    assert main(["crack", str(case_dir), "status"]) == 0
    status = capsys.readouterr().out
    assert "cracked" in status and "m0 default IoT passwords" in status
    assert main(["crack", str(case_dir), "pause"]) == 2  # needs an id
    assert main(["crack", str(case_dir), "run", "--hashcat", "/no/such/hashcat"]) == 2


def test_cli_crypto_and_websurface(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from textolit.core.case import Case
    from textolit.core.ledger import add_artifact

    case_dir = tmp_path / "case"
    case = Case.create(case_dir)
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc").mkdir(parents=True)
    (root / "www").mkdir()
    (root / "etc/shadow").write_text("root:$1$abcdefgh$" + "a" * 22 + ":0:0:::\n")
    (root / "www/index.html").write_text(
        '<form action="/cgi-bin/x.cgi"><input type="password"></form>'
    )
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    case.close()
    assert main(["fswalk", str(case_dir)]) == 0
    assert main(["crypto", str(case_dir)]) == 0
    out = capsys.readouterr().out
    assert "md5crypt" in out and "500" in out and "textolit crack" in out
    assert main(["websurface", str(case_dir)]) == 0
    assert "1 web roots" in capsys.readouterr().out


def test_cli_report_formats(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(4096))
    case = tmp_path / "case"
    assert main(["init", str(case), "--image", str(img)]) == 0
    assert main(["report", str(case), "--format", "md", "--format", "json"]) == 0
    out = capsys.readouterr().out
    assert ".md" in out and "cve-ready-" in out and "no entries" in out
    with pytest.raises(SystemExit) as exc:
        main(["report", str(case), "--format", "rtf"])
    assert exc.value.code == 2


def test_cli_llm_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from llm_server import FakeLlm

    from textolit.core.case import Case
    from textolit.core.ledger import add_finding, ensure_heuristic

    case_dir = tmp_path / "case"
    case = Case.create(case_dir)
    ensure_heuristic(case, "x.a", "t", "t", "high")
    add_finding(
        case,
        heuristic_id="x.a",
        title="lead",
        evidence_path="p",
        line=1,
        snippet="s",
        confidence="high",
        severity="high",
        owasp_iot="I1",
    )
    case.close()

    assert main(["llm", str(case_dir), "status"]) == 0
    assert "LLM off" in capsys.readouterr().out
    assert main(["llm", str(case_dir), "triage"]) == 1  # off: refused, not silent
    with FakeLlm() as srv:
        srv.reply = json.dumps(
            {
                "summary": "s",
                "priorities": [{"finding": "F1", "reason": "r", "cites": ["F1", "E1"]}],
                "unverified": [],
            }
        )
        assert main(["llm", str(case_dir), "config", "--model", "m", "--base-url", srv.url]) == 0
        assert main(["llm", str(case_dir), "on"]) == 0
        out = capsys.readouterr().out
        assert "LLM ACTIVE" in out and "stay on this machine" in out
        assert main(["llm", str(case_dir), "triage"]) == 0
        assert main(["llm", str(case_dir), "calls"]) == 0
        assert "ok" in capsys.readouterr().out
    assert main(["llm", str(case_dir), "off"]) == 0
    assert main(["llm", str(case_dir), "config", "--base-url", "http://192.0.2.9:1"]) == 0
    assert "REMOTE" in capsys.readouterr().out
