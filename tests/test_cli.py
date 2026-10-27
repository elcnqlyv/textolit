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
