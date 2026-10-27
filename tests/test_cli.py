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
