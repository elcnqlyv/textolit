from pathlib import Path

import pytest

from textolit.core.case import Case, CaseError
from textolit.core.ledger import add_artifact


def test_create_open_roundtrip(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c1")
    assert case.llm_enabled is False
    case.set_llm(True)
    case.close()
    again = Case.open(tmp_path / "c1")
    assert again.llm_enabled is True
    with pytest.raises(CaseError):
        Case.create(tmp_path / "c1")


def test_open_missing(tmp_path: Path) -> None:
    with pytest.raises(CaseError):
        Case.open(tmp_path / "nope")


def test_add_artifact_records_hash(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c2")
    f = case.artifacts_dir / "x.bin"
    f.write_bytes(b"abc")
    aid = add_artifact(case, "carved", f)
    row = case.conn.execute("SELECT path,size,sha256 FROM artifacts WHERE id=?", (aid,)).fetchone()
    assert row["path"] == "artifacts/x.bin" and row["size"] == 3 and len(row["sha256"]) == 64
