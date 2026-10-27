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
