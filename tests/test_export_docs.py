import shutil
import subprocess
from pathlib import Path

import pytest

from textolit.export_docs import inline_runs, parse_markdown, write_docx, write_pdf

MD = (
    """# Title here

Textolit intro with **bold** and `code_ident` and _italic words_.

## Table

| a | b |
|---|---|
| x \\| y | `/etc/passwd:1` |
| long | """
    + "very-long-path/" * 12
    + """ |

> quote line one
> quote line two

### Findings

- **[high]** First finding (#1)  
  `path/one:3`
- second finding

Closing paragraph
spanning two lines.
"""
)


def test_parse_markdown_blocks() -> None:
    kinds = [b.kind for b in parse_markdown(MD)]
    assert kinds == ["h", "p", "h", "table", "quote", "h", "bullets", "p"]
    table = parse_markdown(MD)[3]
    assert table.rows[1] == ["x | y", "`/etc/passwd:1`"] and len(table.rows) == 3
    assert parse_markdown(MD)[4].text == "quote line one quote line two"
    bullets = parse_markdown(MD)[6]
    assert len(bullets.items) == 2 and "path/one:3" in bullets.items[0]
    assert parse_markdown(MD)[7].text == "Closing paragraph spanning two lines."


def test_inline_runs() -> None:
    runs = inline_runs("a **b** `c_d` _e f_ snake_case_name")
    assert ("b", "bold") in runs and ("c_d", "code") in runs and ("e f", "italic") in runs
    assert all(style == "plain" for text, style in runs if "snake_case_name" in text)


def test_docx_roundtrip(tmp_path: Path) -> None:
    docx = pytest.importorskip("docx")
    out = tmp_path / "r.docx"
    write_docx(MD, out)
    d = docx.Document(str(out))
    texts = [p.text for p in d.paragraphs]
    assert "Title here" in texts and any("Closing paragraph" in t for t in texts)
    assert len(d.tables) == 1 and d.tables[0].cell(1, 0).text == "x | y"
    assert d.tables[0].cell(0, 0).paragraphs[0].runs[0].bold
    assert d.core_properties.author == "" and d.core_properties.comments == ""
    assert any(p.style.name == "List Bullet" for p in d.paragraphs)


def test_pdf_is_written_and_readable(tmp_path: Path) -> None:
    pytest.importorskip("reportlab")
    out = tmp_path / "r.pdf"
    write_pdf(MD.replace("**bold**", "**bold & <tag>**") + "\nUnicode: arrow → dash —\n", out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 1500
    if shutil.which("pdftotext"):
        text = subprocess.run(
            ["pdftotext", "-layout", str(out), "-"], capture_output=True, text=True, check=True
        ).stdout
        assert "Title here" in text and "bold & <tag>" in text and "/etc/passwd:1" in text
