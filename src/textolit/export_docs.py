"""DOCX and PDF export. Both render the Markdown report, so the three formats never drift.

Only the Markdown subset the report uses is understood: headings, paragraphs, bullet lists
with continuation lines, block quotes, pipe tables, and inline bold, italic and code.
python-docx and reportlab are optional (``pip install 'textolit[report]'``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DOCS_HINT = "install the report extras: pip install 'textolit[report]'"


class ExportError(RuntimeError):
    pass


@dataclass
class Block:
    kind: str  # h, p, quote, bullets, table
    text: str = ""
    level: int = 0
    items: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)


_SEP = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?$")


def _split_row(line: str) -> list[str]:
    cells = re.split(r"(?<!\\)\|", line.strip())
    if cells and cells[0] == "":
        cells = cells[1:]
    if cells and cells[-1] == "":
        cells = cells[:-1]
    return [c.strip().replace("\\|", "|") for c in cells]


def parse_markdown(text: str) -> list[Block]:
    blocks: list[Block] = []
    lines = text.splitlines()
    i = 0
    para: list[str] = []

    def flush() -> None:
        if para:
            blocks.append(Block("p", " ".join(s.strip() for s in para)))
            para.clear()

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            flush()
            i += 1
        elif m := re.match(r"^(#{1,4})\s+(.*)$", line):
            flush()
            blocks.append(Block("h", m.group(2).strip(), level=len(m.group(1))))
            i += 1
        elif (
            line.lstrip().startswith("|")
            and i + 1 < len(lines)
            and _SEP.match(lines[i + 1].strip())
        ):
            flush()
            rows = [_split_row(line)]
            i += 2
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(_split_row(lines[i]))
                i += 1
            blocks.append(Block("table", rows=rows))
        elif line.startswith(">"):
            flush()
            quote = []
            while i < len(lines) and lines[i].startswith(">"):
                quote.append(lines[i].lstrip("> ").strip())
                i += 1
            blocks.append(Block("quote", " ".join(quote)))
        elif re.match(r"^\s*[-*]\s+", line):
            flush()
            items: list[str] = []
            while i < len(lines) and lines[i].strip():
                if re.match(r"^[-*]\s+", lines[i]):
                    items.append(re.sub(r"^[-*]\s+", "", lines[i]).strip())
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            blocks.append(Block("bullets", items=items))
        else:
            para.append(line)
            i += 1
    flush()
    return blocks


_INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|(?<!\w)_(?!_)[^_]+?(?<!_)_(?!\w))")


def inline_runs(text: str) -> list[tuple[str, str]]:
    """Split inline Markdown into (text, style) with style in plain, bold, code, italic."""
    runs: list[tuple[str, str]] = []
    pos = 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            runs.append((text[pos : m.start()], "plain"))
        tok = m.group(0)
        if tok.startswith("**"):
            runs.append((tok[2:-2], "bold"))
        elif tok.startswith("`"):
            runs.append((tok[1:-1], "code"))
        else:
            runs.append((tok[1:-1], "italic"))
        pos = m.end()
    if pos < len(text):
        runs.append((text[pos:], "plain"))
    return runs


def write_docx(markdown: str, path: Path, title: str = "Textolit report") -> None:
    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Pt
    except ImportError as exc:
        raise ExportError(f"python-docx is not installed: {DOCS_HINT}") from exc

    doc = Document()
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    props = doc.core_properties
    props.title, props.author, props.comments, props.last_modified_by = title, "", "", ""

    def add_runs(par: object, text: str, size: float | None = None) -> None:
        for chunk, style in inline_runs(text):
            run = par.add_run(chunk)  # type: ignore[attr-defined]
            run.bold = style == "bold"
            run.italic = style == "italic"
            if style == "code":
                run.font.name = "Courier New"
            if size:
                run.font.size = Pt(size)

    for b in parse_markdown(markdown):
        if b.kind == "h":
            doc.add_heading(b.text, level=min(b.level, 4) - 1 if b.level > 1 else 0)
        elif b.kind == "p":
            add_runs(doc.add_paragraph(), b.text)
        elif b.kind == "quote":
            par = doc.add_paragraph()
            par.paragraph_format.left_indent = Pt(18)
            add_runs(par, b.text)
            for r in par.runs:
                r.italic = True
        elif b.kind == "bullets":
            for item in b.items:
                add_runs(doc.add_paragraph(style="List Bullet"), item)
        elif b.kind == "table" and b.rows:
            cols = max(len(r) for r in b.rows)
            table = doc.add_table(rows=len(b.rows), cols=cols)
            table.style = "Table Grid"
            for ri, row in enumerate(b.rows):
                for ci in range(cols):
                    cell = table.cell(ri, ci)
                    cell.text = ""
                    add_runs(cell.paragraphs[0], row[ci] if ci < len(row) else "", size=8)
                    if ri == 0:
                        for r in cell.paragraphs[0].runs:
                            r.bold = True
            doc.add_paragraph()
    path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(path))


def _pdf_text(text: str) -> str:
    """Escape for reportlab Paragraph markup and drop characters the base fonts lack."""
    safe = text.encode("cp1252", "replace").decode("cp1252")
    return safe.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pdf_inline(text: str) -> str:
    out = []
    for chunk, style in inline_runs(text):
        t = _pdf_text(chunk)
        if style == "bold":
            t = f"<b>{t}</b>"
        elif style == "italic":
            t = f"<i>{t}</i>"
        elif style == "code":
            t = f'<font face="Courier">{t}</font>'
        out.append(t)
    return "".join(out)


def write_pdf(markdown: str, path: Path, title: str = "Textolit report") -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            ListFlowable,
            ListItem,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ExportError(f"reportlab is not installed: {DOCS_HINT}") from exc

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    cell = ParagraphStyle("cell", parent=body, fontSize=7, leading=8.5)
    head = ParagraphStyle("head", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    quote = ParagraphStyle("quote", parent=body, leftIndent=12, fontName="Helvetica-Oblique")
    heads = {
        1: styles["Title"],
        2: styles["Heading2"],
        3: styles["Heading3"],
        4: styles["Heading4"],
    }

    page = landscape(A4)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=page,
        title=title,
        author="",
        creator="Textolit",
        subject="",
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )
    width = page[0] - 28 * mm
    story: list[Any] = []
    for b in parse_markdown(markdown):
        if b.kind == "h":
            story.append(Paragraph(_pdf_inline(b.text), heads.get(b.level, styles["Heading4"])))
        elif b.kind == "p":
            story += [Paragraph(_pdf_inline(b.text), body), Spacer(1, 3)]
        elif b.kind == "quote":
            story += [Paragraph(_pdf_inline(b.text), quote), Spacer(1, 3)]
        elif b.kind == "bullets":
            story.append(
                ListFlowable(
                    [ListItem(Paragraph(_pdf_inline(i), body)) for i in b.items],  # type: ignore[misc]
                    bulletType="bullet",
                    start="-",
                )
            )
        elif b.kind == "table" and b.rows:
            cols = max(len(r) for r in b.rows)
            data = [
                [
                    Paragraph(_pdf_inline(r[c] if c < len(r) else ""), head if ri == 0 else cell)
                    for c in range(cols)
                ]
                for ri, r in enumerate(b.rows)
            ]
            weights = [
                max(8, min(60, max(len(r[c]) if c < len(r) else 0 for r in b.rows)))
                for c in range(cols)
            ]
            widths = [width * w / sum(weights) for w in weights]
            tbl = Table(data, colWidths=widths, repeatRows=1)
            tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e8b57")),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#6b7f73")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f1f4f2")],
                        ),
                    ]
                )
            )
            story += [tbl, Spacer(1, 6)]
    path.parent.mkdir(parents=True, exist_ok=True)

    def stamp(canvas: object, _doc: object) -> None:
        canvas.setProducer("Textolit")  # type: ignore[attr-defined]

    doc.build(story, onFirstPage=stamp, onLaterPages=stamp)
