"""report: Markdown report from the evidence ledger (PDF/DOCX/CVE JSON arrive in sprint 4)."""

from __future__ import annotations

import json
from typing import Any

from textolit.core.case import Case, utcnow
from textolit.core.ledger import add_artifact
from textolit.modules.base import ModuleResult, ProgressFn, no_progress


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_none recorded_\n"
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def render_markdown(case: Case) -> str:
    c = case.conn
    name = c.execute("SELECT name FROM cases WHERE id=?", (case.case_id,)).fetchone()[0]
    out = [
        f"# Textolit report: {name}",
        "",
        "Textolit — firmware triage workbench for CCTV and access-control research.",
        "",
        f"Report time {utcnow()}. Authorized testing only; leads, not verdicts.",
        "",
        "## Images",
        "",
    ]
    imgs = c.execute("SELECT * FROM images ORDER BY id").fetchall()
    out.append(
        _table(
            ["id", "file", "size", "sha256", "type"],
            [
                [
                    i["id"],
                    i["path"],
                    i["size"],
                    i["sha256"],
                    json.loads(i["meta_json"]).get("file_type") or "-",
                ]
                for i in imgs
            ],
        )
    )

    out += ["## Entropy map", ""]
    regs = c.execute("SELECT * FROM regions ORDER BY image_id, offset").fetchall()
    out.append(
        _table(
            ["offset", "length", "entropy", "class"],
            [
                [f"0x{r['offset']:x}", r["length"], f"{r['entropy']:.2f}", r["classification"]]
                for r in regs
            ],
        )
    )
    if any(r["classification"] == "encrypted" for r in regs):
        out += [
            "> Regions marked `encrypted` are a statistical lead (uniform high-entropy data"
            " without a known compression magic). Verify before concluding.",
            "",
        ]

    out += ["## Filesystems", ""]
    fs = c.execute("SELECT kind, path FROM artifacts WHERE kind LIKE 'fs_root:%' ORDER BY id")
    out.append(_table(["type", "path"], [[r["kind"].split(":", 1)[1], r["path"]] for r in fs]))

    out += ["## Findings", ""]
    counts = {
        r["status"]: r["n"]
        for r in c.execute("SELECT status, count(*) AS n FROM findings GROUP BY status")
    }
    if counts:
        out.append(_table(["status", "count"], [[k, v] for k, v in sorted(counts.items())]))
        rows = c.execute(
            "SELECT title, confidence, status, evidence_path FROM findings"
            " WHERE status!='rejected' ORDER BY id"
        ).fetchall()
        out.append(_table(["title", "confidence", "status", "evidence"], [list(r) for r in rows]))
    else:
        out += [
            "_No findings recorded. The missed-findings engine is not enabled yet; an empty"
            " list here is not a clean bill of health._",
            "",
        ]

    out += ["## Command log (appendix)", ""]
    cmds = c.execute("SELECT * FROM commands ORDER BY id").fetchall()
    out.append(
        _table(
            ["id", "argv", "exit", "stdout sha256"],
            [
                [
                    r["id"],
                    " ".join(json.loads(r["argv_json"])),
                    r["exit_code"],
                    (r["stdout_sha256"] or "")[:16],
                ]
                for r in cmds
            ],
        )
    )
    return "\n".join(out)


class Report:
    name = "report"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        text = render_markdown(case)
        case.reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = utcnow().replace(":", "").replace("-", "")[:15]
        path = case.reports_dir / f"report-{stamp}.md"
        path.write_text(text, encoding="utf-8")
        add_artifact(case, "report", path)
        return ModuleResult(
            self.name, True, f"wrote {case.rel(path)}", data={"path": case.rel(path)}
        )
