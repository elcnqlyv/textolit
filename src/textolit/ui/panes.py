"""Tab panes. Each pane reads from the case database and redraws only when data changed."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import DataTable, DirectoryTree, Static

from textolit.core import jobs
from textolit.core.case import Case
from textolit.ui.widgets import blocks

CLASS_STYLE = {
    "plain": "#2e8b57",
    "compressed": "#b87333",
    "encrypted": "#c0392b",
    "empty": "#6b7f73",
}
LEVELS = "▁▂▃▄▅▆▇█"


def entropy_strip(regions: Sequence[Any], width: int) -> Text:
    """One row of block glyphs: height = entropy, colour = classification."""
    text = Text()
    if not regions or width < 1:
        return text
    total = regions[-1]["offset"] + regions[-1]["length"]
    idx = 0
    for col in range(width):
        centre = int((col + 0.5) * total / width)
        while idx + 1 < len(regions) and regions[idx]["offset"] + regions[idx]["length"] <= centre:
            idx += 1
        r = regions[idx]
        level = min(int(r["entropy"] / 8 * len(LEVELS)), len(LEVELS) - 1)
        text.append(LEVELS[level], style=CLASS_STYLE.get(r["classification"], "white"))
    return text


def sync_table(table: DataTable[Any], rows: list[tuple[Any, ...]]) -> None:
    """Repopulate only when contents differ, so cursor and scroll survive refreshes."""
    if getattr(table, "_last_rows", None) == rows:
        return
    table._last_rows = rows  # type: ignore[attr-defined]  # cache for change detection
    table.clear()
    for row in rows:
        table.add_row(*row)


class DashboardPane(VerticalScroll):
    def compose(self) -> ComposeResult:
        yield Static(id="dash-body", markup=False)

    def refresh_data(self, case: Case) -> None:
        c = case.conn
        t = Text()
        name = c.execute("SELECT name FROM cases WHERE id=?", (case.case_id,)).fetchone()[0]
        t.append(f"Case {name}\n", style="bold #c9a227")
        t.append(f"{case.root}\n\n", style="#6b7f73")
        img = c.execute("SELECT * FROM images ORDER BY id DESC LIMIT 1").fetchone()
        t.append("Image\n", style="bold #c9a227")
        if img:
            t.append(f"  {img['path']}  {img['size']} bytes\n  sha256 {img['sha256']}\n")
        else:
            t.append("  none ingested (textolit init <case> --image FILE)\n", style="#d9822b")
        t.append("\nEntropy\n", style="bold #c9a227")
        rows = c.execute(
            "SELECT classification, sum(length) AS n FROM regions GROUP BY classification"
        ).fetchall()
        if rows:
            for r in rows:
                t.append("  ▣ ", style=CLASS_STYLE.get(r["classification"], "white"))
                t.append(f"{r['classification']:<11}{r['n']:>12} bytes\n")
        else:
            t.append("  not run\n", style="#6b7f73")
        fs = c.execute("SELECT count(*) FROM artifacts WHERE kind LIKE 'fs_root:%'").fetchone()[0]
        t.append(f"\nFilesystem roots  {fs}\n", style="bold #c9a227")
        pending = c.execute("SELECT count(*) FROM findings WHERE status='pending'").fetchone()[0]
        style = "bold #d9822b" if pending else "#6b7f73"
        t.append(f"\n{pending} leads pending review\n", style=style)
        js = jobs.list_jobs(case)
        t.append("\nJobs\n", style="bold #c9a227")
        for j in js[-6:]:
            t.append(f"  {blocks(j.progress, 8)} {j.status:<11}{j.module}\n")
        self.query_one("#dash-body", Static).update(t)


class EntropyPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Entropy map  (height = bits/byte, colour = class)", classes="heading")
        yield Static(id="strip", markup=False)
        yield Static(
            "▣ plain  ▣ compressed  ▣ encrypted (lead)  ▣ empty", id="legend", classes="muted"
        )
        yield DataTable(id="regions", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#regions", DataTable).add_columns("offset", "length", "entropy", "class")

    def refresh_data(self, case: Case) -> None:
        regions = case.conn.execute("SELECT * FROM regions ORDER BY image_id, offset").fetchall()
        width = max(self.size.width - 2, 10)
        self.query_one("#strip", Static).update(entropy_strip(regions, width))
        sync_table(
            self.query_one("#regions", DataTable),
            [
                (f"0x{r['offset']:08x}", r["length"], f"{r['entropy']:.3f}", r["classification"])
                for r in regions
            ],
        )


class ArtifactsPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Artifact tree (case artifacts/)", classes="heading")
        yield DirectoryTree("artifacts", id="tree")

    def on_mount(self) -> None:
        self.query_one("#tree", DirectoryTree).path = self.app.case.artifacts_dir  # type: ignore[attr-defined]

    def refresh_data(self, case: Case) -> None:
        # reload is cheap enough at 1 Hz only when something changed; tracked by artifact count
        n = case.conn.execute("SELECT count(*) FROM artifacts").fetchone()[0]
        if getattr(self, "_n", None) != n:
            self._n = n
            self.query_one("#tree", DirectoryTree).reload()


class FindingsPane(Vertical):
    FILTERS = ("pending", "accepted", "rejected", "snoozed", "all")

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.filter = "pending"

    def compose(self) -> ComposeResult:
        yield Static(id="findings-head", markup=False)
        yield DataTable(id="findings", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#findings", DataTable).add_columns(
            "id", "conf", "severity", "status", "title", "evidence"
        )

    def selected_id(self) -> int | None:
        table = self.query_one("#findings", DataTable)
        if table.row_count == 0:
            return None
        return int(table.get_row_at(table.cursor_row)[0])

    def cycle_filter(self) -> str:
        self.filter = self.FILTERS[(self.FILTERS.index(self.filter) + 1) % len(self.FILTERS)]
        return self.filter

    def refresh_data(self, case: Case) -> None:
        q = (
            "SELECT id, confidence, severity, status, title,"
            " evidence_path || coalesce(':' || (SELECT line FROM evidence_links"
            " WHERE finding_id=findings.id LIMIT 1), '') FROM findings"
        )
        args: tuple[str, ...] = ()
        if self.filter != "all":
            q += " WHERE status=?"
            args = (self.filter,)
        order = " ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END, id"
        rows = case.conn.execute(q + order, args).fetchall()
        pending = case.conn.execute("SELECT count(*) FROM findings WHERE status='pending'")
        head = f"{pending.fetchone()[0]} leads pending review   filter: {self.filter}  (F3)"
        self.query_one("#findings-head", Static).update(head)
        sync_table(self.query_one("#findings", DataTable), [tuple(r) for r in rows])


class CommandsPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static(
            "Command log  (Enter on a row shows raw output in the F2 pane)", classes="heading"
        )
        yield DataTable(id="commands", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#commands", DataTable).add_columns("id", "module", "exit", "argv")

    def refresh_data(self, case: Case) -> None:
        rows = case.conn.execute("SELECT * FROM commands ORDER BY id DESC LIMIT 500").fetchall()
        sync_table(
            self.query_one("#commands", DataTable),
            [
                (r["id"], r["module"] or "-", r["exit_code"], " ".join(json.loads(r["argv_json"])))
                for r in rows
            ],
        )


class JobsPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static(
            "Job queue  (state is persisted; killed jobs show as interrupted)", classes="heading"
        )
        yield DataTable(id="jobs", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#jobs", DataTable).add_columns(
            "id", "module", "status", "progress", "message"
        )

    def refresh_data(self, case: Case) -> None:
        rows = [
            (j.id, j.module, j.status, f"{blocks(j.progress)} {j.progress:4.0%}", j.message)
            for j in jobs.list_jobs(case)
        ]
        sync_table(self.query_one("#jobs", DataTable), rows)


class NetMapPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Listen-by-default (source file and line for every row)", classes="heading")
        yield DataTable(id="netmap", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#netmap", DataTable).add_columns(
            "port", "service", "kind", "non-std", "default", "source", "evidence"
        )

    def refresh_data(self, case: Case) -> None:
        rows = case.conn.execute(
            "SELECT e.port, e.proto, s.name, e.nonstandard, e.default_on, e.source_path,"
            " e.source_line, e.evidence FROM network_endpoints e"
            " LEFT JOIN services s ON s.id=e.service_id"
            " ORDER BY e.default_on DESC, e.nonstandard DESC, e.port"
        ).fetchall()
        sync_table(
            self.query_one("#netmap", DataTable),
            [
                (
                    f"{r['port']}/{r['proto']}",
                    r["name"],
                    "-",
                    "NON-STD" if r["nonstandard"] else "",
                    "on" if r["default_on"] else "off",
                    f"{r['source_path']}:{r['source_line']}",
                    r["evidence"][:80],
                )
                for r in rows
            ],
        )
