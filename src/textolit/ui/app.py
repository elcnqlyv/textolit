"""Textolit TUI shell."""

from __future__ import annotations

import json
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.theme import Theme
from textual.widgets import DataTable, Footer, RichLog, Static, TabbedContent, TabPane

from textolit.core import jobs
from textolit.core.case import Case
from textolit.core.ledger import decide
from textolit.ui.panes import (
    ArtifactsPane,
    CommandsPane,
    DashboardPane,
    EntropyPane,
    FindingsPane,
    JobsPane,
    NetMapPane,
)
from textolit.ui.screens.modals import ConfirmScreen, HelpScreen
from textolit.ui.screens.splash import SplashScreen
from textolit.ui.widgets import TraceRule, blocks, toggle

TAGLINE = "Textolit — firmware triage workbench for CCTV and access-control research."

PCB_THEME = Theme(
    name="textolit",
    primary="#c9a227",  # copper
    secondary="#2e8b57",  # trace
    accent="#b87333",  # pad
    warning="#d9822b",
    error="#c0392b",
    success="#2e8b57",
    foreground="#e8e6df",
    background="#0b1a12",  # substrate
    surface="#10261a",
    panel="#10261a",
    dark=True,
)


class TextolitApp(App[None]):
    CSS_PATH = "theme.tcss"
    TITLE = "Textolit"
    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("f2", "toggle_raw", "Raw"),
        Binding("f3", "findings_filter", "Filter"),
        Binding("f4", "show_jobs", "Jobs"),
        Binding("f5", "toggle_llm", "LLM"),
        Binding("f6", "export", "Export"),
        Binding("f10", "quit", "Quit"),
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("p", "pipeline", "Run", show=True),
        Binding("a", "decide('accepted')", "Accept"),
        Binding("x", "decide('rejected')", "Reject"),
        Binding("s", "decide('snoozed')", "Snooze"),
    ]

    def __init__(self, case: Case, *, splash: bool = True, worker: bool = True) -> None:
        super().__init__()
        self.case = case
        self._splash = splash
        self._use_worker = worker
        self._worker: jobs.Worker | None = None

    def compose(self) -> ComposeResult:
        yield Static(TAGLINE, id="brand", markup=False)
        yield TraceRule()
        with TabbedContent(initial="tab-dashboard"):
            with TabPane("Dashboard", id="tab-dashboard"):
                yield DashboardPane(id="pane-dashboard")
            with TabPane("Entropy", id="tab-entropy"):
                yield EntropyPane(id="pane-entropy")
            with TabPane("Artifacts", id="tab-artifacts"):
                yield ArtifactsPane(id="pane-artifacts")
            with TabPane("Netmap", id="tab-netmap"):
                yield NetMapPane(id="pane-netmap")
            with TabPane("Findings", id="tab-findings"):
                yield FindingsPane(id="pane-findings")
            with TabPane("Jobs", id="tab-jobs"):
                yield JobsPane(id="pane-jobs")
            with TabPane("Commands", id="tab-commands"):
                yield CommandsPane(id="pane-commands")
        yield RichLog(id="raw", highlight=False, markup=False, wrap=True)
        yield Static(id="jobbar", markup=False)
        yield Static(id="statusbar", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(PCB_THEME)
        self.theme = PCB_THEME.name
        self.query_one("#raw", RichLog).display = False
        jobs.mark_interrupted(self.case)
        if self._use_worker:
            self._worker = jobs.Worker(self.case)
            self._worker.start()
        self.set_interval(1.0, self.refresh_panes)
        self.refresh_panes()
        if self._splash:
            self.push_screen(SplashScreen())

    def on_unmount(self) -> None:
        if self._worker:
            self._worker.stop()

    # -- refresh ---------------------------------------------------------

    def refresh_panes(self) -> None:
        self.query_one("#pane-dashboard", DashboardPane).refresh_data(self.case)
        self.query_one("#pane-entropy", EntropyPane).refresh_data(self.case)
        self.query_one("#pane-artifacts", ArtifactsPane).refresh_data(self.case)
        self.query_one("#pane-netmap", NetMapPane).refresh_data(self.case)
        self.query_one("#pane-findings", FindingsPane).refresh_data(self.case)
        self.query_one("#pane-jobs", JobsPane).refresh_data(self.case)
        self.query_one("#pane-commands", CommandsPane).refresh_data(self.case)
        self._refresh_jobbar()
        self._refresh_status()

    def _refresh_jobbar(self) -> None:
        live = [j for j in jobs.list_jobs(self.case) if j.status in ("queued", "running")]
        text = Text()
        if not live:
            text.append("jobs: idle", style="#6b7f73")
        for j in live[:5]:
            text.append(f"{blocks(j.progress)} ", style="#b87333")
            text.append(f"{j.module:<10}", style="bold")
            text.append(
                f"{j.status:<8}{j.message}\n" if j.status == "running" else "queued\n",
                style="#6b7f73",
            )
        text.rstrip()
        self.query_one("#jobbar", Static).update(text)

    def _refresh_status(self) -> None:
        bar = self.query_one("#statusbar", Static)
        llm = self.case.llm_enabled
        bar.set_class(llm, "llm-on")
        state = "LLM ACTIVE" if llm else "LLM off"
        bar.update(f"{toggle(llm)} {state}   case: {self.case.root.name}   {self.case.root}")

    # -- actions ---------------------------------------------------------

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_toggle_raw(self) -> None:
        raw = self.query_one("#raw", RichLog)
        raw.display = not raw.display

    def action_findings_filter(self) -> None:
        self.query_one(TabbedContent).active = "tab-findings"
        pane = self.query_one("#pane-findings", FindingsPane)
        self.notify(f"findings filter: {pane.cycle_filter()}")
        pane.refresh_data(self.case)

    def action_show_jobs(self) -> None:
        self.query_one(TabbedContent).active = "tab-jobs"

    def action_toggle_llm(self) -> None:
        if self.case.llm_enabled:
            self.case.set_llm(False)
            self._refresh_status()
            return
        question = (
            "Enable LLM for this case? Case evidence excerpts may be sent to the configured "
            "backend. Default is OFF; every call is logged."
        )

        def decide(ok: bool | None) -> None:
            if ok:
                self.case.set_llm(True)
                self._refresh_status()

        self.push_screen(ConfirmScreen(question), decide)

    def action_decide(self, status: str) -> None:
        if self.query_one(TabbedContent).active != "tab-findings":
            return
        pane = self.query_one("#pane-findings", FindingsPane)
        fid = pane.selected_id()
        if fid is None:
            return
        decide(self.case, fid, status)
        pane.refresh_data(self.case)
        self.notify(f"finding {fid}: {status}")

    def action_export(self) -> None:
        jid = jobs.enqueue(self.case, "report")
        self.notify(f"queued report export (job {jid})")

    def action_pipeline(self) -> None:
        if self.case.conn.execute("SELECT 1 FROM images LIMIT 1").fetchone() is None:
            self.notify(
                "no image ingested; run `textolit init <case> --image FILE`", severity="warning"
            )
            return
        for module in ("unpack", "entropy", "fswalk", "binintel", "netmap"):
            jobs.enqueue(self.case, module)
        self.notify("queued unpack, entropy, fswalk, binintel, netmap (rule sweep follows)")

    async def action_quit(self) -> None:
        busy = jobs.running_count(self.case)
        if not busy:
            self.exit()
            return

        def decide(ok: bool | None) -> None:
            if ok:
                self.exit()

        self.push_screen(
            ConfirmScreen(
                f"{busy} job(s) queued or running. Quit anyway? Running jobs are marked "
                "interrupted and are not restarted automatically."
            ),
            decide,
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "commands":
            return
        cmd_id = event.data_table.get_row(event.row_key)[0]
        row = self.case.conn.execute("SELECT * FROM commands WHERE id=?", (cmd_id,)).fetchone()
        raw = self.query_one("#raw", RichLog)
        raw.clear()
        raw.write(f"$ {' '.join(json.loads(row['argv_json']))}   (exit {row['exit_code']})")
        for label, key in (("stdout", "stdout_path"), ("stderr", "stderr_path")):
            if row[key]:
                data = (self.case.root / row[key]).read_bytes()[:20000]
                raw.write(f"--- {label} ---")
                raw.write(data.decode("utf-8", "replace"))
        raw.display = True


def launch(case_dir: Path) -> int:
    TextolitApp(Case.open(case_dir)).run()
    return 0
