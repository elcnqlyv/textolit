"""Textolit TUI shell."""

from __future__ import annotations

import json
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.css.query import NoMatches
from textual.theme import Theme
from textual.widgets import DataTable, Footer, RichLog, Static, TabbedContent, TabPane

from textolit import crack
from textolit.core import jobs
from textolit.core.case import Case
from textolit.core.ledger import decide
from textolit.hashcat import Profile
from textolit.llm_backends import BackendError, is_loopback, load_config
from textolit.ui.panes import (
    ArtifactsPane,
    CommandsPane,
    CrackPane,
    CryptoPane,
    DashboardPane,
    EntropyPane,
    FindingsPane,
    JobsPane,
    LlmPane,
    NetMapPane,
    WebPane,
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
        Binding("g", "crack_plan", "Crack plan"),
        Binding("t", "llm_task('triage')", "Triage"),
        Binding("c", "llm_task('crypto')", "Crypto LLM"),
        Binding("d", "llm_task('draft')", "Draft"),
        Binding("v", "llm_cve", "CVE draft"),
        Binding("space", "crack_toggle", "Pause/resume"),
    ]

    def __init__(self, case: Case, *, splash: bool = True, worker: bool = True) -> None:
        super().__init__()
        self.case = case
        self._splash = splash
        self._use_worker = worker
        self._job_workers: list[jobs.Worker] = []

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
            with TabPane("Web", id="tab-web"):
                yield WebPane(id="pane-web")
            with TabPane("Crypto", id="tab-crypto"):
                yield CryptoPane(id="pane-crypto")
            with TabPane("Crack", id="tab-crack"):
                yield CrackPane(id="pane-crack")
            with TabPane("LLM", id="tab-llm"):
                yield LlmPane(id="pane-llm")
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
            for long_jobs in (False, True):
                worker = jobs.Worker(self.case, long_jobs=long_jobs)
                worker.start()
                self._job_workers.append(worker)
        self.set_interval(1.0, self.refresh_panes)
        self.refresh_panes()
        if self._splash:
            self.push_screen(SplashScreen())

    def on_unmount(self) -> None:
        for worker in self._job_workers:
            worker.stop()

    # -- refresh ---------------------------------------------------------

    def refresh_panes(self) -> None:
        try:
            self._refresh_all()
        except NoMatches:
            return  # the timer fired while the screen was being torn down

    def _refresh_all(self) -> None:
        self.query_one("#pane-dashboard", DashboardPane).refresh_data(self.case)
        self.query_one("#pane-entropy", EntropyPane).refresh_data(self.case)
        self.query_one("#pane-artifacts", ArtifactsPane).refresh_data(self.case)
        self.query_one("#pane-netmap", NetMapPane).refresh_data(self.case)
        self.query_one("#pane-web", WebPane).refresh_data(self.case)
        self.query_one("#pane-crypto", CryptoPane).refresh_data(self.case)
        self.query_one("#pane-crack", CrackPane).refresh_data(self.case)
        self.query_one("#pane-llm", LlmPane).refresh_data(self.case)
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
        try:
            cfg = load_config(self.case)
            where = "on this machine" if is_loopback(cfg.url) else "to a REMOTE host"
            target = f"{cfg.backend} {cfg.model or '(no model set)'} {where}"
        except BackendError:
            target = "an unreadable llm.json"
        question = (
            f"Enable LLM for this case? Evidence excerpts (secrets masked) go to {target}. "
            "Default is OFF. Every call is logged."
        )

        def decide(ok: bool | None) -> None:
            if ok:
                self.case.set_llm(True)
                self._refresh_status()

        self.push_screen(ConfirmScreen(question), decide)

    def action_decide(self, status: str) -> None:
        tab = self.query_one(TabbedContent).active
        if tab == "tab-crack" and status == "rejected":
            self._crack_control("cancel")
            return
        if tab != "tab-findings":
            return
        pane = self.query_one("#pane-findings", FindingsPane)
        fid = pane.selected_id()
        if fid is None:
            return
        decide(self.case, fid, status)
        pane.refresh_data(self.case)
        self.notify(f"finding {fid}: {status}")

    def _crack_control(self, action: str) -> None:
        if self.query_one(TabbedContent).active != "tab-crack":
            return
        picked = self.query_one("#pane-crack", CrackPane).selected()
        if picked is None:
            return
        tid, _status = picked
        try:
            self.notify(f"task {tid}: {crack.request(self.case, tid, action)}")
        except ValueError as exc:
            self.notify(str(exc), severity="warning")
            return
        if action == "resume":
            jobs.enqueue(self.case, "hashcat")
        self.query_one("#pane-crack", CrackPane).refresh_data(self.case)

    def action_crack_toggle(self) -> None:
        if self.query_one(TabbedContent).active != "tab-crack":
            return
        picked = self.query_one("#pane-crack", CrackPane).selected()
        if picked:
            self._crack_control("resume" if picked[1] == "paused" else "pause")

    def action_crack_plan(self) -> None:
        self.query_one(TabbedContent).active = "tab-crack"
        problem = crack.check_ready()
        if problem:
            self.notify(problem, severity="warning")
            return
        ids, warnings = crack.plan_tasks(self.case, Profile())
        for w in warnings:
            self.notify(w, severity="warning")
        if not ids:
            self.notify("nothing new to queue (no uncracked hashes, or already planned)")
            return
        jobs.enqueue(self.case, "hashcat")
        self.notify(f"queued {len(ids)} crack tasks (-w 2, default list then digit masks)")

    def _llm_ready(self) -> bool:
        if not self.case.llm_enabled:
            self.notify("LLM is off for this case. Press F5 to turn it on.", severity="warning")
            return False
        return True

    def action_llm_task(self, task: str) -> None:
        if self.query_one(TabbedContent).active != "tab-llm" or not self._llm_ready():
            return
        jid = jobs.enqueue(self.case, "llm", task=task)
        self.notify(f"queued LLM {task} (job {jid}). The reply is validated before use.")

    def action_llm_cve(self) -> None:
        if self.query_one(TabbedContent).active != "tab-findings" or not self._llm_ready():
            return
        fid = self.query_one("#pane-findings", FindingsPane).selected_id()
        if fid is None:
            return
        jid = jobs.enqueue(self.case, "llm", task="cve", finding=fid)
        self.notify(f"queued CVE write-up draft for finding {fid} (job {jid})")

    def action_export(self) -> None:
        jid = jobs.enqueue(self.case, "report", formats=["all"])
        self.notify(f"queued report export: md, docx, pdf, CVE json (job {jid})")

    def action_pipeline(self) -> None:
        if self.case.conn.execute("SELECT 1 FROM images LIMIT 1").fetchone() is None:
            self.notify(
                "no image ingested; run `textolit init <case> --image FILE`", severity="warning"
            )
            return
        for module in ("unpack", "entropy", "fswalk", "binintel", "netmap", "crypto", "websurface"):
            jobs.enqueue(self.case, module)
        self.notify("queued the analysis pipeline (rule sweep follows). Cracking is separate: g")

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
