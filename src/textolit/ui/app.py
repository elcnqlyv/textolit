"""Textolit TUI shell."""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.widgets import Footer, Static, TabbedContent, TabPane

from textolit.core.case import Case
from textolit.ui.panes import (
    ArtifactsPane,
    CommandsPane,
    DashboardPane,
    EntropyPane,
    FindingsPane,
)
from textolit.ui.screens.splash import SplashScreen
from textolit.ui.widgets import TraceRule

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

    def __init__(self, case: Case, *, splash: bool = True) -> None:
        super().__init__()
        self.case = case
        self._splash = splash

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
            with TabPane("Findings", id="tab-findings"):
                yield FindingsPane(id="pane-findings")
            with TabPane("Commands", id="tab-commands"):
                yield CommandsPane(id="pane-commands")
        yield Static(f"case: {self.case.root}", id="statusbar", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(PCB_THEME)
        self.theme = PCB_THEME.name
        self.set_interval(1.0, self.refresh_panes)
        self.refresh_panes()
        if self._splash:
            self.push_screen(SplashScreen())

    def refresh_panes(self) -> None:
        self.query_one("#pane-dashboard", DashboardPane).refresh_data(self.case)
        self.query_one("#pane-entropy", EntropyPane).refresh_data(self.case)
        self.query_one("#pane-artifacts", ArtifactsPane).refresh_data(self.case)
        self.query_one("#pane-findings", FindingsPane).refresh_data(self.case)
        self.query_one("#pane-commands", CommandsPane).refresh_data(self.case)


def launch(case_dir: Path) -> int:
    case = Case.open(case_dir)
    TextolitApp(case).run()
    return 0
