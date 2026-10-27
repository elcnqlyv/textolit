"""Textolit TUI shell."""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.widgets import Footer, Static

from textolit.core.case import Case
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
        yield Static(f"case: {self.case.root}", id="statusbar", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(PCB_THEME)
        self.theme = PCB_THEME.name
        if self._splash:
            self.push_screen(SplashScreen())


def launch(case_dir: Path) -> int:
    case = Case.open(case_dir)
    TextolitApp(case).run()
    return 0
