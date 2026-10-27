"""Confirm and help dialogs."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Label

HELP_TEXT = """\
F1   this help             F2   raw output pane
F3   cycle findings filter F4   job queue
F5   LLM on/off (confirm)  F6   export Markdown report
F10  quit (guarded)        p    queue the full pipeline
a/x/s  accept / reject / snooze the selected finding (Findings tab)
g      plan and run hashcat attacks   space  pause/resume   x  cancel (Crack tab)
Tab/Shift+Tab move focus   Enter on a command row loads its raw output

Everything runs through the case ledger; state survives a killed TUI."""


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [("escape", "answer(False)", "No"), ("y", "answer(True)", "Yes")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        yield Label(self.question, id="dialog-q", markup=False)
        with Horizontal():
            yield Button("▣ Yes", id="yes")
            yield Button("▢ No", id="no")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)


class HelpScreen(ModalScreen[None]):
    BINDINGS = [("escape", "dismiss", "Close"), ("f1", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        yield Label(HELP_TEXT, id="dialog-help", markup=False)
