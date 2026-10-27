"""Small PCB-flavoured widgets."""

from __future__ import annotations

from textual.widgets import Static

FILLED, EMPTY = "▓", "░"


def trace(width: int) -> str:
    """A PCB trace: one row of ─ with ● pads at both ends."""
    if width < 3:
        return "●" * max(width, 0)
    return "●" + "─" * (width - 2) + "●"


def toggle(on: bool) -> str:
    return "▣" if on else "▢"


def blocks(fraction: float, width: int = 10) -> str:
    fraction = min(max(fraction, 0.0), 1.0)
    filled = round(fraction * width)
    return FILLED * filled + EMPTY * (width - filled)


class TraceRule(Static):
    """Horizontal rule drawn as a PCB trace; colour comes from TCSS (`$trace`)."""

    def render(self) -> str:
        return trace(self.size.width)
