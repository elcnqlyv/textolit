"""Splash: signature banner above, tone line below, then on to the dashboard."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.events import Key
from textual.screen import Screen
from textual.widgets import Static

from textolit.ui.banner import BANNER, TONE_LINE

SPLASH_SECONDS = 2.5


class SplashScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="splash-banner", markup=False)
        yield Static(TONE_LINE, id="splash-tone", markup=False)

    def on_mount(self) -> None:
        self.set_timer(SPLASH_SECONDS, self._leave)

    def on_key(self, event: Key) -> None:
        event.stop()
        self._leave()

    def _leave(self) -> None:
        if self.is_current:
            self.dismiss(None)
