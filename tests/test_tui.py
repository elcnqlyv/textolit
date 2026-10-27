import asyncio
from pathlib import Path

from textolit.core.case import Case
from textolit.ui.app import TextolitApp
from textolit.ui.banner import BANNER, TONE_LINE
from textolit.ui.screens.splash import SplashScreen
from textolit.ui.widgets import blocks, toggle, trace


def test_widget_helpers() -> None:
    assert trace(6) == "●────●"
    assert blocks(0.5, 4) == "▓▓░░"
    assert toggle(True) == "▣" and toggle(False) == "▢"


def test_splash_then_main(tmp_path: Path) -> None:
    asyncio.run(_splash_flow(tmp_path))


async def _splash_flow(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    app = TextolitApp(case)
    async with app.run_test() as pilot:
        assert isinstance(app.screen, SplashScreen)
        banner = app.screen.query_one("#splash-banner")
        assert BANNER in str(banner.render())
        assert TONE_LINE in str(app.screen.query_one("#splash-tone").render())
        await pilot.press("space")
        await pilot.pause()
        assert not isinstance(app.screen, SplashScreen)
