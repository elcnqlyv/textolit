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


def test_entropy_strip_maps_classes() -> None:
    from textolit.ui.panes import entropy_strip

    regions = [
        {"offset": 0, "length": 100, "entropy": 0.0, "classification": "empty"},
        {"offset": 100, "length": 100, "entropy": 7.99, "classification": "encrypted"},
    ]
    strip = entropy_strip(regions, 4)
    assert strip.plain == "▁▁██"
    assert strip.spans[-1].style == "#c0392b"


def test_panes_render_from_ledger(tmp_path: Path) -> None:
    asyncio.run(_pane_flow(tmp_path))


async def _pane_flow(tmp_path: Path) -> None:
    import os

    from textual.widgets import DataTable

    from textolit.modules.entropy import Entropy
    from textolit.modules.ingest import Ingest

    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(16384))
    case = Case.create(tmp_path / "c")
    Ingest().run(case, image=img)
    Entropy().run(case)
    app = TextolitApp(case, splash=False)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.query_one("#regions", DataTable).row_count >= 1
        assert app.query_one("#commands", DataTable).row_count >= 1
        assert "0 leads pending review" in str(app.query_one("#dash-body").render())


def test_keybinds_and_guard(tmp_path: Path) -> None:
    asyncio.run(_keys_flow(tmp_path))


async def _keys_flow(tmp_path: Path) -> None:
    from textual.widgets import RichLog

    from textolit.core import jobs
    from textolit.ui.screens.modals import ConfirmScreen

    case = Case.create(tmp_path / "c")
    app = TextolitApp(case, splash=False, worker=False)
    async with app.run_test(size=(120, 40)) as pilot:
        raw = app.query_one("#raw", RichLog)
        assert raw.display is False
        await pilot.press("f2")
        assert raw.display is True
        await pilot.press("f4")
        assert app.query_one("TabbedContent").active == "tab-jobs"
        # F5 asks for confirmation; declining leaves the LLM off
        await pilot.press("f5")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert case.llm_enabled is False
        await pilot.press("f5")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        assert case.llm_enabled is True
        assert "LLM ACTIVE" in str(app.query_one("#statusbar").render())
        # quit is guarded while a job is queued
        jobs.enqueue(case, "entropy")
        await pilot.press("f10")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("escape")
