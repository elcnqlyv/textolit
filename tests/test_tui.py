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


def test_findings_decisions_and_netmap(tmp_path: Path) -> None:
    asyncio.run(_review_flow(tmp_path))


async def _review_flow(tmp_path: Path) -> None:
    from textual.widgets import DataTable

    from textolit.core.ledger import add_artifact, add_finding, ensure_heuristic
    from textolit.modules.fswalk import FsWalk
    from textolit.modules.netmap import NetMap

    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc/init.d").mkdir(parents=True)
    (root / "etc/init.d/rcS").write_text("telnetd -p 23456 &\n")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    FsWalk().run(case)
    NetMap().run(case)
    ensure_heuristic(case, "x", "t", "t", "info")
    add_finding(case, heuristic_id="x", title="lead", evidence_path="a/b", confidence="low")
    app = TextolitApp(case, splash=False, worker=False)
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        assert app.query_one("#netmap", DataTable).row_count >= 1
        app.query_one("TabbedContent").active = "tab-findings"
        await pilot.pause()
        assert app.query_one("#findings", DataTable).row_count >= 1
        app.query_one("#findings", DataTable).focus()
        await pilot.press("x")
        await pilot.pause()
        statuses = {r[0] for r in case.conn.execute("SELECT status FROM findings")}
        assert "rejected" in statuses


def test_crack_tab_controls(tmp_path: Path) -> None:
    asyncio.run(_crack_flow(tmp_path))


async def _crack_flow(tmp_path: Path) -> None:
    from textual.widgets import DataTable

    from textolit import crack
    from textolit.hashcat import Profile

    case = Case.create(tmp_path / "c")
    case.conn.execute(
        "INSERT INTO crypto_materials(kind,algo,value,source_path,hashcat_mode,username,"
        "source_line,cracked) VALUES ('hash','md5','5f4dcc3b5aa765d61d8327deb882cf99',"
        "'artifacts/x/etc/shadow',0,'root',1,'password')"
    )
    case.conn.execute(
        "INSERT INTO crypto_materials(kind,algo,value,source_path,hashcat_mode,username,"
        "source_line) VALUES ('hash','md5','ffffffffffffffffffffffffffffffff',"
        "'artifacts/x/etc/shadow',0,'op',2)"
    )
    case.conn.commit()
    crack.plan_tasks(case, Profile(binary="hashcat"))
    app = TextolitApp(case, splash=False, worker=False)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        crypto = app.query_one("#crypto", DataTable)
        assert crypto.row_count == 2
        flat = str([crypto.get_row_at(i) for i in range(2)])
        assert "pa***" in flat and "password" not in flat  # cracked secret is masked
        app.query_one("TabbedContent").active = "tab-crack"
        await pilot.pause()
        table = app.query_one("#crack", DataTable)
        assert table.row_count == 2
        table.focus()
        await pilot.press("space")  # queued task -> paused
        await pilot.pause()
        assert crack.list_tasks(case)[0].status == "paused"
        await pilot.press("space")  # paused -> queued again
        await pilot.pause()
        assert crack.list_tasks(case)[0].status == "queued"
        await pilot.press("x")  # cancel
        await pilot.pause()
        assert crack.list_tasks(case)[0].status == "cancelled"


def test_llm_tab_and_gating(tmp_path: Path) -> None:
    asyncio.run(_llm_flow(tmp_path))


async def _llm_flow(tmp_path: Path) -> None:
    import json
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from llm_server import FakeLlm
    from textual.widgets import DataTable

    from textolit.core import jobs
    from textolit.core.ledger import add_finding, ensure_heuristic
    from textolit.llm_backends import LlmConfig, save_config

    with FakeLlm() as srv:
        srv.reply = json.dumps(
            {
                "summary": "One lead.",
                "priorities": [{"finding": "F1", "reason": "check it", "cites": ["F1", "E1"]}],
                "unverified": [],
            }
        )
        case = Case.create(tmp_path / "c")
        ensure_heuristic(case, "x.a", "t", "t", "high")
        add_finding(
            case,
            heuristic_id="x.a",
            title="lead",
            evidence_path="p",
            line=1,
            snippet="s",
            confidence="high",
            severity="high",
            owasp_iot="I1",
        )
        save_config(case, LlmConfig(model="m", base_url=srv.url))
        app = TextolitApp(case, splash=False, worker=False)
        async with app.run_test(size=(150, 40)) as pilot:
            await pilot.pause()
            assert "LLM off" in str(app.query_one("#llm-status").render())
            app.query_one("TabbedContent").active = "tab-llm"
            await pilot.pause()
            await pilot.press("t")  # off: nothing is queued
            await pilot.pause()
            assert not [j for j in jobs.list_jobs(case) if j.module == "llm"]
            case.set_llm(True)
            await pilot.press("t")
            await pilot.pause()
            queued = [j for j in jobs.list_jobs(case) if j.module == "llm"]
            assert len(queued) == 1 and queued[0].args == {"task": "triage"}
            jobs.run_job(case, queued[0].id)
            app.refresh_panes()
            await pilot.pause()
            assert app.query_one("#llm-calls", DataTable).row_count == 1
            assert "Latest triage" in str(app.query_one("#llm-latest").render())
            assert "LLM ACTIVE" in str(app.query_one("#llm-status").render())
