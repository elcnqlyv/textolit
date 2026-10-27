import json
from pathlib import Path

from textolit.core.case import Case
from textolit.core.runner import run


def test_run_logs_command_and_hashes(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    res = run(case, ["sh", "-c", "echo hi; echo oops >&2; exit 3"], env={"FOO": "bar"})
    assert res.exit_code == 3 and not res.ok
    row = case.conn.execute("SELECT * FROM commands WHERE id=?", (res.command_id,)).fetchone()
    assert json.loads(row["argv_json"])[0] == "sh"
    assert json.loads(row["env_json"]) == {"FOO": "bar"}
    assert row["exit_code"] == 3
    assert (case.root / row["stdout_path"]).read_bytes() == b"hi\n"
    assert (case.root / row["stderr_path"]).read_bytes() == b"oops\n"


def test_missing_binary_is_surfaced(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    res = run(case, ["definitely-not-a-binary-xyz"])
    assert res.error and "not found" in res.error
    assert case.conn.execute("SELECT count(*) FROM commands").fetchone()[0] == 1


def test_timeout(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    res = run(case, ["sleep", "5"], timeout=0.2)
    assert res.error and "timeout" in res.error


def test_streaming_lines_and_hashes(tmp_path: Path) -> None:
    from textolit.core.runner import run_streaming

    case = Case.create(tmp_path / "c")
    seen: list[str] = []
    res = run_streaming(
        case, ["sh", "-c", "echo one; echo two; echo err >&2; exit 4"], on_line=seen.append
    )
    assert seen == ["one", "two"] and res.exit_code == 4 and res.stopped_by is None
    row = case.conn.execute("SELECT * FROM commands WHERE id=?", (res.command_id,)).fetchone()
    assert (case.root / row["stdout_path"]).read_bytes() == b"one\ntwo\n"
    assert (case.root / row["stderr_path"]).read_bytes() == b"err\n"
    assert not list(case.logs_dir.glob(".tmp-*"))


def test_streaming_interrupt_sends_sigint(tmp_path: Path) -> None:
    from textolit.core.runner import run_streaming

    case = Case.create(tmp_path / "c")
    script = (
        "import signal,sys,time\n"
        "signal.signal(signal.SIGINT, lambda *a: (print('checkpoint', flush=True), sys.exit(2)))\n"
        "print('ready', flush=True)\n"
        "time.sleep(30)\n"
    )
    seen: list[str] = []
    res = run_streaming(
        case,
        ["python3", "-c", script],
        on_line=seen.append,
        should_stop=lambda: "ready" in seen,
        poll=0.05,
    )
    assert res.stopped_by == "interrupt" and res.exit_code == 2
    assert seen == ["ready", "checkpoint"]


def test_streaming_missing_binary(tmp_path: Path) -> None:
    from textolit.core.runner import run_streaming

    case = Case.create(tmp_path / "c")
    res = run_streaming(
        case, ["no-such-binary-xyz"], on_line=lambda _l: None, die_with_parent=False
    )
    assert res.error and "not found" in res.error
