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
