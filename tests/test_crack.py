import hashlib
import json
import threading
import time
from pathlib import Path

import pytest

from textolit import crack
from textolit.core.case import Case
from textolit.hashcat import Profile

FAKE = str(Path(__file__).parent / "fake_hashcat.py")
ADMIN = hashlib.md5(b"admin").hexdigest()
OTHER = hashlib.md5(b"zz-not-in-any-list-zz").hexdigest()


def case_with_hashes(tmp: Path) -> Case:
    case = Case.create(tmp / "c")
    for user, value, line in (("admin", ADMIN, 1), ("guest", OTHER, 2)):
        case.conn.execute(
            "INSERT INTO crypto_materials(kind,algo,value,source_path,hashcat_mode,username,"
            "source_line) VALUES ('hash','md5',?,'artifacts/x/etc/shadow',0,?,?)",
            (value, user, line),
        )
    case.conn.commit()
    return case


def test_export_and_plan(tmp_path: Path) -> None:
    case = case_with_hashes(tmp_path)
    ids, warnings = crack.plan_tasks(case, Profile(binary=FAKE), wordlist="/w.txt", rules="/r.rule")
    tasks = crack.list_tasks(case)
    assert [t.label for t in tasks] == [
        "m0 default IoT passwords",
        "m0 wordlist",
        "m0 wordlist + rules",
        "m0 digits 4-8",
    ]
    assert tasks[0].total == 2 and not warnings
    hashes = (case.root / "artifacts/crypto/hashes-0.txt").read_text().split()
    assert sorted(hashes) == sorted([ADMIN, OTHER])
    argv = json.loads(case.conn.execute("SELECT argv_json FROM crack_tasks").fetchone()[0])
    assert argv[0] == FAKE and "-w" in argv and argv[argv.index("-w") + 1] == "2"
    # planning again queues nothing new
    again, _ = crack.plan_tasks(case, Profile(binary=FAKE), wordlist="/w.txt", rules="/r.rule")
    assert ids and again == []
    assert crack.render(case, ids[0]).startswith(FAKE)


def test_run_cracks_and_records(tmp_path: Path) -> None:
    case = case_with_hashes(tmp_path)
    crack.plan_tasks(case, Profile(binary=FAKE), masks=False)
    task = crack.run_next(case)
    assert task is not None and task.status == "exhausted"  # one of two hashes left
    row = case.conn.execute("SELECT * FROM crypto_materials WHERE username='admin'").fetchone()
    assert row["cracked"] == "admin"
    cred = case.conn.execute(
        "SELECT * FROM credentials WHERE secret_kind='plaintext' AND algo='cracked'"
    ).fetchone()
    assert (cred["username"], cred["secret"]) == ("admin", "admin")
    f = case.conn.execute(
        "SELECT * FROM findings WHERE heuristic_id='crypto.hash-cracked'"
    ).fetchone()
    assert f["confidence"] == "high" and f["owasp_iot"] == "I1"
    ev = case.conn.execute(
        "SELECT snippet FROM evidence_links WHERE finding_id=?", (f["id"],)
    ).fetchone()
    assert ev["snippet"] == "admin:ad***"  # the secret is masked in the evidence text
    assert task.speed == "2.0 MH/s" and task.progress == 1.0
    assert crack.run_next(case) is None  # nothing else queued (masks disabled)
    # the command is in the ledger like everything else
    assert (
        case.conn.execute("SELECT count(*) FROM commands WHERE module='hashcat'").fetchone()[0] == 1
    )


def test_pause_and_resume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = case_with_hashes(tmp_path)
    crack.plan_tasks(case, Profile(binary=FAKE), masks=False)
    monkeypatch.setenv("FAKE_SLOW", "1")
    worker_case = Case.open(case.root)
    done: list[crack.Task | None] = []
    t = threading.Thread(target=lambda: done.append(crack.run_next(worker_case)))
    t.start()
    for _ in range(100):
        row = case.conn.execute("SELECT status, progress FROM crack_tasks WHERE id=1").fetchone()
        if row["status"] == "running" and row["progress"] > 0:
            break
        time.sleep(0.05)
    assert crack.request(case, 1, "pause") == "running"  # takes effect when the process stops
    t.join(15)
    assert done and done[0] is not None and done[0].status == "paused"
    assert (case.root / "artifacts/crypto/textolit-1-1.restore").exists()

    assert crack.request(case, 1, "resume") == "queued"
    monkeypatch.delenv("FAKE_SLOW")
    resumed = crack.run_next(case)
    assert resumed is not None and resumed.id == 1
    last = case.conn.execute(
        "SELECT argv_json FROM commands WHERE module='hashcat' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert "--restore" in json.loads(last["argv_json"])


def test_cancel_queued_and_crash_recovery(tmp_path: Path) -> None:
    case = case_with_hashes(tmp_path)
    crack.plan_tasks(case, Profile(binary=FAKE))
    assert crack.request(case, 1, "cancel") == "cancelled"
    case.conn.execute("UPDATE crack_tasks SET status='running' WHERE id=2")
    case.conn.commit()
    assert crack.mark_interrupted(case) == 1
    st = {t.id: t.status for t in crack.list_tasks(case)}
    assert st[1] == "cancelled" and st[2] == "paused"
    with pytest.raises(ValueError):
        crack.request(case, 99, "pause")


def test_missing_hashcat_is_a_failed_task(tmp_path: Path) -> None:
    case = case_with_hashes(tmp_path)
    crack.plan_tasks(case, Profile(binary="/nonexistent/hashcat"), masks=False)
    task = crack.run_next(case)
    assert task is not None and task.status == "failed" and "not found" in task.message


def test_parse_status_and_speed() -> None:
    st = crack.parse_status(
        json.dumps(
            {
                "progress": [50, 200],
                "recovered_hashes": [1, 4],
                "devices": [{"speed": 900000, "temp": 70}, {"speed": 100000}],
            }
        )
    )
    assert st and st["progress"] == 0.25 and st["recovered"] == 1 and st["speed"] == 1000000
    assert crack.parse_status("not json") is None and crack.parse_status("{}") is None
    assert crack.human_speed(1500) == "1.5 kH/s" and crack.human_speed(12) == "12 H/s"
