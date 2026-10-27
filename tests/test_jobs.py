import os
import time
from pathlib import Path

from textolit.core import jobs
from textolit.core.case import Case


def test_enqueue_drain_and_persist(tmp_path: Path) -> None:
    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(5000))
    case = Case.create(tmp_path / "c")
    a = jobs.enqueue(case, "ingest", image=img)
    b = jobs.enqueue(case, "entropy")
    c = jobs.enqueue(case, "fswalk")  # stub: reported as failed, not silent
    results = jobs.drain(case)
    assert [r.ok for r in results] == [True, True, False]
    by_id = {j.id: j for j in jobs.list_jobs(case)}
    assert by_id[a].status == "done" and by_id[b].progress == 1.0
    assert by_id[c].status == "failed" and by_id[c].error


def test_interrupted_on_reopen(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    jid = jobs.enqueue(case, "entropy")
    case.conn.execute("UPDATE jobs SET status='running' WHERE id=?", (jid,))
    case.conn.commit()
    assert jobs.mark_interrupted(case) == 1
    assert jobs.list_jobs(case)[0].status == "interrupted"


def test_worker_thread_and_cancel(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    dead = jobs.enqueue(case, "entropy")
    assert jobs.cancel(case, dead)
    live = jobs.enqueue(case, "entropy")  # fails: no image, but is processed
    worker = jobs.Worker(case)
    worker.start()
    deadline = time.time() + 5
    while time.time() < deadline and jobs.running_count(case):
        time.sleep(0.05)
    worker.stop()
    worker.join(2)
    st = {j.id: j.status for j in jobs.list_jobs(case)}
    assert st[dead] == "cancelled" and st[live] == "failed"
