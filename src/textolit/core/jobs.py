"""Case-scoped persistent job queue.

Jobs live in the ``jobs`` table so a killed TUI resumes from SQLite. Jobs that were
``running`` when the process died are marked ``interrupted`` on next open; they are
never silently restarted. One worker thread runs jobs in order (the GPU and disk are
the bottleneck, not CPU); the worker opens its own connection.
"""

from __future__ import annotations

import json
import threading
import traceback
from dataclasses import dataclass
from typing import Any

from textolit.core.case import Case, utcnow
from textolit.modules.base import ModuleResult
from textolit.modules.registry import builtin_modules

POLL_SECONDS = 0.25


@dataclass(frozen=True)
class Job:
    id: int
    module: str
    args: dict[str, Any]
    status: str
    progress: float
    message: str
    error: str | None


def _row_to_job(row: Any) -> Job:
    return Job(
        row["id"],
        row["module"],
        json.loads(row["args_json"]),
        row["status"],
        row["progress"],
        row["message"],
        row["error"],
    )


def enqueue(case: Case, module: str, **args: Any) -> int:
    if module not in builtin_modules():
        raise ValueError(f"unknown module: {module}")
    with case.conn:
        cur = case.conn.execute(
            "INSERT INTO jobs(module,args_json,created_at) VALUES (?,?,?)",
            (module, json.dumps(args, default=str), utcnow()),
        )
    assert cur.lastrowid is not None
    return cur.lastrowid


def list_jobs(case: Case) -> list[Job]:
    return [_row_to_job(r) for r in case.conn.execute("SELECT * FROM jobs ORDER BY id")]


def mark_interrupted(case: Case) -> int:
    with case.conn:
        cur = case.conn.execute(
            "UPDATE jobs SET status='interrupted', finished_at=?,"
            " message='process exited while running' WHERE status='running'",
            (utcnow(),),
        )
    return cur.rowcount


def running_count(case: Case) -> int:
    row = case.conn.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')")
    return int(row.fetchone()[0])


def cancel(case: Case, job_id: int) -> bool:
    """Cancel a queued job. Running jobs cannot be interrupted safely and are left alone."""
    with case.conn:
        cur = case.conn.execute(
            "UPDATE jobs SET status='cancelled', finished_at=? WHERE id=? AND status='queued'",
            (utcnow(), job_id),
        )
    return cur.rowcount == 1


def run_job(case: Case, job_id: int) -> ModuleResult:
    """Run one job synchronously on ``case`` and persist its outcome."""
    row = case.conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    job = _row_to_job(row)
    with case.conn:
        case.conn.execute(
            "UPDATE jobs SET status='running', started_at=? WHERE id=?", (utcnow(), job_id)
        )

    def progress(fraction: float, message: str) -> None:
        with case.conn:
            case.conn.execute(
                "UPDATE jobs SET progress=?, message=? WHERE id=?",
                (min(max(fraction, 0.0), 1.0), message, job_id),
            )

    try:
        result = builtin_modules()[job.module].run(case, progress, **job.args)
    except Exception:  # noqa: BLE001 - surfaced into the job row, never swallowed
        err = traceback.format_exc()
        with case.conn:
            case.conn.execute(
                "UPDATE jobs SET status='failed', error=?, finished_at=? WHERE id=?",
                (err, utcnow(), job_id),
            )
        return ModuleResult(job.module, False, "crashed", errors=[err])

    status = "done" if result.ok else "failed"
    with case.conn:
        case.conn.execute(
            "UPDATE jobs SET status=?, progress=?, message=?, error=?, finished_at=? WHERE id=?",
            (
                status,
                1.0 if result.ok else row["progress"],
                result.summary,
                "\n".join(result.errors) or None,
                utcnow(),
                job_id,
            ),
        )
    return result


def drain(case: Case) -> list[ModuleResult]:
    """Run every queued job in order (CLI path)."""
    results: list[ModuleResult] = []
    while True:
        row = case.conn.execute(
            "SELECT id FROM jobs WHERE status='queued' ORDER BY id LIMIT 1"
        ).fetchone()
        if row is None:
            return results
        results.append(run_job(case, int(row["id"])))


class Worker:
    """Background thread that drains the queue until stopped."""

    def __init__(self, case: Case) -> None:
        self._root = case.root
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="textolit-worker", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def _loop(self) -> None:
        case = Case.open(self._root)
        try:
            while not self._stop.is_set():
                row = case.conn.execute(
                    "SELECT id FROM jobs WHERE status='queued' ORDER BY id LIMIT 1"
                ).fetchone()
                if row is None:
                    self._stop.wait(POLL_SECONDS)
                    continue
                run_job(case, int(row["id"]))
        finally:
            case.close()
