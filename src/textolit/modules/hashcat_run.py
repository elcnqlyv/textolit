"""hashcat job module: runs queued crack tasks one after another until the queue is empty."""

from __future__ import annotations

from typing import Any

from textolit import crack
from textolit.core.case import Case
from textolit.modules.base import ModuleResult, ProgressFn, no_progress


class HashcatRun:
    name = "hashcat"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        ran: list[crack.Task] = []
        while True:
            queued = case.conn.execute(
                "SELECT count(*) FROM crack_tasks WHERE status='queued'"
            ).fetchone()[0]
            if not queued:
                break
            task = crack.run_next(case)
            if task is None:
                break
            ran.append(task)
            progress(1.0 if not queued else 0.5, f"{task.label}: {task.status}")
        if not ran:
            return ModuleResult(
                self.name,
                False,
                "no queued crack tasks",
                errors=["plan attacks first: textolit crack <case> plan"],
            )
        failed = [t for t in ran if t.status == "failed"]
        paused = [t for t in ran if t.status == "paused"]
        cracked = case.conn.execute(
            "SELECT count(*) FROM crypto_materials WHERE cracked IS NOT NULL"
        ).fetchone()[0]
        summary = (
            f"{len(ran)} tasks run, {len(paused)} paused, {len(failed)} failed, "
            f"{cracked} hashes cracked in total"
        )
        return ModuleResult(
            self.name,
            not failed,
            summary,
            data={
                "tasks": [
                    {"id": t.id, "label": t.label, "status": t.status, "message": t.message}
                    for t in ran
                ]
            },
            warnings=[f"{t.label}: {t.message}" for t in paused],
            errors=[f"{t.label}: {t.message}" for t in failed],
        )
