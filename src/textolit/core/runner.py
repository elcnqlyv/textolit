"""The single subprocess wrapper. Every external command goes through here.

Logs argv, cwd, env overrides, exit code, and writes stdout/stderr to
``logs/<sha256>.out|err`` so the raw output is content-addressed and auditable.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from textolit.core.case import Case, utcnow


@dataclass(frozen=True)
class RunResult:
    command_id: int
    argv: tuple[str, ...]
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    error: str | None = None  # set when the process could not start or timed out

    @property
    def ok(self) -> bool:
        return self.error is None and self.exit_code == 0

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", "replace")


def _store(case: Case, data: bytes, suffix: str) -> tuple[str, Path]:
    digest = hashlib.sha256(data).hexdigest()
    path = case.logs_dir / f"{digest}.{suffix}"
    if not path.exists():
        path.write_bytes(data)
    return digest, path


def run(
    case: Case,
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    module: str | None = None,
) -> RunResult:
    """Run ``argv`` (never through a shell) and record it in the ledger."""
    argv_t = tuple(str(a) for a in argv)
    workdir = (cwd or case.root).resolve()
    overrides = dict(env or {})
    started = utcnow()
    with case.conn:
        cur = case.conn.execute(
            "INSERT INTO commands(started_at, argv_json, cwd, env_json, module) VALUES (?,?,?,?,?)",
            (started, json.dumps(argv_t), str(workdir), json.dumps(overrides), module),
        )
    cmd_id = cur.lastrowid
    assert cmd_id is not None

    error: str | None = None
    code = -1
    out = err = b""
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            argv_t,
            cwd=workdir,
            env={**os.environ, **overrides},
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        error = f"executable not found: {exc.filename}"
    except subprocess.TimeoutExpired as exc:
        error = f"timeout after {timeout}s"
        out, err = exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        error = f"could not start process: {exc}"

    if error:
        err += f"[textolit] {error}\n".encode()
    out_sha, out_path = _store(case, out, "out")
    err_sha, err_path = _store(case, err, "err")
    with case.conn:
        case.conn.execute(
            "UPDATE commands SET finished_at=?, exit_code=?, stdout_sha256=?, stderr_sha256=?,"
            " stdout_path=?, stderr_path=? WHERE id=?",
            (utcnow(), code, out_sha, err_sha, case.rel(out_path), case.rel(err_path), cmd_id),
        )
    return RunResult(cmd_id, argv_t, code, out, err, out_sha, err_sha, error)
