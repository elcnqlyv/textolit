"""The single subprocess wrapper. Every external command goes through here.

Logs argv, cwd, env overrides, exit code, and writes stdout/stderr to
``logs/<sha256>.out|err`` so the raw output is content-addressed and auditable.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
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
    stopped_by: str | None = None  # set when the caller asked the process to stop

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


STOP_GRACE = 30.0


def run_streaming(
    case: Case,
    argv: Sequence[str],
    *,
    on_line: Callable[[str], None],
    should_stop: Callable[[], bool] | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    module: str | None = None,
    die_with_parent: bool = True,
    poll: float = 0.5,
) -> RunResult:
    """Like :func:`run` but for long jobs: stdout lines go to ``on_line`` as they arrive.

    ``should_stop`` is polled while the process runs. When it returns True the process gets
    SIGINT (SIGTERM, then SIGKILL, if it ignores that), which is how hashcat writes a
    restore checkpoint. Output is spooled to disk, so memory stays flat on multi-hour runs.
    """
    argv_t = tuple(str(a) for a in argv)
    workdir = (cwd or case.root).resolve()
    overrides = dict(env or {})
    launch = list(argv_t)
    if die_with_parent and shutil.which("setpriv") and shutil.which(argv_t[0]):
        launch = ["setpriv", "--pdeathsig", "TERM", *launch]
    with case.conn:
        cur = case.conn.execute(
            "INSERT INTO commands(started_at, argv_json, cwd, env_json, module) VALUES (?,?,?,?,?)",
            (utcnow(), json.dumps(argv_t), str(workdir), json.dumps(overrides), module),
        )
    cmd_id = cur.lastrowid
    assert cmd_id is not None

    tmp_out = case.logs_dir / f".tmp-{cmd_id}.out"
    tmp_err = case.logs_dir / f".tmp-{cmd_id}.err"
    error: str | None = None
    stopped: str | None = None
    code = -1
    out_h = hashlib.sha256()
    try:
        with tmp_out.open("wb") as fout, tmp_err.open("wb") as ferr:
            proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                launch,
                cwd=workdir,
                env={**os.environ, **overrides},
                stdout=subprocess.PIPE,
                stderr=ferr,
                stdin=subprocess.DEVNULL,
            )
            lines: queue.Queue[bytes | None] = queue.Queue()

            def pump() -> None:
                assert proc.stdout is not None
                for raw in proc.stdout:
                    lines.put(raw)
                lines.put(None)

            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            started = time.monotonic()
            asked_at: float | None = None
            done = False
            while not done:
                try:
                    raw = lines.get(timeout=poll)
                    if raw is None:
                        done = True
                    else:
                        fout.write(raw)
                        out_h.update(raw)
                        on_line(raw.decode("utf-8", "replace").rstrip("\n"))
                        continue
                except queue.Empty:
                    pass
                if proc.poll() is not None and not reader.is_alive():
                    done = True
                if asked_at is None and should_stop is not None and should_stop():
                    stopped, asked_at = "interrupt", time.monotonic()
                    proc.send_signal(signal.SIGINT)
                elif asked_at is None and timeout and time.monotonic() - started > timeout:
                    error, asked_at = f"timeout after {timeout}s", time.monotonic()
                    proc.send_signal(signal.SIGINT)
                elif asked_at is not None and time.monotonic() - asked_at > STOP_GRACE:
                    proc.kill()
            code = proc.wait()
    except FileNotFoundError as exc:
        error = f"executable not found: {exc.filename}"
    except OSError as exc:
        error = f"could not start process: {exc}"

    out = tmp_out.read_bytes() if tmp_out.exists() else b""
    err = tmp_err.read_bytes() if tmp_err.exists() else b""
    if error:
        err += f"[textolit] {error}\n".encode()
    out_sha, out_path = _store(case, out, "out")
    err_sha, err_path = _store(case, err, "err")
    tmp_out.unlink(missing_ok=True)
    tmp_err.unlink(missing_ok=True)
    with case.conn:
        case.conn.execute(
            "UPDATE commands SET finished_at=?, exit_code=?, stdout_sha256=?, stderr_sha256=?,"
            " stdout_path=?, stderr_path=? WHERE id=?",
            (utcnow(), code, out_sha, err_sha, case.rel(out_path), case.rel(err_path), cmd_id),
        )
    return RunResult(cmd_id, argv_t, code, b"", err, out_sha, err_sha, error, stopped)
