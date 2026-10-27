"""Crack queue: plan hashcat attacks, run them one at a time, pause and resume safely.

State lives in ``crack_tasks``, so the TUI can show and control it while a worker thread
runs it. Pause sends SIGINT, which makes hashcat write a restore checkpoint. Nothing
restarts without the operator: a task found ``running`` after a crash becomes ``paused``.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from textolit.core.case import Case, utcnow
from textolit.core.ledger import add_artifact, add_finding, ensure_heuristic, sha256_file
from textolit.core.runner import run_streaming
from textolit.hashcat import (
    Attack,
    Plan,
    Profile,
    build_command,
    default_passwords_text,
    hashcat_available,
    plan_attacks,
)

CRYPTO_DIR = "artifacts/crypto"
ACTIVE = ("queued", "running", "paused", "done", "exhausted", "cracked")


@dataclass(frozen=True)
class Task:
    id: int
    label: str
    mode: int
    status: str
    progress: float
    speed: str
    recovered: int
    total: int
    message: str
    session: str


def _task(row: Any) -> Task:
    return Task(
        row["id"],
        row["label"],
        row["hash_mode"],
        row["status"],
        row["progress"],
        row["speed"],
        row["recovered"],
        row["total"],
        row["message"],
        row["session"],
    )


def list_tasks(case: Case) -> list[Task]:
    return [_task(r) for r in case.conn.execute("SELECT * FROM crack_tasks ORDER BY id")]


def export_hashfiles(case: Case) -> dict[int, tuple[Path, int]]:
    """Write one hash list per hashcat mode from uncracked ``crypto_materials`` rows."""
    out_dir = case.root / CRYPTO_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    by_mode: dict[int, list[str]] = {}
    rows = case.conn.execute(
        "SELECT DISTINCT hashcat_mode, value FROM crypto_materials"
        " WHERE kind='hash' AND cracked IS NULL AND hashcat_mode IS NOT NULL ORDER BY 1, 2"
    )
    for r in rows:
        by_mode.setdefault(int(r["hashcat_mode"]), []).append(r["value"])
    result: dict[int, tuple[Path, int]] = {}
    for mode, values in by_mode.items():
        path = out_dir / f"hashes-{mode}.txt"
        path.write_text("\n".join(values) + "\n", encoding="utf-8")
        add_artifact(case, "hashlist", path)
        result[mode] = (path, len(values))
    return result


def plan_tasks(
    case: Case,
    profile: Profile,
    *,
    wordlist: str | None = None,
    rules: str | None = None,
    masks: bool = True,
    modes: Sequence[int] | None = None,
) -> tuple[list[int], list[str]]:
    """Queue attacks for every exported hash mode. Returns (new task ids, warnings)."""
    hashfiles = export_hashfiles(case)
    out_dir = case.root / CRYPTO_DIR
    defaults = out_dir / "default-passwords.txt"
    defaults.write_text(default_passwords_text(), encoding="utf-8")
    new_ids: list[int] = []
    warnings: list[str] = []
    for mode, (hpath, count) in sorted(hashfiles.items()):
        if modes and mode not in modes:
            continue
        hsha = sha256_file(hpath)
        plan: Plan = plan_attacks(
            mode, default_list=case.rel(defaults), wordlist=wordlist, rules=rules, masks=masks
        )
        warnings += [f"mode {mode}: {w}" for w in plan.warnings]
        for attack in plan.attacks:
            spec = {**attack.to_json(), "hashset": hsha}
            dup = case.conn.execute(
                "SELECT 1 FROM crack_tasks WHERE hash_mode=? AND attack=? AND status IN"
                " ('queued','running','paused','done','exhausted','cracked')",
                (mode, json.dumps(spec, sort_keys=True)),
            ).fetchone()
            if dup:
                continue
            with case.conn:
                cur = case.conn.execute(
                    "INSERT INTO crack_tasks(label,hash_mode,hashfile,attack,argv_json,session,"
                    "total,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        "",
                        mode,
                        case.rel(hpath),
                        json.dumps(spec, sort_keys=True),
                        "[]",
                        "x",
                        count,
                        utcnow(),
                    ),
                )
                tid = cur.lastrowid
                assert tid is not None
                session = f"textolit-{case.case_id}-{tid}"
                argv = build_command(
                    profile,
                    mode=mode,
                    hashfile=case.rel(hpath),
                    outfile=f"{CRYPTO_DIR}/out-{tid}.txt",
                    potfile=f"{CRYPTO_DIR}/hashcat.pot",
                    session=session,
                    restore_file=f"{CRYPTO_DIR}/{session}.restore",
                    attack=attack,
                )
                case.conn.execute(
                    "UPDATE crack_tasks SET label=?, session=?, argv_json=? WHERE id=?",
                    (f"m{mode} {attack.label}", session, json.dumps(argv), tid),
                )
            new_ids.append(tid)
    return new_ids, warnings


def render(case: Case, task_id: int) -> str:
    row = case.conn.execute("SELECT argv_json FROM crack_tasks WHERE id=?", (task_id,)).fetchone()
    return shlex.join(json.loads(row["argv_json"]))


def request(case: Case, task_id: int, action: str) -> str:
    """pause, resume or cancel. Returns the resulting status."""
    row = case.conn.execute("SELECT status FROM crack_tasks WHERE id=?", (task_id,)).fetchone()
    if row is None:
        raise ValueError(f"no such task: {task_id}")
    status = row["status"]
    with case.conn:
        if action == "pause":
            if status == "running":
                case.conn.execute("UPDATE crack_tasks SET control='pause' WHERE id=?", (task_id,))
            elif status == "queued":
                case.conn.execute("UPDATE crack_tasks SET status='paused' WHERE id=?", (task_id,))
        elif action == "resume":
            if status == "paused":
                case.conn.execute(
                    "UPDATE crack_tasks SET status='queued', control=NULL WHERE id=?", (task_id,)
                )
        elif action == "cancel":
            if status == "running":
                case.conn.execute("UPDATE crack_tasks SET control='cancel' WHERE id=?", (task_id,))
            elif status in ("queued", "paused"):
                case.conn.execute(
                    "UPDATE crack_tasks SET status='cancelled', finished_at=? WHERE id=?",
                    (utcnow(), task_id),
                )
        else:
            raise ValueError(f"unknown action: {action}")
    return str(
        case.conn.execute("SELECT status FROM crack_tasks WHERE id=?", (task_id,)).fetchone()[0]
    )


def mark_interrupted(case: Case) -> int:
    """Tasks left ``running`` by a dead process become ``paused``: the operator resumes them."""
    with case.conn:
        cur = case.conn.execute(
            "UPDATE crack_tasks SET status='paused', control=NULL,"
            " message='process exited while running: resume restores the checkpoint if one exists'"
            " WHERE status='running'"
        )
    return cur.rowcount


def parse_status(line: str) -> dict[str, Any] | None:
    """One ``--status-json`` line -> progress fields, or None for anything else."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict) or "progress" not in doc:
        return None
    prog = doc.get("progress") or [0, 0]
    rec = doc.get("recovered_hashes") or [0, 0]
    speed = sum(int(d.get("speed", 0)) for d in doc.get("devices", []) if isinstance(d, dict))
    temps = [
        int(d["temp"]) for d in doc.get("devices", []) if isinstance(d, dict) and d.get("temp")
    ]
    fraction = (prog[0] / prog[1]) if len(prog) == 2 and prog[1] else 0.0
    return {
        "progress": min(max(fraction, 0.0), 1.0),
        "recovered": int(rec[0]),
        "total": int(rec[1]) if len(rec) > 1 else 0,
        "speed": speed,
        "temp": max(temps) if temps else None,
    }


def human_speed(hps: int) -> str:
    for unit, div in (("GH/s", 1e9), ("MH/s", 1e6), ("kH/s", 1e3)):
        if hps >= div:
            return f"{hps / div:.1f} {unit}"
    return f"{hps} H/s"


def ingest_outfile(case: Case, task_id: int, mode: int) -> int:
    """Record ``hash:plain`` results: update materials, add credentials and a finding."""
    out = case.root / f"{CRYPTO_DIR}/out-{task_id}.txt"
    if not out.is_file():
        return 0
    ensure_heuristic(case, "crypto.hash-cracked", "crypto", "Password hash cracked", "high")
    n = 0
    for raw in out.read_text("utf-8", "replace").splitlines():
        value, sep, plain = raw.partition(":")
        if not sep:
            continue
        mats = case.conn.execute(
            "SELECT * FROM crypto_materials WHERE kind='hash' AND value=? AND hashcat_mode=?"
            " AND cracked IS NULL",
            (value, mode),
        ).fetchall()
        for m in mats:
            n += 1
            with case.conn:
                case.conn.execute(
                    "UPDATE crypto_materials SET cracked=? WHERE id=?", (plain, m["id"])
                )
                case.conn.execute(
                    "INSERT INTO credentials(username,secret,secret_kind,algo,source_path,"
                    "source_line) VALUES (?,?,?,?,?,?)",
                    (
                        m["username"],
                        plain,
                        "plaintext",
                        "cracked",
                        m["source_path"],
                        m["source_line"],
                    ),
                )
            add_finding(
                case,
                heuristic_id="crypto.hash-cracked",
                title=f"Cracked password for '{m['username'] or '?'}' ({m['algo']})",
                detail="Recovered with hashcat from the hash in the image. Verify on the device.",
                evidence_path=m["source_path"],
                line=m["source_line"],
                snippet=f"{m['username'] or '?'}:{plain[:2]}***",
                confidence="high",
                severity="high",
                cwe="CWE-521",
                owasp_iot="I1",
            )
    return n


def run_next(case: Case) -> Task | None:
    """Run the oldest queued task to completion, pause or failure. None if the queue is empty."""
    row = case.conn.execute(
        "SELECT * FROM crack_tasks WHERE status='queued' ORDER BY id LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    tid, mode, session = int(row["id"]), int(row["hash_mode"]), row["session"]
    argv: list[str] = json.loads(row["argv_json"])
    restore_file = case.root / f"{CRYPTO_DIR}/{session}.restore"
    resumed = row["started_at"] is not None and restore_file.is_file()
    if resumed:
        profile_bin = argv[0]
        argv = build_command(
            Profile(binary=profile_bin),
            mode=mode,
            hashfile=row["hashfile"],
            outfile="",
            potfile=f"{CRYPTO_DIR}/hashcat.pot",
            session=session,
            restore_file=f"{CRYPTO_DIR}/{session}.restore",
            attack=Attack("mask", "", mask="x"),
            restore=True,
        )
    with case.conn:
        case.conn.execute(
            "UPDATE crack_tasks SET status='running', control=NULL,"
            " started_at=COALESCE(started_at,?), message=? WHERE id=?",
            (utcnow(), "resuming from checkpoint" if resumed else "starting", tid),
        )

    last: dict[str, Any] = {}

    def on_line(line: str) -> None:
        st = parse_status(line)
        if not st:
            return
        last.update(st)
        with case.conn:
            case.conn.execute(
                "UPDATE crack_tasks SET progress=?, speed=?, recovered=?, total=?, message=?"
                " WHERE id=?",
                (
                    st["progress"],
                    human_speed(st["speed"]),
                    st["recovered"],
                    st["total"],
                    f"temp {st['temp']}C" if st["temp"] else "",
                    tid,
                ),
            )

    def should_stop() -> bool:
        c = case.conn.execute("SELECT control FROM crack_tasks WHERE id=?", (tid,)).fetchone()
        return bool(c and c["control"])

    result = run_streaming(case, argv, on_line=on_line, should_stop=should_stop, module="hashcat")
    control = case.conn.execute("SELECT control FROM crack_tasks WHERE id=?", (tid,)).fetchone()[0]
    cracked = ingest_outfile(case, tid, mode)

    code = result.exit_code
    if result.error and "not found" in result.error:
        status, msg = "failed", result.error
    elif control == "cancel":
        status, msg = "cancelled", "cancelled by operator"
    elif control == "pause" or (code == 2 and result.stopped_by is None):
        status, msg = "paused", "paused: resume continues from the checkpoint"
    elif code == 0:
        status, msg = "cracked", f"all hashes recovered ({cracked} new)"
    elif code == 1:
        status, msg = "exhausted", f"keyspace exhausted ({cracked} new)"
    elif code == 3:
        status, msg = "exhausted", f"gpu budget reached ({cracked} new)"
    else:
        tail = result.stderr[-300:].decode("utf-8", "replace").strip()
        status, msg = "failed", f"hashcat exit {code}: {tail}"
    with case.conn:
        case.conn.execute(
            "UPDATE crack_tasks SET status=?, control=NULL, message=?, finished_at=?,"
            " progress=CASE WHEN ? IN ('cracked','exhausted') THEN 1 ELSE progress END WHERE id=?",
            (status, msg, utcnow() if status not in ("paused",) else None, status, tid),
        )
    return _task(case.conn.execute("SELECT * FROM crack_tasks WHERE id=?", (tid,)).fetchone())


def check_ready(binary: str = "hashcat") -> str | None:
    return None if hashcat_available(binary) else f"{binary} not found in PATH"
