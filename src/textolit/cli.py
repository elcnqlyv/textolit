"""Command-line entrypoint: every module is scriptable as ``textolit <module> <case> ...``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from textolit import __version__
from textolit.core import jobs
from textolit.core.case import Case, CaseError
from textolit.core.ledger import decide
from textolit.modules.base import ModuleResult
from textolit.modules.registry import builtin_modules

TAGLINE = "Textolit — firmware triage workbench for CCTV and access-control research."

# Per-module CLI options: (flag, argparse kwargs, option name passed to the module)
MODULE_OPTIONS: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "ingest": [
        ("--image", {"type": Path, "required": True, "help": "firmware image to ingest"}),
        ("--chunk-size", {"type": int, "dest": "chunk_size", "help": "bytes per hash chunk"}),
    ],
    "unpack": [("--timeout", {"type": float, "help": "seconds per binwalk invocation"})],
    "entropy": [("--window", {"type": int, "help": "window size in bytes (default 4096)"})],
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="textolit", description=TAGLINE)
    parser.add_argument("--version", action="version", version=f"textolit {__version__}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="create a case directory (optionally ingest an image)")
    init.add_argument("case", type=Path)
    init.add_argument("--image", type=Path)
    init.add_argument("--name")

    tui = sub.add_parser("tui", help="open the workbench for a case")
    tui.add_argument("case", type=Path)

    jl = sub.add_parser("jobs", help="list queued/finished jobs for a case")
    jl.add_argument("case", type=Path)

    fl = sub.add_parser("findings", help="list findings (leads) for a case")
    fl.add_argument("case", type=Path)
    fl.add_argument(
        "--status", default="pending", choices=["pending", "accepted", "rejected", "snoozed", "all"]
    )

    fd = sub.add_parser("decide", help="accept, reject or snooze a finding")
    fd.add_argument("case", type=Path)
    fd.add_argument("finding_id", type=int)
    fd.add_argument("decision", choices=["accept", "reject", "snooze", "reopen"])
    fd.add_argument("--note", default="")

    for name in builtin_modules():
        p = sub.add_parser(name, help=f"run the {name} module")
        p.add_argument("case", type=Path)
        p.add_argument("--json", action="store_true", help="machine-readable output")
        for flag, kwargs in MODULE_OPTIONS.get(name, []):
            p.add_argument(flag, **kwargs)
    return parser


def _print_result(result: ModuleResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.__dict__, default=str, indent=2))
        return
    print(f"[{'ok' if result.ok else 'FAIL'}] {result.module}: {result.summary}")
    for w in result.warnings:
        print(f"  warning: {w}")
    for e in result.errors:
        print(f"  error: {e}", file=sys.stderr)


def _print_netmap(result: ModuleResult) -> None:
    rows = [t for t in result.data.get("table", []) if t["default_on"]]
    if not rows:
        return
    print(f"  {'port':<11}{'service':<20}{'kind':<9}{'std':<5}source")
    for t in rows:
        flag = "NON" if t["nonstandard"] else ""
        print(
            f"  {str(t['port']) + '/' + t['proto']:<11}{t['service'][:19]:<20}"
            f"{t['kind']:<9}{flag:<5}{t['source']}"
        )


def run_module(case: Case, module: str, as_json: bool, **options: Any) -> int:
    job_id = jobs.enqueue(case, module, **options)
    result = jobs.run_job(case, job_id)
    _print_result(result, as_json)
    if module == "netmap" and result.ok and not as_json:
        _print_netmap(result)
    ok = result.ok
    # follow-up jobs queued by this one (e.g. the rule sweep) run now, so the CLI never
    # leaves evidence unexamined.
    for follow in jobs.drain(case):
        _print_result(follow, as_json)
        ok = ok and follow.ok
    return 0 if ok else 1


def list_findings(case: Case, status: str) -> int:
    q = (
        "SELECT id, confidence, severity, status, title, evidence_path, "
        "(SELECT line FROM evidence_links WHERE finding_id=findings.id LIMIT 1) AS line "
        "FROM findings"
    )
    args: tuple[str, ...] = ()
    if status != "all":
        q += " WHERE status=?"
        args = (status,)
    order = "CASE confidence WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END, id"
    rows = case.conn.execute(f"{q} ORDER BY {order}", args).fetchall()
    for r in rows:
        where = r["evidence_path"] + (f":{r['line']}" if r["line"] else "")
        print(
            f"{r['id']:>5} [{r['confidence']:<4}] {r['severity']:<7} {r['status']:<9} {r['title']}"
        )
        print(f"        {where}")
    pending = case.conn.execute("SELECT count(*) FROM findings WHERE status='pending'")
    print(f"{len(rows)} shown; {pending.fetchone()[0]} leads pending review")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "init":
            case = Case.create(args.case, args.name)
            print(f"created case at {case.root}")
            if args.image:
                return run_module(case, "ingest", False, image=args.image)
            return 0
        case = Case.open(args.case)
        jobs.mark_interrupted(case)
        if args.command == "findings":
            return list_findings(case, args.status)
        if args.command == "decide":
            status = {
                "accept": "accepted",
                "reject": "rejected",
                "snooze": "snoozed",
                "reopen": "pending",
            }[args.decision]
            try:
                decide(case, args.finding_id, status, args.note)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(f"finding {args.finding_id}: {status}")
            return 0
        if args.command == "tui":
            from textolit.ui.app import TextolitApp

            TextolitApp(case).run()
            return 0
        if args.command == "jobs":
            for j in jobs.list_jobs(case):
                print(f"{j.id:>4} {j.status:<11} {j.progress:4.0%} {j.module:<14} {j.message}")
            return 0
        skip = {"command", "case", "json"}
        options = {k: v for k, v in vars(args).items() if k not in skip and v is not None}
        return run_module(case, args.command, args.json, **options)
    except CaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
