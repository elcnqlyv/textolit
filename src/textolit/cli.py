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


def run_module(case: Case, module: str, as_json: bool, **options: Any) -> int:
    job_id = jobs.enqueue(case, module, **options)
    result = jobs.run_job(case, job_id)
    _print_result(result, as_json)
    return 0 if result.ok else 1


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
