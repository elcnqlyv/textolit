"""Command-line entrypoint."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from textolit import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="textolit",
        description="Textolit — firmware triage workbench for CCTV and access-control research.",
    )
    parser.add_argument("--version", action="version", version=f"textolit {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
