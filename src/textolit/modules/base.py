"""Module contract: every module takes a Case and returns a structured result."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from textolit.core.case import Case

ProgressFn = Callable[[float, str], None]


def no_progress(fraction: float, message: str) -> None:
    """Default progress sink for CLI use."""


@dataclass
class ModuleResult:
    module: str
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Module(Protocol):
    """Pluggable analysis step. Implementations must not touch global state."""

    name: str

    def run(
        self, case: Case, progress: ProgressFn = no_progress, **options: Any
    ) -> ModuleResult: ...
