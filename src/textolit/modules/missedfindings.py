"""missedfindings module (planned for sprint 2)."""

from __future__ import annotations

from typing import Any

from textolit.core.case import Case
from textolit.modules.base import ModuleResult, ProgressFn, no_progress


class MissedFindings:
    name = "missedfindings"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        return ModuleResult(
            self.name, ok=False, summary="not implemented yet", errors=["planned for sprint 2"]
        )
