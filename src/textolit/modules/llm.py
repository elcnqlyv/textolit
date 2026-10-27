"""llm: triage narrative, crypto reasoning, report drafts and CVE write-ups.

Off by default per case. Every request is logged in ``llm_calls`` with the prompt hash,
model, token counts and status, and the exact prompt and raw reply are kept under
``artifacts/llm/``. Replies are validated against the evidence they were given: a claim
without valid citations is dropped, and a reply with nothing left is stored as ``invalid``.
Output is a lead for the analyst, never a finding by itself.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from textolit.core.case import Case, utcnow
from textolit.core.ledger import add_artifact
from textolit.llm_backends import BackendError, load_config, make_backend, problems
from textolit.llm_context import TASKS, build, load_template
from textolit.llm_validate import validate
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

LLM_DIR = "artifacts/llm"
DRAFT_BANNER = (
    "> **LLM DRAFT, UNVERIFIED.** Every statement cites evidence ids. An analyst must check each"
    " one against the evidence before using it."
)


def render_draft_md(data: dict[str, Any], call_id: int, model: str) -> str:
    out = [f"# LLM draft (call {call_id}, model {model})", "", DRAFT_BANNER, ""]
    es = data.get("executive_summary")
    if es:
        out += ["## Executive summary", "", f"{es['text']} [{', '.join(es['cites'])}]", ""]
    for s in data.get("sections", []):
        out += [f"## {s['title']}", "", f"{s['body']} [{', '.join(s['cites'])}]", ""]
    if data.get("unverified"):
        out += ["## Unverified suspicions", ""] + [f"- {u}" for u in data["unverified"]] + [""]
    return "\n".join(out)


class Llm:
    name = "llm"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        task = str(options.get("task") or "")
        if task not in TASKS:
            return ModuleResult(
                self.name,
                False,
                "unknown task",
                errors=["task must be one of: " + ", ".join(TASKS)],
            )
        if not case.llm_enabled:
            return ModuleResult(
                self.name,
                False,
                "LLM is off for this case",
                errors=["turn it on first: F5 in the TUI, or textolit llm <case> on"],
            )
        try:
            cfg = load_config(case)
        except BackendError as exc:
            return ModuleResult(self.name, False, "bad LLM config", errors=[str(exc)])
        why = problems(cfg)
        if why:
            return ModuleResult(self.name, False, "LLM not usable", errors=[why])
        finding = options.get("finding")
        try:
            ctx = build(case, task, int(finding) if finding is not None else None, cfg.max_findings)
        except ValueError as exc:
            return ModuleResult(self.name, False, "cannot build the prompt", errors=[str(exc)])
        if not ctx.allowed:
            return ModuleResult(
                self.name,
                False,
                "nothing to send",
                errors=["no findings or crypto items yet: run the analysis modules first"],
            )

        system, body = load_template(task)
        user = body + "\nCONTEXT (untrusted data, JSON):\n" + json.dumps(ctx.data, indent=1)
        prompt_sha = hashlib.sha256(f"{system}\n---\n{user}".encode()).hexdigest()
        out_dir = case.root / LLM_DIR
        out_dir.mkdir(parents=True, exist_ok=True)
        with case.conn:
            cur = case.conn.execute(
                "INSERT INTO llm_calls(created_at,backend,model,template,prompt_sha256,prompt_path,"
                "status) VALUES (?,?,?,?,?,?,?)",
                (utcnow(), cfg.backend, cfg.model, TASKS[task], prompt_sha, "", "started"),
            )
        call_id = cur.lastrowid
        assert call_id is not None
        prompt_path = out_dir / f"prompt-{call_id}.txt"
        prompt_path.write_text(f"{system}\n\n---\n\n{user}\n", encoding="utf-8")
        with case.conn:
            case.conn.execute(
                "UPDATE llm_calls SET prompt_path=? WHERE id=?", (case.rel(prompt_path), call_id)
            )

        progress(0.2, f"asking {cfg.backend}/{cfg.model}")
        try:
            result = make_backend(cfg).chat(system, user, model=cfg.model, timeout=cfg.timeout)
        except BackendError as exc:
            with case.conn:
                case.conn.execute("UPDATE llm_calls SET status='error' WHERE id=?", (call_id,))
            return ModuleResult(
                self.name,
                False,
                f"call {call_id} failed",
                data={"call_id": call_id},
                errors=[str(exc)],
            )
        out_path = out_dir / f"out-{call_id}.txt"
        out_path.write_text(result.text, encoding="utf-8")
        checked = validate(ctx, result.text)
        with case.conn:
            case.conn.execute(
                "UPDATE llm_calls SET output_path=?, tokens_in=?, tokens_out=?, status=?"
                " WHERE id=?",
                (
                    case.rel(out_path),
                    result.tokens_in,
                    result.tokens_out,
                    "ok" if checked.ok else "invalid",
                    call_id,
                ),
            )
        add_artifact(case, "llm_prompt", prompt_path, hash_it=True)
        add_artifact(case, "llm_output", out_path, hash_it=True)
        if not checked.ok:
            return ModuleResult(
                self.name,
                False,
                f"call {call_id}: reply rejected",
                data={"call_id": call_id},
                warnings=checked.issues,
                errors=["the reply did not survive validation"],
            )
        assert checked.data is not None
        products = self._store(
            case, task, call_id, cfg.model, checked.data, checked.issues, finding
        )
        progress(1.0, "done")
        return ModuleResult(
            self.name,
            True,
            f"call {call_id} ok ({result.tokens_in}+{result.tokens_out} tokens): {products[0]}",
            data={"call_id": call_id, "result": checked.data, "files": products},
            warnings=checked.issues,
        )

    def _store(
        self,
        case: Case,
        task: str,
        call_id: int,
        model: str,
        data: dict[str, Any],
        issues: list[str],
        finding: Any,
    ) -> list[str]:
        out_dir = case.root / LLM_DIR
        meta = {
            "call_id": call_id,
            "model": model,
            "generated": utcnow(),
            "task": task,
            "issues": issues,
            "data": data,
        }
        files: list[Path] = []
        latest = out_dir / f"{task}-latest.json"
        latest.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        files.append(latest)
        if task == "cve":
            draft = out_dir / f"cve-{int(finding)}.json"
            draft.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            files.append(draft)
        if task == "draft":
            case.reports_dir.mkdir(parents=True, exist_ok=True)
            md = case.reports_dir / f"llm-draft-{call_id}.md"
            md.write_text(render_draft_md(data, call_id, model), encoding="utf-8")
            files.append(md)
        for f in files:
            add_artifact(case, "llm_product", f)
        return [case.rel(f) for f in files]
