"""Check an LLM reply against its schema and the evidence it was given.

A claim survives only if it cites at least one id that was in the prompt and every id it
cites was in the prompt. Claims that invent CVE ids are dropped. Nothing is "fixed up":
dropped items are listed in ``issues`` so the operator sees what was rejected and why.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from textolit.llm_context import Context

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)


@dataclass
class Validated:
    data: dict[str, Any] | None
    issues: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.data is not None


def parse_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    raw = text.strip()
    m = _FENCE.match(raw)
    if m:
        raw = m.group(1)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"reply is not valid JSON: {exc}"
    if not isinstance(doc, dict):
        return None, "reply is JSON but not an object"
    return doc, None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v.strip()[:400] for v in value if isinstance(v, str) and v.strip()]


def _cites(item: dict[str, Any], ctx: Context, label: str, issues: list[str]) -> list[str] | None:
    cites = item.get("cites")
    if not isinstance(cites, list) or not cites or not all(isinstance(c, str) for c in cites):
        issues.append(f"{label}: dropped, no citations")
        return None
    bad = [c for c in cites if c not in ctx.allowed]
    if bad:
        issues.append(f"{label}: dropped, cites ids not in the evidence: {', '.join(bad)}")
        return None
    return list(cites)


def _invented_cve(text: str, ctx: Context) -> list[str]:
    return [c for c in _CVE.findall(text) if c not in ctx.corpus]


def _text_field(item: dict[str, Any], key: str, label: str, issues: list[str]) -> str | None:
    v = item.get(key)
    if not isinstance(v, str) or not v.strip():
        issues.append(f"{label}: dropped, missing '{key}'")
        return None
    return v.strip()


def _vet_item(
    item: Any, ctx: Context, label: str, text_keys: tuple[str, ...], issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        issues.append(f"{label}: dropped, not an object")
        return None
    out: dict[str, Any] = {}
    for key in text_keys:
        v = _text_field(item, key, label, issues)
        if v is None:
            return None
        out[key] = v
    invented = _invented_cve(" ".join(out.values()), ctx)
    if invented:
        issues.append(f"{label}: dropped, names CVE ids not in the evidence: {', '.join(invented)}")
        return None
    cites = _cites(item, ctx, label, issues)
    if cites is None:
        return None
    out["cites"] = cites
    return out


def validate(ctx: Context, text: str) -> Validated:
    doc, err = parse_json(text)
    if doc is None:
        return Validated(None, [err or "unparseable reply"])
    issues: list[str] = []
    task = ctx.task
    result: dict[str, Any] = {"unverified": _strings(doc.get("unverified"))}

    if task == "triage":
        summary = doc.get("summary")
        result["summary"] = summary.strip() if isinstance(summary, str) else ""
        prios = []
        for i, p in enumerate(doc.get("priorities") or []):
            item = _vet_item(p, ctx, f"priority {i + 1}", ("finding", "reason"), issues)
            if item and item["finding"] in ctx.allowed and item["finding"].startswith("F"):
                prios.append(item)
            elif item:
                issues.append(f"priority {i + 1}: dropped, unknown finding {item['finding']}")
        result["priorities"] = prios
        keep = bool(prios)
    elif task == "crypto":
        rows = []
        for i, a in enumerate(doc.get("assessments") or []):
            item = _vet_item(a, ctx, f"assessment {i + 1}", ("material", "assessment"), issues)
            if not item:
                continue
            if item["material"] not in ctx.allowed:
                issues.append(f"assessment {i + 1}: dropped, unknown item {item['material']}")
                continue
            step = a.get("suggested_attack")
            item["suggested_attack"] = (
                step.strip() if isinstance(step, str) and step.strip() else None
            )
            rows.append(item)
        result["assessments"] = rows
        keep = bool(rows)
    elif task == "draft":
        es = doc.get("executive_summary")
        summary = _vet_item(es, ctx, "executive_summary", ("text",), issues) if es else None
        sections = []
        for i, s in enumerate(doc.get("sections") or []):
            item = _vet_item(s, ctx, f"section {i + 1}", ("title", "body"), issues)
            if item:
                sections.append(item)
        result["executive_summary"] = summary
        result["sections"] = sections
        keep = bool(summary or sections)
    else:  # cve
        item = _vet_item(
            doc, ctx, "cve draft", ("finding", "title", "description", "impact"), issues
        )
        if item is None:
            return Validated(None, issues)
        fid = item["finding"]
        expected = ctx.data["finding"]["id"]
        if fid != expected:
            return Validated(None, [*issues, f"cve draft: answers {fid}, expected {expected}"])
        cwe = doc.get("cwe")
        if cwe != ctx.data["finding"]["cwe"]:
            if cwe:
                issues.append(
                    f"cwe {cwe!r} replaced by the finding's own {ctx.data['finding']['cwe']!r}"
                )
            cwe = ctx.data["finding"]["cwe"]
        affected = doc.get("affected")
        item.update(
            {
                "cwe": cwe,
                "affected": affected.strip() if isinstance(affected, str) else "",
                "references_needed": _strings(doc.get("references_needed")),
                "unverified": result["unverified"],
            }
        )
        return Validated(item, issues)

    if not keep:
        return Validated(None, [*issues, "nothing in the reply survived validation"])
    return Validated(result, issues)
