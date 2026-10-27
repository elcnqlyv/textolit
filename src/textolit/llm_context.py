"""Build the CONTEXT block for each LLM task, and the set of ids a reply may cite.

Ids are short and stable inside one prompt: F<n> findings, E<n> evidence links, M<n> crypto
items, W<n> web surface rows. Secrets are masked and hash values never leave the case.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from textolit.core.case import Case
from textolit.cvss import base_score, full_vector, severity, suggest
from textolit.export_cve import CWE_NAMES
from textolit.hashtypes import MODES
from textolit.redact import mask_snippet
from textolit.taxonomy import OWASP_IOT

TASKS = {"triage": "triage.txt", "crypto": "crypto.txt", "draft": "draft.txt", "cve": "cve.txt"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SNIPPET_MAX = 200


@dataclass
class Context:
    task: str
    data: dict[str, Any]
    allowed: set[str] = field(default_factory=set)
    corpus: str = ""  # all text in the context, to check that cited facts exist in it


def clean(text: str | None, limit: int = SNIPPET_MAX) -> str:
    return mask_snippet(_CTRL.sub("", text or ""))[:limit]


def load_template(task: str) -> tuple[str, str]:
    """(system rules, task body) from the packaged prompt_templates directory."""
    root = resources.files("textolit.prompt_templates")
    return (root / "_rules.txt").read_text("utf-8"), (root / TASKS[task]).read_text("utf-8")


def _finding_entry(case: Case, f: Any, allowed: set[str]) -> dict[str, Any]:
    ev = []
    for e in case.conn.execute(
        "SELECT * FROM evidence_links WHERE finding_id=? ORDER BY id LIMIT 5", (f["id"],)
    ):
        eid = f"E{e['id']}"
        allowed.add(eid)
        ev.append(
            {
                "id": eid,
                "path": clean(e["path"], 300),
                "line": e["line"],
                "snippet": clean(e["snippet"]),
            }
        )
    fid = f"F{f['id']}"
    allowed.add(fid)
    return {
        "id": fid,
        "title": clean(f["title"], 200),
        "rule": f["heuristic_id"],
        "confidence": f["confidence"],
        "severity": f["severity"],
        "cwe": f["cwe"],
        "owasp_iot": f["owasp_iot"],
        "status": f["status"],
        "evidence": ev,
    }


def findings_context(
    case: Case, limit: int = 40, statuses: tuple[str, ...] = ("pending", "accepted")
) -> tuple[list[dict[str, Any]], set[str]]:
    marks = ",".join("?" for _ in statuses)
    rows = case.conn.execute(
        f"SELECT * FROM findings WHERE status IN ({marks})"
        " ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END, id LIMIT ?",
        (*statuses, limit),
    ).fetchall()
    allowed: set[str] = set()
    return [_finding_entry(case, f, allowed) for f in rows], allowed


def crypto_items(case: Case) -> tuple[list[dict[str, Any]], set[str]]:
    items: list[dict[str, Any]] = []
    allowed: set[str] = set()
    for m in case.conn.execute("SELECT * FROM crypto_materials ORDER BY id LIMIT 200"):
        mid = f"M{m['id']}"
        allowed.add(mid)
        item: dict[str, Any] = {
            "id": mid,
            "kind": m["kind"],
            "algo": m["algo"],
            "user": m["username"],
            "source": clean(m["source_path"], 200),
        }
        if m["kind"] == "hash":
            info = MODES.get(m["hashcat_mode"]) if m["hashcat_mode"] is not None else None
            item.update(
                {
                    "hashcat_mode": m["hashcat_mode"],
                    "speed_class": info.speed if info else None,
                    "already_cracked": m["cracked"] is not None,
                }
            )
        elif m["kind"] == "cert":
            d = json.loads(m["detail"])
            item.update(
                {
                    k: d.get(k)
                    for k in (
                        "subject",
                        "sig_algo",
                        "key_bits",
                        "key_type",
                        "self_signed",
                        "expired",
                        "not_after",
                    )
                }
            )
        items.append(item)
    return items, allowed


def web_items(case: Case, limit: int = 60) -> tuple[list[dict[str, Any]], set[str]]:
    rows = case.conn.execute(
        "SELECT * FROM web_surface WHERE category IN ('server','auth','upload')"
        " ORDER BY id LIMIT ?",
        (limit,),
    ).fetchall()
    allowed = {f"W{r['id']}" for r in rows}
    return (
        [
            {
                "id": f"W{r['id']}",
                "category": r["category"],
                "key": clean(r["key"], 100),
                "value": clean(r["value"], 100),
                "confidence": r["confidence"],
                "source": clean(r["source_path"], 200),
            }
            for r in rows
        ],
        allowed,
    )


def _firmware(case: Case) -> list[dict[str, Any]]:
    return [
        {"file": clean(r["path"].rsplit("/", 1)[-1], 100), "size": r["size"], "sha256": r["sha256"]}
        for r in case.conn.execute("SELECT * FROM images")
    ]


def build(case: Case, task: str, finding_id: int | None = None, limit: int = 40) -> Context:
    if task not in TASKS:
        raise ValueError(f"unknown llm task: {task}")
    data: dict[str, Any] = {"firmware": _firmware(case)}
    allowed: set[str] = set()
    if task == "triage":
        data["findings"], allowed = findings_context(case, limit)
    elif task == "crypto":
        data["crypto"], allowed = crypto_items(case)
    elif task == "draft":
        data["findings"], a1 = findings_context(case, limit)
        data["crypto"], a2 = crypto_items(case)
        data["web"], a3 = web_items(case)
        allowed = a1 | a2 | a3
    else:  # cve
        if finding_id is None:
            raise ValueError("the cve task needs a finding id")
        f = case.conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if f is None:
            raise ValueError(f"no such finding: {finding_id}")
        entry = _finding_entry(case, f, allowed)
        vec = suggest(f["heuristic_id"])
        score = base_score(vec) if vec else None
        entry["suggested_cvss"] = (
            {
                "vector": full_vector(vec),
                "score": score,
                "severity": severity(score),
                "confirmed": False,
            }
            if vec and score is not None
            else None
        )
        entry["cwe_name"] = CWE_NAMES.get(f["cwe"] or "")
        entry["owasp_iot_name"] = OWASP_IOT.get(f["owasp_iot"] or "")
        entry["detail"] = clean(f["detail"], 400)
        data["finding"] = entry
    return Context(task, data, allowed, json.dumps(data))
