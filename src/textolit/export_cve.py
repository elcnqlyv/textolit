"""CVE-ready JSON export: one entry per vetted finding, with the fields a CVE request needs.

Nothing here is a verdict. CVSS vectors come from a small suggestion table and are marked
``confirmed: false``. Affected vendor versions are left for the analyst to fill in. Evidence
snippets are masked the same way as in the Markdown report.
"""

from __future__ import annotations

import json
import re
from typing import Any

from textolit import __version__
from textolit.core.case import Case, utcnow
from textolit.cvss import base_score, full_vector, severity, suggest
from textolit.redact import mask_snippet
from textolit.taxonomy import OWASP_IOT

SCHEMA = "textolit-cve-ready/1"
LLM_DIR = "artifacts/llm"

CWE_NAMES = {
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-258": "Empty Password in Configuration File",
    "CWE-295": "Improper Certificate Validation",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-489": "Active Debug Code",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-547": "Use of Hard-coded, Security-relevant Constants",
    "CWE-602": "Client-Side Enforcement of Server-Side Security",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-912": "Hidden Functionality",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1327": "Binding to an Unrestricted IP Address",
}
COMPONENT_TITLE = re.compile(r"^(\w[\w.-]*) (\d[\w.]*):")


def _firmware(case: Case) -> list[dict[str, Any]]:
    out = []
    for r in case.conn.execute("SELECT * FROM images ORDER BY id"):
        meta = json.loads(r["meta_json"])
        out.append(
            {
                "file": meta.get("filename") or r["path"],
                "size": r["size"],
                "sha256": r["sha256"],
                "md5": r["md5"],
            }
        )
    return out


def _llm_draft(case: Case, finding_id: int) -> dict[str, Any] | None:
    path = case.root / LLM_DIR / f"cve-{finding_id}.json"
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def build(case: Case, statuses: tuple[str, ...] = ("accepted",)) -> dict[str, Any]:
    name = case.conn.execute("SELECT name FROM cases WHERE id=?", (case.case_id,)).fetchone()[0]
    marks = ",".join("?" for _ in statuses)
    rows = case.conn.execute(
        f"SELECT * FROM findings WHERE status IN ({marks}) ORDER BY id", statuses
    ).fetchall()
    firmware = _firmware(case)
    entries: list[dict[str, Any]] = []
    for f in rows:
        evidence = [
            {"path": e["path"], "line": e["line"], "snippet": mask_snippet(e["snippet"] or "")}
            for e in case.conn.execute(
                "SELECT * FROM evidence_links WHERE finding_id=? ORDER BY id", (f["id"],)
            )
        ]
        vec = suggest(f["heuristic_id"])
        cvss: dict[str, Any] | None = None
        if vec:
            score = base_score(vec)
            cvss = {
                "vector": full_vector(vec),
                "base_score": score,
                "severity": severity(score),
                "source": "suggested by textolit",
                "confirmed": False,
            }
        cwe = f["cwe"]
        comp = COMPONENT_TITLE.match(f["title"])
        entry: dict[str, Any] = {
            "id": f"TXL-{case.case_id}-{f['id']}",
            "finding_id": f["id"],
            "title": f["title"],
            "description": f["detail"] or f["title"],
            "rule": f["heuristic_id"],
            "status": f["status"],
            "confidence": f["confidence"],
            "severity_hint": f["severity"],
            "cwe": {"id": cwe, "name": CWE_NAMES.get(cwe or "")} if cwe else None,
            "cvss_v31": cvss,
            "owasp_iot": (
                {"id": f["owasp_iot"], "name": OWASP_IOT.get(f["owasp_iot"], "")}
                if f["owasp_iot"]
                else None
            ),
            "affected": {
                "firmware": firmware,
                "components": [{"name": comp.group(1), "version": comp.group(2)}] if comp else [],
                "affected_versions": [],
                "needs_input": "vendor, product and firmware version range",
            },
            "evidence": evidence,
            "poc": {"status": "none", "steps": [], "notes": ""},
            "references": [],
            "analyst_notes": f["decision_note"] or "",
        }
        draft = _llm_draft(case, f["id"])
        if draft:
            entry["llm_draft"] = {"source": "llm-draft, unverified", **draft}
        entries.append(entry)
    return {
        "schema": SCHEMA,
        "tool": f"textolit {__version__}",
        "generated": utcnow(),
        "case": name,
        "firmware": firmware,
        "included_statuses": list(statuses),
        "notes": (
            "CVSS vectors are suggestions and must be confirmed. Affected versions, PoC and "
            "references are for the analyst to complete before any CVE request."
        ),
        "entries": entries,
    }
