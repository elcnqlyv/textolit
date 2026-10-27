import json
import os
from pathlib import Path

from textolit.core.case import Case
from textolit.core.ledger import add_finding, decide, ensure_heuristic
from textolit.export_cve import SCHEMA, build
from textolit.modules.ingest import Ingest


def make_case(tmp: Path) -> Case:
    img = tmp / "cam-fw-1.2.bin"
    img.write_bytes(os.urandom(2048))
    case = Case.create(tmp / "c")
    Ingest().run(case, image=img)
    ensure_heuristic(case, "creds.empty-password-field", "creds", "t", "high")
    ensure_heuristic(case, "binintel.version-hint", "binintel", "t", "info")
    ensure_heuristic(case, "creds.plaintext-password", "creds", "t", "medium")
    return case


def test_accepted_only_by_default_with_cvss_and_slots(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    a = add_finding(
        case,
        heuristic_id="creds.empty-password-field",
        title="Account with an empty password field",
        evidence_path="artifacts/x/etc/passwd",
        line=1,
        snippet="root::0:0",
        confidence="high",
        severity="high",
        cwe="CWE-258",
        owasp_iot="I1",
    )
    b = add_finding(
        case,
        heuristic_id="binintel.version-hint",
        title="openssl 1.0.1e: Heartbleed range",
        evidence_path="artifacts/x/usr/sbin/httpd",
        confidence="low",
        severity="medium",
        cwe="CWE-1104",
        owasp_iot="I5",
    )
    c = add_finding(
        case,
        heuristic_id="creds.plaintext-password",
        title="Password assigned in a config",
        evidence_path="artifacts/x/etc/app.conf",
        line=4,
        snippet="password=letmein",
        confidence="low",
        severity="medium",
        cwe="CWE-798",
        owasp_iot="I1",
    )
    assert a and b and c
    decide(case, a, "accepted", "confirmed on device")
    decide(case, b, "accepted")
    doc = build(case)
    assert doc["schema"] == SCHEMA and [e["finding_id"] for e in doc["entries"]] == [a, b]
    first, second = doc["entries"]
    assert first["cwe"] == {"id": "CWE-258", "name": "Empty Password in Configuration File"}
    assert first["cvss_v31"]["base_score"] == 9.8 and first["cvss_v31"]["confirmed"] is False
    assert first["cvss_v31"]["vector"].startswith("CVSS:3.1/")
    assert first["poc"] == {"status": "none", "steps": [], "notes": ""}
    assert first["affected"]["firmware"][0]["file"] == "cam-fw-1.2.bin"
    assert first["affected"]["affected_versions"] == [] and first["affected"]["needs_input"]
    assert first["analyst_notes"] == "confirmed on device"
    assert second["cvss_v31"] is None  # no suggestion for version hints
    assert second["affected"]["components"] == [{"name": "openssl", "version": "1.0.1e"}]
    json.dumps(doc)  # serialisable


def test_pending_included_on_request_and_secrets_masked(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    add_finding(
        case,
        heuristic_id="creds.plaintext-password",
        title="Password assigned in a config",
        evidence_path="artifacts/x/etc/app.conf",
        line=4,
        snippet="password=letmein",
        confidence="low",
        severity="medium",
        cwe="CWE-798",
        owasp_iot="I1",
    )
    assert build(case)["entries"] == []
    doc = build(case, ("accepted", "pending"))
    ev = doc["entries"][0]["evidence"][0]
    assert ev["snippet"] == "password=le*****" and "letmein" not in json.dumps(doc)


def test_llm_draft_is_labelled(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    fid = add_finding(
        case,
        heuristic_id="creds.empty-password-field",
        title="t",
        evidence_path="p",
        confidence="high",
        cwe="CWE-258",
    )
    assert fid
    decide(case, fid, "accepted")
    d = case.root / "artifacts/llm"
    d.mkdir(parents=True)
    (d / f"cve-{fid}.json").write_text(json.dumps({"description": "draft text"}))
    entry = build(case)["entries"][0]
    assert entry["llm_draft"]["source"] == "llm-draft, unverified"
    assert entry["llm_draft"]["description"] == "draft text"
