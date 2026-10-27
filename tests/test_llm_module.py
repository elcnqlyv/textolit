import hashlib
import json
import os
from pathlib import Path

import pytest
from llm_server import FakeLlm

from textolit.core.case import Case
from textolit.core.ledger import add_finding, decide, ensure_heuristic
from textolit.export_cve import build as build_cve
from textolit.llm_backends import LlmConfig, save_config
from textolit.modules.ingest import Ingest
from textolit.modules.llm import Llm


def make_case(tmp: Path, url: str = "http://127.0.0.1:9", on: bool = True) -> Case:
    img = tmp / "fw.bin"
    img.write_bytes(os.urandom(1024))
    case = Case.create(tmp / "c")
    Ingest().run(case, image=img)
    ensure_heuristic(case, "creds.empty-password-field", "creds", "t", "high")
    ensure_heuristic(case, "creds.plaintext-password", "creds", "t", "medium")
    add_finding(
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
    save_config(case, LlmConfig(model="test-model", base_url=url))
    case.set_llm(on)
    return case


TRIAGE_OK = json.dumps(
    {
        "summary": "Root has no password.",
        "priorities": [
            {"finding": "F1", "reason": "empty password field in passwd", "cites": ["F1", "E1"]}
        ],
        "unverified": ["may be reachable over telnet"],
    }
)


def calls(case: Case) -> list[dict[str, object]]:
    return [dict(r) for r in case.conn.execute("SELECT * FROM llm_calls ORDER BY id")]


def test_off_means_no_request_and_no_log(tmp_path: Path) -> None:
    with FakeLlm() as srv:
        case = make_case(tmp_path, srv.url, on=False)
        res = Llm().run(case, task="triage")
        assert not res.ok and "off for this case" in res.summary
        assert srv.requests == [] and calls(case) == []


def test_refuses_remote_and_missing_model(tmp_path: Path) -> None:
    case = make_case(tmp_path, "http://192.0.2.7:11434")
    res = Llm().run(case, task="triage")
    assert not res.ok and "leave this machine" in res.errors[0] and calls(case) == []
    save_config(case, LlmConfig(base_url="http://127.0.0.1:9"))
    assert "no model" in Llm().run(case, task="triage").errors[0]
    assert not Llm().run(case, task="poem").ok


def test_triage_success_is_logged_and_auditable(tmp_path: Path) -> None:
    with FakeLlm() as srv:
        srv.reply = TRIAGE_OK
        case = make_case(tmp_path, srv.url)
        res = Llm().run(case, task="triage")
        assert res.ok, res.errors
        (row,) = calls(case)
        assert (row["backend"], row["model"], row["template"], row["status"]) == (
            "ollama",
            "test-model",
            "triage.txt",
            "ok",
        )
        assert (row["tokens_in"], row["tokens_out"]) == (11, 7)
        prompt = (case.root / str(row["prompt_path"])).read_text()
        system, user = (
            srv.requests[0]["body"]["messages"][0]["content"],
            srv.requests[0]["body"]["messages"][1]["content"],
        )
        assert hashlib.sha256(f"{system}\n---\n{user}".encode()).hexdigest() == row["prompt_sha256"]
        assert (
            "untrusted data" in prompt and "letmein" not in prompt and "password=le*****" in prompt
        )
        assert (case.root / str(row["output_path"])).read_text() == TRIAGE_OK
        latest = json.loads((case.root / "artifacts/llm/triage-latest.json").read_text())
        assert latest["data"]["priorities"][0]["finding"] == "F1" and latest["call_id"] == row["id"]
        # an LLM answer creates no finding by itself
        assert case.conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 2


def test_invalid_reply_is_stored_as_invalid_not_used(tmp_path: Path) -> None:
    with FakeLlm() as srv:
        srv.reply = json.dumps(
            {"summary": "x", "priorities": [{"finding": "F1", "reason": "r", "cites": ["E99"]}]}
        )
        case = make_case(tmp_path, srv.url)
        res = Llm().run(case, task="triage")
        assert not res.ok and any("E99" in w for w in res.warnings)
        assert calls(case)[0]["status"] == "invalid"
        assert not (case.root / "artifacts/llm/triage-latest.json").exists()
        srv.reply = "Sure! Here is my analysis."
        assert not Llm().run(case, task="triage").ok and calls(case)[1]["status"] == "invalid"


def test_backend_error_is_logged(tmp_path: Path) -> None:
    with FakeLlm() as srv:
        srv.status = 500
        case = make_case(tmp_path, srv.url)
        res = Llm().run(case, task="triage")
        assert not res.ok and "HTTP 500" in res.errors[0]
        assert calls(case)[0]["status"] == "error" and calls(case)[0]["prompt_path"]


def test_cve_draft_feeds_the_cve_export(tmp_path: Path) -> None:
    with FakeLlm() as srv:
        srv.reply = json.dumps(
            {
                "finding": "F1",
                "title": "Empty root password",
                "description": "passwd gives root no password.",
                "impact": "Login as root without a password if a login service is reachable.",
                "cwe": "CWE-258",
                "affected": "",
                "references_needed": ["affected versions"],
                "cites": ["F1", "E1"],
                "unverified": [],
            }
        )
        case = make_case(tmp_path, srv.url)
        res = Llm().run(case, task="cve", finding=1)
        assert res.ok, res.errors
        decide(case, 1, "accepted")
        entry = build_cve(case)["entries"][0]
        assert entry["llm_draft"]["source"] == "llm-draft, unverified"
        assert entry["llm_draft"]["title"] == "Empty root password"
        assert not Llm().run(case, task="cve").ok  # needs a finding id


def test_draft_writes_labelled_markdown(tmp_path: Path) -> None:
    with FakeLlm() as srv:
        srv.reply = json.dumps(
            {
                "executive_summary": {"text": "Weak credentials.", "cites": ["F1"]},
                "sections": [
                    {
                        "title": "Credentials",
                        "body": "Root has an empty password.",
                        "cites": ["F1", "E1"],
                    }
                ],
                "unverified": ["telnet may be on"],
            }
        )
        case = make_case(tmp_path, srv.url)
        res = Llm().run(case, task="draft")
        assert res.ok, res.errors
        md = (case.root / res.data["files"][-1]).read_text()
        assert "LLM DRAFT, UNVERIFIED" in md and "[F1, E1]" in md and "telnet may be on" in md


def test_api_key_never_reaches_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEXTOLIT_LLM_API_KEY", "sk-never-store-me")
    with FakeLlm() as srv:
        srv.reply = TRIAGE_OK
        case = make_case(tmp_path, srv.url + "/v1")
        save_config(case, LlmConfig(backend="openai", model="m", base_url=srv.url + "/v1"))
        res = Llm().run(case, task="triage")
        assert res.ok, res.errors
        assert srv.requests[0]["auth"] == "Bearer sk-never-store-me"
        for p in case.root.rglob("*"):
            if p.is_file() and p.suffix != ".db":
                assert b"sk-never-store-me" not in p.read_bytes(), p
        assert b"sk-never-store-me" not in (case.root / "case.db").read_bytes()
