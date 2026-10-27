import json
from pathlib import Path

import pytest
from llm_server import FakeLlm

from textolit.core.case import Case
from textolit.llm_backends import (
    BackendError,
    LlmConfig,
    OllamaBackend,
    OpenAIBackend,
    is_loopback,
    load_config,
    make_backend,
    problems,
    save_config,
)


def test_loopback_detection() -> None:
    for url in ("http://127.0.0.1:11434", "http://localhost:8080/v1", "http://[::1]:9"):
        assert is_loopback(url)
    for url in ("http://192.0.2.5:11434", "https://api.example.com/v1", "http://10.0.0.2"):
        assert not is_loopback(url)


def test_problems_gate_remote_and_missing_pieces(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "no model" in (problems(LlmConfig()) or "")
    assert problems(LlmConfig(model="m")) is None  # ollama on the default loopback URL
    assert "no base URL" in (problems(LlmConfig(backend="openai", model="m")) or "")
    remote = LlmConfig(backend="openai", model="m", base_url="https://api.example.com/v1")
    assert "leave this machine" in (problems(remote) or "")
    remote.allow_remote = True
    monkeypatch.delenv("TEXTOLIT_LLM_API_KEY", raising=False)
    assert "TEXTOLIT_LLM_API_KEY" in (problems(remote) or "")
    monkeypatch.setenv("TEXTOLIT_LLM_API_KEY", "k")
    assert problems(remote) is None
    assert "unknown backend" in (problems(LlmConfig(backend="x", model="m")) or "")


def test_config_roundtrip_has_no_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEXTOLIT_LLM_API_KEY", "sk-very-secret")
    case = Case.create(tmp_path / "c")
    save_config(case, LlmConfig(backend="openai", model="m", base_url="http://127.0.0.1:1/v1"))
    text = (case.root / "llm.json").read_text()
    assert "sk-very-secret" not in text and "api_key_env" in text
    assert load_config(case).model == "m"


def test_ollama_backend() -> None:
    with FakeLlm() as srv:
        srv.reply = '{"ok": true}'
        res = OllamaBackend(srv.url).chat("sys", "usr", model="llama", timeout=5)
        assert (res.text, res.tokens_in, res.tokens_out) == ('{"ok": true}', 11, 7)
        sent = srv.requests[0]["body"]
        assert (
            sent["format"] == "json" and sent["options"]["temperature"] == 0 and not sent["stream"]
        )
        assert [m["role"] for m in sent["messages"]] == ["system", "user"]


def test_openai_backend_auth_and_usage() -> None:
    with FakeLlm() as srv:
        srv.reply = "{}"
        res = OpenAIBackend(srv.url + "/v1", "sk-test").chat("s", "u", model="m", timeout=5)
        assert (res.tokens_in, res.tokens_out) == (21, 9)
        req = srv.requests[0]
        assert req["path"] == "/v1/chat/completions" and req["auth"] == "Bearer sk-test"
        assert req["body"]["response_format"] == {"type": "json_object"}


def test_openai_backend_retries_without_json_mode() -> None:
    with FakeLlm() as srv:
        srv.reject_json_mode = True
        OpenAIBackend(srv.url + "/v1", None).chat("s", "u", model="m", timeout=5)
        assert len(srv.requests) == 2 and "response_format" not in srv.requests[1]["body"]
        assert srv.requests[1]["auth"] is None


def test_errors_are_surfaced_and_hide_the_key() -> None:
    with FakeLlm() as srv:
        srv.status = 500
        with pytest.raises(BackendError, match="HTTP 500"):
            OllamaBackend(srv.url).chat("s", "u", model="m", timeout=5)
    with pytest.raises(BackendError, match="cannot reach"):
        OllamaBackend("http://127.0.0.1:9").chat("s", "u", model="m", timeout=2)
    backend = make_backend(LlmConfig(backend="openai", model="m", base_url="http://127.0.0.1:9/v1"))
    with pytest.raises(BackendError) as exc:
        backend.chat("s", "u", model="m", timeout=2)
    assert "sk-" not in json.dumps(str(exc.value))
