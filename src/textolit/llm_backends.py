"""LLM backends: Ollama (local) and a generic OpenAI-compatible adapter.

Both use only the standard library. The API key is read from an environment variable named
in the case config and is never written to the case, the ledger or error text. A backend on
a non-loopback host is refused unless the operator set ``allow_remote`` for the case.
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from textolit.core.case import Case

CONFIG_NAME = "llm.json"
DEFAULT_OLLAMA = "http://127.0.0.1:11434"
BACKENDS = ("ollama", "openai")


class BackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChatResult:
    text: str
    tokens_in: int | None
    tokens_out: int | None


@dataclass
class LlmConfig:
    backend: str = "ollama"
    model: str = ""
    base_url: str = ""
    api_key_env: str = "TEXTOLIT_LLM_API_KEY"
    allow_remote: bool = False
    timeout: float = 180.0
    max_findings: int = 40

    @property
    def url(self) -> str:
        return (self.base_url or (DEFAULT_OLLAMA if self.backend == "ollama" else "")).rstrip("/")


def config_path(case: Case) -> Path:
    return case.root / CONFIG_NAME


def load_config(case: Case) -> LlmConfig:
    path = config_path(case)
    cfg = LlmConfig()
    if path.is_file():
        try:
            raw = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackendError(f"bad {CONFIG_NAME}: {exc}") from exc
        for key, val in raw.items():
            if hasattr(cfg, key):
                setattr(cfg, key, val)
    return cfg


def save_config(case: Case, cfg: LlmConfig) -> None:
    config_path(case).write_text(json.dumps(asdict(cfg), indent=2) + "\n", encoding="utf-8")


def is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def problems(cfg: LlmConfig) -> str | None:
    """Why this config may not be used, or None. Checked before any request is made."""
    if cfg.backend not in BACKENDS:
        return f"unknown backend {cfg.backend!r} (use one of {', '.join(BACKENDS)})"
    if not cfg.model:
        return "no model configured: textolit llm <case> config --model NAME"
    if not cfg.url:
        return "no base URL configured: textolit llm <case> config --base-url URL"
    if not is_loopback(cfg.url):
        if not cfg.allow_remote:
            return (
                f"{cfg.url} is not a local address. Case data would leave this machine. "
                "Set it explicitly: textolit llm <case> config --allow-remote"
            )
        if cfg.backend == "openai" and not os.environ.get(cfg.api_key_env):
            return f"environment variable {cfg.api_key_env} is not set (API key)"
    return None


class Backend(Protocol):
    name: str

    def chat(self, system: str, user: str, *, model: str, timeout: float) -> ChatResult: ...


def _post(
    url: str, body: dict[str, Any], headers: dict[str, str], timeout: float, secret: str | None
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 - scheme checked by the caller
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    handlers = [urllib.request.ProxyHandler({})] if is_loopback(url) else []
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(400).decode("utf-8", "replace")
        if secret:
            detail = detail.replace(secret, "***")
        raise BackendError(f"HTTP {exc.code} from {urlparse(url).netloc}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BackendError(f"cannot reach {urlparse(url).netloc}: {exc}") from exc
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise BackendError("backend returned a non-JSON response") from exc
    if not isinstance(doc, dict):
        raise BackendError("backend returned an unexpected response shape")
    return doc


@dataclass
class OllamaBackend:
    base_url: str
    name: str = "ollama"

    def chat(self, system: str, user: str, *, model: str, timeout: float) -> ChatResult:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        doc = _post(
            f"{self.base_url}/api/chat",
            {
                "model": model,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
                "messages": messages,
            },
            {},
            timeout,
            None,
        )
        msg = doc.get("message")
        if not isinstance(msg, dict) or not isinstance(msg.get("content"), str):
            raise BackendError("ollama reply has no message content")
        return ChatResult(msg["content"], doc.get("prompt_eval_count"), doc.get("eval_count"))


@dataclass
class OpenAIBackend:
    base_url: str
    api_key: str | None
    name: str = "openai"

    def chat(self, system: str, user: str, *, model: str, timeout: float) -> ChatResult:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body: dict[str, Any] = {
            "model": model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
        }
        url = f"{self.base_url}/chat/completions"
        try:
            doc = _post(url, body, headers, timeout, self.api_key)
        except BackendError as exc:
            if "HTTP 400" not in str(exc) or "response_format" not in str(exc):
                raise
            body.pop("response_format")  # some servers reject JSON mode: ask without it
            doc = _post(url, body, headers, timeout, self.api_key)
        try:
            text = doc["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError("openai-style reply has no choices[0].message.content") from exc
        usage: dict[str, Any] = doc["usage"] if isinstance(doc.get("usage"), dict) else {}
        return ChatResult(str(text), usage.get("prompt_tokens"), usage.get("completion_tokens"))


def make_backend(cfg: LlmConfig) -> Backend:
    if cfg.backend == "ollama":
        return OllamaBackend(cfg.url)
    return OpenAIBackend(cfg.url, os.environ.get(cfg.api_key_env) or None)
