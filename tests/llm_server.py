"""Tiny local HTTP server that stands in for Ollama and an OpenAI-compatible API."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


class FakeLlm:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.reply: str = "{}"
        self.status: int = 200
        self.reject_json_mode = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append(
                    {"path": self.path, "body": body, "auth": self.headers.get("Authorization")}
                )
                if outer.reject_json_mode and "response_format" in body:
                    self._send(400, {"error": "unsupported parameter: response_format"})
                    return
                if outer.status != 200:
                    self._send(outer.status, {"error": "boom"})
                elif self.path.endswith("/api/chat"):
                    self._send(
                        200,
                        {
                            "message": {"role": "assistant", "content": outer.reply},
                            "prompt_eval_count": 11,
                            "eval_count": 7,
                        },
                    )
                else:
                    self._send(
                        200,
                        {
                            "choices": [{"message": {"content": outer.reply}}],
                            "usage": {"prompt_tokens": 21, "completion_tokens": 9},
                        },
                    )

            def _send(self, code: int, doc: dict[str, Any]) -> None:
                raw = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_a: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> FakeLlm:
        self.thread.start()
        return self

    def __exit__(self, *_a: object) -> None:
        self.server.shutdown()
        self.server.server_close()
