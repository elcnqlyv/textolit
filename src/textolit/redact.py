"""Masking for secrets that must not leave the case database unredacted."""

from __future__ import annotations

from textolit.modules.netmap import PASS_RE


def mask(secret: str | None) -> str:
    if not secret:
        return ""
    return secret[:2] + "*" * max(len(secret) - 2, 2)


def mask_snippet(text: str) -> str:
    """Mask password-looking values in a line of evidence."""
    return PASS_RE.sub(lambda m: m.group(0).replace(m.group(1), mask(m.group(1))), text)
