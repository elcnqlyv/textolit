"""Hash recognition and hashcat mode suggestions.

Recognition is by format only. A 32-hex string could be MD5, MD4 or NTLM, so ambiguous
formats return the likeliest mode plus the other candidates and a lower confidence.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModeInfo:
    mode: int
    name: str
    speed: str  # fast, medium, slow
    vram_heavy: bool = False


MODES: dict[int, ModeInfo] = {
    m.mode: m
    for m in (
        ModeInfo(0, "MD5", "fast"),
        ModeInfo(100, "SHA1", "fast"),
        ModeInfo(900, "MD4", "fast"),
        ModeInfo(1000, "NTLM", "fast"),
        ModeInfo(1400, "SHA2-256", "fast"),
        ModeInfo(1700, "SHA2-512", "fast"),
        ModeInfo(101, "nsldap SHA1 base64", "fast"),
        ModeInfo(111, "nsldaps SSHA1 base64", "fast"),
        ModeInfo(1500, "DES crypt", "fast"),
        ModeInfo(500, "md5crypt $1$", "medium"),
        ModeInfo(1600, "Apache apr1 MD5", "medium"),
        ModeInfo(7400, "sha256crypt $5$", "slow"),
        ModeInfo(1800, "sha512crypt $6$", "slow"),
        ModeInfo(3200, "bcrypt $2*$", "slow"),
        ModeInfo(8900, "scrypt", "slow", vram_heavy=True),
    )
}

_B64 = r"[A-Za-z0-9+/]"
_CRYPT = r"[./0-9A-Za-z]"


@dataclass(frozen=True)
class HashGuess:
    algo: str
    mode: int | None
    confidence: str  # high, med, low
    candidates: tuple[int, ...] = field(default=())
    note: str = ""

    @property
    def info(self) -> ModeInfo | None:
        return MODES.get(self.mode) if self.mode is not None else None


LOCKED = {"", "*", "!", "!!", "x", "X", "NP", "*LK*", "LK", "*0", "*1", "!*"}


def is_locked(value: str) -> bool:
    """True for placeholders that mean no usable password hash (locked or shadowed)."""
    return value in LOCKED or value.startswith(("!", "*"))


def classify_hash(value: str) -> HashGuess | None:
    v = value.strip()
    if not v or is_locked(v):
        return None
    if re.fullmatch(rf"\$1\$[^$]{{0,8}}\${_CRYPT}{{22}}", v):
        return HashGuess("md5crypt", 500, "high")
    if re.fullmatch(rf"\$apr1\$[^$]{{0,8}}\${_CRYPT}{{22}}", v):
        return HashGuess("apr1", 1600, "high")
    if re.fullmatch(rf"\$5\$(?:rounds=\d+\$)?[^$]{{0,16}}\${_CRYPT}{{43}}", v):
        return HashGuess("sha256crypt", 7400, "high")
    if re.fullmatch(rf"\$6\$(?:rounds=\d+\$)?[^$]{{0,16}}\${_CRYPT}{{86}}", v):
        return HashGuess("sha512crypt", 1800, "high")
    if re.fullmatch(rf"\$2[abxy]?\$\d\d\${_CRYPT}{{53}}", v):
        return HashGuess("bcrypt", 3200, "high")
    if v.startswith("$y$"):
        return HashGuess("yescrypt", None, "high", note="no hashcat mode for yescrypt")
    if re.fullmatch(rf"\{{SHA\}}{_B64}{{27}}=", v):
        return HashGuess("sha1-base64", 101, "high")
    if m := re.fullmatch(rf"\{{SSHA\}}({_B64}+=*)", v):
        try:
            if len(base64.b64decode(m.group(1))) > 20:
                return HashGuess("ssha1-base64", 111, "high")
        except ValueError:
            return None
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return HashGuess("md5", 0, "med", (0, 900, 1000), "could also be MD4 or NTLM")
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return HashGuess("sha1", 100, "med")
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return HashGuess("sha256", 1400, "med")
    if re.fullmatch(r"[0-9a-fA-F]{128}", v):
        return HashGuess("sha512", 1700, "med")
    if re.fullmatch(rf"{_CRYPT}{{13}}", v):
        return HashGuess("des-crypt", 1500, "med", note="13 chars of crypt alphabet")
    return None
