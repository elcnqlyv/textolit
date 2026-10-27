"""CVSS v3.1 base score calculator and suggested vectors for common firmware findings.

The calculator follows the FIRST v3.1 specification. Suggested vectors are a starting
point for the analyst, never a verdict: exports label them as unconfirmed.
"""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_VECTOR = re.compile(
    r"^(?:CVSS:3\.1/)?AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])$"
)


class VectorError(ValueError):
    pass


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest number with one decimal that is >= value."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = _VECTOR.match(vector.strip())
    if not m:
        raise VectorError(f"not a CVSS v3.1 base vector: {vector!r}")
    av, ac, pr, ui, scope, c, i, a = m.groups()
    changed = scope == "C"
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * _AV[av] * _AC[ac] * (_PR_C if changed else _PR_U)[pr] * _UI[ui]
    if impact <= 0:
        return 0.0
    total = impact + exploit
    return roundup(min((1.08 if changed else 1.0) * total, 10.0))


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def full_vector(vector: str) -> str:
    v = vector.strip()
    return v if v.startswith("CVSS:3.1/") else f"CVSS:3.1/{v}"


NET_FULL = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# heuristic id -> suggested base vector. Anything missing has no suggestion on purpose.
SUGGESTED: dict[str, str] = {
    "creds.empty-password-field": NET_FULL,
    "creds.default-pair": NET_FULL,
    "svc.dropbear-blank-password": NET_FULL,
    "crypto.hash-cracked": NET_FULL,
    "web.embedded-basic-credentials": NET_FULL,
    "net.nc-listener": NET_FULL,
    "svc.telnetd-start": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "creds.private-key": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "crypto.md5-crypt-hash": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "crypto.des-crypt-hash": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "web.upload-handler": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "perm.world-writable": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
}


def suggest(heuristic_id: str | None) -> str | None:
    return SUGGESTED.get(heuristic_id or "")
