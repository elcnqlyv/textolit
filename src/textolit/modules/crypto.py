"""crypto: pull password hashes, certificates, private keys and key strings out of the image.

Hash recognition is by format only (see ``hashtypes``). Certificates go through ``openssl``
via the logged runner. Private key bodies are never stored, only their fingerprint.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import posixpath
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import add_finding, ensure_heuristic, fs_roots
from textolit.core.runner import run
from textolit.hashtypes import classify_hash, is_locked
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

MAX_TEXT = 1 << 20
MAX_CERTS = 200
SQLITE_MAGIC = b"SQLite format 3\x00"
KEY_COLUMN = re.compile(r"(?i)pass|pwd|hash|secret")
USER_COLUMN = re.compile(r"(?i)^(user(name)?|login|name|account|uname)$")
PEM_KEY = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?)PRIVATE KEY-----(.*?)-----END", re.S
)
KEY_STRING = re.compile(
    r"""(?i)\b(aes[_-]?key|des[_-]?key|secret[_-]?key|api[_-]?key|master[_-]?key|"""
    r"""enc(?:ryption)?[_-]?key|psk|passphrase|crypt[_-]?key)\b["']?\s*[=:]\s*["']?"""
    r"""([0-9a-fA-F]{16,128}|[A-Za-z0-9+/]{22,}={0,2})["']?"""
)
UHTTPD_LINE = re.compile(r"^(/[^:\s]*):([^:\s]+):(\S+)$")


@dataclass(frozen=True)
class HashRow:
    username: str | None
    value: str
    line: int


def parse_shadow(text: str) -> list[HashRow]:
    """user:hash:... lines from shadow and passwd files. Locked and shadowed entries are skipped."""
    out: list[HashRow] = []
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 2 or is_locked(parts[1]):
            continue
        if classify_hash(parts[1]):
            out.append(HashRow(parts[0] or None, parts[1], n))
    return out


def parse_htpasswd(text: str) -> list[HashRow]:
    """htpasswd ``user:hash`` lines and uhttpd/httpd.conf ``/path:user:hash`` lines."""
    out: list[HashRow] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = UHTTPD_LINE.match(line)
        user, value = (m.group(2), m.group(3)) if m else (line.split(":", 1) + [""])[:2]
        if value and not is_locked(value) and classify_hash(value):
            out.append(HashRow(user or None, value, n))
    return out


def scan_sqlite(path: Path) -> list[HashRow]:
    """Hash-looking values in password-ish text columns. Opened read-only and immutable."""
    rows: list[HashRow] = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error:
        return rows
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            key_cols = [c for c in cols if KEY_COLUMN.search(c)]
            user_col = next((c for c in cols if USER_COLUMN.match(c)), None)
            for kc in key_cols:
                sel = f'"{kc}"' + (f', "{user_col}"' if user_col else "")
                for i, r in enumerate(conn.execute(f'SELECT {sel} FROM "{table}" LIMIT 200'), 1):
                    if isinstance(r[0], str) and classify_hash(r[0]):
                        user = str(r[1]) if user_col and r[1] is not None else None
                        rows.append(HashRow(user, r[0], i))
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return rows


def parse_private_keys(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in PEM_KEY.finditer(text):
        kind = m.group(1).strip() or "PKCS8"
        body = m.group(2)
        out.append(
            {
                "algo": kind,
                "encrypted": "ENCRYPTED" in kind or "Proc-Type: 4,ENCRYPTED" in body,
                "fingerprint": hashlib.sha256(body.encode()).hexdigest()[:32],
                "line": text[: m.start()].count("\n") + 1,
            }
        )
    return out


def parse_key_strings(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", "//")):
            continue
        m = KEY_STRING.search(line)
        if m and len(set(m.group(2))) > 3:  # skip 0000..., aaaa... placeholders
            out.append((m.group(1), m.group(2), n))
    return out


def parse_cert_text(text: str) -> dict[str, Any]:
    """Pick the fields we need from ``openssl x509 -text -fingerprint`` output."""

    def grab(pat: str) -> str | None:
        m = re.search(pat, text)
        return m.group(1).strip() if m else None

    not_after = grab(r"Not After\s*:\s*(.+)")
    expired = False
    if not_after:
        with contextlib.suppress(ValueError):
            expired = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT").replace(
                tzinfo=UTC
            ) < datetime.now(UTC)
    bits = grab(r"Public-Key:\s*\((\d+) bit\)")
    subject, issuer = grab(r"Subject:\s*(.+)"), grab(r"Issuer:\s*(.+)")
    return {
        "subject": subject,
        "issuer": issuer,
        "self_signed": bool(subject and subject == issuer),
        "not_after": not_after,
        "expired": expired,
        "sig_algo": grab(r"Signature Algorithm:\s*(\S+)"),
        "key_bits": int(bits) if bits else None,
        "key_type": grab(r"Public Key Algorithm:\s*(\S+)"),
        "fingerprint": grab(r"(?i)sha256 Fingerprint=(\S+)"),
    }


def weak_signature(algo: str | None) -> bool:
    return bool(algo and re.search(r"(?i)md[245]|sha1", algo))


def _route(rel: str) -> str | None:
    base = posixpath.basename(rel).lower()
    if base in ("shadow", "shadow-", "passwd", "passwd-", "master.passwd"):
        return "shadow"
    if "htpasswd" in base or base in ("httpd.conf", "uhttpd.passwd"):
        return "htpasswd"
    return None


class Crypto:
    name = "crypto"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        roots = dict(fs_roots(case))
        rows = case.conn.execute("SELECT * FROM files WHERE is_symlink=0 ORDER BY id").fetchall()
        if not roots or not rows:
            return ModuleResult(
                self.name, False, "no files indexed", errors=["run unpack and fswalk first"]
            )
        for hid, title, sev in (
            ("crypto.hash-extracted", "Password hash recovered from the image", "medium"),
            ("crypto.cert-weak", "Certificate with weak signature or key", "low"),
            ("crypto.cert-expired", "Expired certificate shipped in the image", "low"),
            ("crypto.hardcoded-key-string", "Hard-coded key or passphrase string", "medium"),
        ):
            ensure_heuristic(case, hid, "crypto", title, sev)
        with case.conn:
            case.conn.execute("DELETE FROM crypto_materials")
            case.conn.execute("DELETE FROM credentials WHERE secret_kind IN ('hash','key')")

        stats = {"hashes": 0, "certs": 0, "keys": 0, "key_strings": 0}
        by_algo: dict[str, int] = {}
        warnings: list[str] = []
        cert_budget = int(options.get("max_certs", MAX_CERTS))

        def material(kind: str, src: str, **kw: Any) -> None:
            with case.conn:
                case.conn.execute(
                    "INSERT INTO crypto_materials(kind,algo,value,source_path,hashcat_mode,"
                    "username,source_line,detail) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        kind,
                        kw.get("algo"),
                        kw.get("value"),
                        src,
                        kw.get("mode"),
                        kw.get("username"),
                        kw.get("line"),
                        json.dumps(kw.get("detail", {})),
                    ),
                )

        def add_hashes(found: list[HashRow], src: str, rel: str) -> None:
            for h in found:
                guess = classify_hash(h.value)
                assert guess is not None
                stats["hashes"] += 1
                by_algo[guess.algo] = by_algo.get(guess.algo, 0) + 1
                material(
                    "hash",
                    src,
                    algo=guess.algo,
                    value=h.value,
                    mode=guess.mode,
                    username=h.username,
                    line=h.line,
                    detail={
                        "confidence": guess.confidence,
                        "candidates": list(guess.candidates),
                        "note": guess.note,
                    },
                )
                with case.conn:
                    case.conn.execute(
                        "INSERT INTO credentials(username,secret,secret_kind,algo,source_path,"
                        "source_line) VALUES (?,?,?,?,?,?)",
                        (h.username, h.value, "hash", guess.algo, src, h.line),
                    )
                weak = guess.info is not None and guess.info.speed in ("fast", "medium")
                add_finding(
                    case,
                    heuristic_id="crypto.hash-extracted",
                    title=f"{guess.algo} password hash for '{h.username or '?'}' in {rel}",
                    detail=(f"hashcat mode {guess.mode}. " if guess.mode is not None else "")
                    + (guess.note or ""),
                    evidence_path=src,
                    line=h.line,
                    snippet=f"{h.username or '?'}:{h.value[:12]}...",
                    confidence="high" if guess.confidence == "high" else "med",
                    severity="medium" if weak else "low",
                    cwe="CWE-916" if weak else "CWE-522",
                    owasp_iot="I1",
                )

        for i, row in enumerate(rows):
            base = roots.get(row["artifact_id"])
            if base is None:
                continue
            path = base / row["path"].lstrip("/")
            src = case.rel(path)
            rel = row["path"]
            ftype = row["ftype"]
            route = _route(rel)
            try:
                if ftype in ("text", "script") and row["size"] <= MAX_TEXT:
                    text = path.read_text("utf-8", "replace")
                    if route == "shadow":
                        add_hashes(parse_shadow(text), src, rel)
                    elif route == "htpasswd":
                        add_hashes(parse_htpasswd(text), src, rel)
                    for key in parse_private_keys(text):
                        stats["keys"] += 1
                        material(
                            "private_key",
                            src,
                            algo=key["algo"],
                            value=key["fingerprint"],
                            line=key["line"],
                            detail={"encrypted": key["encrypted"]},
                        )
                    for name, val, line in parse_key_strings(text):
                        stats["key_strings"] += 1
                        material("key_string", src, algo=name.lower(), value=val, line=line)
                        add_finding(
                            case,
                            heuristic_id="crypto.hardcoded-key-string",
                            title=f"Hard-coded {name} value",
                            evidence_path=src,
                            line=line,
                            snippet=f"{name}={val[:4]}...",
                            confidence="low",
                            severity="medium",
                            cwe="CWE-321",
                            owasp_iot="I7",
                        )
                    if "BEGIN CERTIFICATE" in text and cert_budget > 0:
                        cert_budget -= 1
                        self._cert(case, path, src, False, stats, material)
                elif ftype in ("data", "unreadable") and row["size"] > 0:
                    with path.open("rb") as fh:
                        head = fh.read(16)
                    if head == SQLITE_MAGIC:
                        add_hashes(scan_sqlite(path), src, rel)
                    elif path.suffix.lower() in (".der", ".cer", ".crt") and cert_budget > 0:
                        cert_budget -= 1
                        self._cert(case, path, src, True, stats, material)
            except OSError as exc:
                warnings.append(f"{rel}: {exc}")
            if i % 100 == 0:
                progress(i / len(rows), f"crypto {rel}")

        summary = (
            f"{stats['hashes']} hashes {by_algo or ''}, {stats['certs']} certificates, "
            f"{stats['keys']} private keys, {stats['key_strings']} key strings"
        )
        listing = [
            {
                "user": r["username"],
                "algo": r["algo"],
                "mode": r["hashcat_mode"],
                "source": f"{r['source_path']}:{r['source_line']}",
            }
            for r in case.conn.execute(
                "SELECT * FROM crypto_materials WHERE kind='hash' ORDER BY id"
            )
        ]
        return ModuleResult(
            self.name,
            True,
            summary,
            data={**stats, "by_algo": by_algo, "hash_list": listing},
            warnings=warnings[:20],
        )

    def _cert(
        self, case: Case, path: Path, src: str, der: bool, stats: dict[str, int], material: Any
    ) -> None:
        argv = ["openssl", "x509", "-in", str(path), "-noout", "-text", "-fingerprint", "-sha256"]
        if der:
            argv[4:4] = ["-inform", "DER"]
        res = run(case, argv, module=self.name, timeout=30)
        if not res.ok:
            return
        info = parse_cert_text(res.text)
        stats["certs"] += 1
        material("cert", src, algo=info["sig_algo"], value=info["fingerprint"], detail=info)
        why = []
        if weak_signature(info["sig_algo"]):
            why.append(f"signature {info['sig_algo']}")
        if (
            info["key_bits"]
            and info["key_bits"] < 2048
            and (info["key_type"] or "").startswith("rsa")
        ):
            why.append(f"{info['key_bits']}-bit RSA key")
        if why:
            add_finding(
                case,
                heuristic_id="crypto.cert-weak",
                title="Certificate with " + " and ".join(why),
                detail=f"Subject {info['subject']}. Issuer {info['issuer']}.",
                evidence_path=src,
                confidence="high",
                severity="low",
                cwe="CWE-327",
                owasp_iot="I7",
            )
        if info["expired"]:
            add_finding(
                case,
                heuristic_id="crypto.cert-expired",
                title=f"Expired certificate (not after {info['not_after']})",
                detail=f"Subject {info['subject']}.",
                evidence_path=src,
                confidence="high",
                severity="low",
                cwe="CWE-298",
                owasp_iot="I7",
            )
