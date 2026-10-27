"""Evidence ledger helpers: artifacts and findings are always recorded, never implied."""

from __future__ import annotations

import hashlib
from pathlib import Path

from textolit.core.case import Case, utcnow


def sha256_file(path: Path, bufsize: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(bufsize):
            h.update(chunk)
    return h.hexdigest()


def add_artifact(
    case: Case,
    kind: str,
    path: Path,
    *,
    image_id: int | None = None,
    parent_id: int | None = None,
    produced_by: int | None = None,
    hash_it: bool = True,
) -> int:
    is_file = path.is_file()
    with case.conn:
        cur = case.conn.execute(
            "INSERT INTO artifacts(image_id,parent_id,kind,path,sha256,size,produced_by,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                image_id,
                parent_id,
                kind,
                case.rel(path),
                sha256_file(path) if is_file and hash_it else None,
                path.stat().st_size if is_file else None,
                produced_by,
                utcnow(),
            ),
        )
    assert cur.lastrowid is not None
    return cur.lastrowid


def add_finding(
    case: Case,
    *,
    heuristic_id: str,
    title: str,
    evidence_path: str,
    confidence: str,
    severity: str = "info",
    detail: str = "",
    line: int | None = None,
    snippet: str | None = None,
    owasp_iot: str | None = None,
    cwe: str | None = None,
) -> int | None:
    """Insert a finding unless an identical one exists (same rule, path, line).

    Returns the new id, or None when it was already recorded. A rejected or snoozed
    finding keeps its status, so a re-scan never resurrects a decision the operator made.
    """
    fingerprint = hashlib.sha256(
        f"{heuristic_id}\0{evidence_path}\0{line or 0}".encode()
    ).hexdigest()
    with case.conn:
        cur = case.conn.execute(
            "INSERT OR IGNORE INTO findings(heuristic_id,title,detail,confidence,severity,"
            "owasp_iot,cwe,evidence_path,fingerprint,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                heuristic_id,
                title,
                detail,
                confidence,
                severity,
                owasp_iot,
                cwe,
                evidence_path,
                fingerprint,
                utcnow(),
            ),
        )
        if cur.rowcount == 0:
            return None
        fid = cur.lastrowid
        assert fid is not None
        case.conn.execute(
            "INSERT INTO evidence_links(finding_id,kind,path,line,snippet) VALUES (?,?,?,?,?)",
            (fid, "file", evidence_path, line, snippet),
        )
    return fid


def ensure_heuristic(case: Case, hid: str, pack: str, title: str, severity: str) -> None:
    with case.conn:
        case.conn.execute(
            "INSERT OR REPLACE INTO heuristics(id,pack,title,severity) VALUES (?,?,?,?)",
            (hid, pack, title, severity),
        )


def fs_roots(case: Case) -> list[tuple[int, Path]]:
    """(artifact id, absolute path) for every extracted filesystem root, or the extract root."""
    rows = case.conn.execute(
        "SELECT id, path FROM artifacts WHERE kind LIKE 'fs_root:%' ORDER BY id"
    ).fetchall()
    if not rows:
        rows = case.conn.execute(
            "SELECT id, path FROM artifacts WHERE kind='extract_root' ORDER BY id"
        ).fetchall()
    return [(int(r["id"]), case.root / r["path"]) for r in rows]
