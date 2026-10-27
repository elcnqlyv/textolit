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
