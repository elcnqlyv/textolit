"""Case directory layout: one directory, one SQLite database, on-disk artifacts."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from textolit.db.connection import connect, migrate

DB_NAME = "case.db"


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class CaseError(Exception):
    """Raised for missing, duplicate or corrupt cases."""


@dataclass
class Case:
    root: Path
    conn: sqlite3.Connection
    case_id: int

    @property
    def db_path(self) -> Path:
        return self.root / DB_NAME

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def extract_dir(self) -> Path:
        return self.artifacts_dir / "extract"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def llm_enabled(self) -> bool:
        row = self.conn.execute(
            "SELECT llm_enabled FROM cases WHERE id=?", (self.case_id,)
        ).fetchone()
        return bool(row[0])

    def set_llm(self, enabled: bool) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE cases SET llm_enabled=? WHERE id=?", (int(enabled), self.case_id)
            )

    def rel(self, path: Path) -> str:
        """Path relative to the case root, as stored in the database."""
        return str(path.resolve().relative_to(self.root.resolve()))

    def close(self) -> None:
        self.conn.close()

    @classmethod
    def create(cls, root: Path, name: str | None = None) -> Case:
        root = root.resolve()
        if (root / DB_NAME).exists():
            raise CaseError(f"case already exists: {root}")
        for sub in ("artifacts/extract", "artifacts/carved", "logs", "reports"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        conn = connect(root / DB_NAME)
        migrate(conn)
        with conn:
            cur = conn.execute(
                "INSERT INTO cases(name, created_at) VALUES (?, ?)", (name or root.name, utcnow())
            )
        assert cur.lastrowid is not None
        return cls(root, conn, cur.lastrowid)

    @classmethod
    def open(cls, root: Path) -> Case:
        root = root.resolve()
        if not (root / DB_NAME).exists():
            raise CaseError(f"not a textolit case (no {DB_NAME}): {root}")
        conn = connect(root / DB_NAME)
        migrate(conn)
        row = conn.execute("SELECT id FROM cases ORDER BY id LIMIT 1").fetchone()
        if row is None:
            raise CaseError(f"case database has no case row: {root}")
        return cls(root, conn, int(row[0]))
