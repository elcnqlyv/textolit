"""SQLite connection helper and forward-only migration runner."""

from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path


def connect(path: Path) -> sqlite3.Connection:
    """Open a case database in WAL mode with foreign keys enforced."""
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _migrations() -> list[tuple[int, str]]:
    root = resources.files("textolit.db") / "migrations"
    found: list[tuple[int, str]] = []
    for entry in root.iterdir():
        if entry.name.endswith(".sql"):
            found.append((int(entry.name.split("_", 1)[0]), entry.read_text(encoding="utf-8")))
    return sorted(found)


def migrate(conn: sqlite3.Connection) -> list[int]:
    """Apply pending migrations; return the versions applied."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    applied: list[int] = []
    for version, sql in _migrations():
        if version in done:
            continue
        record = f"INSERT INTO schema_migrations(version) VALUES ({int(version)});"
        conn.executescript(f"BEGIN;\n{sql}\n{record}\nCOMMIT;")
        applied.append(version)
    return applied
