from pathlib import Path

from textolit.db.connection import connect, migrate

EXPECTED = {
    "cases", "images", "artifacts", "regions", "files", "binaries", "services",
    "network_endpoints", "credentials", "crypto_materials", "findings", "heuristics",
    "llm_calls", "commands", "evidence_links", "jobs",
}


def test_migration_creates_schema_and_is_idempotent(tmp_path: Path) -> None:
    conn = connect(tmp_path / "case.db")
    assert migrate(conn) == [1]
    assert migrate(conn) == []
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables >= EXPECTED
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
