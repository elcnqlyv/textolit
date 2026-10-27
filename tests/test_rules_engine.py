import os
from pathlib import Path

import pytest

from textolit.core.case import Case
from textolit.core.ledger import add_artifact, decide
from textolit.modules.fswalk import FsWalk
from textolit.modules.missedfindings import (
    RULE_CAP,
    RuleError,
    is_public_ip,
    parse_pack,
    sweep,
)

PACK = """
pack: t
rules:
  - id: t.pw
    title: password
    kind: content
    confidence: low
    severity: medium
    pattern: '(?i)password\\s*=\\s*\\S+'
    globs: ['/etc/*']
    exclude: '^\\s*#'
  - id: t.ww
    title: world writable
    kind: perm
    world_writable: true
    confidence: med
    skip_paths: '^/tmp/'
  - id: t.dbl
    title: double ext
    kind: path
    pattern: '\\.jpg\\.sh$'
    confidence: med
  - id: t.magic
    title: magic
    kind: magic
    exts: [png]
    bad_ftypes: [elf]
    confidence: med
  - id: t.ip
    title: public ip
    kind: content
    post: public_ip
    pattern: '(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.])'
    confidence: low
  - id: t.key
    title: key bytes
    kind: content
    bytes: true
    pattern: 'PRIVATE KEY'
    confidence: high
"""


def build(tmp: Path) -> Case:
    case = Case.create(tmp / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    for d in ("etc", "www", "tmp", "lib"):
        (root / d).mkdir(parents=True)
    (root / "etc/app.conf").write_text(
        "# password=commented\npassword=hunter2\nip=8.8.8.8\nlan=192.168.1.1\n"
    )
    (root / "etc/open.cfg").write_text("x")
    (root / "etc/open.cfg").chmod(0o666)
    (root / "tmp/ok").write_text("x")
    (root / "tmp/ok").chmod(0o666)
    (root / "www/a.jpg.sh").write_text("#!/bin/sh\n")
    (root / "www/logo.png").write_bytes(b"\x7fELF" + os.urandom(64))
    (root / "lib/blob.bin").write_bytes(b"\x00\x01-----BEGIN RSA PRIVATE KEY-----\x00")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    FsWalk().run(case)
    return case


def by_rule(case: Case) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in case.conn.execute("SELECT heuristic_id, evidence_path FROM findings"):
        out.setdefault(r[0], []).append(r[1].rsplit("/", 1)[-1])
    return out


def test_pack_validation() -> None:
    with pytest.raises(RuleError):
        parse_pack("pack: x\nrules:\n  - {id: a, title: t, kind: nope, confidence: low}")
    with pytest.raises(RuleError):
        parse_pack(
            "pack: x\nrules:\n  - {id: a, title: t, kind: content, confidence: low, pattern: '('}"
        )
    with pytest.raises(RuleError):
        parse_pack(
            "pack: x\nrules:\n  - {id: a, title: t, kind: path, confidence: maybe, pattern: x}"
        )


def test_public_ip() -> None:
    assert is_public_ip("8.8.8.8") and not is_public_ip("192.168.1.1")
    assert not is_public_ip("127.0.0.1") and not is_public_ip("999.1.1.1")


def test_sweep_hits(tmp_path: Path) -> None:
    case = build(tmp_path)
    new, capped, notes = sweep(case, parse_pack(PACK))
    assert not capped and not notes
    hits = by_rule(case)
    assert hits["t.pw"] == ["app.conf"]  # commented line excluded
    assert hits["t.ww"] == ["open.cfg"]  # /tmp skipped
    assert hits["t.dbl"] == ["a.jpg.sh"]
    assert hits["t.magic"] == ["logo.png"]
    assert hits["t.ip"] == ["app.conf"]  # 8.8.8.8 only, not 192.168.x
    assert hits["t.key"] == ["blob.bin"]
    row = case.conn.execute("SELECT * FROM findings WHERE heuristic_id='t.pw'").fetchone()
    ev = case.conn.execute(
        "SELECT * FROM evidence_links WHERE finding_id=?", (row["id"],)
    ).fetchone()
    assert ev["line"] == 2 and "hunter2" in ev["snippet"]


def test_resweep_is_idempotent_and_keeps_decisions(tmp_path: Path) -> None:
    case = build(tmp_path)
    rules = parse_pack(PACK)
    sweep(case, rules)
    n = case.conn.execute("SELECT count(*) FROM findings").fetchone()[0]
    fid = case.conn.execute("SELECT id FROM findings WHERE heuristic_id='t.pw'").fetchone()[0]
    decide(case, fid, "rejected", "test fixture")
    new, _, _ = sweep(case, rules)
    assert new == {}
    assert case.conn.execute("SELECT count(*) FROM findings").fetchone()[0] == n
    row = case.conn.execute(
        "SELECT status, decision_note FROM findings WHERE id=?", (fid,)
    ).fetchone()
    assert (row["status"], row["decision_note"]) == ("rejected", "test fixture")
    assert (
        case.conn.execute("SELECT count(*) FROM findings WHERE status='pending'").fetchone()[0]
        == n - 1
    )


def test_cap_is_reported(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    root.mkdir(parents=True)
    for i in range(RULE_CAP + 20):
        (root / f"f{i}.sh").write_text("x")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    FsWalk().run(case)
    rules = parse_pack(
        "pack: c\nrules:\n  - {id: c.sh, title: sh, kind: path, confidence: low, pattern: '\\.sh$'}"
    )
    _new, capped, notes = sweep(case, rules)
    assert capped == {"c.sh": RULE_CAP + 20} and "cap" in notes[0]
    assert case.conn.execute("SELECT count(*) FROM findings").fetchone()[0] == RULE_CAP
