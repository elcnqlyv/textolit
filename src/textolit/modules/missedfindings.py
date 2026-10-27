"""missedfindings: YAML rule packs swept over every indexed file.

Hits are findings with a confidence and an evidence path, never a verdict. Findings are
deduplicated by (rule, path, line); operator decisions (accepted / rejected / snoozed)
are kept, so a re-sweep never resurrects a rejected lead. Caps are reported, not hidden.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from textolit.core.case import Case
from textolit.core.ledger import add_finding, ensure_heuristic, fs_roots
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

KINDS = {"content", "path", "perm", "magic"}
CONFIDENCE = {"low", "med", "high"}
DEFAULT_TEXT_FTYPES = ("text", "script")
DEFAULT_BYTES_FTYPES = ("text", "script", "data", "elf")
MAX_TEXT = 1 << 20
MAX_BYTES = 4 << 20
RULE_CAP = 200


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    pack: str
    title: str
    kind: str
    confidence: str
    severity: str
    cwe: str | None = None
    owasp_iot: str | None = None
    pattern: re.Pattern[str] | None = None
    bpattern: re.Pattern[bytes] | None = None
    globs: tuple[str, ...] = ()
    skip_paths: re.Pattern[str] | None = None
    exclude: re.Pattern[str] | None = None
    ftypes: tuple[str, ...] = ()
    use_bytes: bool = False
    max_per_file: int = 5
    post: str | None = None
    world_writable: bool = False
    setuid: bool = False
    exts: tuple[str, ...] = ()
    bad_ftypes: tuple[str, ...] = ()
    extras: dict[str, Any] = field(default_factory=dict)


def _rx(src: str | None, rid: str) -> re.Pattern[str] | None:
    if not src:
        return None
    try:
        return re.compile(src)
    except re.error as exc:
        raise RuleError(f"{rid}: bad regex {src!r}: {exc}") from exc


def parse_pack(text: str, source: str = "<pack>") -> list[Rule]:
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict) or "rules" not in doc:
        raise RuleError(f"{source}: expected a mapping with a 'rules' list")
    pack = str(doc.get("pack", source))
    rules: list[Rule] = []
    for raw in doc["rules"]:
        rid = raw.get("id")
        for key in ("id", "title", "kind", "confidence"):
            if key not in raw:
                raise RuleError(f"{source}: rule missing '{key}': {raw}")
        if raw["kind"] not in KINDS:
            raise RuleError(f"{rid}: unknown kind {raw['kind']!r}")
        if raw["confidence"] not in CONFIDENCE:
            raise RuleError(f"{rid}: confidence must be one of {sorted(CONFIDENCE)}")
        pat = _rx(raw.get("pattern"), rid)
        if raw["kind"] in ("content", "path") and pat is None:
            raise RuleError(f"{rid}: '{raw['kind']}' rules need a pattern")
        use_bytes = bool(raw.get("bytes", False))
        ftypes = tuple(raw.get("ftypes", ()))
        if raw["kind"] == "content" and not ftypes:
            ftypes = DEFAULT_BYTES_FTYPES if use_bytes else DEFAULT_TEXT_FTYPES
        rules.append(
            Rule(
                id=rid,
                pack=pack,
                title=raw["title"],
                kind=raw["kind"],
                confidence=raw["confidence"],
                severity=raw.get("severity", "info"),
                cwe=raw.get("cwe"),
                owasp_iot=raw.get("owasp_iot"),
                pattern=pat,
                bpattern=re.compile(pat.pattern.encode(), re.M) if pat and use_bytes else None,
                globs=tuple(raw.get("globs", ())),
                skip_paths=_rx(raw.get("skip_paths"), rid),
                exclude=_rx(raw.get("exclude"), rid),
                ftypes=ftypes,
                use_bytes=use_bytes,
                max_per_file=int(raw.get("max_per_file", 5)),
                post=raw.get("post"),
                world_writable=bool(raw.get("world_writable", False)),
                setuid=bool(raw.get("setuid", False)),
                exts=tuple(e.lower() for e in raw.get("exts", ())),
                bad_ftypes=tuple(raw.get("bad_ftypes", ())),
            )
        )
    return rules


def load_builtin_rules() -> list[Rule]:
    rules: list[Rule] = []
    for entry in sorted(resources.files("textolit.rules").iterdir(), key=lambda e: e.name):
        if entry.name.endswith((".yaml", ".yml")):
            rules += parse_pack(entry.read_text(encoding="utf-8"), entry.name)
    return rules


def load_dir(path: Path) -> list[Rule]:
    rules: list[Rule] = []
    for f in sorted(path.glob("*.y*ml")):
        rules += parse_pack(f.read_text(encoding="utf-8"), f.name)
    return rules


def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _globs_match(path: str, globs: tuple[str, ...]) -> bool:
    return not globs or any(fnmatch.fnmatchcase(path, g) for g in globs)


def applies_to_path(rule: Rule, path: str) -> bool:
    if rule.skip_paths and rule.skip_paths.search(path):
        return False
    return _globs_match(path, rule.globs)


@dataclass(frozen=True)
class Hit:
    rule: Rule
    path: str  # file path within the filesystem root
    line: int | None
    snippet: str


def match_file(rule: Rule, row: Any, read: Any) -> list[Hit]:
    """Apply one rule to one ``files`` row. ``read(limit, as_bytes)`` loads content lazily."""
    path = row["path"]
    if not applies_to_path(rule, path):
        return []
    if rule.kind == "path":
        if rule.ftypes and row["ftype"] not in rule.ftypes:
            return []
        assert rule.pattern is not None
        return [Hit(rule, path, None, path)] if rule.pattern.search(path) else []
    if rule.kind == "perm":
        if row["is_symlink"] or row["ftype"] in ("symlink", "special"):
            return []
        mode = row["mode"]
        if (rule.world_writable and mode & 0o002) or (rule.setuid and mode & 0o4000):
            return [Hit(rule, path, None, oct(mode))]
        return []
    if rule.kind == "magic":
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        if ext in rule.exts and row["ftype"] in rule.bad_ftypes:
            return [Hit(rule, path, None, f".{ext} but content is {row['ftype']}")]
        return []
    # content
    if row["ftype"] not in rule.ftypes or row["is_symlink"]:
        return []
    hits: list[Hit] = []
    if rule.use_bytes:
        data = read(MAX_BYTES, True)
        if data is None or rule.bpattern is None:
            return []
        for m in rule.bpattern.finditer(data):
            line = (
                data.count(b"\n", 0, m.start()) + 1 if row["ftype"] in ("text", "script") else None
            )
            snippet = m.group(0).decode("utf-8", "replace")[:160]
            hits.append(Hit(rule, path, line, snippet))
            if len(hits) >= rule.max_per_file:
                break
        return hits
    text = read(MAX_TEXT, False)
    if text is None or rule.pattern is None:
        return []
    for n, line in enumerate(text.splitlines(), 1):
        if rule.exclude and rule.exclude.search(line):
            continue
        tm = rule.pattern.search(line)
        if not tm:
            continue
        if rule.post == "public_ip" and not is_public_ip(tm.group(0)):
            continue
        hits.append(Hit(rule, path, n, line.strip()[:200]))
        if len(hits) >= rule.max_per_file:
            break
    return hits


def sweep(
    case: Case, rules: Iterable[Rule], progress: ProgressFn = no_progress
) -> tuple[dict[str, int], dict[str, int], list[str]]:
    """Run ``rules`` over the files table. Returns (new hits per rule, capped counts, notes)."""
    rules = list(rules)
    roots = dict(fs_roots(case))
    rows = case.conn.execute("SELECT * FROM files ORDER BY id").fetchall()
    new: dict[str, int] = {}
    total: dict[str, int] = {}
    notes: list[str] = []
    for r in rules:
        ensure_heuristic(case, r.id, r.pack, r.title, r.severity)
    for i, row in enumerate(rows):
        base = roots.get(row["artifact_id"])
        if base is None:
            continue
        abs_path = base / row["path"].lstrip("/")
        cache: dict[bool, Any] = {}

        def read(limit: int, as_bytes: bool, p: Path = abs_path, c: dict[bool, Any] = cache) -> Any:
            if as_bytes not in c:
                try:
                    with p.open("rb") as fh:
                        raw = fh.read(limit)
                except OSError:
                    raw = None
                c[as_bytes] = raw if (as_bytes or raw is None) else raw.decode("utf-8", "replace")
            return c[as_bytes]

        for rule in rules:
            for hit in match_file(rule, row, read):
                total[rule.id] = total.get(rule.id, 0) + 1
                if total[rule.id] > RULE_CAP:
                    continue  # keep counting so the cap is reported, but stop recording
                fid = add_finding(
                    case,
                    heuristic_id=rule.id,
                    title=rule.title,
                    detail=f"Rule pack '{rule.pack}'. {hit.snippet}" if hit.snippet else "",
                    evidence_path=case.rel(abs_path),
                    line=hit.line,
                    snippet=hit.snippet,
                    confidence=rule.confidence,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    owasp_iot=rule.owasp_iot,
                )
                if fid is not None:
                    new[rule.id] = new.get(rule.id, 0) + 1
        if i % 100 == 0:
            progress(i / max(len(rows), 1), f"sweeping {row['path']}")
    for rid, n in total.items():
        if n > RULE_CAP:
            notes.append(f"rule {rid} hit its cap of {RULE_CAP}; more matches exist (narrow it)")
    return new, {k: v for k, v in total.items() if v > RULE_CAP}, notes


class MissedFindings:
    name = "missedfindings"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        errors: list[str] = []
        try:
            rules = load_builtin_rules()
            if options.get("rules_dir"):
                rules += load_dir(Path(options["rules_dir"]))
        except (RuleError, yaml.YAMLError, OSError) as exc:
            return ModuleResult(self.name, False, "rule pack failed to load", errors=[str(exc)])
        if case.conn.execute("SELECT 1 FROM files LIMIT 1").fetchone() is None:
            return ModuleResult(
                self.name, False, "no files indexed", errors=["run unpack and fswalk first"]
            )
        new, capped, notes = sweep(case, rules, progress)
        pending = case.conn.execute("SELECT count(*) FROM findings WHERE status='pending'")
        n_pending = pending.fetchone()[0]
        return ModuleResult(
            self.name,
            not errors,
            f"{len(rules)} rules; {sum(new.values())} new leads; {n_pending} leads pending review",
            data={"new": new, "capped": capped, "rules": len(rules), "pending": n_pending},
            warnings=notes,
            errors=errors,
        )
