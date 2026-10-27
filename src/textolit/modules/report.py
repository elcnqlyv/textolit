"""report: Markdown report from the evidence ledger (PDF/DOCX/CVE JSON arrive in sprint 4)."""

from __future__ import annotations

import json
from typing import Any

from textolit.core.case import Case, utcnow
from textolit.core.ledger import add_artifact
from textolit.modules.base import ModuleResult, ProgressFn, no_progress
from textolit.redact import mask as _mask
from textolit.redact import mask_snippet as _mask_snippet
from textolit.taxonomy import OWASP_IOT


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_none recorded_\n"
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(lines) + "\n"


CONF_ORDER = {"high": 0, "med": 1, "low": 2}


def _scalar(conn: Any, sql: str) -> int:
    return int(conn.execute(sql).fetchone()[0])


def _findings_section(conn: Any) -> list[str]:
    out = ["## Findings by OWASP IoT Top 10", ""]
    total = _scalar(conn, "SELECT count(*) FROM findings")
    if not total:
        return out + [
            "_No findings recorded. An empty list is not a clean bill of health: run `fswalk`,"
            " `netmap` and `missedfindings` first._",
            "",
        ]
    rows = conn.execute(
        "SELECT f.*, (SELECT line FROM evidence_links WHERE finding_id=f.id LIMIT 1) AS line,"
        " (SELECT snippet FROM evidence_links WHERE finding_id=f.id LIMIT 1) AS snippet"
        " FROM findings f WHERE status IN ('pending','accepted')"
    ).fetchall()
    rows = sorted(rows, key=lambda r: (CONF_ORDER.get(r["confidence"], 3), r["id"]))
    groups: dict[str, list[Any]] = {}
    for r in rows:
        groups.setdefault(r["owasp_iot"] or "unmapped", []).append(r)
    for key in [*OWASP_IOT, "unmapped"]:
        if key not in groups:
            continue
        name = OWASP_IOT.get(key, "Unmapped")
        out += [f"### {key} {name}", ""]
        for r in groups[key]:
            where = r["evidence_path"] + (f":{r['line']}" if r["line"] else "")
            cwe = f" {r['cwe']}" if r["cwe"] else ""
            out.append(
                f"- **[{r['confidence']}]** {r['title']} (#{r['id']}, {r['status']}{cwe})  "
                f"\n  `{where}`"
            )
            if r["snippet"]:
                out.append(f"  \n  evidence text: `{_mask_snippet(r['snippet'])[:140]}`")
        out.append("")
    decided = conn.execute(
        "SELECT id, title, status, decision_note, evidence_path FROM findings"
        " WHERE status IN ('rejected','snoozed') ORDER BY id"
    ).fetchall()
    out += ["### Decisions recorded (rejected and snoozed leads)", ""]
    out.append(
        _table(
            ["id", "status", "title", "evidence", "note"],
            [
                [r["id"], r["status"], r["title"], r["evidence_path"], r["decision_note"] or ""]
                for r in decided
            ],
        )
    )
    return out


def _web_section(conn: Any) -> list[str]:
    out = ["## Web surface (static)", ""]
    rows = conn.execute("SELECT * FROM web_surface ORDER BY id").fetchall()
    if not rows:
        return out + ["_websurface has not run, or no web interface was found._", ""]

    def cat(name: str) -> list[Any]:
        return [r for r in rows if r["category"] == name]

    def where(r: Any) -> str:
        return f"{r['source_path']}:{r['source_line']}" if r["source_line"] else r["source_path"]

    out.append("No requests were made. Everything below comes from the extracted files.\n")
    out += ["### Servers", ""]
    out.append(
        _table(
            ["server", "version or note", "confidence", "source"],
            [[r["key"], r["value"], r["confidence"], where(r)] for r in cat("server")],
        )
    )
    out += ["### Authentication (guess)", ""]
    out.append(
        _table(
            ["mechanism", "detail", "confidence", "source"],
            [[r["key"], r["value"], r["confidence"], where(r)] for r in cat("auth")],
        )
    )
    out += ["### Upload and firmware handlers", ""]
    out.append(
        _table(
            ["url", "why", "confidence", "source"],
            [[r["key"], r["value"], r["confidence"], where(r)] for r in cat("upload")],
        )
    )
    eps = cat("endpoint")
    out += [f"### Endpoints ({len(eps)} found, first 80 shown)", ""]
    out.append(
        _table(
            ["url", "kind or method", "source"],
            [[r["key"], r["value"], where(r)] for r in eps[:80]],
        )
    )
    creds = [r for r in cat("credential")]
    out += ["### Credentials visible in front-end code (values masked)", ""]
    out.append(
        _table(
            ["kind", "value", "source"],
            [
                [r["key"], "***" if r["key"] != "prefilled-username" else r["value"], where(r)]
                for r in creds
            ],
        )
    )
    return out


def _crypto_section(conn: Any) -> list[str]:
    out = ["## Crypto material", ""]
    mats = conn.execute("SELECT * FROM crypto_materials ORDER BY id").fetchall()
    if not mats:
        return out + ["_crypto has not run, or nothing was found._", ""]
    hashes = [m for m in mats if m["kind"] == "hash"]
    out += ["### Password hashes", ""]
    out.append(
        _table(
            ["user", "algorithm", "hashcat -m", "cracked", "source"],
            [
                [
                    m["username"] or "-",
                    m["algo"],
                    m["hashcat_mode"] if m["hashcat_mode"] is not None else "none",
                    _mask(m["cracked"]) if m["cracked"] else "no",
                    f"{m['source_path']}:{m['source_line']}",
                ]
                for m in hashes
            ],
        )
    )
    certs = [m for m in mats if m["kind"] == "cert"]
    out += ["### Certificates", ""]
    rows = []
    for m in certs:
        d = json.loads(m["detail"])
        rows.append(
            [
                d.get("subject"),
                d.get("sig_algo"),
                d.get("key_bits"),
                d.get("not_after"),
                "yes" if d.get("expired") else "no",
                m["source_path"],
            ]
        )
    out.append(_table(["subject", "signature", "key bits", "not after", "expired", "source"], rows))
    keys = [m for m in mats if m["kind"] == "private_key"]
    out += ["### Private keys and key strings", ""]
    out.append(
        _table(
            ["kind", "type", "detail", "source"],
            [
                [
                    m["kind"],
                    m["algo"],
                    "encrypted" if json.loads(m["detail"]).get("encrypted") else "",
                    f"{m['source_path']}:{m['source_line']}",
                ]
                for m in keys
            ]
            + [
                [
                    "key_string",
                    m["algo"],
                    _mask(m["value"]),
                    f"{m['source_path']}:{m['source_line']}",
                ]
                for m in mats
                if m["kind"] == "key_string"
            ],
        )
    )
    tasks = conn.execute("SELECT * FROM crack_tasks ORDER BY id").fetchall()
    out += ["### Crack queue", ""]
    out.append(
        _table(
            ["id", "attack", "status", "found", "note"],
            [
                [t["id"], t["label"], t["status"], f"{t['recovered']}/{t['total']}", t["message"]]
                for t in tasks
            ],
        )
    )
    return out


def render_markdown(case: Case) -> str:
    c = case.conn
    name = c.execute("SELECT name FROM cases WHERE id=?", (case.case_id,)).fetchone()[0]
    pending = _scalar(c, "SELECT count(*) FROM findings WHERE status='pending'")
    out = [
        f"# Textolit report: {name}",
        "",
        "Textolit \u2014 firmware triage workbench for CCTV and access-control research.",
        "",
        f"Report time {utcnow()}. Authorized testing only; leads, not verdicts.",
        "",
        f"**{pending} leads pending review.** Findings below carry a confidence and an evidence"
        " path; confirm each before relying on it.",
        "",
        "## Images",
        "",
    ]
    imgs = c.execute("SELECT * FROM images ORDER BY id").fetchall()
    out.append(
        _table(
            ["id", "file", "size", "sha256", "type"],
            [
                [
                    i["id"],
                    i["path"],
                    i["size"],
                    i["sha256"],
                    json.loads(i["meta_json"]).get("file_type") or "-",
                ]
                for i in imgs
            ],
        )
    )

    out += ["## Entropy map", ""]
    regs = c.execute("SELECT * FROM regions ORDER BY image_id, offset").fetchall()
    out.append(
        _table(
            ["offset", "length", "entropy", "class"],
            [
                [f"0x{r['offset']:x}", r["length"], f"{r['entropy']:.2f}", r["classification"]]
                for r in regs
            ],
        )
    )
    if any(r["classification"] == "encrypted" for r in regs):
        out += [
            "> Regions marked `encrypted` are a statistical lead (uniform high-entropy data"
            " without a known compression magic). Verify before concluding.",
            "",
        ]

    out += ["## Filesystems", ""]
    fs = c.execute("SELECT kind, path FROM artifacts WHERE kind LIKE 'fs_root:%' ORDER BY id")
    out.append(_table(["type", "path"], [[r["kind"].split(":", 1)[1], r["path"]] for r in fs]))

    n_files = _scalar(c, "SELECT count(*) FROM files")
    out += ["## File index", ""]
    if n_files:
        anomalies = [
            [
                "world-writable files",
                _scalar(
                    c,
                    "SELECT count(*) FROM files WHERE is_symlink=0"
                    " AND ftype!='special' AND (mode & 2)!=0",
                ),
            ],
            [
                "setuid files",
                _scalar(c, "SELECT count(*) FROM files WHERE (mode & 2048)!=0 AND is_symlink=0"),
            ],
            ["symlinks", _scalar(c, "SELECT count(*) FROM files WHERE is_symlink=1")],
            ["interesting paths", _scalar(c, "SELECT count(*) FROM files WHERE interesting=1")],
        ]
        out.append(f"{n_files} entries indexed.\n")
        out.append(_table(["check", "count"], anomalies))
    else:
        out += ["_fswalk has not run._", ""]

    out += ["## Listen-by-default (netmap)", ""]
    eps = c.execute(
        "SELECT e.*, s.name AS svc FROM network_endpoints e LEFT JOIN services s"
        " ON s.id=e.service_id ORDER BY e.default_on DESC, e.nonstandard DESC, e.port"
    ).fetchall()
    out.append(
        _table(
            ["port", "service", "non-std", "default", "source", "evidence"],
            [
                [
                    f"{e['port']}/{e['proto']}",
                    e["svc"],
                    "yes" if e["nonstandard"] else "",
                    "on" if e["default_on"] else "off",
                    f"{e['source_path']}:{e['source_line']}",
                    e["evidence"][:100],
                ]
                for e in eps
            ],
        )
    )
    if eps:
        out += [
            "> Config-file ports are leads: a number in a config does not prove anything binds it."
            " Init-script, inetd and systemd rows are stronger.",
            "",
        ]

    out += ["## Binary inventory (binintel)", ""]
    bins = c.execute("SELECT * FROM binaries").fetchall()
    if bins:
        arch: dict[str, int] = {}
        comps: dict[str, set[str]] = {}
        for b in bins:
            arch[b["arch"]] = arch.get(b["arch"], 0) + 1
            for k, v in json.loads(b["versions_json"]).items():
                if not k.startswith("_"):
                    comps.setdefault(k, set()).add(v)
        stripped = sum(1 for b in bins if b["stripped"])
        out.append(f"{len(bins)} ELF files, {stripped} stripped.\n")
        out.append(_table(["arch", "count"], [[k, v] for k, v in sorted(arch.items())]))
        out.append(
            _table(
                ["component", "versions"],
                [[k, ", ".join(sorted(v))] for k, v in sorted(comps.items())],
            )
        )
    else:
        out += ["_binintel has not run._", ""]

    out += ["## Plaintext credentials in configs", ""]
    creds = c.execute("SELECT * FROM credentials ORDER BY id").fetchall()
    out.append(
        _table(
            ["user", "secret (masked)", "source"],
            [
                [r["username"] or "-", _mask(r["secret"]), f"{r['source_path']}:{r['source_line']}"]
                for r in creds
            ],
        )
    )

    out += _web_section(c)
    out += _crypto_section(c)
    out += _findings_section(c)

    out += ["## Command log (appendix)", ""]
    cmds = c.execute("SELECT * FROM commands ORDER BY id").fetchall()
    out.append(
        _table(
            ["id", "argv", "exit", "stdout sha256"],
            [
                [
                    r["id"],
                    " ".join(json.loads(r["argv_json"])),
                    r["exit_code"],
                    (r["stdout_sha256"] or "")[:16],
                ]
                for r in cmds
            ],
        )
    )
    return "\n".join(out)


class Report:
    name = "report"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        text = render_markdown(case)
        case.reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = utcnow().replace(":", "").replace("-", "")[:15]
        path = case.reports_dir / f"report-{stamp}.md"
        path.write_text(text, encoding="utf-8")
        add_artifact(case, "report", path)
        return ModuleResult(
            self.name, True, f"wrote {case.rel(path)}", data={"path": case.rel(path)}
        )
