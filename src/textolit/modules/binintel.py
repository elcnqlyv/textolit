"""binintel: batch ELF inventory: arch, stripped?, needed libs, embedded version strings.

CVE hints come from version fingerprints only. They are leads: a vendor may have
backported a fix, and a string may sit in dead code. Findings are recorded at low
confidence for that reason.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import add_finding, ensure_heuristic, fs_roots
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

MACHINES = {
    3: "x86",
    8: "mips",
    10: "mips",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    62: "x86_64",
    94: "xtensa",
    183: "aarch64",
    243: "riscv",
    164: "hexagon",
}
SHT_SYMTAB, SHT_DYNAMIC = 2, 6
DT_NEEDED = 1
MAX_SCAN_BYTES = 16 << 20


@dataclass
class ElfInfo:
    bits: int
    endian: str
    arch: str
    stripped: bool
    libs: list[str] = field(default_factory=list)


def parse_elf(data: bytes) -> ElfInfo | None:
    """Parse the pieces we need from an ELF image held in memory; None if malformed."""
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    bits = 32 if data[4] == 1 else 64
    e = "<" if data[5] == 1 else ">"
    try:
        machine = struct.unpack_from(e + "H", data, 18)[0]
        if bits == 32:
            shoff = struct.unpack_from(e + "I", data, 32)[0]
            shentsize, shnum = struct.unpack_from(e + "HH", data, 46)
        else:
            shoff = struct.unpack_from(e + "Q", data, 40)[0]
            shentsize, shnum = struct.unpack_from(e + "HH", data, 58)
        info = ElfInfo(
            bits,
            "little" if e == "<" else "big",
            MACHINES.get(machine, f"e_machine={machine}"),
            True,
        )
        if not shoff or not shnum or shoff + shnum * shentsize > len(data):
            return info  # no section headers (common when stripped hard): leave stripped=True

        def section(i: int) -> tuple[int, int, int, int, int]:
            o = shoff + i * shentsize
            if bits == 32:
                _n, t, _f, _a, off, size, link, _i, _al, entsize = struct.unpack_from(
                    e + "10I", data, o
                )
            else:
                _n, t, _f, _a, off, size, link, _i, _al, entsize = struct.unpack_from(
                    e + "IIQQQQIIQQ", data, o
                )
            return t, off, size, link, entsize

        for i in range(shnum):
            t, off, size, link, entsize = section(i)
            if t == SHT_SYMTAB:
                info.stripped = False
            elif t == SHT_DYNAMIC and entsize:
                _t2, stroff, strsize, _l, _e = section(link)
                strtab = data[stroff : stroff + strsize]
                for k in range(size // entsize):
                    fmt = e + ("iI" if bits == 32 else "qQ")
                    tag, val = struct.unpack_from(fmt, data, off + k * entsize)
                    if tag == 0:
                        break
                    if tag == DT_NEEDED and val < len(strtab):
                        end = strtab.index(b"\0", val)
                        info.libs.append(strtab[val:end].decode("ascii", "replace"))
        return info
    except (struct.error, ValueError):
        return None


# (name, regex over bytes). Group 1 is the version.
VERSION_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("busybox", re.compile(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)")),
    ("dropbear", re.compile(rb"[Dd]ropbear(?: sshd)?[ _]v?(20\d\d\.\d+)")),
    ("lighttpd", re.compile(rb"lighttpd/(\d+\.\d+\.\d+)")),
    ("boa", re.compile(rb"Boa/(\d+\.\d+\.\d+\w*)")),
    ("mini_httpd", re.compile(rb"mini_httpd/(\d+\.\d+)")),
    ("thttpd", re.compile(rb"thttpd/(\d+\.\d+\w*)")),
    ("uhttpd", re.compile(rb"uhttpd[ /](\d+\.\d+(?:\.\d+)?)")),
    ("goahead", re.compile(rb"GoAhead[-/ ](?:Webs/|http/)?(\d+\.\d+\.\d+)")),
    ("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)")),
    ("uclibc", re.compile(rb"uClibc(?:-ng)?[- ](\d+\.\d+\.\d+)")),
    ("glibc", re.compile(rb"GNU C Library [^\n]{0,40}version (\d+\.\d+)")),
    ("linux", re.compile(rb"Linux version (\d+\.\d+\.\d+)")),
    ("curl", re.compile(rb"libcurl/(\d+\.\d+\.\d+)")),
)


def find_versions(data: bytes) -> dict[str, str]:
    found: dict[str, str] = {}
    for name, pat in VERSION_PATTERNS:
        m = pat.search(data)
        if m:
            found[name] = m.group(1).decode("ascii", "replace")
    return found


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


# Version-fingerprint hints. Each entry: (component, predicate, hint text, cve ids).
def _openssl_heartbleed(v: str) -> bool:
    return bool(re.fullmatch(r"1\.0\.1[a-f]?", v))


HINTS: tuple[tuple[str, Any, str, tuple[str, ...]], ...] = (
    (
        "openssl",
        _openssl_heartbleed,
        "OpenSSL 1.0.1 through 1.0.1f (Heartbleed range)",
        ("CVE-2014-0160",),
    ),
    (
        "dropbear",
        lambda v: _vkey(v) < (2016, 74),
        "Dropbear older than 2016.74",
        ("CVE-2016-3116",),
    ),
    ("goahead", lambda v: _vkey(v) < (3, 6, 5), "GoAhead older than 3.6.5", ("CVE-2017-17562",)),
    ("boa", lambda v: True, "Boa web server is unmaintained upstream (last release 2005)", ()),
)


def cve_hints(versions: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for comp, pred, text, cves in HINTS:
        v = versions.get(comp)
        if v and pred(v):
            out.append({"component": comp, "version": v, "hint": text, "cves": list(cves)})
    return out


class BinIntel:
    name = "binintel"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        roots = {aid: root for aid, root in fs_roots(case)}
        elfs = case.conn.execute(
            "SELECT id, artifact_id, path FROM files WHERE ftype='elf' ORDER BY id"
        ).fetchall()
        if not roots or not elfs:
            return ModuleResult(
                self.name, False, "no ELF files indexed", errors=["run unpack and fswalk first"]
            )
        ensure_heuristic(
            case, "binintel.version-hint", "binintel", "Version fingerprint hint", "info"
        )
        with case.conn:
            case.conn.execute("DELETE FROM binaries")

        archs: dict[str, int] = {}
        stripped = 0
        versions_seen: dict[str, set[str]] = {}
        hint_count = 0
        warnings: list[str] = []
        for i, row in enumerate(elfs):
            path: Path = roots[row["artifact_id"]] / row["path"].lstrip("/")
            try:
                data = path.read_bytes()[:MAX_SCAN_BYTES]
            except OSError as exc:
                warnings.append(f"unreadable ELF {row['path']}: {exc}")
                continue
            info = parse_elf(data)
            if info is None:
                warnings.append(f"malformed ELF header: {row['path']}")
                continue
            versions = find_versions(data)
            hints = cve_hints(versions)
            archs[info.arch] = archs.get(info.arch, 0) + 1
            stripped += int(info.stripped)
            for k, v in versions.items():
                versions_seen.setdefault(k, set()).add(v)
            with case.conn:
                case.conn.execute(
                    "INSERT INTO binaries(file_id,arch,bits,endian,stripped,libs_json,"
                    "versions_json) VALUES (?,?,?,?,?,?,?)",
                    (
                        row["id"],
                        info.arch,
                        info.bits,
                        info.endian,
                        int(info.stripped),
                        json.dumps(info.libs),
                        json.dumps({**versions, "_hints": hints}),
                    ),
                )
            rel = str((roots[row["artifact_id"]] / row["path"].lstrip("/")).relative_to(case.root))
            for h in hints:
                hint_count += 1
                add_finding(
                    case,
                    heuristic_id="binintel.version-hint",
                    title=f"{h['component']} {h['version']}: {h['hint']}",
                    detail=(
                        "Version-string fingerprint only; check for vendor backports. "
                        + (", ".join(h["cves"]) if h["cves"] else "no CVE id")
                    ),
                    evidence_path=rel,
                    confidence="low",
                    severity="medium" if h["cves"] else "low",
                    cwe="CWE-1104",
                    owasp_iot="I5",
                )
            if i % 25 == 0:
                progress(i / len(elfs), f"inspecting {row['path']}")

        summary = (
            f"{len(elfs)} ELF files; arch {archs}; {stripped} stripped; "
            f"{len(versions_seen)} components fingerprinted; {hint_count} CVE hints"
        )
        return ModuleResult(
            self.name,
            True,
            summary,
            data={
                "arch": archs,
                "stripped": stripped,
                "versions": {k: sorted(v) for k, v in versions_seen.items()},
                "hints": hint_count,
            },
            warnings=warnings[:20],
        )
