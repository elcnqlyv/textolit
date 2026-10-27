"""fswalk: exhaustive index of every extracted file, with interesting-path flags.

Symlinks are recorded and never followed. Permission and symlink anomalies are counted
here and judged by the missedfindings rules from the ``files`` table.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import fs_roots
from textolit.modules.base import ModuleResult, ProgressFn, no_progress
from textolit.modules.entropy import shannon

MAX_HASH_BYTES = 64 << 20
ENTROPY_SAMPLE = 64 << 10

# Directories where CCTV / access-control firmware keeps config, web UI and persistent state.
INTERESTING_DIRS = (
    "/etc",
    "/www",
    "/web",
    "/htdocs",
    "/cgi-bin",
    "/mnt",
    "/tmp",
    "/nvram",
    "/mnt/mtd",
    "/usr/www",
    "/var/www",
    "/config",
    "/conf",
    "/app",
    "/home",
    "/root",
    "/opt",
    "/usr/local/etc",
    "/mtd",
    "/param",
    "/oem",
    "/customer",
    "/appfs",
    "/system/etc",
)
INTERESTING_NAMES = re.compile(
    r"(^|/)(passwd|shadow|group|htpasswd|\.htpasswd|inittab|rcS|rc\.local|authorized_keys|"
    r"id_rsa|id_dsa|shadow-|hosts|resolv\.conf|inetd\.conf|xinetd\.conf|profile|"
    r"[^/]*\.(pem|key|crt|cer|p12|pfx|cfg|conf|ini|db|sqlite3?|sh|cgi|lua|php|asp))$"
)


def sniff(head: bytes, size: int) -> str:
    """Coarse file type from magic bytes; deliberately small and dependency-free."""
    if size == 0:
        return "empty"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(
        (
            b"\x1f\x8b",
            b"\xfd7zXZ",
            b"BZh",
            b"PK\x03\x04",
            b"hsqs",
            b"sqsh",
            b"\x28\xb5\x2f\xfd",
            b"7z\xbc\xaf",
        )
    ):
        return "archive"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"\x00\x00\x01\x00")):
        return "image"
    sample = head[:4096]
    if b"\x00" not in sample:
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
        if printable / max(len(sample), 1) > 0.95:
            return "text"
    return "data"


def is_interesting(rel: str) -> bool:
    return (
        rel == "/"
        or any(rel == d or rel.startswith(d + "/") for d in INTERESTING_DIRS)
        or bool(INTERESTING_NAMES.search(rel))
    )


def _walk(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames) + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]:
            out.append(Path(dirpath) / name)
    return out


class FsWalk:
    name = "fswalk"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        roots = fs_roots(case)
        if not roots:
            return ModuleResult(self.name, False, "nothing to walk", errors=["run unpack first"])

        counts = {
            "files": 0,
            "symlinks": 0,
            "interesting": 0,
            "world_writable": 0,
            "setuid": 0,
            "dangling_symlinks": 0,
            "absolute_symlinks": 0,
            "unreadable": 0,
        }
        samples: dict[str, list[str]] = {k: [] for k in counts}

        def note(kind: str, rel: str) -> None:
            counts[kind] += 1
            if len(samples[kind]) < 25:
                samples[kind].append(rel)

        for art_id, root in roots:
            with case.conn:
                case.conn.execute("DELETE FROM files WHERE artifact_id=?", (art_id,))
            paths = _walk(root)
            rows: list[tuple[Any, ...]] = []
            for i, p in enumerate(paths):
                rel = "/" + str(p.relative_to(root))
                st = p.lstat()
                interesting = int(is_interesting(rel))
                link_target: str | None = None
                sha = ent = None
                ftype = "data"
                if stat.S_ISLNK(st.st_mode):
                    link_target = os.readlink(p)
                    ftype = "symlink"
                    note("symlinks", rel)
                    if os.path.isabs(link_target):
                        note("absolute_symlinks", f"{rel} -> {link_target}")
                    else:
                        resolved = Path(os.path.normpath(p.parent / link_target))
                        if not resolved.exists() and not resolved.is_symlink():
                            note("dangling_symlinks", f"{rel} -> {link_target}")
                elif stat.S_ISREG(st.st_mode):
                    try:
                        with p.open("rb") as fh:
                            head = fh.read(ENTROPY_SAMPLE)
                            ftype = sniff(head, st.st_size)
                            if st.st_size >= 256:
                                ent = round(shannon(head), 4)
                            if st.st_size <= MAX_HASH_BYTES:
                                h = hashlib.sha256(head)
                                while chunk := fh.read(1 << 20):
                                    h.update(chunk)
                                sha = h.hexdigest()
                    except OSError:
                        note("unreadable", rel)
                        ftype = "unreadable"
                    if st.st_mode & stat.S_IWOTH:
                        note("world_writable", f"{rel} {oct(st.st_mode & 0o7777)}")
                    if st.st_mode & stat.S_ISUID:
                        note("setuid", rel)
                else:
                    ftype = "special"
                counts["files"] += 1
                if interesting:
                    counts["interesting"] += 1
                rows.append(
                    (
                        art_id,
                        rel,
                        st.st_size,
                        st.st_mode & 0o7777,
                        st.st_uid,
                        st.st_gid,
                        sha,
                        ftype,
                        int(link_target is not None),
                        link_target,
                        ent,
                        interesting,
                    )
                )
                if i % 200 == 0:
                    progress(i / max(len(paths), 1), f"indexing {rel}")
            with case.conn:
                case.conn.executemany(
                    "INSERT INTO files(artifact_id,path,size,mode,uid,gid,sha256,ftype,"
                    "is_symlink,link_target,entropy,interesting) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )
        warnings = [
            f"{counts[k]} {k.replace('_', ' ')}: "
            + "; ".join(samples[k][:3])
            + (" ..." if counts[k] > 3 else "")
            for k in ("world_writable", "setuid", "dangling_symlinks", "unreadable")
            if counts[k]
        ]
        return ModuleResult(
            self.name,
            True,
            f"{counts['files']} entries in {len(roots)} root(s), "
            f"{counts['interesting']} interesting",
            data={"counts": counts, "samples": samples},
            warnings=warnings,
        )
