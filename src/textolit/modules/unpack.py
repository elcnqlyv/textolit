"""unpack: binwalk signature scan + recursive extraction into a sandboxed case directory.

binwalk (-e -M) does the recursive descent. We then index what it produced: detected
filesystem roots (squashfs/ubifs/jffs2/cramfs/cpio), content-hash dedup, and symlinks
that point outside the extraction tree (never followed). If binwalk extracts nothing
but a squashfs signature exists, we carve and fall back to unsquashfs/sasquatch.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import add_artifact, sha256_file
from textolit.core.runner import run
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

FS_ROOT_NAMES = {
    "squashfs-root": "squashfs",
    "jffs2-root": "jffs2",
    "cramfs-root": "cramfs",
    "ubifs-root": "ubifs",
    "cpio-root": "cpio",
}
SIG_LINE = re.compile(r"^(\d+)\s+0x([0-9A-Fa-f]+)\s+(.*)$")
FS_WORDS = (
    ("squashfs", "squashfs"),
    ("ubi", "ubifs"),
    ("jffs2", "jffs2"),
    ("cramfs", "cramfs"),
)
DEFAULT_TIMEOUT = 900.0
# Extractors apply the caller's umask, which silently strips world-writable bits and would
# hide a whole class of findings. Run them under umask 0 so recorded modes are the image's.
UMASK0 = ["sh", "-c", 'umask 0; exec "$@"', "textolit-umask0"]


def parse_signatures(text: str) -> list[dict[str, Any]]:
    """Parse ``binwalk`` table output into offset/description records."""
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = SIG_LINE.match(line.strip())
        if m:
            desc = m.group(3)
            lower = desc.lower()
            fs = next((name for word, name in FS_WORDS if word in lower), None)
            out.append({"offset": int(m.group(1)), "description": desc, "filesystem": fs})
    return out


def _escaping_symlinks(root: Path) -> list[str]:
    """Symlinks whose target is absolute or resolves outside ``root``; reported, not followed."""
    bad: list[str] = []
    real_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            target = os.readlink(p)
            resolved = Path(os.path.normpath(Path(dirpath) / target))
            if os.path.isabs(target) or not resolved.is_relative_to(real_root):
                bad.append(f"{p.relative_to(root)} -> {target}")
    return bad


def _dedup(root: Path) -> tuple[int, int, int]:
    """Return (files, unique, duplicate_bytes) by content hash; symlinks are skipped."""
    seen: dict[str, int] = {}
    files = dup_bytes = 0
    for dirpath, _dirs, names in os.walk(root, followlinks=False):
        for name in names:
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            files += 1
            digest = sha256_file(p)
            if digest in seen:
                dup_bytes += p.stat().st_size
            else:
                seen[digest] = p.stat().st_size
    return files, len(seen), dup_bytes


def _carve_fallback(case: Case, image: Path, sigs: list[dict[str, Any]], dest: Path) -> list[str]:
    notes: list[str] = []
    tool = shutil.which("sasquatch") or shutil.which("unsquashfs")
    if tool is None:
        return ["no unsquashfs/sasquatch available for fallback extraction"]
    data = image.read_bytes()
    for sig in (s for s in sigs if s["filesystem"] == "squashfs"):
        carved = case.artifacts_dir / "carved" / f"{sig['offset']:x}.squashfs"
        carved.write_bytes(data[sig["offset"] :])
        add_artifact(case, "carved", carved)
        target = dest / f"squashfs-root-{sig['offset']:x}"
        res = run(case, [*UMASK0, tool, "-f", "-d", str(target), str(carved)], module="unpack")
        notes.append(f"fallback {Path(tool).name} at 0x{sig['offset']:x}: exit {res.exit_code}")
    return notes


class Unpack:
    name = "unpack"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        timeout = float(options.get("timeout", DEFAULT_TIMEOUT))
        row = case.conn.execute("SELECT id, path FROM images ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return ModuleResult(self.name, False, "no image", errors=["run ingest first"])
        image_id, image = int(row["id"]), case.root / row["path"]
        dest = case.extract_dir / f"image{image_id}"
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)

        progress(0.05, "binwalk signature scan")
        scan = run(case, ["binwalk", str(image)], cwd=case.root, timeout=timeout, module=self.name)
        if scan.error:
            return ModuleResult(self.name, False, "binwalk unavailable", errors=[scan.error])
        sigs = parse_signatures(scan.text)

        progress(0.2, "binwalk recursive extraction")
        ext = run(
            case,
            [*UMASK0, "binwalk", "-e", "-M", "-C", str(dest), str(image)],
            cwd=case.root,
            timeout=timeout,
            module=self.name,
        )
        warnings = [ln.strip() for ln in ext.text.splitlines() if ln.startswith("WARNING")]
        errors = [ext.error] if ext.error else []

        if not any(dest.rglob("*")) and any(s["filesystem"] == "squashfs" for s in sigs):
            progress(0.6, "fallback squashfs extraction")
            warnings += _carve_fallback(case, image, sigs, dest)

        progress(0.8, "indexing extraction tree")
        root_art = add_artifact(case, "extract_root", dest, image_id=image_id)
        fs_roots: list[dict[str, str]] = []
        for dirpath, dirnames, _files in os.walk(dest, followlinks=False):
            for d in dirnames:
                fs = FS_ROOT_NAMES.get(d) or ("squashfs" if d.startswith("squashfs-root") else None)
                if fs:
                    p = Path(dirpath) / d
                    add_artifact(case, f"fs_root:{fs}", p, image_id=image_id, parent_id=root_art)
                    fs_roots.append({"type": fs, "path": case.rel(p)})

        escaping = _escaping_symlinks(dest)
        warnings += [f"symlink leaves extraction tree: {s}" for s in escaping]
        files, unique, dup_bytes = _dedup(dest)
        progress(1.0, "unpack done")
        return ModuleResult(
            self.name,
            ok=not errors and bool(fs_roots or files),
            summary=(
                f"{len(sigs)} signatures, {len(fs_roots)} filesystem roots, "
                f"{files} files ({unique} unique, {dup_bytes} duplicate bytes)"
            ),
            data={
                "signatures": sigs,
                "fs_roots": fs_roots,
                "extract_dir": case.rel(dest),
                "files": files,
                "unique": unique,
                "escaping_symlinks": escaping,
            },
            warnings=warnings,
            errors=errors,
        )
