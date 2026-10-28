"""unpack: binwalk signature scan + recursive extraction into a sandboxed case directory.

binwalk (-e -M) does the recursive descent. We then index what it produced: detected
filesystem roots (squashfs/ubifs/jffs2/cramfs/cpio), content-hash dedup, and symlinks
that point outside the extraction tree (never followed). If binwalk extracts nothing
but a squashfs signature exists, we carve and fall back to unsquashfs/sasquatch.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import Any

from textolit import carve
from textolit.core.case import Case
from textolit.core.ledger import add_artifact, sha256_file
from textolit.core.runner import run
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

FS_ROOT = re.compile(r"^(squashfs|jffs2|cramfs|ubifs|cpio)-root")
MAX_FALLBACK_IMAGE = 512 << 20
MAX_LAYER_DEPTH = 3
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


def _extract_hit(case: Case, hit: carve.FsHit, blob: Path, dest: Path, tag: str) -> str | None:
    """Extract one carved filesystem. Returns a note when it could not be extracted."""
    if hit.fs == "squashfs":
        tool = shutil.which("sasquatch") or shutil.which("unsquashfs")
        if tool is None:
            return f"squashfs at {tag}: no unsquashfs/sasquatch installed"
        cmd = [*UMASK0, tool, "-f", "-d", str(dest / f"squashfs-root-{tag}"), str(blob)]
    elif hit.fs == "cpio":
        target = dest / f"cpio-root-{tag}"
        target.mkdir(parents=True, exist_ok=True)
        script = 'umask 0; cd "$1" && exec cpio -idm --quiet --no-absolute-filenames < "$2"'
        cmd = ["sh", "-c", script, "textolit-cpio", str(target), str(blob)]
    elif hit.fs == "cramfs":
        target = dest / f"cramfs-root-{tag}"
        if shutil.which("cramfsck"):
            cmd = [*UMASK0, "cramfsck", "-x", str(target), str(blob)]
        elif shutil.which("7z"):
            cmd = [*UMASK0, "7z", "x", "-y", f"-o{target}", str(blob)]
        else:
            return f"cramfs at {tag}: no cramfsck or 7z installed"
    elif hit.fs == "jffs2":
        if not shutil.which("jefferson"):
            return f"jffs2 at {tag}: install jefferson (pip install jefferson) to extract it"
        cmd = [*UMASK0, "jefferson", "-f", "-d", str(dest / f"jffs2-root-{tag}"), str(blob)]
    else:
        if not shutil.which("ubireader_extract_files"):
            return f"ubi at {tag}: install ubi_reader (pip install ubi_reader) to extract it"
        cmd = [
            *UMASK0,
            "ubireader_extract_files",
            "-k",
            "-o",
            str(dest / f"ubifs-root-{tag}"),
            str(blob),
        ]
    res = run(case, cmd, module="unpack")
    return None if res.exit_code == 0 else f"{hit.fs} at {tag}: extractor exit {res.exit_code}"


def _fallback_extract(
    case: Case, image: Path, dest: Path
) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    """Strip vendor headers, decompress, and carve filesystems that binwalk did not extract.

    Returns (notes, wrapper records, recognised-but-not-extracted notes).
    """
    if image.stat().st_size > MAX_FALLBACK_IMAGE:
        return ["image too large for the pure-Python fallback scan"], [], []
    notes: list[str] = []
    wrappers: list[dict[str, Any]] = []
    unextracted: list[str] = []
    seen: set[str] = set()
    layers: list[tuple[str, bytes, int]] = [("img", image.read_bytes(), 0)]
    while layers:
        label, data, depth = layers.pop(0)
        nxt: list[tuple[str, bytes]] = []
        wrap = carve.find_wrapper(data)
        if wrap:
            wrappers.append({"layer": label, **wrap.info, "kind": wrap.kind})
            notes.append(wrap.describe())
            nxt.append((f"{label}.{wrap.kind}", data[wrap.payload_offset :][: wrap.payload_len]))
        dec = carve.decompress_at(data)
        if dec:
            notes.append(f"layer {label}: {dec[0]} stream, {len(dec[1])} bytes")
            nxt.append((f"{label}.{dec[0]}", dec[1]))
        for hit in carve.find_filesystems(data):
            blob_data = data[hit.offset :]
            if hit.length is not None:
                blob_data = blob_data[: hit.length]
            digest = hashlib.sha256(blob_data).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            tag = f"{label.replace('.', '-')}-{hit.offset:x}"
            blob = case.artifacts_dir / "carved" / f"{tag}.{hit.fs}"
            blob.write_bytes(blob_data)
            add_artifact(case, "carved", blob)
            note = _extract_hit(case, hit, blob, dest, tag)
            if note:
                unextracted.append(note)
            else:
                notes.append(f"fallback extracted {hit.fs} at {label} 0x{hit.offset:x}")
        if depth + 1 < MAX_LAYER_DEPTH:
            layers += [(lab, blob_d, depth + 1) for lab, blob_d in nxt]
    return notes, wrappers, unextracted


def _index_roots(case: Case, dest: Path, image_id: int, root_art: int) -> list[dict[str, str]]:
    roots: list[dict[str, str]] = []
    for dirpath, dirnames, _files in os.walk(dest, followlinks=False):
        for d in dirnames:
            m = FS_ROOT.match(d)
            if m:
                p = Path(dirpath) / d
                add_artifact(
                    case, f"fs_root:{m.group(1)}", p, image_id=image_id, parent_id=root_art
                )
                roots.append({"type": m.group(1), "path": case.rel(p)})
    return roots


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

        root_art = add_artifact(case, "extract_root", dest, image_id=image_id)
        fs_roots = _index_roots(case, dest, image_id, root_art)
        wrappers: list[dict[str, Any]] = []
        unextracted: list[str] = []
        if not fs_roots:
            progress(0.6, "fallback: vendor headers, streams and filesystem magic")
            notes, wrappers, unextracted = _fallback_extract(case, image, dest)
            warnings += notes + unextracted
            progress(0.8, "indexing extraction tree")
            fs_roots = _index_roots(case, dest, image_id, root_art)
        if not fs_roots:
            warnings.append(
                "no filesystem recognised: the image may be encrypted, obfuscated or in an "
                "unsupported format. Check the entropy tab before reading anything into this."
            )

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
                "wrappers": wrappers,
                "unextracted": unextracted,
            },
            warnings=warnings,
            errors=errors,
        )
