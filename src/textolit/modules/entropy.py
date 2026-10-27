"""entropy: sliding-window Shannon entropy with a compressed/encrypted/plain classifier.

The compressed-vs-encrypted split is a heuristic: both look near-uniform. A window run
is called ``compressed`` when a known compression magic appears at its start, and
``encrypted`` only when no such magic is present and the byte histogram is uniform.
Treat ``encrypted`` as a lead, not a verdict.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import add_artifact
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

DEFAULT_WINDOW = 4096
HIGH_ENTROPY = 7.2  # bits/byte; below this a window is plain or low-entropy structured data
EMPTY_ENTROPY = 0.3

# Chi-square (255 dof) acceptance band for uniform bytes, roughly p in [0.001, 0.999],
# scaled for windows large enough to have ~16 expected hits per byte value.
CHI2_LOW, CHI2_HIGH = 190.0, 330.0

COMPRESSION_MAGICS: tuple[bytes, ...] = (
    b"\x1f\x8b\x08",  # gzip
    b"\xfd7zXZ\x00",  # xz
    b"BZh",  # bzip2
    b"\x28\xb5\x2f\xfd",  # zstd
    b"hsqs",  # squashfs LE
    b"sqsh",  # squashfs BE
    b"\x5d\x00\x00",  # lzma alone
    b"PK\x03\x04",  # zip
    b"\x85\x19\x02\xe0",  # jffs2 node
    b"\x45\x3d\xcd\x28",  # cramfs LE
    b"UBI#",  # ubi erase counter header
)


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def chi_square(data: bytes) -> float:
    if not data:
        return 0.0
    expected = len(data) / 256
    counts = Counter(data)
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


def classify_window(data: bytes) -> str:
    """Return empty / plain / highent for one window (highent is resolved later)."""
    h = shannon(data)
    if h < EMPTY_ENTROPY:
        return "empty"
    if h < HIGH_ENTROPY:
        return "plain"
    return "highent"


def _resolve_high(first_bytes: bytes, chi: float) -> str:
    if any(m in first_bytes for m in COMPRESSION_MAGICS):
        return "compressed"
    return "encrypted" if CHI2_LOW <= chi <= CHI2_HIGH else "compressed"


@dataclass(frozen=True)
class Region:
    offset: int
    length: int
    entropy: float
    classification: str


def scan_file(
    path: Path, window: int = DEFAULT_WINDOW, progress: ProgressFn = no_progress
) -> list[Region]:
    """Scan ``path`` and return merged regions."""
    size = path.stat().st_size
    windows: list[tuple[int, int, float, str, float, bytes]] = []
    with path.open("rb") as fh:
        offset = 0
        while block := fh.read(window):
            h = shannon(block)
            cls = classify_window(block)
            chi = chi_square(block) if cls == "highent" and len(block) >= window else -1.0
            windows.append((offset, len(block), h, cls, chi, block[:512]))
            offset += len(block)
            progress(offset / max(size, 1), f"entropy {offset >> 20} MiB")

    regions: list[Region] = []
    i = 0
    while i < len(windows):
        j = i
        group_cls = windows[i][3]
        while j + 1 < len(windows) and windows[j + 1][3] == group_cls:
            j += 1
        group = windows[i : j + 1]
        length = sum(w[1] for w in group)
        mean_h = sum(w[2] * w[1] for w in group) / length
        if group_cls == "highent":
            chis = [w[4] for w in group if w[4] >= 0]
            chi = sum(chis) / len(chis) if chis else -1.0
            # A magic anywhere in the first window of the run marks it compressed.
            group_cls = _resolve_high(group[0][5], chi)
        regions.append(Region(group[0][0], length, round(mean_h, 4), group_cls))
        i = j + 1
    return regions


class Entropy:
    name = "entropy"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        window = int(options.get("window", DEFAULT_WINDOW))
        row = case.conn.execute("SELECT id, path FROM images ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return ModuleResult(self.name, False, "no image", errors=["run ingest first"])
        image_id, image_path = int(row["id"]), case.root / row["path"]

        regions = scan_file(image_path, window, progress)
        with case.conn:
            case.conn.execute("DELETE FROM regions WHERE image_id=?", (image_id,))
            case.conn.executemany(
                "INSERT INTO regions(image_id,offset,length,entropy,classification)"
                " VALUES (?,?,?,?,?)",
                [(image_id, r.offset, r.length, r.entropy, r.classification) for r in regions],
            )
        chart = case.artifacts_dir / "entropy" / "regions.json"
        chart.parent.mkdir(parents=True, exist_ok=True)
        chart.write_text(json.dumps([r.__dict__ for r in regions], indent=1), encoding="utf-8")
        add_artifact(case, "entropy_map", chart, image_id=image_id)

        by_class: dict[str, int] = {}
        for r in regions:
            by_class[r.classification] = by_class.get(r.classification, 0) + r.length
        warnings = []
        if by_class.get("encrypted"):
            warnings.append(
                f"{by_class['encrypted']} bytes classified encrypted (heuristic; verify manually)"
            )
        return ModuleResult(
            self.name,
            True,
            f"{len(regions)} regions; bytes by class: {by_class}",
            data={"regions": len(regions), "bytes_by_class": by_class, "window": window},
            warnings=warnings,
        )
