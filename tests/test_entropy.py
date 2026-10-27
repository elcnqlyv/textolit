import os
from pathlib import Path

from textolit.core.case import Case
from textolit.modules.entropy import Entropy, scan_file, shannon

TEXT = (b"root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n" * 400)[:16384]


def test_shannon_bounds() -> None:
    assert shannon(b"") == 0.0
    assert shannon(b"\x00" * 1000) == 0.0
    assert shannon(bytes(range(256)) * 4) == 8.0


def test_classes(tmp_path: Path) -> None:
    rnd = os.urandom(32768)
    gz = b"\x1f\x8b\x08\x00" + os.urandom(32768)
    img = tmp_path / "mix.bin"
    img.write_bytes(b"\x00" * 8192 + TEXT + rnd + b"\xff" * 4096 + gz)
    regions = scan_file(img, 4096)
    by_off = {r.offset: r.classification for r in regions}
    assert by_off[0] == "empty"
    assert by_off[8192] == "plain"
    assert by_off[8192 + 16384] == "encrypted"
    assert by_off[8192 + 16384 + 32768] == "empty"
    assert by_off[8192 + 16384 + 32768 + 4096] == "compressed"


def test_module_persists_regions(tmp_path: Path) -> None:
    from textolit.modules.ingest import Ingest

    img = tmp_path / "fw.bin"
    img.write_bytes(TEXT + os.urandom(16384))
    case = Case.create(tmp_path / "c")
    Ingest().run(case, image=img)
    res = Entropy().run(case)
    assert res.ok
    classes = [
        r[0] for r in case.conn.execute("SELECT classification FROM regions ORDER BY offset")
    ]
    assert classes == ["plain", "encrypted"]
    assert res.warnings


def test_random_prefix_then_compressed_run_split(tmp_path: Path) -> None:
    img = tmp_path / "fw.bin"
    img.write_bytes(os.urandom(8192) + b"hsqs" + os.urandom(16380))
    regions = scan_file(img, 4096)
    assert [(r.offset, r.classification) for r in regions] == [
        (0, "encrypted"),
        (8192, "compressed"),
    ]
