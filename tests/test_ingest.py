import hashlib
import os
from pathlib import Path

from textolit.core.case import Case
from textolit.modules.ingest import Ingest


def test_ingest_hashes_and_chunks(tmp_path: Path) -> None:
    data = os.urandom(3000)
    img = tmp_path / "fw.bin"
    img.write_bytes(data)
    case = Case.create(tmp_path / "c")
    res = Ingest().run(case, image=img, chunk_size=1024)
    assert res.ok
    row = case.conn.execute("SELECT * FROM images").fetchone()
    assert row["sha256"] == hashlib.sha256(data).hexdigest()
    assert row["chunk_count"] == 3 and row["size"] == 3000
    assert (case.root / row["path"]).read_bytes() == data


def test_ingest_missing_image(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    res = Ingest().run(case, image=tmp_path / "none")
    assert not res.ok and res.errors
