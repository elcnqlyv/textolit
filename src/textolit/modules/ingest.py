"""ingest: copy the image into the case, hash it, chunk it, capture metadata."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from textolit.core.case import Case, utcnow
from textolit.core.ledger import add_artifact
from textolit.core.runner import run
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

DEFAULT_CHUNK = 1 << 20


class Ingest:
    name = "ingest"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        src = Path(options["image"])
        chunk_size = int(options.get("chunk_size", DEFAULT_CHUNK))
        if not src.is_file():
            return ModuleResult(
                self.name, False, "image not found", errors=[f"no such file: {src}"]
            )

        dest_dir = case.artifacts_dir / "image"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        shutil.copyfile(src, dest)

        size = dest.stat().st_size
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324
        chunks: list[dict[str, Any]] = []
        done = 0
        with dest.open("rb") as fh:
            while block := fh.read(chunk_size):
                md5.update(block)
                sha1.update(block)
                sha256.update(block)
                chunks.append(
                    {
                        "offset": done,
                        "length": len(block),
                        "sha256": hashlib.sha256(block).hexdigest(),
                    }
                )
                done += len(block)
                progress(done / max(size, 1), f"hashing {done >> 20} MiB")

        file_res = run(case, ["file", "-b", str(dest)], module=self.name)
        meta = {
            "filename": src.name,
            "source_path": str(src.resolve()),
            "mtime": src.stat().st_mtime,
            "file_type": file_res.text.strip() if file_res.ok else None,
        }
        chunks_path = dest_dir / f"{src.name}.chunks.json"
        chunks_path.write_text(json.dumps(chunks), encoding="utf-8")

        with case.conn:
            cur = case.conn.execute(
                "INSERT INTO images(case_id,path,size,md5,sha1,sha256,chunk_size,chunk_count,"
                "meta_json,ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    case.case_id,
                    case.rel(dest),
                    size,
                    md5.hexdigest(),
                    sha1.hexdigest(),
                    sha256.hexdigest(),
                    chunk_size,
                    len(chunks),
                    json.dumps(meta),
                    utcnow(),
                ),
            )
        image_id = cur.lastrowid
        assert image_id is not None
        art = add_artifact(case, "image", dest, image_id=image_id, hash_it=False)
        case.conn.execute("UPDATE artifacts SET sha256=? WHERE id=?", (sha256.hexdigest(), art))
        case.conn.commit()
        add_artifact(case, "chunk_index", chunks_path, image_id=image_id, parent_id=art)

        warnings = [] if file_res.ok else ["`file` unavailable; file type not captured"]
        return ModuleResult(
            self.name,
            True,
            f"ingested {src.name} ({size} bytes, sha256 {sha256.hexdigest()[:12]})",
            data={
                "image_id": image_id,
                "sha256": sha256.hexdigest(),
                "size": size,
                "chunks": len(chunks),
                "artifact_id": art,
            },
            warnings=warnings,
        )
