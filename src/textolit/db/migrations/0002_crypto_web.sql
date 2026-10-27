-- Sprint 3: crack queue, web surface inventory, richer crypto material rows.

ALTER TABLE crypto_materials ADD COLUMN username TEXT;
ALTER TABLE crypto_materials ADD COLUMN source_line INTEGER;
ALTER TABLE crypto_materials ADD COLUMN detail TEXT NOT NULL DEFAULT '{}';
ALTER TABLE crypto_materials ADD COLUMN cracked TEXT;

CREATE TABLE crack_tasks (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    hash_mode     INTEGER NOT NULL,
    hashfile      TEXT NOT NULL,          -- relative to the case dir
    attack        TEXT NOT NULL,          -- JSON description of the attack stage
    argv_json     TEXT NOT NULL,          -- the exact hashcat command, as built
    session       TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','paused','done','exhausted',
                                    'cracked','failed','cancelled')),
    control       TEXT CHECK (control IN ('pause','cancel')),
    progress      REAL NOT NULL DEFAULT 0,
    speed         TEXT NOT NULL DEFAULT '',
    recovered     INTEGER NOT NULL DEFAULT 0,
    total         INTEGER NOT NULL DEFAULT 0,
    message       TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT
);

CREATE TABLE web_surface (
    id            INTEGER PRIMARY KEY,
    category      TEXT NOT NULL,          -- root, server, auth, endpoint, upload, credential
    key           TEXT NOT NULL,
    value         TEXT NOT NULL DEFAULT '',
    confidence    TEXT NOT NULL DEFAULT 'low' CHECK (confidence IN ('low','med','high')),
    source_path   TEXT NOT NULL,
    source_line   INTEGER,
    evidence      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_web_category ON web_surface(category);
