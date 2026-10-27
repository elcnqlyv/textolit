-- Textolit schema 0001. One database per case directory.

CREATE TABLE cases (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    llm_enabled   INTEGER NOT NULL DEFAULT 0,
    notes         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE images (
    id            INTEGER PRIMARY KEY,
    case_id       INTEGER NOT NULL REFERENCES cases(id),
    path          TEXT NOT NULL,
    size          INTEGER NOT NULL,
    md5           TEXT NOT NULL,
    sha1          TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    chunk_size    INTEGER NOT NULL,
    chunk_count   INTEGER NOT NULL,
    meta_json     TEXT NOT NULL DEFAULT '{}',
    ingested_at   TEXT NOT NULL
);

-- Any file-like object the pipeline produced or consumed.
CREATE TABLE artifacts (
    id            INTEGER PRIMARY KEY,
    image_id      INTEGER REFERENCES images(id),
    parent_id     INTEGER REFERENCES artifacts(id),
    kind          TEXT NOT NULL,          -- image, carved, extract_root, report, ...
    path          TEXT NOT NULL,          -- relative to case dir
    sha256        TEXT,
    size          INTEGER,
    produced_by   INTEGER REFERENCES commands(id),
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_artifacts_sha ON artifacts(sha256);

CREATE TABLE regions (
    id            INTEGER PRIMARY KEY,
    image_id      INTEGER NOT NULL REFERENCES images(id),
    offset        INTEGER NOT NULL,
    length        INTEGER NOT NULL,
    entropy       REAL NOT NULL,
    classification TEXT NOT NULL          -- plain, compressed, encrypted, empty
);

CREATE TABLE files (
    id            INTEGER PRIMARY KEY,
    artifact_id   INTEGER REFERENCES artifacts(id),
    path          TEXT NOT NULL,          -- path within extract root
    size          INTEGER NOT NULL,
    mode          INTEGER NOT NULL,
    uid           INTEGER,
    gid           INTEGER,
    sha256        TEXT,
    ftype         TEXT,
    is_symlink    INTEGER NOT NULL DEFAULT 0,
    link_target   TEXT,
    entropy       REAL,
    interesting   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_files_path ON files(path);

CREATE TABLE binaries (
    id            INTEGER PRIMARY KEY,
    file_id       INTEGER NOT NULL REFERENCES files(id),
    arch          TEXT,
    bits          INTEGER,
    endian        TEXT,
    stripped      INTEGER,
    libs_json     TEXT NOT NULL DEFAULT '[]',
    versions_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE services (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    command       TEXT,
    source_path   TEXT NOT NULL,
    source_line   INTEGER,
    evidence      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE network_endpoints (
    id            INTEGER PRIMARY KEY,
    service_id    INTEGER REFERENCES services(id),
    port          INTEGER NOT NULL,
    proto         TEXT NOT NULL DEFAULT 'tcp',
    bind_addr     TEXT,
    nonstandard   INTEGER NOT NULL DEFAULT 0,
    default_on    INTEGER NOT NULL DEFAULT 1,
    source_path   TEXT NOT NULL,
    source_line   INTEGER,
    evidence      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE credentials (
    id            INTEGER PRIMARY KEY,
    username      TEXT,
    secret        TEXT,
    secret_kind   TEXT NOT NULL,          -- plaintext, hash, key
    algo          TEXT,
    source_path   TEXT NOT NULL,
    source_line   INTEGER
);

CREATE TABLE crypto_materials (
    id            INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL,          -- cert, private_key, hash, key_string
    algo          TEXT,
    value         TEXT,
    source_path   TEXT NOT NULL,
    hashcat_mode  INTEGER
);

CREATE TABLE heuristics (
    id            TEXT PRIMARY KEY,       -- rule id
    pack          TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    version       TEXT NOT NULL DEFAULT '1'
);

CREATE TABLE findings (
    id            INTEGER PRIMARY KEY,
    heuristic_id  TEXT REFERENCES heuristics(id),
    title         TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    confidence    TEXT NOT NULL CHECK (confidence IN ('low','med','high')),
    severity      TEXT NOT NULL DEFAULT 'info',
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','accepted','rejected','snoozed')),
    owasp_iot     TEXT,
    cwe           TEXT,
    evidence_path TEXT NOT NULL,
    fingerprint   TEXT NOT NULL UNIQUE,   -- dedupe key
    created_at    TEXT NOT NULL,
    decided_at    TEXT,
    decision_note TEXT
);

CREATE TABLE llm_calls (
    id            INTEGER PRIMARY KEY,
    created_at    TEXT NOT NULL,
    backend       TEXT NOT NULL,
    model         TEXT NOT NULL,
    template      TEXT NOT NULL,
    prompt_sha256 TEXT NOT NULL,
    prompt_path   TEXT NOT NULL,
    output_path   TEXT,
    tokens_in     INTEGER,
    tokens_out    INTEGER,
    status        TEXT NOT NULL
);

CREATE TABLE commands (
    id            INTEGER PRIMARY KEY,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    argv_json     TEXT NOT NULL,
    cwd           TEXT NOT NULL,
    env_json      TEXT NOT NULL DEFAULT '{}',
    exit_code     INTEGER,
    stdout_sha256 TEXT,
    stderr_sha256 TEXT,
    stdout_path   TEXT,
    stderr_path   TEXT,
    module        TEXT
);

CREATE TABLE evidence_links (
    id            INTEGER PRIMARY KEY,
    finding_id    INTEGER NOT NULL REFERENCES findings(id),
    kind          TEXT NOT NULL,          -- file, artifact, region, command, endpoint, credential
    ref_id        INTEGER,
    path          TEXT,
    line          INTEGER,
    snippet       TEXT
);
CREATE INDEX idx_evidence_finding ON evidence_links(finding_id);

CREATE TABLE jobs (
    id            INTEGER PRIMARY KEY,
    module        TEXT NOT NULL,
    args_json     TEXT NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','done','failed','interrupted','cancelled')),
    progress      REAL NOT NULL DEFAULT 0,
    message       TEXT NOT NULL DEFAULT '',
    error         TEXT,
    created_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT
);
