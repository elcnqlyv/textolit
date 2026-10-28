-- Per-rule sweep statistics: how many matches a rule produced in the last sweep, including
-- those past the per-rule cap. Used to find rules that are too noisy to be useful.
CREATE TABLE rule_stats (
    heuristic_id  TEXT PRIMARY KEY REFERENCES heuristics(id),
    matches       INTEGER NOT NULL,
    recorded      INTEGER NOT NULL,
    swept_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
