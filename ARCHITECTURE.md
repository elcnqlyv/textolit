# Architecture

Textolit is a case-scoped pipeline. A **case** is a directory:

```
case/
  case.db        SQLite (WAL): the evidence ledger
  artifacts/     image/, extract/, carved/, entropy/ ...
  logs/          <sha256>.out / .err  raw stdout/stderr of every command
  reports/
```

## Data flow

```
ingest -> unpack -> entropy -> (fswalk -> binintel -> netmap -> websurface -> crypto)
                                   \________________ missedfindings (every new artifact)
                                                      -> findings -> report / llm
```

Each arrow is a job in the `jobs` table. Modules read and write only the case
database and case directory.

## Boundaries

- `core/case.py`: create/open a case; the only place paths are made relative.
- `core/runner.py`: **the only subprocess call site.** Logs argv, cwd, env overrides, exit
  code; stores output content-addressed under `logs/`. Missing binaries and timeouts come
  back as a result with `error` set and are also recorded.
- `core/ledger.py`: artifact registration (hashes, parentage, producing command).
- `core/jobs.py`: persistent queue. One worker thread, own DB connection. Jobs that were
  running when the process died become `interrupted`; nothing restarts silently.
- `modules/base.py`: `Module` protocol: `run(case, progress, **options) -> ModuleResult`.
  Results are structured (`ok`, `summary`, `data`, `warnings`, `errors`). No exceptions
  for expected failures.
- `modules/registry.py`: builds the module map per call (no global registry).
- `ui/`: Textual app. Reads the database on a 1 Hz timer; never calls modules directly,
  only enqueues jobs. The CLI uses the same enqueue/run path, so both leave the same trail.

## Evidence model (sprint 2)

- `files` is the index every later module reads (path, mode, type, hash, entropy).
- `binaries`, `services`, `network_endpoints`, `credentials` hold parsed facts with the
  source path and line they came from.
- `findings` rows are deduplicated by (rule, path, line, title). Operator decisions live on
  the row (`accepted`, `rejected`, `snoozed`, with a note) and survive re-sweeps.
- `missedfindings` rule caps (200 hits per rule) are reported, never silent.
- Jobs in `jobs.SWEEP_AFTER` queue a sweep when they finish successfully.

## Crypto and cracking (sprint 3)

- `crypto` writes `crypto_materials` (hashes, certs, key fingerprints, key strings). Private
  key bodies are never stored. `hashtypes.py` recognises formats and maps them to hashcat modes.
- `hashcat.py` only builds argv from a `Profile` (GTX1650 defaults) and an `Attack`. Nothing
  there runs a process, so commands can be printed, queued or run by hand.
- `crack.py` owns `crack_tasks`. It runs one task at a time through `core.runner.run_streaming`,
  which streams stdout, spools it to disk and sends SIGINT when the operator pauses. hashcat
  writes its restore file into the case, so a resume works after a restart.
- The `hashcat` job module drains queued tasks. `jobs.Worker(long_jobs=True)` runs it on its
  own thread so analysis jobs keep flowing.
- Cracked results update `crypto_materials.cracked`, add a `credentials` row and a finding.

## Web surface (sprint 3)

`websurface` reads files only. It fills `web_surface` (roots, servers, auth guesses, endpoints,
upload handlers, front-end credentials) and raises findings for upload handlers, browser-side
login logic and embedded credentials.

## Where future modules plug in

A new module is a class with `name` and `run`, listed in `registry.py`; it gets a CLI
subcommand automatically and a job type for the TUI.

- **Ghidra headless / r2 batch**: new modules (`ghidra`, `r2batch`) that call
  `core.runner.run` with the headless script and register output as artifacts
  (`kind="ghidra_project"`, `"r2_json"`), then emit rows into `binaries` or `findings`
  with `evidence_links` pointing at the artifact. They read `files`/`binaries` produced by
  `fswalk`/`binintel` to pick targets.
- **Dynamic emulation**: out of scope for v1. It would be a module that consumes an
  `fs_root` artifact and writes `services`/`network_endpoints` observed at runtime, tagged
  so static and observed evidence stay distinguishable.
- **Missed-findings rule packs**: YAML under `rules/`; each hit becomes a `findings` row
  (deduplicated by `fingerprint`) plus `evidence_links`. Accept/reject/snooze are
  recorded on the row, never deleted.

## Invariants

- Silence is a bug: a stub or failed module reports failure; an empty findings list in a
  report says so explicitly.
- Classifiers that guess (e.g. encrypted vs compressed) are labelled leads in output.
- LLM is off per case by default; enabling requires confirmation and every call is logged.
- Extraction never follows symlinks out of the case tree; escaping links are reported.
