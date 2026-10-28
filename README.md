<p align="center">
  <br>
  <a href="https://github.com/elcnqlyv/textolit" target="_blank"><img src="textolit-banner.svg" alt="textolit" width="72%"/></a>
  <br>
  <br>
  <span>Firmware triage workbench for CCTV and access-control research. Unpack, map, sweep, report. <b>Leads, not verdicts</b>.</span>
  <br>
</p>

<p align="center">
  <a href="#install">Install</a>
     •   
  <a href="#workflow">Workflow</a>
     •   
  <a href="#workbench-tui">TUI</a>
     •   
  <a href="#rule-packs">Rule packs</a>
     •   
  <a href="#case-layout">Case layout</a>
     •   
  <a href="#license">License</a>
</p>

```console
$ textolit tui ./case-foo
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢁⣿⣿⣷⡄⠀⠀⠀⠀⠀⣴⣿⣿⣷⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⢸⡿⠿⣿⣿⣦⣤⣤⣤⣤⣬⣉⣻⣿⣧
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠀⣶⣶⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡝⠆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⣿⣿⣿⣿⡏⠉⢻
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⣿⣿⣿⣿⣷⣄⣼⣷⡒
⠀⢀⣠⣤⣤ ⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⠖⣻⣶⣾⣿⣿⣿⣧⣿⣿⣿⣿⠉
⣿⣿⣿⣿⣿⣷⣄⠀ ⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠏      ⠀⠀⠀⢀⡴⢲⡄⠀⠀⠀⢀⣀
⠈⢿⣿⣿⣿⣿⣿⣿⡄   ⠙⠛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡋⠁       ⠀⠀⢀⡞⠀⠀⡇⠀⢀⡴⠋⠁⢸
⠀⠀⠉⢻⣿⣿⣿⣿⣧   ⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀       ⠀⠀⣸⠁⠀⠀⡇⣠⠟⠀⠀⠀⣼⣠⣤⣤⣀
⠀⠀⠀⠘⣿⣿⣿⣿⡟ ⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇       ⠀⠀⣿⠀⢠⢤⡿⠃⣀⠀⢀⡞⠉⠁⠀⠀⠈⠙⠶⡄
⠀⠀⠀⢰⣿⣿⣿⣿⠇⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿       ⠀⠀⣻⣰⡏⣼⢁⡴⠋⣰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⣀⡀
⠀⠀⠀⣾⣿⣿⣿⡟⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡿       ⢀⡾⠋⠉⠁⠀⠙⠁⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡈⢷
⠀⠀⢰⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⡇⣼⡇       ⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⢀⣧⡾⠁
⠀⠀⢸⣿⣿⣿⣇⠀⣿⣿⣿⣿⣿⣿⣿⣷⣌⢻⣿⣿⣿⣿⣿⣴⣿⡇       ⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⣾⠃
⠀⠀⠸⣿⣿⣿⣿⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⣿⣿⣿⣿⡏⢸⣿⡇       ⣹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠁⠀⠀⡀⠀⠀⢰⡾⠋
⠀⠀⠀⠙⢿⣿⣿⡇⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀⣿⣿⣿⣿⡇⣿⣿        ⢻⡇⣀⡀⠀⠺⣿⠇⠀⣀⣤⣄⣀⣠⣬⣥⣤⠾⠛⠁
⠀⠀⠀⠀⠀⠉⠙⠛⠂⠙⠛⠛⠛⠛⠛⠛⠐⠓⠈⠙⠋⠋⠃⠉⠉        ⠀⠉⠛⠓⠂⠤⠤⠖⠊⠉⠉⠉⠉⠁

  authorized testing only · leads, not verdicts · every command logged
```

One command-line tool and one terminal workbench turn a vendor firmware download into an auditable case:

- **Ingest and unpack**: hash the image, run `binwalk` recursively, detect squashfs, ubifs, jffs2 and cramfs roots. When binwalk finds no filesystem, a fallback strips uImage and TRX headers, inflates gzip, xz and lzma streams, and carves squashfs, cpio and cramfs by magic
- **Entropy map**: sliding-window entropy that marks plain, compressed and possibly encrypted regions
- **File index**: every extracted file with type, hash, entropy and mode, plus the paths that matter on CCTV and access-control devices
- **Binary inventory**: ELF architecture, libraries, stripped or not, and version strings with CVE hints
- **Netmap**: a listen-by-default table with the file and line behind every port
- **Crypto**: password hashes from shadow, passwd, htpasswd and SQLite files, certificates, private keys and key strings, each tagged with a hashcat mode
- **Cracking**: a hashcat queue tuned for a GTX1650 that you can pause and resume
- **Web surface**: a static map of the web interface, its server, login style, upload handlers and visible credentials
- **Missed-findings sweep**: YAML rule packs that turn every odd thing into a lead with a confidence and an evidence path
- **Report**: Markdown, DOCX, PDF and CVE-ready JSON, grouped by the OWASP IoT Top 10, with a summary rollup and an evidence appendix
- **LLM assist**: optional and off by default. Triage notes, crypto reasoning, report drafts and CVE write-ups with every claim tied to evidence ids

Every command goes through one subprocess wrapper. It records the argv, the working directory, the exit code and the hashes of stdout and stderr in the case database. The TUI and the CLI share the same job queue, so both leave the same trail.

Textolit needs Python 3.11 or newer. It depends on `textual` and `pyyaml`. The `report` extra adds `python-docx` and `reportlab` for DOCX and PDF export. Markdown and JSON need nothing extra. It calls external tools when they are present: `binwalk`, `unsquashfs` or `sasquatch`, and `file`. `hashcat` is optional and only needed to run the crack queue. `radare2` is planned for a later module.

> [!WARNING]
> **Authorized testing only.** Textolit reads firmware you are allowed to analyze. It does not emulate, exploit or touch a live device. It stays air-gapped by default. The LLM toggle is off per case until you turn it on and confirm.

## Install

```bash
git clone https://github.com/elcnqlyv/textolit.git
cd textolit
pipx install '.[report]'
textolit --version
```

For development, use a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
```

| Platform | Install the external tools |
| --- | --- |
| **Kali** (intended runtime) | `sudo apt-get install -y binwalk squashfs-tools sasquatch pipx` |
| **Arch** | `sudo pacman -S binwalk squashfs-tools python-pipx` |

`sasquatch` is optional and helps with vendor-patched squashfs. `unsquashfs` is the fallback.

## Commands

```console
usage: textolit [-h] [--version]
                {init,tui,jobs,findings,decide,ingest,unpack,entropy,fswalk,binintel,netmap,missedfindings,crypto,websurface,llm,report} ...

Textolit: firmware triage workbench for CCTV and access-control research.

positional arguments:
  {init,tui,jobs,findings,decide,ingest,unpack,entropy,fswalk,binintel,netmap,missedfindings,crypto,websurface,llm,report}
    init                create a case directory (optionally ingest an image)
    tui                 open the workbench for a case
    jobs                list queued/finished jobs for a case
    findings            list findings (leads) for a case
    decide              accept, reject or snooze a finding
    ingest              run the ingest module
    unpack              run the unpack module
    entropy             run the entropy module
    fswalk              run the fswalk module
    binintel            run the binintel module
    netmap              run the netmap module
    missedfindings      run the missedfindings module
    crypto              run the crypto module
    websurface          run the websurface module
    llm                 run the llm module
    report              run the report module

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

Every module takes the case directory as its first argument, so the same commands work in scripts. The `llm` command has its own actions, described below.

## Workflow

Each step reads what the one before it recorded. `fswalk`, `binintel` and `netmap` each queue a rule sweep when they finish, so new evidence never goes unexamined.

```text
   ┌── ingest ───┬── unpack ───┬── entropy ─┐
   │  sha256     │  binwalk    │  windows   │
   │  chunks     │  fs roots   │  regions   │
   │  file type  │  dedup      │  leads     │
   └─────────────┴─────────────┴────────────┘
                       │
   ┌── fswalk ───┬── binintel ─┬── netmap ──┐
   │  index      │  ELF facts  │  ports     │
   │  modes      │  versions   │  creds     │
   │  symlinks   │  CVE hints  │  sources   │
   └─────────────┴─────────────┴────────────┘
                       │
                ╔══════▼═══════╗
                ║  RULE SWEEP  ║   queued after each step
                ║  YAML packs  ║   hits become findings
                ╚══════╤═══════╝
                       │
   ┌── review ───┬── report ───┐
   │  accept     │  Markdown   │
   │  reject     │  OWASP IoT  │
   │  snooze     │  evidence   │
   └─────────────┴─────────────┘
```

The same flow from the shell:

```bash
# 1. open a case and ingest the image
textolit init ./case-foo --image firmware.bin

# 2. unpack and map entropy
textolit unpack ./case-foo
textolit entropy ./case-foo

# 3. index files, inventory binaries, map listening ports
textolit fswalk ./case-foo
textolit binintel ./case-foo
textolit netmap ./case-foo

# 4. extract hashes and keys, map the web interface
textolit crypto ./case-foo
textolit websurface ./case-foo

# 5. review leads
textolit findings ./case-foo
textolit decide ./case-foo 4 reject --note "lab placeholder"

# 6. write the report: md by default, or docx, pdf, json (CVE-ready), all
textolit report ./case-foo --format all
```

Extraction runs under `umask 0`. File modes in the index are the image's modes, so a world-writable file stays visible.

## Cracking with hashcat

`textolit crypto` lists every hash it found with the hashcat mode it suggests. Raw 32-hex hashes are ambiguous (MD5, MD4 or NTLM), so those carry a lower confidence. Then plan and run the attacks:

```bash
textolit crack ./case-foo plan --wordlist /usr/share/wordlists/rockyou.txt --gpu-budget 90m
textolit crack ./case-foo run
textolit crack ./case-foo status
textolit crack ./case-foo pause 3      # SIGINT, hashcat writes a checkpoint
textolit crack ./case-foo resume 3     # continues from the checkpoint
```

`plan` prints the exact hashcat command for every stage and queues it. Stages run cheapest first: a short list of IoT default passwords, then your wordlist, then your wordlist with `best64`/`best66` rules, then digit masks. The default profile is built for a GTX1650 with 4 GB of VRAM:

| Setting | Default | Why |
| --- | --- | --- |
| `-w` | `2` | Leaves the desktop usable. Use `-w 3` when the machine is idle |
| `-O` | fast hashes only | Optimized kernels cap the password length, so slow modes skip them |
| `--gpu-budget` | none | Wall-clock cap per stage, passed to hashcat as `--runtime` |
| `--temp-abort` | `85` | Passed as `--hwmon-temp-abort` |
| VRAM kept free | `10%` | `--backend-devices-keepfree` |

Memory-hard modes such as scrypt only get the default list and a warning. A cracked password becomes a high-confidence finding with the source file and line of the hash. The queue lives in SQLite, so a killed session leaves tasks `paused` and nothing restarts until you resume it. Pass `--hashcat /path/to/hashcat` to use another binary.

## Reports and exports

```bash
textolit report ./case-foo                          # Markdown
textolit report ./case-foo --format pdf --format docx
textolit report ./case-foo --format json            # CVE-ready JSON
textolit report ./case-foo --format all --include-pending --include-llm
```

The Markdown report opens with a summary rollup (severity by confidence, OWASP IoT category counts, decisions). It ends with an evidence appendix that lists artifacts with their hashes. DOCX and PDF render the same Markdown, so the formats never drift. Secrets are masked in every format.

The CVE JSON has one entry per accepted finding. Use `--include-pending` to add pending ones. Each entry carries the CWE with its name, a suggested CVSS 3.1 vector with the computed score, the OWASP IoT category, the firmware hashes, the evidence with file and line, and an empty slot for the PoC. **The CVSS vector is a suggestion and is marked `confirmed: false`.** Affected versions and references are left for you to fill in, because the firmware cannot tell Textolit what the vendor calls its releases.

## LLM assistance

The LLM is off for every case until you turn it on. It is never needed. Nothing else in Textolit calls a model.

```bash
textolit llm ./case-foo config --backend ollama --model <your-model>
textolit llm ./case-foo on
textolit llm ./case-foo triage             # rank the leads
textolit llm ./case-foo crypto             # reason about hashes and certificates
textolit llm ./case-foo draft              # report narrative, written to reports/
textolit llm ./case-foo cve 4              # write-up draft for finding 4
textolit llm ./case-foo calls              # the call log
```

Two backends exist: Ollama on this machine, and any OpenAI-compatible API. The API key comes from an environment variable (`TEXTOLIT_LLM_API_KEY` by default) and is never written to the case. A backend on a non-local address is refused until you run `config --allow-remote`, because case evidence would leave the machine. The TUI shows `LLM ACTIVE` in the status bar whenever it is on, and `F5` asks for confirmation first.

The prompt templates live in `src/textolit/prompt_templates/`. They tell the model to treat firmware content as untrusted data, to cite evidence ids for every claim, to put anything unproven in an `unverified` list, and to answer with one JSON object. Textolit then checks the reply. A claim with no valid citation is dropped. A claim that names a CVE id absent from the evidence is dropped. A reply with nothing left is stored as `invalid` and not used. The CWE in a write-up is always the finding's own. Hash values and cracked passwords are never sent. Snippets are masked.

Every call is recorded in `llm_calls` with the backend, model, prompt hash and token counts. The exact prompt and raw reply stay in `artifacts/llm/`. A model reply never creates a finding. It stays a labeled draft until you accept it. `report --include-llm` adds the validated notes under an "unverified" banner.

## Workbench (TUI)

```bash
textolit tui ./case-foo
```

The workbench opens on the signature banner, then the dashboard. Tabs cover Dashboard, Entropy, Artifacts, Netmap, Web, Crypto, Crack, LLM, Findings, Jobs and Commands. Cracking runs on its own worker, so analysis jobs never wait behind it. A job footer shows progress for queued and running jobs. State lives in SQLite, so a killed session resumes where it stopped. Jobs that were running when the process died show as `interrupted` and do not restart on their own.

| Key | Action |
| --- | --- |
| `F1` | Help |
| `F2` | Toggle the raw output pane (Enter on a Commands row loads that command's output) |
| `F3` | Cycle the findings filter |
| `F4` | Job queue |
| `F5` | LLM on or off, with a confirm step. The status bar shows `LLM ACTIVE` when on |
| `F6` | Export the report as Markdown, DOCX, PDF and CVE JSON |
| `F10` | Quit, with a guard while jobs are running |
| `p` | Queue the full pipeline |
| `a` `x` `s` | Accept, reject or snooze the selected finding |
| `t` `c` `d` | LLM triage, crypto reasoning and report draft (LLM tab, needs the LLM on) |
| `v` | LLM write-up draft for the selected finding (Findings tab) |
| `g` | Plan and run hashcat attacks. On the Crack tab `space` pauses or resumes and `x` cancels |

## Rule packs

Packs live in `src/textolit/rules/` as YAML: `creds`, `services`, `files` and `iot`. The `iot` pack covers camera and access-control leads such as credentials inside RTSP URLs, streams with authentication switched off, firmware fetched over HTTP, shipped SSH host keys, OSDP and MIFARE default keys, and CGI scripts that pass request data to a shell. Load extra packs with `--rules-dir`:

```bash
textolit missedfindings ./case-foo --rules-dir ./my-rules
```

A rule has a `kind` of `content`, `path`, `perm` or `magic`. It also has a confidence of `low`, `med` or `high`, plus optional CWE and OWASP IoT tags.

To see which rules are noisy, list the hit counts from the last sweep next to your accept and reject decisions:

```bash
textolit findings ./case-foo --stats
```

A rule is flagged when it passes its per-rule cap, when most of its decided hits were rejected, or when it matched nothing at all.

```yaml
- id: svc.dropbear-blank-password
  title: dropbear started with -B (blank passwords allowed)
  kind: content
  confidence: high
  severity: high
  cwe: CWE-258
  owasp_iot: I1
  pattern: '\bdropbear\b[^\n#]*\s-B\b'
```

## Case layout

```text
case-foo/
├── case.db      SQLite (WAL): images, files, binaries, services, endpoints,
│                credentials, findings, evidence links, jobs, commands
├── artifacts/   image/  extract/  carved/  entropy/
├── logs/        <sha256>.out and .err for every command
└── reports/     report-<UTC-stamp>.md
```

## Design notes and limits

- **Leads, not verdicts.** A version string is a fingerprint, not proof. Vendors backport fixes. CVE hints are low confidence on purpose.
- **Encrypted versus compressed is a heuristic.** Both look uniform. A run counts as compressed once a known magic appears, and as encrypted only when no magic came first and the byte histogram is uniform.
- **Config ports are weaker evidence.** A port number in a config file does not prove anything binds it. Init scripts, inetd and systemd units are stronger and are labeled that way.
- **Silence is a bug.** A stub reports that it is a stub. A rule that hits its cap of 200 says so. An empty findings list in a report says it is not a clean bill of health.
- **Decisions persist.** Rejected and snoozed leads stay in the database and in the report. A re-sweep never brings them back.
- **No dynamic analysis.** There is no emulation, no decompilation orchestration and no automatic exploitation in v1.

## License

GPL-3.0-or-later. Copyright (C) 2026 Elchin Guliyev. See [LICENSE](LICENSE).

For authorized security testing only. You must have written permission before you analyze firmware you do not own.

<p align="center">
  <br>
  <img src="textolit-logo.svg" alt="textolit" width="96"/>
  <br>
  <sub><b>texto</b><span>lit</span> · authorized testing only · leads, not verdicts</sub>
</p>
