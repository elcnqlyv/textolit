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

- **Ingest and unpack**: hash the image, run `binwalk` recursively, detect squashfs, ubifs, jffs2 and cramfs roots
- **Entropy map**: sliding-window entropy that marks plain, compressed and possibly encrypted regions
- **File index**: every extracted file with type, hash, entropy and mode, plus the paths that matter on CCTV and access-control devices
- **Binary inventory**: ELF architecture, libraries, stripped or not, and version strings with CVE hints
- **Netmap**: a listen-by-default table with the file and line behind every port
- **Crypto**: password hashes from shadow, passwd, htpasswd and SQLite files, certificates, private keys and key strings, each tagged with a hashcat mode
- **Cracking**: a hashcat queue tuned for a GTX1650 that you can pause and resume
- **Web surface**: a static map of the web interface, its server, login style, upload handlers and visible credentials
- **Missed-findings sweep**: YAML rule packs that turn every odd thing into a lead with a confidence and an evidence path
- **Report**: Markdown grouped by the OWASP IoT Top 10

Every command goes through one subprocess wrapper. It records the argv, the working directory, the exit code and the hashes of stdout and stderr in the case database. The TUI and the CLI share the same job queue, so both leave the same trail.

Textolit needs Python 3.11 or newer. It depends on `textual` and `pyyaml`. It calls external tools when they are present: `binwalk`, `unsquashfs` or `sasquatch`, and `file`. `hashcat` is optional and only needed to run the crack queue. `radare2` is planned for a later module.

> [!WARNING]
> **Authorized testing only.** Textolit reads firmware you are allowed to analyze. It does not emulate, exploit or touch a live device. It stays air-gapped by default. The LLM toggle is off per case until you turn it on and confirm.

## Install

```bash
git clone https://github.com/elcnqlyv/textolit.git
cd textolit
pipx install .
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

Every module takes the case directory as its first argument, so the same commands work in scripts. The `llm` module is a stub for now and reports that it is not implemented.

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

# 6. write the report
textolit report ./case-foo
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

## Workbench (TUI)

```bash
textolit tui ./case-foo
```

The workbench opens on the signature banner, then the dashboard. Tabs cover Dashboard, Entropy, Artifacts, Netmap, Web, Crypto, Crack, Findings, Jobs and Commands. Cracking runs on its own worker, so analysis jobs never wait behind it. A job footer shows progress for queued and running jobs. State lives in SQLite, so a killed session resumes where it stopped. Jobs that were running when the process died show as `interrupted` and do not restart on their own.

| Key | Action |
| --- | --- |
| `F1` | Help |
| `F2` | Toggle the raw output pane (Enter on a Commands row loads that command's output) |
| `F3` | Cycle the findings filter |
| `F4` | Job queue |
| `F5` | LLM on or off, with a confirm step. The status bar shows `LLM ACTIVE` when on |
| `F6` | Export the Markdown report |
| `F10` | Quit, with a guard while jobs are running |
| `p` | Queue the full pipeline |
| `a` `x` `s` | Accept, reject or snooze the selected finding |
| `g` | Plan and run hashcat attacks. On the Crack tab `space` pauses or resumes and `x` cancels |

## Rule packs

Packs live in `src/textolit/rules/` as YAML: `creds`, `services` and `files`. Load extra packs with `--rules-dir`:

```bash
textolit missedfindings ./case-foo --rules-dir ./my-rules
```

A rule has a `kind` of `content`, `path`, `perm` or `magic`. It also has a confidence of `low`, `med` or `high`, plus optional CWE and OWASP IoT tags.

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
