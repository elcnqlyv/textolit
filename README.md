# Textolit

Textolit — firmware triage workbench for CCTV and access-control research.

```
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
```

authorized testing only · leads, not verdicts · every command logged

## Install

    pipx install .

Requires Python 3.11+. External tools are optional per module: binwalk, unsquashfs
(or sasquatch), hashcat, radare2.

## Usage

    textolit init ./case-foo --image firmware.bin
    textolit unpack ./case-foo
    textolit entropy ./case-foo
    textolit report ./case-foo
    textolit tui ./case-foo

Cases are directories: `case.db` (SQLite, WAL) plus `artifacts/`. Relaunching resumes
from the database. LLM use is off by default and toggled per case.
