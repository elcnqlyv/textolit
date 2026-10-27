#!/usr/bin/env python3
"""Stand-in for hashcat in tests: md5 wordlist attacks, status JSON, SIGINT checkpoint."""

import hashlib
import json
import os
import signal
import sys
import time

argv = sys.argv[1:]


def opt(name: str) -> str | None:
    return argv[argv.index(name) + 1] if name in argv else None


restore_file = opt("--restore-file-path")


def on_int(*_a: object) -> None:
    if restore_file:
        with open(restore_file, "w") as fh:
            fh.write("checkpoint\n")
    print("checkpoint written", flush=True)
    sys.exit(2)


signal.signal(signal.SIGINT, on_int)

if "--restore" in argv:
    print("restored session", flush=True)
    sys.exit(1)

if os.environ.get("FAKE_SLOW"):
    n = 0
    while True:
        n += 1
        print(
            json.dumps(
                {
                    "status": 3,
                    "progress": [n, 1000],
                    "recovered_hashes": [0, 2],
                    "devices": [{"speed": 1500000, "temp": 61}],
                }
            ),
            flush=True,
        )
        time.sleep(0.1)

with open(argv[-2]) as fh:
    hashes = fh.read().split()
mode_attack = opt("-a")
found = {}
if mode_attack == "0":
    with open(argv[-1]) as fh:
        words = fh.read().split()
    for w in words:
        d = hashlib.md5(w.encode()).hexdigest()
        if d in hashes:
            found[d] = w
print(
    json.dumps(
        {
            "status": 3,
            "progress": [10, 10],
            "recovered_hashes": [len(found), len(hashes)],
            "devices": [{"speed": 2000000, "temp": 55}],
        }
    ),
    flush=True,
)
with open(opt("-o"), "a") as out:
    for h, w in found.items():
        out.write(f"{h}:{w}\n")
sys.exit(0 if len(found) == len(hashes) else 1)
