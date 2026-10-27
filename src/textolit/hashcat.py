"""hashcat command builder with a GTX1650 (Turing, 4 GB) default profile.

Nothing here runs hashcat. ``build_command`` returns an argv so the same command can be
queued, logged, or printed for the operator to run by hand.

Profile choices for a 4 GB laptop or desktop card:
- ``-w 2`` (default workload) leaves the desktop usable. ``-w 3`` is opt-in.
- ``-O`` (optimized kernels) only for fast hashes, where it helps most and the password
  length limit hurts least.
- ``--hwmon-temp-abort 85`` and ``--backend-devices-keepfree 10`` protect the card and
  keep some VRAM for the display.
- ``--gpu-budget`` caps wall-clock time per attack stage (hashcat ``--runtime``).
- Memory-hard modes (``vram_heavy``) get a warning instead of silently stalling.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from textolit.hashtypes import MODES, ModeInfo

RULE_DIRS = (
    "/usr/share/hashcat/rules",
    "/usr/share/doc/hashcat/rules",
    "/usr/local/share/hashcat/rules",
)
# best64 was renamed best66 in newer hashcat releases
RULE_NAMES = ("best66.rule", "best64.rule")


class BudgetError(ValueError):
    pass


def parse_budget(text: str | None) -> int | None:
    """``90m`` -> 5400. Accepts s, m, h, d suffixes. Plain numbers are seconds. 0 or None = none."""
    if text is None or str(text).strip() in ("", "0"):
        return None
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", str(text).strip().lower())
    if not m:
        raise BudgetError(f"bad --gpu-budget {text!r}: use forms like 90m, 2h, 3600")
    seconds = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if seconds <= 0:
        raise BudgetError("--gpu-budget must be positive")
    return seconds


@dataclass(frozen=True)
class Profile:
    binary: str = "hashcat"
    workload: int = 2
    optimized: bool | None = None  # None = auto: only for fast hash modes
    temp_abort: int = 85
    keep_vram_free: int = 10
    status_timer: int = 5
    devices: str | None = None
    budget_seconds: int | None = None


@dataclass(frozen=True)
class Attack:
    kind: str  # wordlist or mask
    label: str
    wordlist: str | None = None
    rules: str | None = None
    mask: str | None = None
    increment: tuple[int, int] | None = None

    def to_json(self) -> dict[str, object]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass(frozen=True)
class Plan:
    attacks: list[Attack]
    warnings: list[str] = field(default_factory=list)


def default_passwords_text() -> str:
    return (resources.files("textolit.data") / "default_passwords.txt").read_text("utf-8")


def find_rules() -> str | None:
    for d in RULE_DIRS:
        for name in RULE_NAMES:
            if (Path(d) / name).is_file():
                return str(Path(d) / name)
    return None


def mode_info(mode: int) -> ModeInfo:
    return MODES.get(mode, ModeInfo(mode, f"mode {mode}", "medium"))


def plan_attacks(
    mode: int,
    *,
    default_list: str,
    wordlist: str | None = None,
    rules: str | None = None,
    masks: bool = True,
) -> Plan:
    """Ordered, cheapest first: IoT default passwords, then a user wordlist, then digit masks."""
    info = mode_info(mode)
    warnings: list[str] = []
    if info.vram_heavy:
        warnings.append(
            f"{info.name} is memory-hard: expect very low speed on a 4 GB card, "
            "so only the default list is queued"
        )
    attacks = [Attack("wordlist", "default IoT passwords", wordlist=default_list)]
    if info.vram_heavy:
        return Plan(attacks, warnings)
    if wordlist:
        attacks.append(Attack("wordlist", "wordlist", wordlist=wordlist))
        r = rules or find_rules()
        if r:
            attacks.append(Attack("wordlist", "wordlist + rules", wordlist=wordlist, rules=r))
        elif rules is None:
            warnings.append("no best64/best66 rule file found: skipping the rules stage")
    if masks:
        top = {"fast": 8, "medium": 7, "slow": 6}.get(info.speed, 6)
        attacks.append(Attack("mask", f"digits 4-{top}", mask="?d" * top, increment=(4, top)))
    if info.speed == "slow":
        warnings.append(f"{info.name} is slow: keep wordlists short and set --gpu-budget")
    return Plan(attacks, warnings)


def build_command(
    profile: Profile,
    *,
    mode: int,
    hashfile: str,
    outfile: str,
    potfile: str,
    session: str,
    attack: Attack,
    restore_file: str,
    restore: bool = False,
) -> list[str]:
    if restore:
        return [
            profile.binary,
            "--session",
            session,
            "--restore",
            "--restore-file-path",
            restore_file,
            "--potfile-path",
            potfile,
            "--status",
            "--status-json",
            "--status-timer",
            str(profile.status_timer),
        ]
    info = mode_info(mode)
    optimized = profile.optimized if profile.optimized is not None else info.speed == "fast"
    argv = [
        profile.binary,
        "-m",
        str(mode),
        "-a",
        "0" if attack.kind == "wordlist" else "3",
        "-w",
        str(profile.workload),
        "--session",
        session,
        "--restore-file-path",
        restore_file,
        "--potfile-path",
        potfile,
        "-o",
        outfile,
        "--outfile-format",
        "1,2",
        "--status",
        "--status-json",
        "--status-timer",
        str(profile.status_timer),
        "--hwmon-temp-abort",
        str(profile.temp_abort),
        "--backend-devices-keepfree",
        str(profile.keep_vram_free),
    ]
    if optimized:
        argv.append("-O")
    if profile.budget_seconds:
        argv += ["--runtime", str(profile.budget_seconds)]
    if profile.devices:
        argv += ["-d", profile.devices]
    if attack.increment:
        argv += [
            "--increment",
            "--increment-min",
            str(attack.increment[0]),
            "--increment-max",
            str(attack.increment[1]),
        ]
    if attack.rules and attack.kind == "wordlist":
        argv += ["-r", attack.rules]
    target = attack.wordlist if attack.kind == "wordlist" else attack.mask
    if not target:
        raise ValueError(f"attack {attack.label!r} has no wordlist or mask")
    return [*argv, hashfile, target]


def hashcat_available(binary: str = "hashcat") -> bool:
    return shutil.which(binary) is not None
