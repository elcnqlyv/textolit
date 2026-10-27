import pytest

from textolit.hashcat import (
    Attack,
    BudgetError,
    Profile,
    build_command,
    default_passwords_text,
    parse_budget,
    plan_attacks,
)


def test_parse_budget() -> None:
    assert parse_budget("90m") == 5400 and parse_budget("2h") == 7200
    assert (
        parse_budget("3600") == 3600 and parse_budget("45s") == 45 and parse_budget("1d") == 86400
    )
    assert parse_budget(None) is None and parse_budget("0") is None
    for bad in ("fast", "-5m", "1.5h", "m"):
        with pytest.raises(BudgetError):
            parse_budget(bad)


def test_default_profile_is_w2_and_gtx1650_safe() -> None:
    argv = build_command(
        Profile(),
        mode=0,
        hashfile="h.txt",
        outfile="o.txt",
        potfile="p.pot",
        session="s1",
        restore_file="r.restore",
        attack=Attack("wordlist", "l", wordlist="w.txt"),
    )
    assert argv[:7] == ["hashcat", "-m", "0", "-a", "0", "-w", "2"]
    assert "-O" in argv  # fast hash: optimized kernels
    assert argv[argv.index("--hwmon-temp-abort") + 1] == "85"
    assert argv[argv.index("--backend-devices-keepfree") + 1] == "10"
    assert "--status-json" in argv and "--runtime" not in argv
    assert argv[-2:] == ["h.txt", "w.txt"]


def test_slow_modes_skip_optimized_and_budget_sets_runtime() -> None:
    argv = build_command(
        Profile(budget_seconds=1800, devices="1", workload=3),
        mode=1800,
        hashfile="h",
        outfile="o",
        potfile="p",
        session="s",
        restore_file="r",
        attack=Attack("mask", "m", mask="?d?d?d?d", increment=(4, 4)),
    )
    assert "-O" not in argv and argv[argv.index("-w") + 1] == "3"
    assert argv[argv.index("--runtime") + 1] == "1800" and argv[argv.index("-d") + 1] == "1"
    assert "--increment" in argv and argv[-2:] == ["h", "?d?d?d?d"]
    assert argv[argv.index("-a") + 1] == "3"


def test_restore_command() -> None:
    argv = build_command(
        Profile(),
        mode=0,
        hashfile="h",
        outfile="o",
        potfile="p",
        session="s9",
        attack=Attack("wordlist", "l", wordlist="w"),
        restore=True,
        restore_file="s9.restore",
    )
    assert argv[:6] == [
        "hashcat",
        "--session",
        "s9",
        "--restore",
        "--restore-file-path",
        "s9.restore",
    ]
    assert "--status-json" in argv


def test_plan_orders_cheap_first_and_warns() -> None:
    plan = plan_attacks(1800, default_list="d.txt", wordlist="big.txt", rules="r.rule")
    assert [a.label for a in plan.attacks] == [
        "default IoT passwords",
        "wordlist",
        "wordlist + rules",
        "digits 4-6",
    ]
    assert any("slow" in w for w in plan.warnings)
    heavy = plan_attacks(8900, default_list="d.txt", wordlist="big.txt")
    assert [a.label for a in heavy.attacks] == ["default IoT passwords"]
    assert any("memory-hard" in w for w in heavy.warnings)
    assert plan_attacks(0, default_list="d.txt").attacks[-1].increment == (4, 8)


def test_default_list_has_known_iot_credentials() -> None:
    words = set(default_passwords_text().split())
    assert {"admin", "12345", "xc3511", "vizxv"} <= words
