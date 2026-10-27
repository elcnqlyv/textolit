import pytest

from textolit.cvss import (
    SUGGESTED,
    VectorError,
    base_score,
    full_vector,
    roundup,
    severity,
    suggest,
)

KNOWN = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
]


@pytest.mark.parametrize(("vector", "score"), KNOWN)
def test_known_scores(vector: str, score: float) -> None:
    assert base_score(vector) == score


def test_roundup_follows_spec() -> None:
    assert roundup(4.02) == 4.1 and roundup(4.0) == 4.0 and roundup(0.1 + 0.2) == 0.3


def test_severity_bands() -> None:
    assert [severity(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)] == [
        "None",
        "Low",
        "Low",
        "Medium",
        "Medium",
        "High",
        "High",
        "Critical",
        "Critical",
    ]


@pytest.mark.parametrize(
    "bad", ["", "AV:N", "AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:2.0/AV:N"]
)
def test_bad_vectors(bad: str) -> None:
    with pytest.raises(VectorError):
        base_score(bad)


def test_suggestions_are_valid_vectors() -> None:
    for hid, vec in SUGGESTED.items():
        assert base_score(vec) > 0, hid
    assert suggest("binintel.version-hint") is None and suggest(None) is None
    assert full_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").startswith("CVSS:3.1/")
