import pytest

from textolit.hashtypes import MODES, classify_hash, is_locked

CASES = [
    ("$1$abcdefgh$" + "a" * 22, "md5crypt", 500),
    ("$apr1$abcdefgh$" + "b" * 22, "apr1", 1600),
    ("$5$saltsalt$" + "c" * 43, "sha256crypt", 7400),
    ("$6$rounds=5000$saltsalt$" + "d" * 86, "sha512crypt", 1800),
    ("$2y$10$" + "e" * 53, "bcrypt", 3200),
    ("{SHA}" + "A" * 27 + "=", "sha1-base64", 101),
    ("{SSHA}" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", "ssha1-base64", 111),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "md5", 0),
    ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "sha1", 100),
    ("a" * 64, "sha256", 1400),
    ("b" * 128, "sha512", 1700),
    ("ab1CdEfGhIjKl", "des-crypt", 1500),
]


@pytest.mark.parametrize(("value", "algo", "mode"), CASES)
def test_classify(value: str, algo: str, mode: int) -> None:
    g = classify_hash(value)
    assert g is not None and (g.algo, g.mode) == (algo, mode)
    assert mode in MODES


def test_ambiguous_md5_lists_candidates() -> None:
    g = classify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert g is not None and g.confidence == "med" and 1000 in g.candidates


def test_yescrypt_has_no_mode() -> None:
    g = classify_hash("$y$j9T$abc$def")
    assert g is not None and g.mode is None and g.info is None


@pytest.mark.parametrize(
    "value", ["", "*", "!", "x", "!!", "*LK*", "!$1$abc$def", "hello world", "short"]
)
def test_rejects_non_hashes(value: str) -> None:
    assert classify_hash(value) is None


def test_locked() -> None:
    assert is_locked("!") and is_locked("*") and not is_locked("$1$a$b")
