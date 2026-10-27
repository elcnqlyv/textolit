import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from textolit.core.case import Case
from textolit.core.ledger import add_artifact
from textolit.modules.crypto import (
    Crypto,
    parse_cert_text,
    parse_htpasswd,
    parse_key_strings,
    parse_private_keys,
    parse_shadow,
    scan_sqlite,
    weak_signature,
)
from textolit.modules.fswalk import FsWalk

MD5C = "$1$abcdefgh$" + "a" * 22
SHA512C = "$6$saltsalt$" + "b" * 86


def test_parse_shadow_skips_locked_and_shadowed() -> None:
    text = f"root:{MD5C}:0:0:::\ndaemon:*:0:0\nbin:!:0\nnobody:x:65534:65534\nadmin:{SHA512C}:1\n"
    rows = parse_shadow(text)
    assert [(r.username, r.line) for r in rows] == [("root", 1), ("admin", 5)]


def test_parse_htpasswd_and_uhttpd() -> None:
    text = f"# c\nalice:{MD5C}\nbob:{{SHA}}{'A' * 27}=\n/cgi-bin:admin:{MD5C}\nbad:short\n"
    users = [r.username for r in parse_htpasswd(text)]
    assert users == ["alice", "bob", "admin"]


def test_scan_sqlite(tmp_path: Path) -> None:
    db = tmp_path / "users.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE users (username TEXT, password TEXT, note TEXT)")
    con.execute("INSERT INTO users VALUES ('admin', ?, 'x'), ('guest', 'plain', 'y')", (MD5C,))
    con.commit()
    con.close()
    rows = scan_sqlite(db)
    assert [(r.username, r.value) for r in rows] == [("admin", MD5C)]
    assert scan_sqlite(tmp_path / "missing.db") == []


def test_private_keys_store_fingerprint_not_body() -> None:
    pem = "x\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----\n"
    keys = parse_private_keys(pem)
    assert keys[0]["algo"] == "RSA" and keys[0]["encrypted"] and keys[0]["line"] == 2
    assert "abc" not in str(keys)


def test_key_strings() -> None:
    text = 'aes_key = "00112233445566778899aabbccddeeff"\napi_key=aaaaaaaaaaaaaaaaaaaa\n# secret_key=0123456789abcdef0123\n'
    found = parse_key_strings(text)
    assert [(n, line) for n, _v, line in found] == [("aes_key", 1)]


def test_cert_text_parse() -> None:
    text = """
        Signature Algorithm: md5WithRSAEncryption
        Issuer: CN=cam
            Not After : Jan  1 00:00:00 2015 GMT
        Subject: CN=cam
            Public Key Algorithm: rsaEncryption
                Public-Key: (512 bit)
sha256 Fingerprint=AA:BB
"""
    info = parse_cert_text(text)
    assert info["expired"] and info["self_signed"] and info["key_bits"] == 512
    assert weak_signature(info["sig_algo"]) and not weak_signature("sha256WithRSAEncryption")


def build(tmp: Path) -> Case:
    case = Case.create(tmp / "c")
    r = case.extract_dir / "image1" / "squashfs-root"
    (r / "etc/ssl").mkdir(parents=True)
    (r / "www").mkdir()
    (r / "etc/shadow").write_text(f"root:{MD5C}:0:0:::\ndaemon:*:0:0\n")
    (r / "www/.htpasswd").write_text(f"admin:{SHA512C}\n")
    (r / "etc/app.conf").write_text('aes_key="00112233445566778899aabbccddeeff"\n')
    con = sqlite3.connect(r / "etc/users.db")
    con.execute("CREATE TABLE u (login TEXT, pwd TEXT)")
    con.execute("INSERT INTO u VALUES ('op', ?)", ("5f4dcc3b5aa765d61d8327deb882cf99",))
    con.commit()
    con.close()
    add_artifact(case, "fs_root:squashfs", r, hash_it=False)
    return case


def test_module_extracts_and_records(tmp_path: Path) -> None:
    case = build(tmp_path)
    assert FsWalk().run(case).ok
    res = Crypto().run(case)
    assert res.ok, res.errors
    assert res.data["hashes"] == 3 and res.data["key_strings"] == 1
    mats = {
        (r["username"], r["algo"], r["hashcat_mode"])
        for r in case.conn.execute("SELECT * FROM crypto_materials WHERE kind='hash'")
    }
    assert mats == {("root", "md5crypt", 500), ("admin", "sha512crypt", 1800), ("op", "md5", 0)}
    assert (
        case.conn.execute("SELECT count(*) FROM credentials WHERE secret_kind='hash'").fetchone()[0]
        == 3
    )
    titles = [r[0] for r in case.conn.execute("SELECT title FROM findings")]
    assert any("md5crypt password hash for 'root'" in t for t in titles)
    # idempotent
    Crypto().run(case)
    assert (
        case.conn.execute("SELECT count(*) FROM crypto_materials WHERE kind='hash'").fetchone()[0]
        == 3
    )
    assert case.conn.execute("SELECT count(*) FROM findings").fetchone()[0] == len(titles)


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
def test_real_certificate(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    r = case.extract_dir / "image1" / "squashfs-root"
    (r / "etc").mkdir(parents=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:1024",
            "-sha1",
            "-nodes",
            "-keyout",
            str(tmp_path / "k.pem"),
            "-out",
            str(r / "etc/server.crt"),
            "-days",
            "30",
            "-subj",
            "/CN=cam.local",
        ],
        check=True,
        capture_output=True,
    )
    add_artifact(case, "fs_root:squashfs", r, hash_it=False)
    FsWalk().run(case)
    res = Crypto().run(case)
    assert res.data["certs"] == 1
    t = case.conn.execute(
        "SELECT title FROM findings WHERE heuristic_id='crypto.cert-weak'"
    ).fetchone()
    assert t and "sha1WithRSAEncryption" in t[0] and "1024-bit" in t[0]
