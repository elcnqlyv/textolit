import os
from pathlib import Path

from textolit.core.case import Case
from textolit.core.ledger import add_artifact
from textolit.modules.fswalk import FsWalk
from textolit.modules.missedfindings import MissedFindings, load_builtin_rules


def test_builtin_packs_load_and_ids_unique() -> None:
    rules = load_builtin_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)) and len(ids) >= 20
    assert {r.pack for r in rules} == {"creds", "files", "services"}


def fixture(tmp: Path) -> Case:
    case = Case.create(tmp / "c")
    r = case.extract_dir / "image1" / "squashfs-root"
    for d in ("etc/init.d", "www/cgi-bin", "usr/lib", "tmp", "mnt/mtd"):
        (r / d).mkdir(parents=True)
    (r / "etc/passwd").write_text("root::0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/bin/false\n")
    (r / "etc/shadow").write_text(
        "admin:$1$abcdefgh$abcdefghijklmnopqrstuv:0:0:99999:7:::\nold:ab1CdEfGhIjKl:0:0::::\n"
    )
    (r / "etc/inittab").write_text("::sysinit:/etc/init.d/rcS\nttyS0::askfirst:-/bin/sh\n")
    (r / "etc/init.d/rcS").write_text(
        "#!/bin/sh\ntelnetd -l /bin/sh &\ndropbear -B -p 22 &\n# telnetd old\nkillall telnetd\n"
    )
    (r / "etc/app.conf").write_text(
        "user=admin\npassword=letmein\nupdate=8.8.4.4\nlan=10.0.0.1\n"
    )
    (r / "etc/ssl.conf").write_text("ssl_verify = 0\nciphers = RC4-SHA\n")
    (r / "etc/creds.txt").write_text("admin:admin\n")
    (r / "etc/k.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    (r / "www/index.html").write_text("<html>ok</html>")
    (r / "www/cgi-bin/debug.cgi").write_text("#!/bin/sh\n")
    (r / "www/tool.elf").write_bytes(b"\x7fELF" + os.urandom(100))
    (r / "www/cgi-bin/ok.elf").write_bytes(b"\x7fELF" + os.urandom(100))
    (r / "www/photo.jpg.cgi").write_text("#!/bin/sh\n")
    (r / "mnt/mtd/payload").write_bytes(b"\x7fELF" + os.urandom(100))
    # libraries are skipped on purpose; the same string in a daemon must hit
    (r / "usr/lib/libx.so").write_bytes(b"\x7fELF" + b"backdoor" + os.urandom(100))
    (r / "usr/sbin").mkdir(parents=True)
    (r / "usr/sbin/svcd").write_bytes(b"\x7fELF\x00debug_shell\x00" + os.urandom(100))
    (r / "usr/bin").mkdir(parents=True)
    (r / "usr/bin/suid").write_bytes(b"\x7fELF" + os.urandom(20))
    (r / "usr/bin/suid").chmod(0o4755)
    (r / "etc/wr.conf").write_text("x")
    (r / "etc/wr.conf").chmod(0o666)
    add_artifact(case, "fs_root:squashfs", r, hash_it=False)
    FsWalk().run(case)
    return case


def test_packs_fire_on_fixture(tmp_path: Path) -> None:
    case = fixture(tmp_path)
    res = MissedFindings().run(case)
    assert res.ok, res.errors
    hits: dict[str, set[str]] = {}
    for f in case.conn.execute("SELECT heuristic_id, evidence_path FROM findings"):
        hits.setdefault(f[0], set()).add(f[1].rsplit("/", 1)[-1])
    expect = {
        "creds.empty-password-field": {"passwd"},
        "creds.default-pair": {"creds.txt"},
        "creds.plaintext-password": {"app.conf"},
        "creds.private-key": {"k.pem"},
        "crypto.md5-crypt-hash": {"shadow"},
        "crypto.des-crypt-hash": {"shadow"},
        "crypto.weak-algorithm-config": {"ssl.conf"},
        "crypto.tls-verify-disabled": {"ssl.conf"},
        "svc.telnetd-start": {"rcS"},
        "svc.dropbear-blank-password": {"rcS"},
        "svc.console-shell-inittab": {"inittab"},
        "backdoor.suspicious-strings": {"svcd"},
        "backdoor.debug-endpoint-name": {"debug.cgi"},
        "perm.world-writable": {"wr.conf"},
        "perm.setuid": {"suid"},
        "file.double-extension": {"photo.jpg.cgi"},
        "bin.elf-in-webroot": {"tool.elf"},
        "bin.elf-in-writable-partition": {"payload"},
        "net.hardcoded-public-ip": {"app.conf"},
    }
    for rid, files in expect.items():
        assert hits.get(rid) == files, (rid, hits.get(rid))
    # commented-out and kill lines must not count as telnetd start-up lines
    lines = [
        r["line"]
        for r in case.conn.execute(
            "SELECT e.line FROM evidence_links e JOIN findings f ON f.id=e.finding_id"
            " WHERE f.heuristic_id='svc.telnetd-start'"
        )
    ]
    assert lines == [2]
    assert "pending review" in res.summary
