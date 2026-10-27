from pathlib import Path

from textolit.core.case import Case
from textolit.core.ledger import add_artifact
from textolit.modules.fswalk import FsWalk
from textolit.modules.websurface import (
    WebSurface,
    decode_basic,
    parse_binary_strings,
    parse_front_end,
    parse_roots,
    parse_server_config,
    web_root_of,
)

LOGIN = """<html><body>
<form action="/cgi-bin/login.cgi" method="post">
<input type="text" name="username" value="admin">
<input type="password" name="password" value="admin123">
</form>
<script>
var h = hex_md5(password);
$.ajax({url: "/cgi-bin/get_status.cgi", type: "POST"});
var req = new XMLHttpRequest(); req.open("GET", "/api/status");
req.setRequestHeader("Authorization", "Basic YWRtaW46YWRtaW4=");
</script></body></html>
"""
UPLOAD = (
    '<form action="/cgi-bin/fwupload.cgi" method="post" enctype="multipart/form-data">'
    '<input type="file" name="fw"></form>'
)


def test_web_root_of() -> None:
    assert web_root_of("/usr/www/index.html") == "/usr/www"
    assert web_root_of("/mnt/mtd/webs/a/b.html") == "/mnt/mtd/webs"
    assert web_root_of("/etc/passwd") is None


def test_parse_front_end() -> None:
    items = parse_front_end(LOGIN)
    got = {(i.category, i.key, i.value) for i in items}
    assert ("endpoint", "/cgi-bin/login.cgi", "POST") in got
    assert ("endpoint", "/cgi-bin/get_status.cgi", "POST") in got
    assert ("endpoint", "/api/status", "GET") in got
    assert ("auth", "html-form-login", "/cgi-bin/login.cgi") in got
    assert ("auth", "client-side-hash", "hex_md5") in got
    assert ("auth", "js-basic-auth", "") in got
    assert ("credential", "prefilled-password", "admin123") in got
    assert ("credential", "prefilled-username", "admin") in got
    assert ("credential", "basic-auth-header", "admin:admin") in got
    up = [i for i in parse_front_end(UPLOAD) if i.category == "upload"]
    assert up and up[0].key == "/cgi-bin/fwupload.cgi"


def test_decode_basic_rejects_binary() -> None:
    assert decode_basic("YWRtaW46YWRtaW4=") == "admin:admin"
    assert decode_basic("AAAAAAAAAAAA") is None


def test_server_config_and_roots() -> None:
    conf = (
        'server.document-root = "/www"\nserver.modules = ("mod_auth")\nauth.backend = "htpasswd"\n'
    )
    assert [i.key for i in parse_roots(conf)] == ["/www"]
    keys = {i.key for i in parse_server_config("/etc/lighttpd.conf", conf)}
    assert {"lighttpd-mod_auth", "lighttpd-auth-htpasswd"} <= keys
    uh = parse_server_config("/etc/httpd.conf", "/cgi-bin:admin:$1$abcdefgh$" + "a" * 22 + "\n")
    assert uh[0].key == "httpd.conf-basic-auth" and "***" in uh[0].evidence


def test_binary_strings() -> None:
    blob = b'\x00Server: Boa/0.94.14rc21\x00WWW-Authenticate: Basic realm="IPCamera"\x00'
    items = {(i.category, i.key, i.value) for i in parse_binary_strings(blob)}
    assert ("server", "Server header", "Boa/0.94.14rc21") in items
    assert ("auth", "http-basic", "IPCamera") in items


def build(tmp: Path) -> Case:
    case = Case.create(tmp / "c")
    r = case.extract_dir / "image1" / "squashfs-root"
    for d in ("www/cgi-bin", "www/js", "etc", "usr/sbin"):
        (r / d).mkdir(parents=True)
    (r / "www/index.html").write_text(LOGIN)
    (r / "www/upload.html").write_text(UPLOAD)
    (r / "www/cgi-bin/login.cgi").write_text("#!/bin/sh\n")
    (r / "www/cgi-bin/fwupload.cgi").write_text("#!/bin/sh\n")
    (r / "www/js/app.js").write_text('var password = "letmein";\n')
    (r / "etc/lighttpd.conf").write_text(
        'server.document-root = "/www"\nauth.backend = "htpasswd"\n'
    )
    (r / "usr/sbin/boa").write_bytes(
        b'\x7fELF\x00Server: Boa/0.94.14rc21\x00WWW-Authenticate: Basic realm="IPCamera"\x00'
    )
    add_artifact(case, "fs_root:squashfs", r, hash_it=False)
    return case


def rows(case: Case, category: str) -> set[tuple[str, str]]:
    q = "SELECT key, value FROM web_surface WHERE category=?"
    return {(r["key"], r["value"]) for r in case.conn.execute(q, (category,))}


def test_module(tmp_path: Path) -> None:
    case = build(tmp_path)
    FsWalk().run(case)
    res = WebSurface().run(case)
    assert res.ok, res.errors
    assert "boa" in res.data["servers"] and "lighttpd" in res.data["servers"]
    assert ("/www", "directory name") in rows(case, "root") and ("/www", "declared") in rows(
        case, "root"
    )
    eps = {k for k, _v in rows(case, "endpoint")}
    assert {"/index.html", "/cgi-bin/login.cgi", "/cgi-bin/get_status.cgi", "/api/status"} <= eps
    uploads = {k for k, _v in rows(case, "upload")}
    assert "/cgi-bin/fwupload.cgi" in uploads
    auth = {k for k, _v in rows(case, "auth")}
    assert {"html-form-login", "http-basic", "lighttpd-auth-htpasswd", "client-side-hash"} <= auth

    titles = [r["title"] for r in case.conn.execute("SELECT title FROM findings")]
    assert any("Upload or firmware handler" in t for t in titles)
    assert any("Basic auth header with embedded credentials for 'admin'" in t for t in titles)
    assert any("pre-filled password" in t for t in titles)
    assert any("Login logic in the browser" in t for t in titles)
    creds = {
        (r["username"], r["secret"])
        for r in case.conn.execute("SELECT * FROM credentials WHERE algo='web'")
    }
    assert ("admin", "admin") in creds and (None, "letmein") in creds
    # idempotent
    n = case.conn.execute("SELECT count(*) FROM web_surface").fetchone()[0]
    f = case.conn.execute("SELECT count(*) FROM findings").fetchone()[0]
    WebSurface().run(case)
    assert case.conn.execute("SELECT count(*) FROM web_surface").fetchone()[0] == n
    assert case.conn.execute("SELECT count(*) FROM findings").fetchone()[0] == f
