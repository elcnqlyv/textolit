from pathlib import Path

from textolit.core.case import Case
from textolit.core.ledger import add_artifact
from textolit.modules.fswalk import FsWalk
from textolit.modules.netmap import (
    NetMap,
    is_nonstandard,
    parse_config,
    parse_credentials,
    parse_inetd,
    parse_init_line,
    parse_systemd,
    parse_xinetd,
)


def ports(eps: list) -> set[tuple[int, str]]:  # type: ignore[type-arg]
    return {(e.port, e.service) for e in eps}


def test_init_lines() -> None:
    assert ports(parse_init_line("telnetd -l /bin/sh -p 23456 &", 1)) == {(23456, "telnetd")}
    # no -p: default port is assumed and says so
    eps = parse_init_line("/usr/sbin/telnetd", 2)
    assert ports(eps) == {(23, "telnetd")} and "default port assumed" in eps[0].evidence
    assert ports(parse_init_line("dropbear -p 2222 -B", 3)) == {(2222, "dropbear")}
    assert ports(parse_init_line("tcpsvd 0 9527 telnetd -l /bin/sh", 4)) == {(9527, "telnetd")}
    nc = parse_init_line("nc -l -p 4444 -e /bin/sh &", 5)
    assert nc[0].port == 4444 and nc[0].service == "nc-listener-shell"
    assert ports(
        parse_init_line("start-stop-daemon -S -x /usr/sbin/lighttpd -- -f /etc/l.conf -p 8088", 6)
    ) == {(8088, "lighttpd")}
    assert ports(parse_init_line("[ -x /sbin/telnetd ] && /sbin/telnetd -p 2323", 7)) == {
        (2323, "telnetd")
    }


def test_init_lines_ignore_noise() -> None:
    for line in ("# telnetd -p 23", "killall telnetd", "echo telnetd -p 99", "which httpd", ""):
        assert parse_init_line(line, 1) == []


def test_iptables_accept_and_drop() -> None:
    acc = parse_init_line("iptables -A INPUT -p tcp --dport 9000 -j ACCEPT", 1)
    drop = parse_init_line("iptables -A INPUT -p tcp --dport 23 -j DROP", 2)
    assert acc[0].port == 9000 and acc[0].default_on and acc[0].kind == "firewall"
    assert drop[0].port == 23 and not drop[0].default_on


def test_inetd_xinetd_systemd() -> None:
    inetd = (
        "# c\ntelnet stream tcp nowait root /usr/sbin/telnetd telnetd\n"
        "34567 stream tcp4 nowait root /bin/x x\n"
    )
    assert ports(parse_inetd(inetd)) == {(23, "telnet"), (34567, "34567")}
    x = "service rsh\n{\n port = 514\n protocol = tcp\n disable = yes\n}\n"
    ep = parse_xinetd(x)[0]
    assert ep.port == 514 and not ep.default_on
    unit = (
        "[Socket]\nListenStream=0.0.0.0:7001\nListenDatagram=5000\n"
        "[Service]\nExecStart=/usr/sbin/uhttpd -p 8081\n"
    )
    assert {e.port for e in parse_systemd(unit)} == {7001, 5000, 8081}


def test_config_ports_and_false_friends() -> None:
    text = "\n".join(
        [
            "http_port=8000",
            "rtspPort = 554",
            "Listen 8080",
            '"onvifPort": 3702',
            "<HttpsPort>443</HttpsPort>",
            "support_level=3",
            "remote_port=9999",
            "# port=1234",
            "transport = 80",
        ]
    )
    assert {e.port for e in parse_config(text)} == {8000, 554, 8080, 3702, 443}


def test_credentials_parse() -> None:
    text = "username=admin\npassword=12345\npasswd=$PW\npassword=\nsecret = 'abcd'\n# password=no"
    found = parse_credentials(text)
    assert [(u, s) for u, s, _l, _e in found] == [("admin", "12345"), (None, "abcd")]


def test_nonstandard() -> None:
    assert is_nonstandard(23456) and not is_nonstandard(80) and not is_nonstandard(8080)


def test_module_end_to_end(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "c")
    root = case.extract_dir / "image1" / "squashfs-root"
    (root / "etc/init.d").mkdir(parents=True)
    (root / "etc/init.d/rcS").write_text(
        "#!/bin/sh\ntelnetd -p 23456 &\nnc -l -p 4444 -e /bin/sh &\n"
    )
    (root / "etc/app.conf").write_text("http_port=80\nuser=admin\npassword=admin\n")
    add_artifact(case, "fs_root:squashfs", root, hash_it=False)
    FsWalk().run(case)
    res = NetMap().run(case)
    assert res.ok, res.errors
    listen = {(t["port"], t["service"]) for t in res.data["table"]}
    assert {(23456, "telnetd"), (4444, "nc-listener-shell"), (80, "http_port")} <= listen
    titles = [r["title"] for r in case.conn.execute("SELECT title FROM findings")]
    assert any("23456" in t for t in titles) and any("netcat listener" in t for t in titles)
    cred = case.conn.execute("SELECT * FROM credentials").fetchone()
    assert (cred["username"], cred["secret"]) == ("admin", "admin")
    # re-run is idempotent
    NetMap().run(case)
    assert case.conn.execute("SELECT count(*) FROM network_endpoints").fetchone()[0] == len(listen)
    assert case.conn.execute("SELECT count(*) FROM findings").fetchone()[0] == len(titles)
