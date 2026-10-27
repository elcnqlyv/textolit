"""netmap: what does this firmware listen on by default, and where is that stated?

Parses init scripts, inetd/xinetd, systemd units, iptables lines and config files.
Every endpoint carries its source file, line and the matching text so each row can be
checked by hand. Config-file ports are leads (a port number in a config is not proof
that anything binds it); init-script and inetd entries are stronger evidence.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import add_finding, ensure_heuristic, fs_roots
from textolit.modules.base import ModuleResult, ProgressFn, no_progress

SERVICE_PORTS = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "tftp": 69,
    "http": 80,
    "www": 80,
    "pop3": 110,
    "ntp": 123,
    "snmp": 161,
    "https": 443,
    "rtsp": 554,
    "sip": 5060,
    "microsoft-ds": 445,
    "netbios-ns": 137,
    "netbios-ssn": 139,
    "syslog": 514,
    "echo": 7,
    "discard": 9,
    "daytime": 13,
    "time": 37,
    "finger": 79,
}
DAEMON_PORTS = {
    "telnetd": 23,
    "dropbear": 22,
    "sshd": 22,
    "httpd": 80,
    "lighttpd": 80,
    "boa": 80,
    "mini_httpd": 80,
    "thttpd": 80,
    "uhttpd": 80,
    "goahead": 80,
    "nginx": 80,
    "ftpd": 21,
    "vsftpd": 21,
    "tftpd": 69,
    "snmpd": 161,
    "miniupnpd": 1900,
    "upnpd": 1900,
    "rtspd": 554,
    "smbd": 445,
    "mosquitto": 1883,
}
OTHER_DAEMONS = {"gdbserver", "socat", "inetd", "xinetd", "dnsmasq", "udhcpd", "onvif_server"}
LISTENERS = {"nc", "netcat", "ncat"}
# High ports that are customary enough not to flag on their own.
COMMON_HIGH = {1883, 1900, 3306, 5060, 5353, 5432, 8000, 8008, 8080, 8081, 8443, 8554, 8883, 8888}
SKIP_CMDS = {
    "kill",
    "killall",
    "pkill",
    "which",
    "rm",
    "ls",
    "cat",
    "grep",
    "echo",
    "printf",
    "stop",
    "type",
    "test",
    "chmod",
    "chown",
    "mkdir",
    "touch",
    "ln",
    "cp",
    "mv",
}
PORT_FLAG = re.compile(r"(?:^|\s)(?:-p|-P|-port|--port|-l|--listen)[=\s]*(\d{1,5})(?=\s|$)")
LP_FLAG = re.compile(r"(?:^|\s)-[a-zA-Z]*l[a-zA-Z]*p\s*(\d{1,5})(?=\s|$)")
BIND_COLON = re.compile(r"(?:0\.0\.0\.0|\*|\[::\]):(\d{1,5})\b")
IPT = re.compile(
    r"iptables\s.*?-[AI]\s+(INPUT)\b.*?-p\s+(tcp|udp).*?--dports?\s+(\d{1,5})(?:[:,]\S*)?"
    r".*?-j\s+(ACCEPT|DROP|REJECT)"
)
FALSE_FRIENDS = (
    "support",
    "report",
    "transport",
    "export",
    "import",
    "portal",
    "passport",
    "airport",
    "deport",
    "portable",
    "purport",
)
CLIENT_KEYS = (
    "remote",
    "dst",
    "dest",
    "peer",
    "proxy",
    "upstream",
    "target",
    "client",
    "smtp",
    "mail",
    "stun",
    "ddns",
    "ntp",
    "cloud",
    "src_port",
    "dport",
)
CONF_PORT = re.compile(
    r"""^\s*(?:listen\s+|port\s+)?["']?([\w.\-]*[Pp][Oo][Rr][Tt][\w.\-]*)["']?\s*[=:]?\s*["']?(\d{1,5})["']?\s*[;,]?\s*(?:#.*)?$"""
    r"""|^\s*(Listen|listen|Port)\s+(\d{1,5})\b"""
    r"""|<(\w*[Pp]ort\w*)>\s*(\d{1,5})\s*</"""
)
USER_RE = re.compile(r"""(?i)\b(?:user(?:name)?|login|admin_?name)\s*[=:]\s*["']?([^\s"';<>,]+)""")
PASS_RE = re.compile(r"""(?i)\b(?:pass(?:word|wd)?|pwd|secret)\s*[=:]\s*["']?([^\s"';<>,]{1,64})""")
PLACEHOLDER_START = ("$", "%", "{", "<", "(", "*", "?", "@", "[")
PLACEHOLDER_WORDS = {"x", "null", "none", "nil", "true", "false", "yes", "no", "", "0", "1"}


@dataclass(frozen=True)
class Endpoint:
    port: int
    proto: str
    service: str
    command: str
    line: int
    evidence: str
    kind: str  # init, inetd, xinetd, systemd, firewall, config
    default_on: bool = True
    bind: str | None = None


def is_nonstandard(port: int) -> bool:
    return port > 1024 and port not in COMMON_HIGH


def _valid(port: int) -> bool:
    return 0 < port < 65536


def _split_commands(line: str) -> list[str]:
    line = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
    line = re.sub(r"\s&\s*$", "", line.strip())
    return [c.strip() for c in re.split(r"&&|\|\||;|\|", line) if c.strip()]


def parse_init_line(text: str, lineno: int) -> list[Endpoint]:
    """Parse one shell line for daemons that bind a port, and for iptables ACCEPT rules."""
    out: list[Endpoint] = []
    stripped = text.strip()
    if not stripped or stripped.startswith("#"):
        return out
    m = IPT.search(stripped)
    if m:
        accept = m.group(4) == "ACCEPT"
        out.append(
            Endpoint(
                int(m.group(3)),
                m.group(2),
                "iptables",
                stripped,
                lineno,
                stripped,
                "firewall",
                accept,
            )
        )
    for cmd in _split_commands(stripped):
        toks = cmd.split()
        while toks and (re.match(r"^\w+=\S*$", toks[0]) or toks[0] in ("nohup", "exec", "busybox")):
            toks = toks[1:]
        if not toks:
            continue
        head = posixpath.basename(toks[0])
        args = " ".join(toks[1:])
        if head == "start-stop-daemon":
            exe = re.search(r"(?:-x|--exec|-a)\s+(\S+)", cmd)
            if not exe:
                continue
            head = posixpath.basename(exe.group(1))
            args = cmd.split(" -- ", 1)[1] if " -- " in cmd else ""
        if head in SKIP_CMDS or head.startswith("["):
            continue
        svd = re.match(r"(tcp|udp)svd$", head)
        if svd:
            sm = re.search(r"(?:^|\s)(?:-\S+\s+)*(\S+)\s+(\d{1,5})\s+(\S+)", args)
            if sm and _valid(int(sm.group(2))):
                out.append(
                    Endpoint(
                        int(sm.group(2)),
                        svd.group(1),
                        posixpath.basename(sm.group(3)),
                        cmd,
                        lineno,
                        stripped,
                        "init",
                        True,
                        None if sm.group(1) in ("0", "0.0.0.0") else sm.group(1),
                    )
                )
            continue
        if head in LISTENERS:
            if not re.search(r"(?:^|\s)-[a-zA-Z]*l", args):
                continue
            pm = LP_FLAG.search(" " + args) or PORT_FLAG.search(" " + args)
            if pm and _valid(int(pm.group(1))):
                shell = " -e " in f" {args} " or " -c " in f" {args} "
                ev = stripped + ("   [binds a shell]" if shell else "")
                out.append(
                    Endpoint(
                        int(pm.group(1)),
                        "udp" if " -u" in f" {args}" else "tcp",
                        "nc-listener" + ("-shell" if shell else ""),
                        cmd,
                        lineno,
                        ev,
                        "init",
                    )
                )
            continue
        if head in DAEMON_PORTS or head in OTHER_DAEMONS:
            pm = PORT_FLAG.search(" " + args) or BIND_COLON.search(args)
            if pm:
                port, assumed = int(pm.group(1)), False
            elif head in DAEMON_PORTS:
                port, assumed = DAEMON_PORTS[head], True
            else:
                continue
            if _valid(port):
                ev = stripped + ("   [default port assumed]" if assumed else "")
                out.append(
                    Endpoint(
                        port,
                        "udp" if head in ("tftpd", "snmpd") else "tcp",
                        head,
                        cmd,
                        lineno,
                        ev,
                        "init",
                    )
                )
    return out


def parse_inetd(text: str, services: dict[str, int] | None = None) -> list[Endpoint]:
    ports = {**SERVICE_PORTS, **(services or {})}
    out: list[Endpoint] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        if len(f) < 6:
            continue
        svc, proto = f[0].split("/")[-1] if "/" in f[0] else f[0], f[2].rstrip("46")
        port = int(svc) if svc.isdigit() else ports.get(svc, 0)
        if _valid(port):
            out.append(
                Endpoint(
                    port,
                    proto if proto in ("tcp", "udp") else "tcp",
                    svc,
                    " ".join(f[5:]),
                    n,
                    line,
                    "inetd",
                )
            )
    return out


def parse_xinetd(text: str) -> list[Endpoint]:
    out: list[Endpoint] = []
    for m in re.finditer(r"service\s+(\S+)\s*\{(.*?)\}", text, re.S):
        name, body = m.group(1), m.group(2)
        kv = dict(re.findall(r"^\s*(\w+)\s*=\s*(\S+)", body, re.M))
        port = int(kv["port"]) if kv.get("port", "").isdigit() else SERVICE_PORTS.get(name, 0)
        if not _valid(port):
            continue
        lineno = text[: m.start()].count("\n") + 1
        out.append(
            Endpoint(
                port,
                kv.get("protocol", "tcp"),
                name,
                kv.get("server", ""),
                lineno,
                f"service {name} {{ port={port} disable={kv.get('disable', 'no')} }}",
                "xinetd",
                kv.get("disable", "no").lower() != "yes",
            )
        )
    return out


def parse_systemd(text: str) -> list[Endpoint]:
    out: list[Endpoint] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        sm = re.match(r"Listen(Stream|Datagram)\s*=\s*(?:.*:)?(\d{1,5})$", line)
        if sm and _valid(int(sm.group(2))):
            out.append(
                Endpoint(
                    int(sm.group(2)),
                    "tcp" if sm.group(1) == "Stream" else "udp",
                    "systemd-socket",
                    line,
                    n,
                    line,
                    "systemd",
                )
            )
        em = re.match(r"ExecStart\s*=\s*(.*)", line)
        if em:
            for ep in parse_init_line(em.group(1).lstrip("-@+!"), n):
                out.append(
                    Endpoint(
                        ep.port,
                        ep.proto,
                        ep.service,
                        ep.command,
                        n,
                        line,
                        "systemd",
                        ep.default_on,
                        ep.bind,
                    )
                )
    return out


def parse_config(text: str) -> list[Endpoint]:
    out: list[Endpoint] = []
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith(("#", ";", "//")):
            continue
        m = CONF_PORT.match(raw)
        if not m:
            jm = re.search(r'"(\w*[Pp]ort\w*)"\s*:\s*"?(\d{1,5})"?', raw)
            if not jm:
                continue
            key, val = jm.group(1), jm.group(2)
        else:
            key = m.group(1) or m.group(3) or m.group(5)
            val = m.group(2) or m.group(4) or m.group(6)
        low = key.lower()
        if any(f in low for f in FALSE_FRIENDS) or any(c in low for c in CLIENT_KEYS):
            continue
        if _valid(int(val)):
            out.append(Endpoint(int(val), "tcp", key, raw.strip(), n, raw.strip(), "config"))
    return out


def parse_credentials(text: str) -> list[tuple[str | None, str, int, str]]:
    """(username, secret, line, evidence) for plaintext password assignments."""
    found: list[tuple[str | None, str, int, str]] = []
    last_user: tuple[str, int] | None = None
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith(("#", "//")):
            continue
        um = USER_RE.search(raw)
        if um:
            last_user = (um.group(1), n)
        pm = PASS_RE.search(raw)
        if not pm:
            continue
        val = pm.group(1)
        if val.lower() in PLACEHOLDER_WORDS or val.startswith(PLACEHOLDER_START):
            continue
        user = last_user[0] if last_user and n - last_user[1] <= 3 else None
        found.append((user, val, n, raw.strip()[:200]))
    return found


def load_services_file(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\d+)/(?:tcp|udp)", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


SCRIPT_HINT = re.compile(
    r"(^|/)(rcS|rc\.local|inittab|profile|S\d\d\w*|K\d\d\w*)$|\.sh$|/etc/rc|/init\.d/"
)
WEB_EXT = (".js", ".css", ".html", ".htm", ".png", ".jpg", ".gif", ".svg", ".ico", ".map")


def parse_file(rel: str, text: str, services: dict[str, int]) -> list[Endpoint]:
    base = posixpath.basename(rel)
    out: list[Endpoint] = []
    if base == "inetd.conf":
        return parse_inetd(text, services)
    if base == "xinetd.conf" or "/xinetd.d/" in rel:
        return parse_xinetd(text)
    if base.endswith((".socket", ".service")) and "systemd" in rel:
        return parse_systemd(text)
    if SCRIPT_HINT.search(rel):
        for n, line in enumerate(text.splitlines(), 1):
            out += parse_init_line(line, n)
    out += parse_config(text)
    return out


class NetMap:
    name = "netmap"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        roots = dict(fs_roots(case))
        rows = case.conn.execute(
            "SELECT artifact_id, path, size FROM files WHERE ftype IN ('text','script')"
            " AND is_symlink=0 AND size<=1048576 ORDER BY id"
        ).fetchall()
        if not roots or not rows:
            return ModuleResult(
                self.name, False, "no text files indexed", errors=["run unpack and fswalk first"]
            )
        ensure_heuristic(case, "net.nonstandard-port", "netmap", "High non-standard port", "medium")
        ensure_heuristic(case, "net.nc-listener", "netmap", "netcat listener at boot", "high")

        services: dict[str, int] = {}
        for r in rows:
            if r["path"] == "/etc/services":
                services = load_services_file(
                    (roots[r["artifact_id"]] / "etc/services").read_text("utf-8", "replace")
                )
        with case.conn:
            case.conn.execute("DELETE FROM network_endpoints")
            case.conn.execute("DELETE FROM services")
            case.conn.execute("DELETE FROM credentials WHERE algo='config'")

        seen: set[tuple[Any, ...]] = set()
        table: list[dict[str, Any]] = []
        creds = 0
        for i, r in enumerate(rows):
            if r["path"].lower().endswith(WEB_EXT):
                continue
            abs_path = roots[r["artifact_id"]] / r["path"].lstrip("/")
            try:
                text = abs_path.read_text("utf-8", "replace")
            except OSError:
                continue
            src = case.rel(abs_path)
            for ep in parse_file(r["path"], text, services):
                key = (ep.service, ep.port, ep.proto, src, ep.line)
                if key in seen:
                    continue
                seen.add(key)
                nonstd = is_nonstandard(ep.port)
                with case.conn:
                    sid = case.conn.execute(
                        "INSERT INTO services(name,command,source_path,source_line,evidence)"
                        " VALUES (?,?,?,?,?)",
                        (ep.service, ep.command, src, ep.line, ep.evidence),
                    ).lastrowid
                    case.conn.execute(
                        "INSERT INTO network_endpoints(service_id,port,proto,bind_addr,nonstandard,"
                        "default_on,source_path,source_line,evidence) VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            sid,
                            ep.port,
                            ep.proto,
                            ep.bind,
                            int(nonstd),
                            int(ep.default_on),
                            src,
                            ep.line,
                            ep.evidence,
                        ),
                    )
                table.append(
                    {
                        "port": ep.port,
                        "proto": ep.proto,
                        "service": ep.service,
                        "kind": ep.kind,
                        "default_on": ep.default_on,
                        "nonstandard": nonstd,
                        "source": f"{src}:{ep.line}",
                        "evidence": ep.evidence,
                    }
                )
                strong = ep.kind in ("init", "inetd", "xinetd", "systemd")
                caveat = "" if strong else "A config value only; confirm something binds it."
                caveat = "" if strong else "A config value only; confirm something binds it."
                if nonstd and ep.default_on:
                    add_finding(
                        case,
                        heuristic_id="net.nonstandard-port",
                        title=(
                            f"Non-standard port {ep.port}/{ep.proto} ({ep.service}) on by default"
                        ),
                        detail=f"Source kind: {ep.kind}. " + caveat,
                        evidence_path=src,
                        line=ep.line,
                        snippet=ep.evidence,
                        confidence="med" if strong else "low",
                        severity="medium",
                        cwe="CWE-1327",
                        owasp_iot="I2",
                    )
                if ep.service.startswith("nc-listener"):
                    add_finding(
                        case,
                        heuristic_id="net.nc-listener",
                        title=f"netcat listener on {ep.port}/{ep.proto} started at boot",
                        evidence_path=src,
                        line=ep.line,
                        snippet=ep.evidence,
                        confidence="high" if ep.service.endswith("shell") else "med",
                        severity="high",
                        cwe="CWE-912",
                        owasp_iot="I2",
                    )
            for user, secret, line, _ev in parse_credentials(text):
                creds += 1
                with case.conn:
                    case.conn.execute(
                        "INSERT INTO credentials(username,secret,secret_kind,algo,source_path,"
                        "source_line) VALUES (?,?,?,?,?,?)",
                        (user, secret, "plaintext", "config", src, line),
                    )
            if i % 50 == 0:
                progress(i / len(rows), f"parsing {r['path']}")

        table.sort(key=lambda t: (not t["default_on"], not t["nonstandard"], t["port"]))
        listen = [t for t in table if t["default_on"]]
        return ModuleResult(
            self.name,
            True,
            f"{len(listen)} listen-by-default endpoints "
            f"({sum(t['nonstandard'] for t in listen)} non-standard), "
            f"{creds} plaintext credentials",
            data={"table": table, "credentials": creds},
            warnings=[
                f"{t['port']}/{t['proto']} {t['service']} at {t['source']}"
                for t in listen
                if t["nonstandard"] and t["kind"] != "config"
            ][:20],
        )
