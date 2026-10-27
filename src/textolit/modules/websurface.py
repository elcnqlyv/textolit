"""websurface: static map of the web interface in an extracted filesystem.

No requests are made. It lists web roots, pages, CGI and upload handlers, URLs referenced
by the front end, the web server in use, how login probably works, and credentials that
are visible in front-end code. Everything cites a source file and line.
"""

from __future__ import annotations

import base64
import binascii
import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from textolit.core.case import Case
from textolit.core.ledger import add_finding, ensure_heuristic, fs_roots
from textolit.modules.base import ModuleResult, ProgressFn, no_progress
from textolit.modules.netmap import parse_credentials

WEB_DIR_NAMES = {
    "www",
    "web",
    "htdocs",
    "html",
    "webs",
    "wwwroot",
    "webroot",
    "webpages",
    "webui",
    "web_root",
    "site",
    "httpd_root",
}
PAGE_EXTS = (".html", ".htm", ".shtml", ".asp", ".aspx", ".jsp", ".php")
SCRIPT_EXTS = (".cgi", ".lua", ".php", ".asp", ".aspx", ".jsp", ".sh", ".pl", ".py")
FRONT_EXTS = (".html", ".htm", ".shtml", ".asp", ".aspx", ".jsp", ".php", ".js", ".xml", ".json")
UPLOAD_NAME = re.compile(
    r"(?i)(upload|firmware|upgrade|update|restore|import|fwupdate|flash|backup|setconfig)"
)
SERVER_BINARIES = {
    "boa": "boa",
    "lighttpd": "lighttpd",
    "mini_httpd": "mini_httpd",
    "thttpd": "thttpd",
    "uhttpd": "uhttpd",
    "goahead": "goahead",
    "webs": "goahead",
    "nginx": "nginx",
    "apache2": "apache",
    "httpd": "httpd",
    "appweb": "appweb",
    "mongoose": "mongoose",
    "civetweb": "civetweb",
    "hiawatha": "hiawatha",
    "dhttpd": "dhttpd",
    "minihttpd": "minihttpd",
}
ROOT_CONF = (
    re.compile(r"""server\.document-root\s*=\s*["']([^"']+)["']"""),
    re.compile(r"""(?i)^\s*DocumentRoot\s+["']?([^\s"']+)"""),
    re.compile(r"""^\s*root\s+([^\s;]+);"""),
    re.compile(r"""(?i)option\s+home\s+["']?([^\s"']+)"""),
    re.compile(r"""(?:^|\s)(?:uhttpd|mini_httpd|thttpd)\b.*?\s-[hd]\s+(/\S+)"""),
)
REF_ABS = re.compile(
    r"""["'(=]\s*(/(?:cgi-bin|ISAPI|onvif|axis-cgi|api|cgi|ipc|System|Streaming|PSIA|config|"""
    r"""goform|web|webs|login|logout)[^"'\s<>)]{0,160})"""
)
REF_FILE = re.compile(
    r"""["'(=]\s*([\w./-]{1,80}\.(?:cgi|php|asp|aspx|lua|jsp)(?:\?[^"'\s<>)]{0,80})?)["')]"""
)
FORM_RE = re.compile(r"(?is)<form\b([^>]*)>(.*?)(?:</form>|$)")
AJAX_URL = re.compile(
    r"""(?is)\burl\s*:\s*["']([^"']+)["'](.{0,120}?)(?:type|method)\s*:\s*["'](\w+)["']"""
)
XHR_OPEN = re.compile(r"""\.open\(\s*["'](GET|POST|PUT|DELETE)["']\s*,\s*["']([^"']+)["']""")
SERVER_STR = re.compile(rb"Server:\s*([A-Za-z0-9._/ -]{3,50})")
WWW_AUTH = re.compile(rb"WWW-Authenticate:\s*(Basic|Digest)(?:\s+realm=\"([^\"]*)\")?", re.I)
B64_BASIC = re.compile(r"""Basic\s+([A-Za-z0-9+/]{8,}={0,2})""")
PW_INPUT = re.compile(r"(?i)<input\b[^>]*type\s*=\s*[\"']?password[^>]*>")
INPUT_VALUE = re.compile(r"""(?i)\bvalue\s*=\s*["']([^"']+)["']""")
INPUT_NAME = re.compile(r"""(?i)\bname\s*=\s*["']?(\w+)""")
USER_INPUT = re.compile(
    r"(?i)<input\b[^>]*name\s*=\s*[\"']?(user\w*|login\w*|uname|admin\w*)[^>]*>"
)
CLIENT_HASH = re.compile(
    r"(?i)\b(hex_md5|md5|sha1|sha256|CryptoJS\.(?:MD5|SHA\d*)|btoa)\s*\(.{0,80}?(?:pass|pwd)"
)
JS_BASIC = re.compile(r"""(?i)setRequestHeader\(\s*["']Authorization["']|["']Basic\s*["']\s*\+""")
COOKIE_AUTH = re.compile(r"(?i)document\.cookie\s*=.{0,80}(?:user|pass|auth|login)")


@dataclass(frozen=True)
class Item:
    category: str
    key: str
    value: str = ""
    confidence: str = "low"
    line: int | None = None
    evidence: str = ""


def web_root_of(rel: str) -> str | None:
    """Directory (inside the filesystem) that looks like a web root for ``rel``, if any."""
    parts = rel.strip("/").split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() in WEB_DIR_NAMES:
            return "/" + "/".join(parts[: i + 1])
    return None


def parse_roots(text: str) -> list[Item]:
    items: list[Item] = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for rx in ROOT_CONF:
            m = rx.search(line)
            if m:
                items.append(Item("root", m.group(1), "declared", "high", n, line.strip()[:160]))
                break
    return items


def parse_front_end(text: str) -> list[Item]:
    """URLs, forms, upload inputs, auth and credential hints from one HTML or JS file."""
    items: list[Item] = []
    seen: set[tuple[str, str]] = set()

    def add(item: Item) -> None:
        k = (item.category, item.key + "|" + item.value)
        if k not in seen:
            seen.add(k)
            items.append(item)

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    for m in REF_ABS.finditer(text):
        add(Item("endpoint", m.group(1), "reference", "low", line_of(m.start(1)), m.group(0)[:120]))
    for m in REF_FILE.finditer(text):
        add(Item("endpoint", m.group(1), "reference", "low", line_of(m.start(1)), m.group(0)[:120]))
    for m in XHR_OPEN.finditer(text):
        add(Item("endpoint", m.group(2), m.group(1), "med", line_of(m.start()), m.group(0)[:120]))
    for m in AJAX_URL.finditer(text):
        add(
            Item(
                "endpoint",
                m.group(1),
                m.group(3).upper(),
                "med",
                line_of(m.start()),
                m.group(0)[:120],
            )
        )
    for m in FORM_RE.finditer(text):
        attrs, body = m.group(1), m.group(2)
        am = re.search(r"""(?i)\baction\s*=\s*["']?([^"'\s>]+)""", attrs)
        mm = re.search(r"""(?i)\bmethod\s*=\s*["']?(\w+)""", attrs)
        action = am.group(1) if am else ""
        method = (mm.group(1) if mm else "GET").upper()
        line = line_of(m.start())
        if action:
            add(Item("endpoint", action, method, "med", line, f"<form action={action}>"))
        is_upload = bool(
            re.search(r"(?i)multipart/form-data", attrs)
            or re.search(r"(?i)type\s*=\s*[\"']?file", body)
        )
        if is_upload:
            add(
                Item(
                    "upload",
                    action or "(form without action)",
                    "form with file input",
                    "high",
                    line,
                    f"<form action={action} multipart/file>",
                )
            )
        if PW_INPUT.search(body):
            add(
                Item(
                    "auth", "html-form-login", action or "", "med", line, "password input in a form"
                )
            )
            pw = PW_INPUT.search(body)
            assert pw is not None
            pv = INPUT_VALUE.search(pw.group(0))
            if pv:
                add(
                    Item(
                        "credential",
                        "prefilled-password",
                        pv.group(1),
                        "med",
                        line_of(m.start() + (m.group(0).find(pw.group(0)) or 0)),
                        pw.group(0)[:120],
                    )
                )
        for um in USER_INPUT.finditer(body):
            uv = INPUT_VALUE.search(um.group(0))
            if uv:
                add(
                    Item(
                        "credential",
                        "prefilled-username",
                        uv.group(1),
                        "low",
                        line_of(m.start()),
                        um.group(0)[:120],
                    )
                )
    for m in CLIENT_HASH.finditer(text):
        add(
            Item(
                "auth", "client-side-hash", m.group(1), "med", line_of(m.start()), m.group(0)[:120]
            )
        )
    for m in JS_BASIC.finditer(text):
        add(Item("auth", "js-basic-auth", "", "med", line_of(m.start()), m.group(0)[:120]))
    for m in COOKIE_AUTH.finditer(text):
        add(Item("auth", "cookie-auth", "", "low", line_of(m.start()), m.group(0)[:120]))
    for m in B64_BASIC.finditer(text):
        decoded = decode_basic(m.group(1))
        if decoded:
            add(
                Item(
                    "credential",
                    "basic-auth-header",
                    decoded,
                    "high",
                    line_of(m.start()),
                    f"Basic {m.group(1)[:8]}...",
                )
            )
    return items


def decode_basic(token: str) -> str | None:
    """``user:pass`` if the token is printable Basic credentials, else None."""
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if ":" in raw and raw.isprintable() and 3 <= len(raw) <= 80:
        return raw
    return None


def parse_server_config(rel: str, text: str) -> list[Item]:
    """Auth and server hints from web server configuration files."""
    items: list[Item] = []
    base = posixpath.basename(rel).lower()
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if m := re.search(r"""auth\.backend\s*=\s*["'](\w+)["']""", s):
            items.append(Item("auth", f"lighttpd-auth-{m.group(1)}", "", "high", n, s[:160]))
        elif re.search(r"auth\.require|mod_auth", s):
            items.append(Item("auth", "lighttpd-mod_auth", "", "med", n, s[:160]))
        elif re.match(r"(?i)auth_basic\b", s):
            items.append(Item("auth", "nginx-auth_basic", "", "high", n, s[:160]))
        elif m := re.match(r"(?i)AuthType\s+(Basic|Digest)", s):
            items.append(Item("auth", f"apache-{m.group(1).lower()}", "", "high", n, s[:160]))
        elif re.match(r"(?i)AuthRealm\b", s):
            items.append(Item("auth", "boa-AuthRealm", "", "med", n, s[:160]))
        elif base in ("httpd.conf", "uhttpd.passwd") and (
            m := re.match(r"^(/[^:\s]*):([^:\s]+):(\S+)$", s)
        ):
            items.append(
                Item(
                    "auth",
                    "httpd.conf-basic-auth",
                    m.group(1),
                    "high",
                    n,
                    f"{m.group(1)}:{m.group(2)}:***",
                )
            )
    return items


def parse_binary_strings(data: bytes) -> list[Item]:
    items: list[Item] = []
    for m in SERVER_STR.finditer(data):
        val = m.group(1).decode("ascii", "replace").strip()
        if val and not val.lower().startswith(("%s", "%d")):
            items.append(Item("server", "Server header", val, "med", None, f"Server: {val}"))
            break
    for m in WWW_AUTH.finditer(data):
        scheme = m.group(1).decode().lower()
        realm = (m.group(2) or b"").decode("ascii", "replace")
        items.append(
            Item(
                "auth",
                f"http-{scheme}",
                realm,
                "high",
                None,
                f"WWW-Authenticate: {scheme} realm={realm!r}",
            )
        )
        break
    return items


def server_from_name(rel: str) -> str | None:
    return SERVER_BINARIES.get(posixpath.basename(rel).lower())


class WebSurface:
    name = "websurface"

    def run(self, case: Case, progress: ProgressFn = no_progress, **options: Any) -> ModuleResult:
        roots_by_art = dict(fs_roots(case))
        rows = case.conn.execute("SELECT * FROM files WHERE is_symlink=0 ORDER BY id").fetchall()
        if not roots_by_art or not rows:
            return ModuleResult(
                self.name, False, "no files indexed", errors=["run unpack and fswalk first"]
            )
        for hid, title, sev, conf in (
            ("web.upload-handler", "Upload or firmware handler in the web interface", "low", None),
            ("web.client-side-auth", "Login logic that runs in the browser", "low", None),
            (
                "web.embedded-basic-credentials",
                "Basic auth credentials embedded in front end",
                "high",
                None,
            ),
            ("web.prefilled-credentials", "Login form with pre-filled credentials", "medium", None),
            ("web.plaintext-credential", "Credential assignment in web files", "medium", None),
            ("web.http-basic-auth", "HTTP Basic authentication in use", "low", None),
        ):
            ensure_heuristic(case, hid, "websurface", title, sev)
            _ = conf
        with case.conn:
            case.conn.execute("DELETE FROM web_surface")
            case.conn.execute("DELETE FROM credentials WHERE algo='web'")

        counts = {"roots": 0, "pages": 0, "cgi": 0, "endpoints": 0, "uploads": 0, "auth": 0}
        servers: dict[str, str] = {}

        def store(it: Item, src: str) -> None:
            with case.conn:
                case.conn.execute(
                    "INSERT INTO web_surface(category,key,value,confidence,source_path,"
                    "source_line,evidence) VALUES (?,?,?,?,?,?,?)",
                    (it.category, it.key, it.value, it.confidence, src, it.line, it.evidence),
                )

        # pass 1: which directories are web roots, and what is in them
        roots: dict[tuple[int, str], Path] = {}
        for row in rows:
            r = web_root_of(row["path"])
            if r and row["artifact_id"] in roots_by_art:
                roots.setdefault((row["artifact_id"], r), roots_by_art[row["artifact_id"]])
        for (_art, r), root_base in sorted(roots.items()):
            src = case.rel(root_base / r.lstrip("/"))
            store(Item("root", r, "directory name", "med", None, "web-style directory"), src)
            counts["roots"] += 1

        for i, row in enumerate(rows):
            base = roots_by_art.get(row["artifact_id"])
            if base is None:
                continue
            rel = row["path"]
            path = base / rel.lstrip("/")
            src = case.rel(path)
            low = rel.lower()
            in_root = web_root_of(rel)
            ftype = row["ftype"]

            name_server = server_from_name(rel)
            if name_server and ftype == "elf":
                servers.setdefault(name_server, rel)
                store(Item("server", name_server, "", "med", None, f"binary {rel}"), src)
                try:
                    for it in parse_binary_strings(path.read_bytes()[: 8 << 20]):
                        store(it, src)
                        counts["auth"] += it.category == "auth"
                except OSError:
                    pass

            if in_root:
                url = "/" + rel[len(in_root) :].lstrip("/")
                if low.endswith(PAGE_EXTS):
                    counts["pages"] += 1
                    store(Item("endpoint", url, "page", "high", None, rel), src)
                if "/cgi-bin/" in low or low.endswith(SCRIPT_EXTS) or (ftype == "elf" and in_root):
                    counts["cgi"] += 1
                    store(Item("endpoint", url, "cgi", "high", None, rel), src)
                    if UPLOAD_NAME.search(posixpath.basename(low)):
                        counts["uploads"] += 1
                        store(Item("upload", url, "handler name", "med", None, rel), src)
                        self._upload_finding(case, url, src, None, "name suggests a handler")

            if ftype in ("text", "script") and row["size"] <= (1 << 20):
                try:
                    text = path.read_text("utf-8", "replace")
                except OSError:
                    continue
                if low.endswith(FRONT_EXTS) and in_root:
                    for it in parse_front_end(text):
                        store(it, src)
                        if it.category == "endpoint":
                            counts["endpoints"] += 1
                        elif it.category == "upload":
                            counts["uploads"] += 1
                            self._upload_finding(case, it.key, src, it.line, it.evidence)
                        elif it.category == "auth":
                            counts["auth"] += 1
                            if it.key in ("client-side-hash", "js-basic-auth", "cookie-auth"):
                                add_finding(
                                    case,
                                    heuristic_id="web.client-side-auth",
                                    title=f"Login logic in the browser ({it.key})",
                                    evidence_path=src,
                                    line=it.line,
                                    snippet=it.evidence,
                                    confidence="low",
                                    severity="low",
                                    cwe="CWE-602",
                                    owasp_iot="I3",
                                )
                        elif it.category == "credential":
                            self._credential(case, it, src)
                    for user, secret, line, ev in parse_credentials(text):
                        with case.conn:
                            case.conn.execute(
                                "INSERT INTO credentials(username,secret,secret_kind,algo,"
                                "source_path,source_line) VALUES (?,?,?,?,?,?)",
                                (user, secret, "plaintext", "web", src, line),
                            )
                        store(
                            Item(
                                "credential",
                                "plaintext-assignment",
                                user or "",
                                "med",
                                line,
                                ev[:80],
                            ),
                            src,
                        )
                        add_finding(
                            case,
                            heuristic_id="web.plaintext-credential",
                            title="Credential assignment in a web file",
                            evidence_path=src,
                            line=line,
                            snippet=ev[:100],
                            confidence="med",
                            severity="medium",
                            cwe="CWE-798",
                            owasp_iot="I1",
                        )
                for it in parse_roots(text):
                    store(it, src)
                    counts["roots"] += 1
                if (
                    posixpath.basename(low)
                    in (
                        "lighttpd.conf",
                        "boa.conf",
                        "httpd.conf",
                        "uhttpd.passwd",
                        "nginx.conf",
                        "mini_httpd.conf",
                        "thttpd.conf",
                        "goahead.conf",
                    )
                    or "/etc/lighttpd" in low
                    or "/nginx/" in low
                ):
                    for it in parse_server_config(rel, text):
                        store(it, src)
                        counts["auth"] += 1
                        if it.key.endswith(("basic-auth", "basic")) or "basic" in it.key:
                            add_finding(
                                case,
                                heuristic_id="web.http-basic-auth",
                                title=f"HTTP Basic authentication configured ({it.key})",
                                detail="Credentials travel base64-encoded unless TLS is enforced.",
                                evidence_path=src,
                                line=it.line,
                                snippet=it.evidence,
                                confidence="low",
                                severity="low",
                                cwe="CWE-319",
                                owasp_iot="I7",
                            )
                    srv = {
                        "lighttpd.conf": "lighttpd",
                        "boa.conf": "boa",
                        "nginx.conf": "nginx",
                        "mini_httpd.conf": "mini_httpd",
                        "thttpd.conf": "thttpd",
                    }.get(posixpath.basename(low))
                    if srv:
                        servers.setdefault(srv, rel)
                        store(Item("server", srv, "config present", "med", None, rel), src)
            if i % 200 == 0:
                progress(i / max(len(rows), 1), f"web {rel}")

        # versions already fingerprinted by binintel
        for b in case.conn.execute(
            "SELECT f.path, f.artifact_id, b.versions_json FROM binaries b JOIN files f"
            " ON f.id=b.file_id"
        ):
            for comp, ver in json.loads(b["versions_json"]).items():
                if comp in ("lighttpd", "boa", "mini_httpd", "thttpd", "uhttpd", "goahead"):
                    servers[comp] = ver
                    base = roots_by_art.get(b["artifact_id"])
                    if base:
                        store(
                            Item(
                                "server", comp, ver, "high", None, f"version string in {b['path']}"
                            ),
                            case.rel(base / b["path"].lstrip("/")),
                        )

        summary = (
            f"{counts['roots']} web roots, {counts['pages']} pages, {counts['cgi']} cgi/scripts, "
            f"{counts['endpoints']} referenced endpoints, {counts['uploads']} upload handlers, "
            f"servers: {', '.join(sorted(servers)) or 'none identified'}"
        )
        return ModuleResult(self.name, True, summary, data={**counts, "servers": servers})

    def _upload_finding(self, case: Case, url: str, src: str, line: int | None, why: str) -> None:
        add_finding(
            case,
            heuristic_id="web.upload-handler",
            title=f"Upload or firmware handler: {url}",
            detail=why,
            evidence_path=src,
            line=line,
            snippet=why[:100],
            confidence="med",
            severity="low",
            cwe="CWE-434",
            owasp_iot="I3",
        )

    def _credential(self, case: Case, it: Item, src: str) -> None:
        if it.key == "basic-auth-header":
            user, _, secret = it.value.partition(":")
            with case.conn:
                case.conn.execute(
                    "INSERT INTO credentials(username,secret,secret_kind,algo,source_path,"
                    "source_line) VALUES (?,?,?,?,?,?)",
                    (user, secret, "plaintext", "web", src, it.line),
                )
            add_finding(
                case,
                heuristic_id="web.embedded-basic-credentials",
                title=f"Basic auth header with embedded credentials for '{user}'",
                evidence_path=src,
                line=it.line,
                snippet=f"{user}:{secret[:2]}***",
                confidence="high",
                severity="high",
                cwe="CWE-798",
                owasp_iot="I1",
            )
        elif it.key == "prefilled-password":
            add_finding(
                case,
                heuristic_id="web.prefilled-credentials",
                title="Login form with a pre-filled password",
                evidence_path=src,
                line=it.line,
                snippet="password input with a value attribute",
                confidence="med",
                severity="medium",
                cwe="CWE-798",
                owasp_iot="I1",
            )
