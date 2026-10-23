#!/usr/bin/env python3
"""
php-scan — CVE-2026-109618 / CVE-2026-109619 exposure scanner.

Defensive scanner. Probes EXPOSURE and PREREQUISITES only — never sends
memory-corruption payloads, never crashes workers, never injects code.

Modes:
  --target URL    Remote black-box probe (headers, session-name learning,
                  session fixation, upload_progress reachability, SAPI).
  --targets FILE  Batch: one URL per line.
  --path DIR      Local code/config audit (php.ini, .user.ini handler
                  mismatch, unserialize/LFI sinks, __destruct gadgets).
  --crawl         Recursive same-domain crawl of --target (links + form
                  endpoints). ON by default when --target is given;
                  --no-crawl scans only the given URL.

Reports: each run writes ONE timestamped file into <script_dir>/reports/
(<ts>_<domain>_<SEV>.<fmt>) unless --output is given or --cumulative
selects the shared php-scan-results.xlsx workbook.
  --confirm       Behavioral confirmation: actually triggers BENIGN
                  primitives and verifies their fingerprints server-side
                  (session file creation, marker in session data, and —
                  for mod_php — the "Unknown on line 0" OOM signature).
                  Requires a host-side channel:
                    --session-path DIR   session dir reachable locally
                                         (mounted volume / same host)
                    --exec-cmd 'TEMPLATE' run checks on host, {cmd}
                                         placeholder, e.g.
                                         'docker exec c sh -c "{cmd}"'
                                         'ssh host "{cmd}"'

Verdict tiers: affected (version) < confirmed (behavior fingerprint
observed) < exploited (real RCE echo — not implemented, use lab exploit).

For authorized security assessment only.
"""
import argparse
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

FIXED = {2: 35, 3: 36, 4: 27, 5: 12}   # PHP 8.X must be >= 8.X.FIXED[X]
FIXED_STR = "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def parse_ver(text):
    m = re.search(r"PHP[/ ]?(\d+)\.(\d+)(?:\.(\d+))?", text)
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


def version_state(ver):
    """ver tuple (major, minor[, patch]) -> (status, detail)."""
    if not ver:
        return "unknown", f"version not disclosed; verify manually against {FIXED_STR}"
    major, minor = ver[0], ver[1]
    patch = ver[2] if len(ver) > 2 else 0
    if major < 5 or (major == 5 and minor < 4):
        return "not_applicable", (
            f"PHP {major}.{minor}.{patch} predates session.upload_progress "
            "(introduced in 5.4) — outside both CVEs' range")
    if major < 8 or (major == 8 and minor < 2):
        return "eol", (f"PHP {major}.{minor}.{patch} is EOL — no official fix; "
                       "upgrade required (or isolate + upload_progress=Off)")
    if major == 8 and 2 <= minor <= 5:
        st = "affected" if patch < FIXED[minor] else "patched"
        return st, (f"PHP {major}.{minor}.{patch} "
                    f"{'<' if st == 'affected' else '>='} fixed 8.{minor}.{FIXED[minor]}")
    return "unknown", f"PHP {major}.{minor}.{patch} outside documented range"


UA = ("Mozilla/5.0 (compatible; php-scan/1.0; authorized security assessment)")
BASE_HEADERS = (f"User-Agent: {UA}\r\nAccept: */*\r\nAccept-Language: en\r\n")


def status_line(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO-RESPONSE"


# cookies that are definitely not the PHP session name (CDN/WAF/LB/CSRF)
NON_SESSION_COOKIES = {
    "httponly", "acw_tc", "acw_sc__v2", "aliyungf_tc", "cdn_sec_tc",
    "ali_ab", "isg", "__cf_bm", "cf_clearance",
    "cfduid", "awsalb", "awsalbcors", "ts", "incap_ses", "visid_incap",
    "nlbi", "reese84", "x-xsrf-token", "xsrf-token", "csrf_token",
}
KNOWN_SESSION_NAMES = {
    "phpsessid", "laravel_session", "symfony", "ci_session", "yii",
    "cakephp", "wp_session", "sec_session_id", "jsessionid", "aspsessionid",
}


def pick_session_name(cookies):
    """Choose the most session-like cookie name.
    Returns (name, confidence 'high'|'low'|None)."""
    names = [c for c in cookies if c.lower() not in NON_SESSION_COOKIES]
    if not names:
        return None, None
    for c in names:
        if c.lower() in KNOWN_SESSION_NAMES or "sess" in c.lower():
            return c, "high"
    return names[0], "low"


# ---------------------------------------------------------------- utils

def http(host, port, raw, tls=False, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    s.sendall(raw)
    s.settimeout(timeout)
    resp = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            resp += d
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
        pass
    s.close()
    return resp


def split(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    return head.decode("latin1", "replace"), body


# ---------------------------------------------------------------- host channel

class HostExec:
    """Host-side verification channel for --confirm mode.

    Two transports:
      session_path: read session files directly (same host / mounted volume)
      exec_cmd:     run shell commands on the host ({cmd} placeholder)
    """

    def __init__(self, session_path=None, exec_cmd=None):
        self.session_path = session_path
        self.exec_cmd = exec_cmd

    @property
    def available(self):
        return bool(self.session_path or self.exec_cmd)

    def _run(self, cmd):
        if not self.exec_cmd:
            return None
        full = self.exec_cmd.replace("{cmd}", cmd)
        try:
            r = subprocess.run(full, shell=True, capture_output=True,
                               text=True, timeout=15)
            return (r.stdout or "") + (r.stderr or "")
        except (subprocess.TimeoutExpired, OSError) as e:
            return f"__exec_error:{e}"

    def _path(self, name):
        """Resolve a session file path on the host."""
        return os.path.join(self.session_path, name) if self.session_path else name

    def file_exists(self, name):
        p = self._path(name)
        if self.session_path and not self.exec_cmd:
            return os.path.exists(p)
        out = self._run(f"test -f {shlex.quote(p)} && echo YES || echo NO")
        return bool(out and "YES" in out)

    def out(self, cmd):
        """Run a read-only command on the host, return combined output."""
        return self._run(cmd)

    def file_contains(self, name, needle):
        p = self._path(name)
        if self.session_path and not self.exec_cmd:
            try:
                return needle in open(p, errors="replace").read()
            except OSError:
                return False
        out = self._run(f"grep -l {shlex.quote(needle)} {shlex.quote(p)} 2>/dev/null")
        return bool(out and p in out)


# ---------------------------------------------------------------- crawler

# static resources & files we never crawl/scan
STATIC_EXT = re.compile(
    r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|"
    r"woff2?|ttf|otf|eot|mp[34]|webm|mov|avi|pdf|zip|rar|7z|gz|tar|"
    r"docx?|xlsx?|pptx?|csv|xml|txt|md|json|wasm|data)([?#].*)?$", re.I)

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "ftp:")


def crawl_site(target, cookie=None, max_pages=50, max_depth=3, timeout=10):
    """Same-domain BFS crawler. Returns (pages, endpoints):
      pages     — crawlable HTML page URLs (deduped)
      endpoints — form action URLs found on those pages ("interfaces")
    Only follows same-domain links; skips static assets and externals."""
    u = urlparse(target if "://" in target else "http://" + target)
    host, tls = u.hostname, u.scheme == "https"
    port = u.port or (443 if tls else 80)
    seen = set()
    pages, endpoints = [], set()
    origin = (f"{'https' if tls else 'http'}://{host}"
              f"{':' + str(port) if port not in (80, 443) else ''}")
    queue = [(u.path or "/", 0)]
    cookie_line = f"Cookie: {cookie}\r\n" if cookie else ""

    def norm(path):
        path = path.split("#", 1)[0]
        return path or "/"

    while queue and len(pages) < max_pages:
        path, depth = queue.pop(0)
        path = norm(path)
        if path in seen:
            continue
        seen.add(path)
        if STATIC_EXT.search(path):
            continue
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n" + BASE_HEADERS +
               cookie_line + "Connection: close\r\n\r\n").encode()
        try:
            resp = http(host, port, req, tls=tls, timeout=timeout)
        except OSError:
            continue
        if not resp:
            continue
        head, body = split(resp)
        status = head.split("\r\n", 1)[0]
        # follow redirects once (same-domain Location)
        m = re.search(r"^HTTP/1\.\d\s+30[0-9]", status)
        loc = re.search(r"Location:\s*([^\r\n]+)", head, re.I)
        if m and loc:
            # redirects don't consume link depth — follow at same depth
            t = loc.group(1).strip()
            if t.startswith("/") or not urlparse(t).netloc:
                # same-host absolute-path or relative redirect (e.g. "login.php")
                queue.append((norm(urljoin(path, t)), depth))
            elif urlparse(t).hostname == host:
                queue.append((norm(urlparse(t).path or "/"), depth))
            continue
        ctype = re.search(r"Content-Type:\s*([^\r\n;]+)", head, re.I)
        if ctype and "html" not in ctype.group(1).lower():
            continue
        pages.append(origin + path)
        if depth >= max_depth:
            continue
        html = body.decode("utf-8", "replace")
        for link in re.findall(
                r'''(?:href|action)\s*=\s*["']([^"']+)["']''', html, re.I):
            link = link.strip()
            if not link or link.startswith(SKIP_SCHEMES) or link.startswith("#"):
                continue
            if link.startswith("//"):
                continue                          # protocol-relative external
            lu = urlparse(link)
            if lu.netloc and lu.hostname != host:
                continue                          # external domain — skip
            # resolve relative links (about.php, ../x, ?q=1) against page path
            fu = urlparse(urljoin(path, link))
            lp = norm(fu.path or "/")
            if fu.query:
                lp += "?" + fu.query
            if STATIC_EXT.search(lp):
                continue
            # form actions are endpoints; links are crawlable pages
            tag_is_form = bool(re.search(
                r'''action\s*=\s*["']''' + re.escape(link) + r'''["']''',
                html, re.I))
            if tag_is_form:
                endpoints.add(origin + lp)
            elif lp not in seen:
                queue.append((lp, depth + 1))
    return pages, sorted(endpoints)


# ---------------------------------------------------------------- remote

class RemoteScan:
    def __init__(self, target, path="/", timeout=10, host=None, confirm=False,
                 oom_mb=160, cookie=None, force_oom=False, oom_strategy="auto",
                 progress_name="PHP_SESSION_UPLOAD_PROGRESS"):
        u = urlparse(target if "://" in target else "http://" + target)
        self.host = u.hostname
        self.tls = u.scheme == "https"
        self.port = u.port or (443 if self.tls else 80)
        self.base = u.path.rstrip("/") or ""
        self.probe_path = path
        self.timeout = timeout
        self.host_ch = host or HostExec()
        self.confirm = confirm
        self.oom_mb = oom_mb
        # user-supplied Cookie header minus any session id we override
        self.cookie = self._strip_sid(cookie or "")
        self._sess_name = "PHPSESSID"   # refined by fingerprint() from Set-Cookie
        self._sapi = "unknown"
        self.force_oom = force_oom
        self.oom_strategy = oom_strategy
        self.progress_name = progress_name   # session.upload_progress.name
        self._sid_leak = None           # anomalous session Set-Cookie (heap leak sig)
        self._iocs = []                 # exploit signatures seen in responses
        self._redirected = None         # Location followed by the last probe
        self.checks = {}

    _REDIR = re.compile(rb"HTTP/1\.\d\s+30[12378]\s")

    @staticmethod
    def _loc_url(resp):
        """Location header value on a 30x response, else None."""
        m = re.search(rb"(?im)^Location:\s*(\S+)",
                      resp.split(b"\r\n\r\n", 1)[0])
        return m.group(1).decode("latin1") if m else None

    @staticmethod
    def _resolve_loc(loc, host, port, tls):
        """Parse a Location into (host, port, tls, path). Absolute URLs may
        point at a different host — followed once without a domain check."""
        if loc.startswith(("http://", "https://")):
            u = urlparse(loc)
            return (u.hostname or host, u.port or port,
                    u.scheme == "https", u.path or "/")
        return host, port, tls, loc

    # response-body exploit signatures (ikow detection SID 2026110/2026111)
    RESPONSE_IOCS = [
        (re.compile(rb"Session object destruction failed"),
         "'Session object destruction failed' — stale BG(unserialize) state "
         "consumed during rfc1867 (CVE-2026-109619 exploitation signature)"),
        (re.compile(rb"Allowed memory size.{0,200}in\s*<?b?>?\s*Unknown",
                    re.S),
         "'Allowed memory size … in Unknown on line 0' — OOM fired during "
         "SAPI/request startup, not userland code"),
    ]

    def _scan_body_iocs(self, body):
        for rx, desc in self.RESPONSE_IOCS:
            if rx.search(body) and desc not in self._iocs:
                self._iocs.append(desc)

    @staticmethod
    def _strip_sid(cookie):
        parts = [p.strip() for p in cookie.split(";")
                 if p.strip() and "sess" not in p.strip().lower().split("=")[0]]
        return "; ".join(parts)

    def _cookie_line(self, extra=None):
        c = "; ".join(x for x in (extra, self.cookie) if x)
        return f"Cookie: {c}\r\n" if c else ""

    def _get(self, path, cookie=None):
        host, port, tls = self.host, self.port, self.tls
        resp = None
        for _ in range(2):  # original request + one redirect follow
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n" + BASE_HEADERS
                   + self._cookie_line(cookie)
                   + "Connection: close\r\n\r\n").encode()
            resp = http(host, port, req, tls=tls, timeout=self.timeout)
            if not resp or not self._REDIR.match(resp):
                break
            loc = self._loc_url(resp)
            if not loc:
                break
            self._redirected = loc
            host, port, tls, path = self._resolve_loc(loc, host, port, tls)
        if resp:
            self._scan_body_iocs(resp.partition(b"\r\n\r\n")[2])
        return resp

    def _upload(self, path, fields, filename="probe.txt", method="POST"):
        b = "PHPSCAN" + uuid.uuid4().hex[:8]
        body = b""
        for n, v in fields.items():
            body += (f"--{b}\r\nContent-Disposition: form-data; "
                     f'name="{n}"\r\n\r\n{v}\r\n').encode("latin-1")
        body += (f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; "
                 f'filename="{filename}"\r\n\r\nZ\r\n--{b}--\r\n').encode("latin-1")
        host, port, tls = self.host, self.port, self.tls
        resp = None
        for _ in range(2):  # original request + one redirect follow
            req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
                   + BASE_HEADERS
                   + f"Content-Type: multipart/form-data; boundary={b}\r\n"
                   + self._cookie_line()
                   + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                   ).encode() + body
            resp = http(host, port, req, tls=tls, timeout=self.timeout)
            if not resp or not self._REDIR.match(resp):
                break
            loc = self._loc_url(resp)
            if not loc:
                break
            self._redirected = loc
            host, port, tls, path = self._resolve_loc(loc, host, port, tls)
        if resp:
            self._scan_body_iocs(resp.partition(b"\r\n\r\n")[2])
        return resp

    def fingerprint(self):
        resp = self._get(self.probe_path)
        if not resp:
            self.checks["reachable"] = {"status": "fail", "detail": "no response"}
            return False
        head, body = split(resp)
        powered = re.search(r"X-Powered-By:\s*([^\r\n]+)", head, re.I)
        server = re.search(r"Server:\s*([^\r\n]+)", head, re.I)
        self.checks["reachable"] = {
            "status": "ok",
            "detail": (head.splitlines()[0] if head else "") +
                      (f" — redirected to {self._redirected}"
                       if self._redirected else "")}
        self.checks["server_header"] = {"status": "info",
                                        "detail": server.group(1).strip() if server else "absent"}
        self.checks["x_powered_by"] = {"status": "info",
                                       "detail": powered.group(1).strip() if powered else "absent"}
        # learn the session cookie name — rfc1867/upload_progress only accept
        # the SID via session.name, which frameworks often rename
        # (e.g. symfony, laravel_session). Collect ALL Set-Cookie names and
        # pick the most session-like; CDN/WAF cookies (acw_tc, __cf_bm,
        # AWSALB...) are filtered so probes don't use a wrong name.
        cookies = re.findall(r"Set-Cookie:\s*([\w.\-]+)=", head, re.I)
        name, confidence = pick_session_name(cookies)
        if name:
            self._sess_name = name
            self.checks["session_cookie_name"] = {
                "status": "info",
                "detail": name if confidence == "high" else
                          f"{name} (low confidence — no *sess*/known cookie; "
                          f"SID probes may miss the real session.name)"}
        elif cookies:
            self.checks["session_cookie_name"] = {
                "status": "info",
                "detail": f"no session-like cookie ({', '.join(cookies)} are "
                          "WAF/CDN cookies) — SID probes use PHPSESSID fallback"}
        # version: collect EVERY "PHP/x.y.z" mention across X-Powered-By,
        # Server, and body, then keep the WORST verdict (phpcheck.js
        # strategy — a reassuring banner must not mask a vulnerable build).
        # Prerelease builds (dev/alpha/beta/rc) are never trusted → unknown.
        RANK = {"affected": 5, "eol": 4, "unknown": 3, "patched": 2,
                "not_applicable": 1}
        cands = []
        for label, src in (("x-powered-by", powered.group(1) if powered else ""),
                           ("server", server.group(1) if server else ""),
                           ("body", body.decode("latin1", "replace"))):
            for m in re.finditer(r"PHP[/ ]?(\d+)\.(\d+)\.(\d+)([^\s,;)]*)", src):
                v = tuple(int(x) for x in m.groups()[:3])
                pre = bool(re.search(r"dev|alpha|beta|rc", m.group(4), re.I))
                st = "unknown" if pre else version_state(v)[0]
                cands.append((v, label, pre, st))
        ver = ver_src = None
        if cands:
            v, label, pre, st = max(
                cands, key=lambda c: (RANK[c[3]], c[0][2]))
            ver = v
            self._ver_pre = pre
            ver_src = label + (" (prerelease build — not judged)" if pre else "")
            detail = ".".join(map(str, ver)) + f" [from {ver_src}]"
            if len(cands) > 1:
                detail += ("; other PHP versions also advertised: " +
                           ", ".join(".".join(map(str, c[0])) + f" ({c[1]})"
                                     for c in cands if c[0] != v or c[1] != label))
            detail += " — banners cannot rule out a backported fix"
            self.checks["php_version"] = {"status": "ok", "detail": detail}
        else:
            self.checks["php_version"] = {
                "status": "unknown",
                "detail": "not disclosed (expose_php may be Off)"}
        self._ver = ver
        # edge WAF/CDN note — explains filtered probes / dropped chunked bodies
        sh_raw = (server.group(1) if server else "")
        waf = next((w for w in ("cloudflare", "akamai", "awselb", "sucuri",
                                "imperva", "azion", "fastly")
                    if w in sh_raw.lower()), None)
        via = re.search(r"Via:\s*([^\r\n]+)", head, re.I)
        if waf or via:
            self.checks["edge_waf"] = {
                "status": "info",
                "detail": f"edge layer detected ({waf or via.group(1).strip()}) — "
                          "multipart/chunked probes may be filtered; "
                          "inconclusive results should be retried from inside"}
        # SAPI guess — heuristic only
        sh = (server.group(1) if server else "").lower()
        if "apache" in sh and powered and "PHP" in powered.group(1):
            self._sapi = "likely mod_php (Apache + PHP header)"
        elif "frankenphp" in sh or ("caddy" in sh and powered and "PHP" in powered.group(1)):
            self._sapi = "FrankenPHP embedded SAPI"
        elif "nginx" in sh or "caddy" in sh:
            self._sapi = "likely php-fpm / fastcgi"
        elif "lighttpd" in sh:
            self._sapi = "lighttpd fastcgi (likely php-fpm)"
        elif "litespeed" in sh or "openlitespeed" in sh:
            self._sapi = "LiteSpeed LSAPI (lsphp)"
        elif "unit" in sh:
            self._sapi = "NGINX Unit embedded SAPI"
        if b"fpm-fcgi" in body.lower():
            self._sapi = "php-fpm"
        self.checks["sapi"] = {"status": "info", "detail": self._sapi}
        return True

    def version_verdict(self):
        if getattr(self, "_ver_pre", False):
            st, det = ("unknown", "prerelease build (dev/alpha/beta/rc) — "
                                 "cannot be judged against release boundaries")
        else:
            st, det = version_state(self._ver)
        self.checks["cve_affected"] = {"status": st, "detail": det}

    def _sid_anomaly(self, head):
        """Anomalous session-id Set-Cookie → heap leak signature.

        Normal PHP session ids are 26–40 chars of [-,\\w]. A value >=64
        chars or containing url-encoded/binary bytes means uninitialized
        memory is being disclosed through the cookie — the CVE-2026-109618
        stage-1 leak primitive (Sansec IDS SID 2026112)."""
        m = re.search(r"Set-Cookie:\s*" + re.escape(self._sess_name) +
                      r"=([^;\r\n]*)", head, re.I)
        if not m:
            return None
        val = m.group(1).strip()
        if len(val) >= 64 or not re.fullmatch(r"[A-Za-z0-9,\-]{1,48}", val):
            return val
        return None

    def display_errors_probe(self):
        """Benign: exceed max_input_vars with a GET and look for a PHP warning.

        display_errors=On prints 'PHP Warning: ... max_input_vars ...' into
        the body — that setting is what makes the display_errors-dependent
        leak path (9bie stage-1/2 variant) work; display_errors=Off limits
        remote fingerprints to crash signatures only."""
        path = self.probe_path
        sep = "&" if "?" in path else "?"
        q = sep + "&".join(f"p{i}=v" for i in range(1100))
        resp = self._get(path + q)
        if not resp:
            self.checks["display_errors"] = {"status": "unknown",
                                             "detail": "no response"}
            return
        body = resp.partition(b"\r\n\r\n")[2]
        if re.search(rb"max_input_vars|PHP Warning|PHP Fatal error|"
                     rb"Allowed memory size", body):
            self.checks["display_errors"] = {
                "status": "info",
                "detail": "PHP runtime warnings/errors are reflected in the "
                          "response — display_errors=On: the leak-based "
                          "exploit path is easier (and error output aids "
                          "fingerprinting); production should run Off"}
        else:
            self.checks["display_errors"] = {
                "status": "info",
                "detail": "no PHP warning echoed for >max_input_vars input — "
                          "display_errors likely Off (exploitation still "
                          "possible via crash-only path, cf. 9bie "
                          "no-display-errors notes)"}

    def upload_progress_probe(self, sid):
        """Benign: send PHP_SESSION_UPLOAD_PROGRESS with a probe SID via POST body.

        upload_progress runs inside rfc1867 pre-RINIT — the endpoint does NOT
        need session_start() for this to fire. Two remote signals:
          1. a session Set-Cookie on the multipart response → the handler ran
          2. Set-Cookie echoing OUR sid → POST-body fixation accepted
             (pre-PR#22113), confirmed without any host channel."""
        self._fixation = None
        method = "POST"
        resp = self._upload(self.probe_path,
                            {self._sess_name: sid,
                             self.progress_name: "x"})
        if resp and not re.search(rb"HTTP/1\.\d\s+(200|30[0-9])",
                                  resp.split(b"\r\n", 1)[0]):
            # POST didn't take — PHP 8.4's request_parse_body() parses
            # multipart on PUT/PATCH/DELETE too; a PUT retry both reaches
            # the handler and detects the widened surface
            resp = self._upload(self.probe_path,
                                {self._sess_name: sid,
                                 self.progress_name: "x"}, method="PUT")
            if resp and re.search(rb"HTTP/1\.\d\s+(200|30[0-9])",
                                  resp.split(b"\r\n", 1)[0]):
                method = "PUT"
        if not resp:
            self.checks["upload_progress"] = {"status": "unknown", "detail": "no response"}
            return
        head, _ = split(resp)
        leak = self._sid_anomaly(head)
        if leak:
            self._sid_leak = leak
        sline = head.split("\r\n", 1)[0].strip()
        ok = re.search(r"HTTP/1\.\d\s+(200|302)", sline) is not None
        # Set-Cookie analysis: did the rfc1867 handler start a session, and did
        # it adopt our POST-body SID?
        sc = re.search(r"Set-Cookie:\s*" + re.escape(self._sess_name) +
                       r"=([^;\r\n]*)", head, re.I)
        sc_val = sc.group(1).strip() if sc else None
        if sc_val == sid:
            self._fixation = "confirmed"
        elif sc_val:
            self._fixation = "resisted"
        # rfc1867 runs pre-RINIT — BEFORE routing decides 404/405. A session
        # cookie issued on ANY status code is proof the handler fired, so the
        # exposure verdict must not hinge on the endpoint accepting POST.
        fired = ok or bool(sc_val)
        via = (" via PUT — request_parse_body() non-POST multipart surface "
               "accepted (PHP 8.4+); POST-only WAF rules bypassable"
               if method == "PUT" else "")
        if self._redirected:
            via += f"; redirected to {self._redirected}"
        # A disabled-feature refusal looks like a PHP warning mentioning
        # upload_progress + disabled in the same breath. A whole-body
        # boolean check misfires on phpinfo()-style pages that simply
        # LIST the setting name and unrelated "disabled" cells.
        body = resp.partition(b"\r\n\r\n")[2]
        rejected = re.search(
            rb"(?im)upload_progress[^\n<>]{0,160}disabl|"
            rb"warning[^\n]{0,200}upload_progress", body) is not None
        if rejected:
            self.checks["upload_progress"] = {
                "status": "not_exposed", "detail": "server reports feature disabled"}
        elif fired:
            pre = f"{sline}: " + ("" if ok else
                  "endpoint refused the method/path, yet a session cookie was "
                  "issued — rfc1867 runs pre-RINIT, before app routing; ")
            extra = ("; Set-Cookie echoes probe SID → POST-body fixation "
                     "confirmed remotely" if self._fixation == "confirmed"
                     else "; session cookie issued but SID regenerated"
                     if self._fixation == "resisted" else "")
            if self.confirm and self.host_ch.available:
                if self.host_ch.file_exists(f"sess_{sid}"):
                    self.checks["upload_progress"] = {
                        "status": "confirmed",
                        "detail": pre + f"sess_{sid} created on host — "
                                  "upload_progress accepted a session id "
                                  "from POST body (pre-auth)"}
                    self._fixation = "confirmed"
                    return
                self.checks["upload_progress"] = {
                    "status": "confirmed" if self._fixation == "confirmed"
                              else "not_confirmed",
                    "detail": (pre + f"session issued via rfc1867{extra}"
                               if self._fixation else
                               pre + f"no sess_{sid} found via host channel — "
                               "check session.save_path matches --session-path")}
            else:
                self.checks["upload_progress"] = {
                    "status": "confirmed" if self._fixation == "confirmed"
                              else "likely_exposed",
                    "detail": (pre + f"multipart with {self.progress_name} "
                               "accepted" + via + extra +
                               " (confirm on host: check sess_" + sid + ")")}
        else:
            self.checks["upload_progress"] = {"status": "unknown",
                                              "detail": sline + via}

    def session_fixation_probe(self, sid):
        """Send PHPSESSID in POST body, then GET with that SID as cookie.
        If the app/endpoint starts a session and honors the fixated SID
        (no replacement Set-Cookie), fixation via POST body is viable."""
        fx = getattr(self, "_fixation", None)
        if fx == "confirmed":
            self.checks["session_fixation"] = {
                "status": "confirmed",
                "detail": "server adopted the POST-body SID (Set-Cookie echo and/or "
                          "sess file on host) — use_only_cookies bypassed by the "
                          "rfc1867 handler (pre-PR#22113)"}
            return
        resp = self._get(self.probe_path, cookie=f"{self._sess_name}={sid}")
        head, _ = split(resp)
        m = re.search(r"Set-Cookie:\s*" + re.escape(self._sess_name) +
                      r"=([^;\r\n]+)", head, re.I)
        if m and m.group(1).strip() == sid:
            detail, st = ("server re-issued the attacker-chosen SID — fixation accepted",
                          "exposed")
        elif m:
            detail, st = ("server replaced SID — cookie-side fixation resisted "
                          "(POST-body fixation may still work in rfc1867)", "resisted")
        elif resp:
            detail, st = ("endpoint did not start a session for this SID probe; "
                          "check sess_" + sid + " on host to confirm file creation",
                          "inconclusive")
        else:
            detail, st = "no response", "unknown"
        self.checks["session_fixation"] = {"status": st, "detail": detail}

    def filename_injection_probe(self):
        """Benign marker (NOT code) in filename → stored raw in session data.
        Confirms the Chain A primitive without injecting anything executable."""
        marker = "phpscan_marker_" + uuid.uuid4().hex[:12]
        sid = "phpscanfi" + uuid.uuid4().hex[:18]
        self._upload(self.probe_path,
                     {self._sess_name: sid, self.progress_name: "x"},
                     filename=marker)
        # remote-only signal: some endpoints reflect session/upload-progress
        # data back (progress bars, debug output) — if the marker comes back
        # verbatim, injection is confirmed without any host channel.
        resp = self._get(self.probe_path, cookie=f"{self._sess_name}={sid}")
        if resp and marker.encode() in resp.partition(b"\r\n\r\n")[2]:
            self.checks["filename_injection"] = {
                "status": "confirmed",
                "detail": f"marker '{marker}' reflected verbatim by the "
                          "endpoint — raw filename reached session/upload "
                          "state (Chain A primitive; NOT fixed by the CVE patch)"}
            return
        if self.confirm and self.host_ch.available:
            if self.host_ch.file_contains(f"sess_{sid}", marker):
                self.checks["filename_injection"] = {
                    "status": "confirmed",
                    "detail": f"marker '{marker}' found verbatim in sess_{sid} — "
                              "raw filenames reach session storage "
                              "(Chain A primitive; NOT fixed by the CVE patch)"}
            else:
                exists = self.host_ch.file_exists(f"sess_{sid}")
                self.checks["filename_injection"] = {
                    "status": "not_confirmed",
                    "detail": (f"sess_{sid} exists but marker erased — "
                               "upload_progress.cleanup=On removed it"
                               if exists else
                               f"no sess_{sid} found via host channel")}
            return
        self.checks["filename_injection"] = {
            "status": "needs_host_check",
            "detail": f"sent marker filename '{marker}' under sid '{sid}'; "
                      f"confirm on host: grep {marker} <session.save_path>/sess_{sid} "
                      "— if present, raw filenames reach session storage "
                      "(Chain A primitive; NOT fixed by the CVE patch)"}

    # ------------------------------------------------------------ OOM senders
    # Three documented CVE-2026-109618 OOM strategies (advisory GHSA-
    # w8hw-w9fx-j79w / ikow verify_oom_trigger.py):
    #   chunked — no Content-Length → post_max_size bypass, unbounded body
    #   headers — thousands of part headers → ~3-5x memory amplification
    #   nested  — empty file controls with a[b][c]... names → nested-array
    #             multiplication; doesn't count toward max_file_uploads
    # chunked is strongest but edge/WAFs often drop it; the other two are
    # small bounded requests that usually get through.

    def _oom_sock(self):
        s = socket.create_connection((self.host, self.port), timeout=30)
        if self.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        return s

    @staticmethod
    def _oom_recv(s):
        s.settimeout(30)
        resp = b""
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                resp += d
                if len(resp) > 1 << 20:
                    break
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            pass
        s.close()
        return resp

    def _oom_ladder_chunked(self):
        """Chunked bodies carry no Content-Length, so they are NOT bound by
        post_max_size — the only strategy allowed to escalate: send
        64 → oom_mb → 256MB, stopping at the first response that already
        shows the OOM string (or when the connection is cut)."""
        sizes = sorted({64, self.oom_mb, 256})
        r, sent = None, 0
        for mb in sizes:
            r, sent = self._oom_send_chunked(mb)
            if r is None or b"Allowed memory size" in \
                    r.partition(b"\r\n\r\n")[2]:
                break
        return r, sent

    def _oom_send_chunked(self, mb):
        """Unbounded body via chunked encoding. Returns (resp, sent_mb)
        or (None, sent_mb) when the connection was cut mid-upload."""
        boundary = "PHPSCANOOM" + uuid.uuid4().hex[:8]
        head_part = (f"--{boundary}\r\n"
                     f'Content-Disposition: form-data; name="phpscan_data"\r\n\r\n'
                     ).encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        total = mb * 1024 * 1024
        req = (f"POST {self.probe_path} HTTP/1.1\r\nHost: {self.host}\r\n"
               + BASE_HEADERS +
               f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
               + self._cookie_line()
               + f"Transfer-Encoding: chunked\r\n"
               f"Connection: close\r\n\r\n").encode()
        s = self._oom_sock()

        def ch(d):
            s.sendall(f"{len(d):x}\r\n".encode() + d + b"\r\n")

        sent = 0
        try:
            s.sendall(req)
            ch(head_part)
            chunk = b"A" * (1024 * 1024)
            while sent < total:
                n = min(len(chunk), total - sent)
                ch(chunk[:n])
                sent += n
            ch(tail)
            s.sendall(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError, socket.timeout,
                ssl.SSLError, OSError):
            s.close()
            return None, sent >> 20
        return self._oom_recv(s), sent >> 20

    def _oom_send_headers(self):
        """Header amplification: one part with N oversized headers.
        PHP stores each as zend_string + HashTable bucket (~3-5x wire)."""
        boundary = "PHPSCANHDR" + uuid.uuid4().hex[:8]
        # wire bytes ≈ oom_mb/4 → est. PHP memory ≈ oom_mb
        wire = max(2, self.oom_mb // 4) * 1024 * 1024
        hsz = 500
        num = min(20000, max(200, wire // (hsz + 24)))
        part = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="f"; filename="a"\r\n'
                + "".join(f"X-Pad-{i}: {'A' * hsz}\r\n" for i in range(num))
                + f"\r\nZ\r\n--{boundary}--\r\n")
        body = part.encode()
        req = (f"POST {self.probe_path} HTTP/1.1\r\nHost: {self.host}\r\n"
               + BASE_HEADERS +
               f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
               + self._cookie_line()
               + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
               ).encode() + body
        try:
            s = self._oom_sock()
            s.sendall(req)
        except (BrokenPipeError, ConnectionResetError, socket.timeout,
                ssl.SSLError, OSError):
            try:
                s.close()
            except OSError:
                pass
            return None
        return self._oom_recv(s)

    def _oom_send_nested(self):
        """Empty file controls with deeply nested names — nested-array
        multiplication (empty controls skip max_file_uploads)."""
        boundary = "PHPSCANNST" + uuid.uuid4().hex[:8]
        depth = 60
        # each part ≈ depth nested arrays ≈ depth*300B of PHP memory
        width = min(5000, max(50, (self.oom_mb * 1024 * 1024) // (depth * 300)))
        nested = "f" + "[x]" * depth
        parts = "".join(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{nested}[{i}]"; '
            f'filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
            for i in range(width))
        body = (parts + f"--{boundary}--\r\n").encode()
        req = (f"POST {self.probe_path} HTTP/1.1\r\nHost: {self.host}\r\n"
               + BASE_HEADERS +
               f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
               + self._cookie_line()
               + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
               ).encode() + body
        try:
            s = self._oom_sock()
            s.sendall(req)
        except (BrokenPipeError, ConnectionResetError, socket.timeout,
                ssl.SSLError, OSError):
            try:
                s.close()
            except OSError:
                pass
            return None
        return self._oom_recv(s)

    def oom_probe(self):
        """Confirm the CVE-2026-109618 trigger primitive on mod_php:
        force OOM during SAPI body parsing — signature is 'Allowed memory
        size ... in Unknown on line 0'.

        INTRUSIVE: causes memory_limit fatal errors in a worker.
        Does NOT attempt corruption — no heap spray, one request per
        strategy only."""
        strategies = {
            "chunked": self._oom_ladder_chunked,
            # Content-Length bodies are bound by post_max_size — a body over
            # the default 8M may be rejected before memory grows, so
            # headers/nested run at a fixed --oom-mb estimate (no ladder).
            "headers": lambda: (self._oom_send_headers(), 0),
            "nested": lambda: (self._oom_send_nested(), 0),
        }
        order = (["chunked", "headers", "nested"]
                 if self.oom_strategy == "auto"
                 else [self.oom_strategy])
        resp, used, sent_mb = b"", None, 0
        fails = []
        for name in order:
            r, sent_mb = strategies[name]()
            if r is not None:
                resp, used = r, name
                break
            fails.append(name)
        if used is None:
            self.checks["oom_trigger"] = {
                "status": "inconclusive",
                "detail": f"connection cut mid-upload for all strategies "
                          f"({', '.join(order)}; ~{sent_mb}MB sent before drop) "
                          "— usually edge/WAF dropping the body, BUT a cut on "
                          "the chunked rung followed by a healthy server is "
                          "also the patched hard-OOM shape (worker exits on "
                          "OOM instead of longjmp-ing); indistinguishable "
                          "remotely — retry from inside the edge"}
            return

        leak = self._sid_anomaly(split(resp)[0] if resp else "")
        if leak:
            self._sid_leak = leak

        # Differential signals (display_errors=Off hides the fatal string, so
        # crash behavior is the fingerprint — cf. 9bie no-display-errors notes):
        #   patched   → graceful OOM error page, or hard-OOM worker _exit(137)
        #               (clean 500/connection close, next request healthy)
        #   unpatched → stale EG()/BG() → worker abort: connection reset,
        #               empty 500, upstream 502, and/or next request fails
        status_line_txt = status_line(resp) if resp else ""
        m500 = re.search(r"HTTP/1\.\d\s+(\d+)", status_line_txt)
        code = int(m500.group(1)) if m500 else 0
        nbody = len(resp.partition(b"\r\n\r\n")[2]) if resp else 0

        # post-OOM liveness: is the worker/pool still serving?
        time.sleep(0.4)
        try:
            live = bool(self._get(self.probe_path))
        except OSError:
            live = False

        body = resp.decode("latin1", "replace")
        oom = "Allowed memory size" in body
        sapi_scope = re.search(r"in\s*<?b?>?\s*Unknown", body) is not None
        crash_sig = ((not resp) or code == 502 or (code == 500 and nbody == 0))
        strat = f" (strategy: {used}" + (f" — earlier tries cut: {', '.join(fails)}"
                                        if fails else "") + ")"
        if used in ("headers", "nested"):
            strat += ("; body carries Content-Length — bound by "
                      "post_max_size (default 8M): an oversized body may be "
                      "rejected before memory grows, only chunked can "
                      "bypass that")
        if oom and sapi_scope:
            self.checks["oom_trigger"] = {
                "status": "confirmed",
                "detail": "OOM during SAPI multipart parsing observed "
                          "('in Unknown on line 0') — CVE-2026-109618 trigger "
                          "primitive present. Exploitation further requires "
                          "heap control; this probe does not attempt it."
                          + strat}
        elif oom:
            # On PHP 8.2+ the patch rewrote OOM handling: delayed OOM fires
            # at a VM safe point → the error names a real file/line, while
            # the unpatched longjmp produces "in Unknown on line 0".
            # Pre-8.x there IS no delayed-OOM machinery — a concrete-location
            # fatal is just a normal memory_limit error, not patch evidence.
            pre8 = self._ver and self._ver[0] < 8
            loc = re.search(r"in\s+(/\S+|[A-Za-z]:\\\S+|\S+\.php)\s+on line",
                            body)
            if pre8:
                st, why = "partial", ("OOM fatal at a concrete location — on "
                                      "PHP <8 this is an ordinary memory_limit "
                                      "fatal (no delayed-OOM machinery exists); "
                                      "EOL branch has no patched shape to "
                                      "compare against")
            elif loc:
                st, why = "likely_patched", (
                    "OOM fatal fired pointing at a concrete code location — "
                    "consistent with the PATCHED delayed-OOM path "
                    "(zend_handle_delayed_oom at a VM safe point); the "
                    "unpatched longjmp produces 'in Unknown on line 0'")
            else:
                st, why = "partial", ("OOM fatal fired but in user code scope "
                                      "— primitive not confirmed at SAPI stage")
            self.checks["oom_trigger"] = {"status": st,
                                          "detail": why + strat}
        elif crash_sig and not live:
            self.checks["oom_trigger"] = {
                "status": "crash_signature",
                "detail": f"OOM probe → {status_line_txt or 'connection cut'}"
                          " and the target is not serving afterwards — worker "
                          "crash consistent with unpatched stale-EG()/BG() "
                          "behavior (patched PHP exits cleanly and recovers)"
                          + strat}
        elif crash_sig:
            self.checks["oom_trigger"] = {
                "status": "partial",
                "detail": f"OOM probe → {status_line_txt or 'connection cut'} "
                          "(crash-shaped response) but the worker recovered — "
                          "could be patched hard-OOM _exit(137); inconclusive"
                          + strat}
        elif resp:
            self.checks["oom_trigger"] = {
                "status": "not_triggered",
                "detail": (f"{status_line_txt}{strat} — memory_limit not "
                           f"reached (~{sent_mb or self.oom_mb}MB sent; "
                           "display_errors=Off may also hide the OOM "
                           "fingerprint" +
                           ("; note: the chunked rung WAS cut mid-upload — "
                            "that is also the patched hard-OOM shape "
                            "(worker exits on OOM), ambiguous vs a WAF drop"
                            if "chunked" in fails else ""))}
        else:
            self.checks["oom_trigger"] = {"status": "unknown",
                                          "detail": "no response"}

    def mod_php_note(self):
        """Warning note: affected + mod_php is the vendor-demonstrated
        pre-auth RCE configuration — report as critical."""
        if "mod_php" in self._sapi:
            self.checks["mod_php_note"] = {
                "status": "info",
                "detail": "mod_php: CVE-2026-109618 pre-auth RCE demonstrated "
                          "by vendor; treat an 'affected' version as critical"}

    def host_patch_probe(self):
        """Ground truth from the target host (--exec-cmd only): the web SAPI
        banner can be stale (workers not restarted) or hide a backport, so
        ask the host what php binary and distro packages it ACTUALLY runs
        and compare against vendor-fixed revisions (phpcheck-server)."""
        if not self.host_ch.exec_cmd:
            return
        out = self.host_ch.out(
            "(php -v || php-fpm -v || php-cgi -v) 2>/dev/null; "
            "cat /etc/os-release 2>/dev/null; "
            "dpkg-query -W -f='${Package} ${Version}\\n' 'php*' 2>/dev/null || "
            "rpm -qa 'php*' --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n' "
            "2>/dev/null")
        if not out or out.startswith("__exec_error"):
            self.checks["host_patch_status"] = {
                "status": "unknown",
                "detail": "host command produced no usable output"}
            return
        # worst-of every PHP version the host reports
        vers = {tuple(int(x) for x in m.groups())
                for m in re.finditer(r"PHP[/ ]?(\d+)\.(\d+)\.(\d+)", out)}
        st, det = ("unknown", "no PHP version reported by host")
        if vers:
            RANK = {"affected": 5, "eol": 4, "unknown": 3, "patched": 2,
                    "not_applicable": 1}
            st, det = max((version_state(v) for v in vers),
                          key=lambda t: RANK[t[0]])
            det += f" (host binary: {max(vers)})"
        # distro package comparison against vendor-fixed revisions
        osid = re.search(r"^ID=([\w.-]+)", out, re.M)
        osver = re.search(r"^VERSION_ID=\"?([\w.]+)", out, re.M)
        osid = osid.group(1).strip('"').lower() if osid else ""
        osver = osver.group(1) if osver else ""
        pkgnote = ""
        for did, dver, rx, fixed, adv in VENDOR_FIXED:
            if did == osid and osver.startswith(dver):
                m = re.search(rf"^({rx}[^\s]*)\s+(\S+)", out, re.M)
                if m:
                    pkgnote += (f"; {m.group(1)} {m.group(2)} vs vendor-fixed "
                                f"{fixed} ({adv}) — verify with "
                                f"{'dpkg --compare-versions' if did in ('debian','ubuntu') else 'rpmdev-vercmp'}")
        self.checks["host_patch_status"] = {
            "status": st,
            "detail": det + pkgnote +
                      " — host-side values are authoritative over HTTP banners "
                      "(workers may serve an older cached build)"}

    def run(self):
        if not self.fingerprint():
            return self.checks
        self.version_verdict()
        self.mod_php_note()
        sid = "phpscan" + uuid.uuid4().hex[:20]
        self.upload_progress_probe(sid)
        self.session_fixation_probe(sid)
        self.filename_injection_probe()
        self.display_errors_probe()
        if self._iocs:
            self.checks["response_iocs"] = {
                "status": "exposed",
                "detail": "\n".join(self._iocs)}
        self.host_patch_probe()
        if self._sid_leak:
            self.checks["sid_leak"] = {
                "status": "leak_signature",
                "detail": "anomalous session-id in Set-Cookie "
                          f"({self._sid_leak if isinstance(self._sid_leak, str) else 'non-printable/oversized'})"
                          " — heap memory disclosed through the cookie, the "
                          "CVE-2026-109618 stage-1 leak primitive (Sansec "
                          "detection SID 2026112)"}
        if self.confirm:
            if "mod_php" in self._sapi or self.force_oom or \
                    self.checks.get("cve_affected", {}).get("status") in (
                        "affected", "eol"):
                self.oom_probe()
            else:
                self.checks["oom_trigger"] = {
                    "status": "skip",
                    "detail": "SAPI does not look like mod_php and version not "
                              "confirmed affected; use --confirm-oom to force"}
        self.checks["detection_hunting"] = {"status": "info", "detail": HUNT_TIPS}
        return self.checks


# ---------------------------------------------------------------- local

INI_FILES = ("php.ini", ".user.ini")
CONF_HINTS = re.compile(
    r"(php_value|php_flag|php_admin_value|php_admin_flag)\s+([\w.\-]+)\s+(.+)", re.I)
# php-fpm pool / apache conf bracket syntax: php_admin_flag[key] = val
POOL_HINTS = re.compile(
    r"php_(?:admin_)?(?:value|flag)\s*\[\s*([\w.\-]+)\s*\]\s*=\s*([^\s;#]+)", re.I)
# existing mitigations: WAF/rewrite rules that block the trigger field or
# multipart bodies outright (eness apache/.htaccess, lighttpd conf,
# modsecurity rule id 1026109618)
MITIGATION_HINTS = [
    (re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I),
     "blocks PHP_SESSION_UPLOAD_PROGRESS field"),
    (re.compile(r"multipart/form-data.*(access-deny|deny|\[F|,L\b|status:403|"
                r"SecRule|access_deny)", re.I | re.S),
     "blocks multipart/form-data on non-upload routes"),
    (re.compile(r"1026109618|php2shell", re.I),
     "php2shell-specific WAF rule present"),
]

SINKS = [
    (re.compile(r"\bunserialize\s*\("),
     "unserialize() — object-injection sink (chain-B/C precondition)"),
    (re.compile(r"\b(include|include_once|require|require_once)\s*\(?\s*\$"),
     "include/require of variable — LFI sink (chain-A precondition)"),
    (re.compile(r"ini_set\s*\(\s*['\"]session\.serialize_handler"),
     "runtime session.serialize_handler change — chain-C enabler"),
    (re.compile(r"\bsession_set_save_handler\s*\("), "custom session save handler"),
    (re.compile(r"\bsession_decode\s*\("),
     "session_decode() of (possibly tainted) data — unserialize-equivalent sink"),
    (re.compile(r"\brequest_parse_body\s*\("),
     "request_parse_body() — PHP 8.4+ parses multipart on non-POST methods "
     "(widened rfc1867 surface; POST-only WAF rules bypassed)"),
]

DANGER_CALLS = re.compile(
    r"\b(system|exec|shell_exec|passthru|popen|proc_open|eval|assert|"
    r"file_put_contents|fwrite|unlink|call_user_func(?:_array)?|"
    r"create_function)\s*\(")

MAGIC_GADGET = re.compile(
    r"class\s+(\w+)[^{]*\{.*?"
    r"function\s+(__destruct|__wakeup|__unserialize|__call|__invoke|__toString)"
    r"\s*\([^)]*\)\s*\{(.*?)\}", re.S)

# composer packages with publicly documented POP/unserialize chains
KNOWN_GADGET_PKGS = {
    "laravel/framework": "PendingBroadcast / event chains",
    "monolog/monolog": "SyslogUdpHandler / BufferHandler chains",
    "guzzlehttp/guzzle": "FnStream / CookieJar chains",
    "twig/twig": "Template / extension chains",
    "phpunit/phpunit": "dev-only; eval-stdin / global-state chains (should not ship to prod)",
    "fakerphp/faker": "Generator formatter chains",
    "swiftmailer/swiftmailer": "legacy Swift chains (EOL package)",
    "phpoffice/phpspreadsheet": "writer __destruct chains",
    "doctrine/orm": "proxy/collection chains",
    "symfony/symfony": "component chains (Finder, Process, HttpKernel)",
}

PHP_EXT_PATTERN = re.compile(r"\.(php|php[3457]?|phtml|inc|module)$")

# Vendor-fixed package versions — an upstream banner alone cannot judge
# patch status because distros backport (phpcheck-server skill, verified
# 2026-10-22). (distro_id, VERSION_ID, source-package branch regex,
# fixed source version, advisory)
VENDOR_FIXED = [
    ("debian", "12",    r"php8\.2", "8.2.35-1~deb12u1",                  "DLA-4848-1"),
    ("debian", "13",    r"php8\.4", "8.4.27-1~deb13u1",                  "DSA-6574-1"),
    ("ubuntu", "26.10", r"php8\.5", "8.5.9-0ubuntu2.1",                  "USN-8948-1"),
    ("ubuntu", "26.04", r"php8\.5", "8.5.4-0ubuntu1.5",                  "USN-8948-1"),
    ("ubuntu", "24.04", r"php8\.3", "8.3.6-0ubuntu0.24.04.13",           "USN-8948-1"),
    ("ubuntu", "22.04", r"php8\.1", "8.1.2-1ubuntu2.28",                 "USN-8948-1"),
    ("ubuntu", "20.04", r"php7\.4", "7.4.3-4ubuntu2.29+esm5",            "USN-8948-2 (Ubuntu Pro)"),
    ("ubuntu", "18.04", r"php7\.2", "7.2.24-0ubuntu0.18.04.17+esm14",    "USN-8948-2 (Ubuntu Pro)"),
    ("ubuntu", "16.04", r"php7\.0", "7.0.33-0ubuntu0.16.04.16+esm22",    "USN-8948-2 (Ubuntu Pro)"),
    ("ubuntu", "14.04", r"php5",    "5.5.9+dfsg-1ubuntu4.29+esm18",      "USN-8948-2 (Ubuntu Pro)"),
    ("rhel",   "8.10",  r"php",     "7.4.33-8.module+el8.10.0+25117+30337cca", "RHSA-2026:87080"),
    ("rhel",   "9.8",   r"php",     "8.0.30-8.el9_8.1",                  "RHSA-2026:87151"),
]

HUNT_TIPS = ("incident hunting: grep 'PHP_SESSION_UPLOAD_PROGRESS' in "
             "web access logs; flag multipart POSTs without Content-Length "
             "(chunked OOM bypass), multipart parts with hundreds of headers "
             "or deeply nested a[b][c]... field names (low-bandwidth OOM), "
             "oversized/quoted filename= values, filenames containing '<?' "
             "or '|O:' (session/object injection), /sess_ paths in URIs "
             "(LFI on session files), and multipart POSTs to non-upload "
             "endpoints (PHP 8.4+ also accepts multipart on PUT/PATCH/DELETE "
             "via request_parse_body), the comma Content-Type variant "
             "'multipart/form-data,boundary=' (bypasses semicolon-anchored "
             "WAF regexes), and bursts of long-lived half-sent multipart "
             "POSTs from one source (worker pinning, ASLR-bypass setup). "
             "Response/log side: 'Session object "
             "destruction failed', 'Allowed memory size ... in Unknown on "
             "line 0', and anomalous PHPSESSID Set-Cookie values (>=64 chars "
             "or non-hex — heap leak, Sansec SID 2026112). Host side: alert "
             "on php-fpm/httpd workers spawning sh/bash/python/curl/wget/nc "
             "children (e.g. process-watcher in observe mode).")


class LocalScan:
    """Audit code/config of an on-disk PHP project."""

    TRACKED_KEYS = {
        "session.upload_progress.enabled", "session.serialize_handler",
        "session.use_only_cookies", "session.use_strict_mode",
        "session.save_path", "session.name", "session.use_cookies",
        "session.upload_progress.cleanup", "session.upload_progress.min_freq",
        "session.upload_progress.prefix", "session.upload_progress.name",
        "fatal_error_backtraces",
        "memory_limit", "post_max_size", "upload_max_filesize",
        "max_input_vars", "max_file_uploads", "display_errors",
        "expose_php", "disable_functions", "open_basedir",
        "allow_url_include",
        "opcache.enable", "opcache.file_cache", "opcache.enable_cli",
    }

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.checks = {}
        self.findings = []        # (severity, where, what)
        self._versions = set()    # (source_kind, version_str, path)
        self._sapi_evidence = set()
        self._handlers = {}       # serialize_handler value -> [files]
        self._ini_notes = []
        self._settings = {}       # key -> (path, value)
        self._mitig = []          # existing WAF/config mitigations found

    def _mitigations(self, path, txt):
        rel = os.path.relpath(path, self.root)
        for rx, desc in MITIGATION_HINTS:
            if rx.search(txt):
                self._mitig.append(f"{desc} in {rel}")
        # a multipart block that only names POST is bypassable on PHP 8.4+
        # (request_parse_body parses multipart on PUT/PATCH/DELETE)
        if re.search(r"multipart/form-data", txt, re.I) and \
                re.search(r"access-deny|deny|\[F|,L\b|status:403|SecRule",
                          txt, re.I) and \
                not re.search(r"\b(PUT|PATCH|DELETE)\b", txt, re.I):
            self._mitig.append(
                f"{rel}: multipart block appears POST-only — PHP 8.4 "
                "request_parse_body() accepts multipart on PUT/PATCH; "
                "extend the rule or it is bypassable")

    def _walk(self):
        for dirpath, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in
                       (".git", "node_modules", ".svn", "tests", "test")]
            yield dirpath, files

    def _record_setting(self, src, key, val):
        self._settings[key] = (src, val)
        if key == "session.serialize_handler":
            self._handlers.setdefault(val.lower(), []).append(src)
        if key == "session.upload_progress.enabled" and val.lower() in ("off", "0"):
            self._ini_notes.append(
                f"{src}: upload_progress disabled — covers the CVE-2026-109619 "
                "session arms only; does NOT fix CVE-2026-109618 (OOM) — patch "
                "still required")
        if key == "session.use_only_cookies" and val.lower() in ("0", "off"):
            self._ini_notes.append(f"{src}: use_only_cookies=0 — fixation easier")
        if key == "session.use_strict_mode" and val.lower() in ("0", "off"):
            self._ini_notes.append(
                f"{src}: use_strict_mode=0 — attacker-chosen SIDs accepted verbatim")
        if key == "fatal_error_backtraces" and val.lower() not in ("0", "off"):
            self._ini_notes.append(
                f"{src}: fatal_error_backtraces=On — on PHP 8.5 this is the third "
                "persistent-variable arm of CVE-2026-109619; set 0 until patched")
        if key == "memory_limit":
            self._ini_notes.append(
                f"{src}: memory_limit={val} " +
                ("(counterintuitive but GOOD vs CVE-2026-109618 — removes the "
                  "predictable alloc failure; do NOT substitute RLIMIT_AS/"
                  "RLIMIT_DATA, which hit the same vulnerable path)"
                 if val.strip() == "-1" else "(OOM reachable)"))
        if key == "display_errors" and val.lower() in ("1", "on", "stdout"):
            self._ini_notes.append(
                f"{src}: display_errors=On — makes the error-dependent leak "
                "path of CVE-2026-109618 easier and leaks fingerprints; set "
                "Off in production")
        if key == "max_input_vars":
            self._ini_notes.append(
                f"{src}: max_input_vars={val} — the input-var warning is what "
                "sets headers_sent for the display_errors leak path; lower "
                "values reach the warning sooner")
        if key == "session.name" and val.lower() != "phpsessid":
            self._ini_notes.append(
                f"{src}: custom session.name={val} — remote rfc1867 SID "
                "probes must use this cookie name, not PHPSESSID")
        if key == "session.upload_progress.cleanup" and \
                val.lower() in ("0", "off"):
            self._ini_notes.append(
                f"{src}: upload_progress.cleanup=Off — injected filenames "
                "persist in session data even after the upload finishes "
                "(Chain A primitive becomes durable)")
        if key == "session.upload_progress.name" and \
                val.upper() != "PHP_SESSION_UPLOAD_PROGRESS":
            self._ini_notes.append(
                f"{src}: upload_progress.name={val} — the rfc1867 trigger "
                "field is renamed; remote probes and WAF rules must match "
                "this name (--progress-name), not PHP_SESSION_UPLOAD_PROGRESS")
        if key == "opcache.enable" and val.lower() in ("1", "on"):
            self._ini_notes.append(
                f"{src}: OPcache enabled — the OPcache shared-memory arm of "
                "CVE-2026-109619 has NO ini mitigation; patching is the only "
                "fix (JFrog three-arms analysis)")

    def config_audit(self):
        inis, htaccess, docker, comps, websrv, pools = [], [], [], [], [], []
        for dirpath, files in self._walk():
            for f in files:
                p = os.path.join(dirpath, f)
                lf = f.lower()
                if f in INI_FILES or lf.endswith(".ini"):
                    inis.append(p)
                elif f == ".htaccess":
                    htaccess.append(p)
                elif f.startswith("Dockerfile"):
                    docker.append(p)
                elif lf.startswith("docker-compose") or lf in ("compose.yml", "compose.yaml"):
                    comps.append(p)
                elif f == "www.conf" or \
                        (lf.endswith(".conf") and "pool" in dirpath):
                    pools.append(p)   # pool files first — before websrv match
                elif lf in ("nginx.conf", "httpd.conf", "apache2.conf") or \
                        lf.startswith("lighttpd") or \
                        (lf.endswith(".conf") and "fpm" in lf):
                    websrv.append(p)
                elif lf == "caddyfile" or lf.endswith(".caddyfile"):
                    websrv.append(p)

        for p in inis:
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in re.finditer(r"^\s*([\w.\-]+)\s*=\s*(.+?)\s*$", txt, re.M):
                k, v = m.group(1).lower(), m.group(2).strip().strip('"\'')
                if k in self.TRACKED_KEYS:
                    self._record_setting(p, k, v)

        for p in htaccess:
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in CONF_HINTS.finditer(txt):
                k = m.group(2).lower()
                if k in self.TRACKED_KEYS:
                    self._record_setting(p, k, m.group(3).strip())
            for m in POOL_HINTS.finditer(txt):
                if m.group(1).lower() in self.TRACKED_KEYS:
                    self._record_setting(p, m.group(1).lower(),
                                         m.group(2).strip().strip('"\''))
            self._mitigations(p, txt)
            if re.search(r"AddHandler\s+application/x-httpd-php|SetHandler.*php", txt):
                self._sapi_evidence.add(
                    f"mod_php-style handler in {os.path.relpath(p, self.root)}")

        for p in docker + comps:
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in re.finditer(r"-d\s+([\w.\-]+)\s*=\s*([^\s'\"]+)", txt):
                if m.group(1).lower() in self.TRACKED_KEYS:
                    self._record_setting(p, m.group(1).lower(), m.group(2))
            for m in re.finditer(r"(?:FROM|image:)\s*php:?([^\s\"':]+)?", txt):
                tag = m.group(1) or ""
                ver = re.match(r"(\d+\.\d+(?:\.\d+)?)", tag)
                if ver:
                    self._versions.add(("docker", ver.group(1), p))
                if "apache" in tag:
                    self._sapi_evidence.add(
                        f"apache (likely mod_php) image in {os.path.relpath(p, self.root)}")
                if "fpm" in tag:
                    self._sapi_evidence.add(
                        f"fpm image in {os.path.relpath(p, self.root)}")

        for p in websrv:
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in POOL_HINTS.finditer(txt):
                if m.group(1).lower() in self.TRACKED_KEYS:
                    self._record_setting(p, m.group(1).lower(),
                                         m.group(2).strip().strip('"\''))
            self._mitigations(p, txt)
            if re.search(r"fastcgi_pass|fastcgi:|fastcgi\.server", txt):
                self._sapi_evidence.add(
                    f"fastcgi/php-fpm in {os.path.relpath(p, self.root)}")
            if re.search(r"php[0-9_]*_module|libphp", txt):
                self._sapi_evidence.add(
                    f"mod_php in {os.path.relpath(p, self.root)}")
            if re.search(r"frankenphp|php_server", txt, re.I):
                self._sapi_evidence.add(
                    f"FrankenPHP embedded SAPI in {os.path.relpath(p, self.root)}")
            if re.search(r"mod_fastcgi|scgi\.server", txt, re.I):
                self._sapi_evidence.add(
                    f"lighttpd fastcgi in {os.path.relpath(p, self.root)}")

        pool_notes = []
        for p in pools:
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(p, self.root)
            self._sapi_evidence.add(f"php-fpm pool config: {rel}")
            for m in POOL_HINTS.finditer(txt):
                if m.group(1).lower() in self.TRACKED_KEYS:
                    self._record_setting(p, m.group(1).lower(),
                                         m.group(2).strip().strip('"\''))
            self._mitigations(p, txt)
            m = re.search(r"^\s*pm\.max_requests\s*=\s*(\d+)", txt, re.M)
            if m:
                n = int(m.group(1))
                pool_notes.append(
                    f"{rel}: pm.max_requests={n} " +
                    ("— worker recycled per request: Chain E stale-state "
                     "consumer cannot reach the same worker (good)"
                     if n == 1 else
                     "— workers persist across requests: Chain E stale-BG "
                     "consumer viable; pm.max_requests=1 mitigates (perf cost)"))
            m = re.search(r"^\s*pm\s*=\s*(\w+)", txt, re.M)
            if m and m.group(1) == "static":
                pool_notes.append(
                    f"{rel}: pm=static — predictable worker lifetime, no "
                    "mitigation value either way")

        def _rel(s):
            return s if s.startswith("runtime:") else \
                os.path.relpath(s, self.root)
        if self._settings:
            det = "\n".join(f"{k} = {v}  [{_rel(s)}]"
                            for k, (s, v) in sorted(self._settings.items()))
        else:
            det = "no php ini/htaccess settings found"
        extra = "\n".join(self._ini_notes)
        self.checks["ini_audit"] = {"status": "done",
                                    "detail": det + ("\n" + extra if extra else "")}
        self.checks["sapi_evidence"] = {
            "status": "info",
            "detail": "; ".join(sorted(self._sapi_evidence)) or
                      "no web-server config found"}
        self.checks["fpm_pool_cfg"] = {
            "status": "info",
            "detail": "\n".join(pool_notes) if pool_notes else
                      "no php-fpm pool config found (Chain E mitigation "
                      "pm.max_requests=1 not assessable)"}
        self.checks["mitigations"] = {
            "status": "info",
            "detail": "; ".join(sorted(set(self._mitig))) if self._mitig else
                      "no existing WAF/rewrite mitigations found — consider "
                      "blocking PHP_SESSION_UPLOAD_PROGRESS or multipart on "
                      "non-upload routes until patched"}

        if len(self._handlers) > 1:
            detail = "; ".join(
                f"'{h}' in {len(ps)} file(s) "
                f"({', '.join(x if x.startswith('runtime:') else os.path.relpath(x, self.root) for x in ps)})"
                for h, ps in self._handlers.items())
            self.checks["serialize_handler_conflict"] = {
                "status": "exposed",
                "detail": "MULTIPLE serialize_handler values: " + detail +
                          " — Chain C handler-mismatch precondition MET"}
            self.findings.append(("high", "serialize_handler_conflict",
                                  "dual handler config — chain-C precondition met"))

    def version_discovery(self):
        """Best-effort PHP version from Dockerfile / composer.json / lock."""
        hints = []
        for kind, v, src in sorted(self._versions):
            hints.append(f"{v} (from {kind} {os.path.relpath(src, self.root)})")
        for dirpath, files in self._walk():
            for f in files:
                if f not in ("composer.json", "composer.lock"):
                    continue
                p = os.path.join(dirpath, f)
                try:
                    data = json.load(open(p, encoding="utf-8", errors="replace"))
                except (OSError, ValueError):
                    continue
                req = (data.get("require") or {}).get("php") or \
                      (data.get("config", {}).get("platform") or {}).get("php")
                if req:
                    hints.append(f'composer php constraint "{req}" '
                                 f'({os.path.relpath(p, self.root)})')
                if f == "composer.lock":
                    self._gadget_packages(data)
            if len(hints) > 12:
                break
        self.checks["php_version_hints"] = {
            "status": "info",
            "detail": "\n".join(hints) or "no PHP version indicators found"}
        ver = None
        for kind, v, _ in sorted(self._versions):
            m = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
            if m:
                ver = tuple(int(x) for x in m.groups())
                break
        st, det = version_state(ver)
        self.checks["cve_range_local"] = {
            "status": st if ver else "unknown",
            "detail": det if ver else "no exact version pinned in repo configs"}

    def _gadget_packages(self, lock):
        names = set()
        for sec in ("packages", "packages-dev"):
            for pkg in lock.get(sec, []):
                names.add(pkg.get("name", ""))
        hits = [f"{n} — {KNOWN_GADGET_PKGS[n]}"
                for n in sorted(names) if n in KNOWN_GADGET_PKGS]
        if hits:
            self.checks["composer_gadget_pkgs"] = {
                "status": "exposed", "detail": "\n".join(hits)}
            self.findings.append(("medium", "composer_gadget_pkgs",
                                  f"{len(hits)} package(s) with documented POP chains"))

    def upload_progress_cfg(self):
        v = self._settings.get("session.upload_progress.enabled")
        src = v[0] if v and not v[0].startswith("runtime:") else \
            (v[0] if v else None)
        if v and v[1].lower() in ("off", "0"):
            st, det = ("not_exposed",
                       f"disabled in {src} — blocks "
                       "CVE-2026-109619 session arms only; CVE-2026-109618 OOM "
                       "still applies, patch required")
        elif v:
            st, det = "exposed", f"enabled in {src} (default anyway)"
        else:
            st, det = "exposed", "not set → PHP default is On"
        self.checks["upload_progress_cfg"] = {"status": st, "detail": det}
        if st == "exposed":
            self.findings.append(("medium", "upload_progress.enabled",
                                  "On (default) — chain-A trigger + CVE-2026-109619 "
                                  "vector; set Off unless app uses progress bars"))

    def sink_scan(self, max_files=30000, max_bytes=4 << 20):
        hits = {desc: [] for _, desc in SINKS}
        gadgets, n = [], 0
        for dirpath, files in self._walk():
            for f in files:
                if not PHP_EXT_PATTERN.search(f):
                    continue
                n += 1
                if n > max_files:
                    break
                p = os.path.join(dirpath, f)
                try:
                    if os.path.getsize(p) > max_bytes:
                        continue
                    txt = open(p, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                rel = os.path.relpath(p, self.root)
                for rx, desc in SINKS:
                    if rx.search(txt):
                        hits[desc].append(rel)
                for m in MAGIC_GADGET.finditer(txt):
                    if DANGER_CALLS.search(m.group(3)):
                        tag = "vendor" if "/vendor/" in p.replace(os.sep, "/") else "app"
                        gadgets.append(f"{rel}: class {m.group(1)}::{m.group(2)} ({tag})")
        lines = []
        for desc, ps in hits.items():
            if ps:
                lines.append(f"{desc}: {len(ps)} file(s) — e.g. {ps[0]}")
                sev = "high" if ("LFI" in desc or "unserialize" in desc) else "medium"
                self.findings.append((sev, desc, f"{len(ps)} file(s), e.g. {ps[0]}"))
        if gadgets:
            lines.append(f"POP gadget candidates (__destruct/__wakeup/__call + "
                         f"dangerous call): {len(gadgets)} — e.g. {gadgets[0]}")
            self.findings.append(("medium", "POP gadget candidates",
                                  f"{len(gadgets)} classes, e.g. {gadgets[0]}"))
        self.checks["code_sinks"] = {"status": "done",
                                     "detail": "\n".join(lines) or
                                               "no unserialize/LFI/gadget sinks found"}
        self.checks["files_scanned"] = {"status": "info", "detail": f"{n} php files"}

    def runtime_probe(self):
        """Query the installed php CLI (if any) for effective runtime values.

        On-disk ini files are not necessarily the values in force — the CLI
        answers what IT loads, and vendor packages may backport the fix at a
        lower upstream banner (phpcheck-server approach: inspect the actual
        binary/package, not just the advertised version)."""
        php = shutil.which("php")
        if not php:
            return
        try:
            r = subprocess.run(
                [php, "-r",
                 'echo PHP_VERSION,"|",PHP_SAPI,"|",'
                 'ini_get("session.upload_progress.enabled"),"|",'
                 'ini_get("session.serialize_handler"),"|",'
                 'ini_get("session.name"),"|",'
                 'ini_get("display_errors"),"|",'
                 'ini_get("memory_limit"),"|",'
                 'ini_get("session.upload_progress.name"),"|",'
                 'ini_get("opcache.enable");'],
                capture_output=True, text=True, timeout=15)
            parts = (r.stdout or "").split("|")
        except (subprocess.TimeoutExpired, OSError):
            return
        if len(parts) < 9:
            return
        ver_s, sapi = parts[0], parts[1]
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver_s)
        ver = tuple(int(x) for x in m.groups()) if m else None
        st, det = version_state(ver)
        keys = ("session.upload_progress.enabled", "session.serialize_handler",
                "session.name", "display_errors", "memory_limit",
                "session.upload_progress.name", "opcache.enable")
        for k, v in zip(keys, parts[2:9]):
            v = v.strip()
            if v != "":
                # runtime values override on-disk findings (they are what's
                # actually in force for this binary)
                self._record_setting("runtime:php -r", k, v)
        self.checks["runtime_php"] = {
            "status": "info",
            "detail": f"php CLI {ver_s} (SAPI {sapi}) — {det}. Effective ini "
                      "read from the binary itself; it may differ from "
                      "on-disk files and from the web SAPI's config"}

    def vendor_packages(self):
        """Compare installed distro php packages against vendor-fixed
        revisions — a backported fix ships at a LOWER upstream number, so
        the upstream banner alone over-reports (Ubuntu/Debian/RHEL ESM)."""
        osid = osver = None
        try:
            for line in open("/etc/os-release"):
                k, _, v = line.partition("=")
                if k == "ID":
                    osid = v.strip().strip('"').lower()
                elif k == "VERSION_ID":
                    osver = v.strip().strip('"')
        except OSError:
            pass
        if not osid or osid not in {v[0] for v in VENDOR_FIXED}:
            return
        applicable = [v for v in VENDOR_FIXED
                      if v[0] == osid and osver.startswith(v[1])]
        if not applicable:
            self.checks["vendor_packages"] = {
                "status": "info",
                "detail": f"{osid} {osver}: no vendor fix data for this "
                          "release — check the vendor tracker manually"}
            return
        pkgs = []
        if osid in ("debian", "ubuntu") and shutil.which("dpkg-query"):
            try:
                r = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                    capture_output=True, text=True, timeout=20)
                for line in r.stdout.splitlines():
                    name, _, ver = line.partition(" ")
                    if re.match(r"php\d", name) or name == "php5":
                        pkgs.append((name, ver))
            except (subprocess.TimeoutExpired, OSError):
                pass
        elif osid == "rhel" and shutil.which("rpm"):
            try:
                r = subprocess.run(
                    ["rpm", "-qa", "php*",
                     "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"],
                    capture_output=True, text=True, timeout=20)
                for line in r.stdout.splitlines():
                    name, _, ver = line.partition(" ")
                    if ver:
                        pkgs.append((name, ver))
            except (subprocess.TimeoutExpired, OSError):
                pass
        if not pkgs:
            self.checks["vendor_packages"] = {"status": "info",
                                              "detail": "no php packages found"}
            return
        lines, worst = [], "info"
        for name, ver in sorted(pkgs):
            rule = next((v for v in applicable if re.match(v[2], name)), None)
            if not rule:
                continue
            fixed, adv = rule[3], rule[4]
            cmp_rc = None
            if osid in ("debian", "ubuntu") and shutil.which("dpkg"):
                cmp_rc = subprocess.run(
                    ["dpkg", "--compare-versions", ver, "ge", fixed]
                    ).returncode == 0
            if cmp_rc is True:
                lines.append(f"{name} {ver} >= {fixed} ({adv}) — patched")
            elif cmp_rc is False:
                worst = "exposed"
                lines.append(f"{name} {ver} < {fixed} ({adv}) — "
                             "potentially vulnerable")
            else:
                worst = "unknown" if worst == "info" else worst
                lines.append(f"{name} {ver} — compare against fixed {fixed} "
                             f"({adv}) manually")
        if worst == "info" and lines:
            worst = "patched"
        self.checks["vendor_packages"] = {
            "status": worst,
            "detail": "\n".join(lines) or "no php packages matched vendor data"}

    def run(self):
        self.config_audit()
        # runtime after config_audit so the binary's effective ini wins over
        # on-disk files when they disagree (php -r reads what it loads)
        self.runtime_probe()
        self.vendor_packages()
        self.version_discovery()
        self.upload_progress_cfg()
        self.sink_scan()
        self.checks["detection_hunting"] = {"status": "info", "detail": HUNT_TIPS}
        return self.checks


# ---------------------------------------------------------------- report

STATUS_ZH = {
    "ok": "通過", "info": "資訊", "done": "完成", "fail": "失敗",
    "affected": "受影響", "patched": "已修補", "eol": "已終止支援",
    "confirmed": "已確認",
    "exposed": "已暴露", "likely_exposed": "疑似暴露",
    "not_exposed": "未暴露", "not_confirmed": "未確認",
    "not_triggered": "未觸發", "partial": "部分", "skip": "略過",
    "unknown": "未知", "inconclusive": "無法判定", "resisted": "已抵擋",
    "needs_host_check": "待主機確認",
    "not_applicable": "不適用", "crash_signature": "崩潰特徵",
    "leak_signature": "洩漏特徵", "likely_patched": "疑似已修補",
}

SEV_ZH = {"critical": "嚴重", "high": "高", "medium": "中",
          "low": "低", "info": "資訊"}

CHECK_ZH = {
    "reachable": "目標可達性",
    "server_header": "HTTP Server 標頭",
    "x_powered_by": "X-Powered-By 標頭",
    "php_version": "PHP 版本指紋",
    "sapi": "PHP SAPI 類型（mod_php 風險最高）",
    "sapi_evidence": "Web 伺服器 / SAPI 證據",
    "session_cookie_name": "Session cookie 名稱（rfc1867 SID 欄位須與其一致）",
    "cve_affected": "CVE 版本判定（< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 為受影響）",
    "cve_range_local": "CVE 版本判定（依本地配置線索）",
    "upload_progress": "session.upload_progress 無認證觸發面",
    "upload_progress_cfg": "session.upload_progress 組態（預設 On）",
    "session_fixation": "工作階段固定（POST body SID 繞過 use_only_cookies）",
    "filename_injection": "上傳檔名注入 session 儲存（Chain A 原語，修補後仍有效）",
    "oom_trigger": "SAPI 階段 OOM 指紋（CVE-2026-109618 觸發原語；侵入式單次探測）",
    "mod_php_note": "mod_php 前置風險說明",
    "ini_audit": "php.ini / .user.ini / .htaccess 組態審計",
    "serialize_handler_conflict": "serialize_handler 跨目錄衝突（Chain C 前提）",
    "php_version_hints": "PHP 版本線索（Dockerfile / composer）",
    "composer_gadget_pkgs": "含已知 POP 利用鏈的 composer 套件",
    "code_sinks": "程式碼高風險 sink 掃描（unserialize / LFI / POP gadget）",
    "files_scanned": "已掃描 PHP 檔案數",
    "fpm_pool_cfg": "PHP-FPM pool 組態（pm.max_requests 為 Chain E 緩解）",
    "detection_hunting": "日誌狩獵建議（access log 入侵痕跡）",
    "sid_leak": "Session cookie 記憶體洩漏特徵（CVE-2026-109618 stage-1 原語）",
    "display_errors": "display_errors 指紋（錯誤輸出助長洩漏型利用路徑）",
    "edge_waf": "邊緣 WAF/CDN（可能過濾探測，造成無法判定）",
    "mitigations": "既有 WAF/rewrite 緩解措施",
    "response_iocs": "回應內容中的利用特徵（stale-BG 消耗 / SAPI OOM / 錯誤洩漏）",
    "runtime_php": "PHP CLI 執行期版本與生效 ini（磁碟設定可能不同）",
    "vendor_packages": "發行版套件修補狀態（backport 版本，非上游 banner）",
    "host_patch_status": "目標主機實際 PHP 二進位/套件修補狀態（ground truth）",
}


def emit_rules(outdir):
    """Write ready-to-deploy IDS rules derived from the scanner's IoC set:
    Suricata/Snort, ModSecurity, and Sigma. Mirrors of what we probe —
    every signature here is also something the scanner checks for."""
    os.makedirs(outdir, exist_ok=True)

    suricata = r"""# php2shell detection rules — generated by php_scan.py
# CVE-2026-109618 / CVE-2026-109619 — SID range 2026120-2026139

# request side
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL PHP_SESSION_UPLOAD_PROGRESS in multipart body"; \
    flow:established,to_server; http.content_type; \
    content:"multipart/form-data"; http.request_body; \
    content:"PHP_SESSION_UPLOAD_PROGRESS"; \
    classtype:web-application-attack; sid:2026120; rev:1; \
    reference:cve,2026-109618; reference:cve,2026-109619;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL session name as multipart field (fixation)"; \
    flow:established,to_server; http.content_type; \
    content:"multipart/form-data"; http.request_body; \
    pcre:"/name=\"[A-Za-z0-9_]*sess/i"; \
    classtype:web-application-attack; sid:2026121; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL PHP code in upload filename (session injection)"; \
    flow:established,to_server; http.content_type; \
    content:"multipart/form-data"; http.request_body; \
    content:"filename=|22|"; content:"<?"; distance:0; within:500; \
    classtype:web-application-attack; sid:2026122; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL serialized object in filename (handler mismatch)"; \
    flow:established,to_server; http.content_type; \
    content:"multipart/form-data"; http.request_body; \
    content:"filename=|22|"; content:"|7c|O:|22|"; distance:0; within:200; \
    classtype:web-application-attack; sid:2026123; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL chunked multipart (post_max_size bypass)"; \
    flow:established,to_server; http.method; content:"POST"; \
    http.content_type; content:"multipart/form-data"; \
    http.header; content:"Transfer-Encoding"; content:"chunked"; \
    classtype:web-application-attack; sid:2026124; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL comma-variant multipart Content-Type (WAF bypass)"; \
    flow:established,to_server; http.header; \
    content:"multipart/form-data,"; \
    classtype:web-application-attack; sid:2026125; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL multipart on non-POST method (request_parse_body)"; \
    flow:established,to_server; http.method; content:"PUT|PATCH|DELETE"; \
    http.content_type; content:"multipart/form-data"; \
    classtype:web-application-attack; sid:2026126; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL header-amplification multipart (low-bandwidth OOM)"; \
    flow:established,to_server; http.content_type; \
    content:"multipart/form-data"; http.request_body; \
    pcre:"/X-[A-Za-z0-9_-]+:\s*[ -~]{400,}/"; \
    classtype:web-application-attack; sid:2026127; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL deep-nested field names (array-multiplication OOM)"; \
    flow:established,to_server; http.content_type; \
    content:"multipart/form-data"; http.request_body; \
    pcre:"/name=\"[A-Za-z0-9_]+(\[[^\]]*\]){20,}/"; \
    classtype:web-application-attack; sid:2026128; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL session file path in URI (LFI on sess_ files)"; \
    flow:established,to_server; http.uri; content:"/sess_"; \
    classtype:web-application-attack; sid:2026129; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"PHP2SHELL stalled multipart POST (worker pinning)"; \
    flow:established,to_server; http.method; content:"POST"; \
    http.content_type; content:"multipart/form-data"; \
    threshold:type both, track by_src, count 20, seconds 60; \
    classtype:web-application-activity; sid:2026130; rev:1;)

# response side
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"PHP2SHELL OOM error in response"; flow:established,to_client; \
    http.response_body; content:"Allowed memory size"; \
    content:"exhausted"; distance:0; within:100; \
    classtype:web-application-attack; sid:2026131; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"PHP2SHELL OOM in Unknown scope (SAPI-stage longjmp)"; \
    flow:established,to_client; http.response_body; \
    content:"Allowed memory size"; content:"Unknown on line 0"; \
    distance:0; within:300; \
    classtype:web-application-attack; sid:2026132; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"PHP2SHELL session destruction failure (stale-BG consumed)"; \
    flow:established,to_client; http.response_body; \
    content:"Session object destruction failed"; \
    classtype:web-application-attack; sid:2026133; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"PHP2SHELL anomalous session cookie (heap memory leak)"; \
    flow:established,to_client; http.header; content:"Set-Cookie"; \
    pcre:"/Set-Cookie:\s*[A-Za-z0-9_.-]*[Ss][Ee][Ss][Ss][^=]*=[a-zA-Z0-9,-]{64,}/"; \
    classtype:web-application-attack; sid:2026134; rev:1;)
"""

    modsec = r"""# php2shell ModSecurity rules — generated by php_scan.py
SecRequestBodyAccess On
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026109618,phase:2,t:none,deny,status:403,log,\
    msg:'php2shell: upload_progress trigger field (CVE-2026-109618/109619)'"
SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data," \
    "id:1026109619,phase:1,t:none,deny,status:403,log,\
    msg:'php2shell: comma-variant multipart Content-Type'"
SecRule REQUEST_METHOD "@within PUT PATCH DELETE" \
    "id:1026109620,phase:1,t:none,deny,status:403,log,chain,\
    msg:'php2shell: non-POST multipart (request_parse_body)'"
    SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data"
SecRule MULTIPART_FILENAME "@rx <\?(?:php|=)" \
    "id:1026109621,phase:2,t:none,deny,status:403,log,\
    msg:'php2shell: PHP code in upload filename'"
SecRule MULTIPART_FILENAME "@rx \|O:\d+" \
    "id:1026109622,phase:2,t:none,deny,status:403,log,\
    msg:'php2shell: serialized object in upload filename'"
"""

    sigma = r"""# php2shell Sigma rules — generated by php_scan.py
title: php2shell upload_progress exploitation attempt
id: php2shell-sigma-001
status: experimental
logsource:
  category: webserver
detection:
  sel:
    cs-method: [POST, PUT, PATCH]
  kw:
    - 'PHP_SESSION_UPLOAD_PROGRESS'
    - 'multipart/form-data,'
  condition: sel and kw
level: high
tags: [cve.2026.109618, cve.2026.109619, attack.t1190]
---
title: php2shell exploitation fingerprints in responses/logs
id: php2shell-sigma-002
status: experimental
logsource:
  category: webserver
detection:
  kw:
    - 'Session object destruction failed'
    - 'in Unknown on line 0'
  condition: kw
level: critical
tags: [cve.2026.109618, cve.2026.109619]
---
title: php2shell suspicious child process of PHP workers
id: php2shell-sigma-003
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  parent:
    ParentImage|endswith: ['/php-fpm', '/php-cgi', '/httpd', '/apache2']
  child:
    Image|endswith: ['/sh', '/bash', '/python', '/perl', '/curl',
                     '/wget', '/nc', '/ncat']
  condition: parent and child
level: critical
tags: [cve.2026.109618]
"""

    files = {"php2shell-suricata.rules": suricata,
             "php2shell-modsecurity.conf": modsec,
             "php2shell-sigma.yml": sigma}
    for name, content in files.items():
        p = os.path.join(outdir, name)
        with open(p, "w") as f:
            f.write(content.lstrip())
        print(f"[+] wrote {p}", file=sys.stderr)


FILT = {"status": None, "hide": set(), "check_re": None, "min_sev": "info"}


def check_visible(key, check):
    st = check["status"]
    if FILT["status"] and st not in FILT["status"]:
        return False
    if st in FILT["hide"]:
        return False
    if FILT["check_re"] and not (
            FILT["check_re"].search(key) or
            FILT["check_re"].search(CHECK_ZH.get(key, "")) or
            FILT["check_re"].search(check["detail"])):
        return False
    return True


def print_report(title, checks, sev, vp):
    print(f"\n=== php-scan report — {title} [{sev.upper()}] ===")
    for k, c in checks.items():
        if check_visible(k, c):
            print(f"  [{c['status']:>16}] {k}: {c['detail']}")
    print("--- verdict ---")
    for s, line in vp:
        if SEV[s] >= SEV[FILT["min_sev"]]:
            print(f"  [{s.upper():>8}] {line}")
    if SEV["info"] >= SEV[FILT["min_sev"]]:
        # last two verdict() lines: Preconditions + Applicable chains map
        for line in (l for l in verdict(checks)
                     if l.startswith(("Preconditions:", "Applicable chains:"))):
            print(f"  [{'INFO':>8}] {line}")


def _xesc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_xlsx(path, sheets):
    """Minimal .xlsx writer (stdlib only).
    sheets = [(name, [[row], ...]), ...] or (name, rows, widths) where
    widths is a list of column widths in character units."""
    import zipfile
    ct = ('<?xml version="1.0" encoding="UTF-8"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>')
    for i in range(len(sheets)):
        ct += (f'<Override PartName="/xl/worksheets/sheet{i+1}.xml" ContentType='
               '"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    ct += ('<Override PartName="/xl/styles.xml" ContentType='
           '"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>')
    ct += '</Types>'
    styles = ('<?xml version="1.0" encoding="UTF-8"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>'
              '<fills count="1"><fill><patternFill/></fill></fills>'
              '<borders count="1"><border/></borders>'
              '<cellStyleXfs count="1"><xf/></cellStyleXfs>'
              '<cellXfs count="2"><xf/><xf applyAlignment="1">'
              '<alignment wrapText="1" vertical="top"/></xf></cellXfs>'
              '</styleSheet>')
    rels = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')
    wb = ('<?xml version="1.0" encoding="UTF-8"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>')
    wbrels = ('<?xml version="1.0" encoding="UTF-8"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')
    for i, sh in enumerate(sheets):
        name = sh[0]
        wb += f'<sheet name="{_xesc(name)}" sheetId="{i+1}" r:id="rId{i+1}"/>'
        wbrels += (f'<Relationship Id="rId{i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                   f'Target="worksheets/sheet{i+1}.xml"/>')
    wbrels += ('<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
               'Target="styles.xml"/></Relationships>')
    wb += '</sheets></workbook>'

    def sheet_xml(rows, widths):
        x = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
        if widths:
            x += '<cols>'
            for i, w in enumerate(widths, 1):
                x += f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>'
            x += '</cols>'
        x += '<sheetData>'
        def colname(n):
            col = ""
            while n:
                n, rem = divmod(n - 1, 26)
                col = chr(65 + rem) + col
            return col

        for r_i, row in enumerate(rows, 1):
            x += f'<row r="{r_i}">'
            for c_i, cell in enumerate(row):
                x += (f'<c r="{colname(c_i + 1)}{r_i}" t="inlineStr" s="1">'
                      f'<is><t xml:space="preserve">{_xesc(cell)}</t></is></c>')
            x += '</row>'
        x += '</sheetData>'
        # Excel auto-filter dropdowns over the used range (header in row 1)
        if rows:
            x += (f'<autoFilter ref="A1:{colname(len(rows[0]))}'
                  f'{len(rows)}"/>')
        return x + '</worksheet>'

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wbrels)
        z.writestr("xl/styles.xml", styles)
        for i, sh in enumerate(sheets):
            rows = sh[1]
            widths = sh[2] if len(sh) > 2 else None
            z.writestr(f"xl/worksheets/sheet{i+1}.xml",
                       sheet_xml(rows, widths))


def load_xlsx(path):
    """Read back sheets written by write_xlsx → [(name, rows), ...]."""
    import zipfile
    z = zipfile.ZipFile(path)
    wb = z.read("xl/workbook.xml").decode()
    names = re.findall(r'<sheet name="([^"]*)"', wb)
    un = (lambda s: s.replace("&quot;", '"').replace("&gt;", ">")
          .replace("&lt;", "<").replace("&amp;", "&"))
    sheets = []
    for i, name in enumerate(names):
        xml = z.read(f"xl/worksheets/sheet{i+1}.xml").decode()
        rows = []
        for row in re.findall(r"<row[^>]*>(.*?)</row>", xml, re.S):
            rows.append([un(c) for c in
                         re.findall(r"<t[^>]*>(.*?)</t>", row, re.S)])
        sheets.append((name, rows))
    return sheets

def aggregate(checks):
    """Aggregate checks -> (severity, [(sev, line), ...]).
    Severity tiers: info < low < medium < high < critical."""
    out, sev = [], "info"

    def bump(s):
        nonlocal sev
        sev = max((sev, s), key=lambda x: SEV[x])

    cv = checks.get("cve_affected") or checks.get("cve_range_local") or {}
    st = cv.get("status")
    sapi = (checks.get("sapi", {}).get("detail", "") +
            checks.get("sapi_evidence", {}).get("detail", "")).lower()
    mod_php = "mod_php" in sapi or ("apache" in sapi and "php" in sapi)

    if st == "affected":
        if mod_php:
            out.append(("critical",
                        f"{cv['detail']} + mod_php/Apache SAPI → CVE-2026-109618 "
                        "pre-auth RCE range; upgrade is the only fix"))
            sev = "critical"
        else:
            out.append(("high",
                        f"{cv['detail']} → inside CVE-2026-109618/109619 affected "
                        "range; upgrade to fixed release"))
            sev = "high"
    elif st == "eol":
        out.append(("critical", f"{cv['detail']} — no official patch exists"))
        sev = "critical"
    elif st == "patched":
        out.append(("low", f"{cv['detail']} — core bugs fixed "
                           "(commit 3584a98; Chain A filename-injection "
                           "persists by design, and session fixation + "
                           "serializer leak need PR #22113 — the probes "
                           "above verify those separately)"))
    elif st == "not_applicable":
        out.append(("info", cv["detail"]))
    else:
        out.append(("medium", cv.get("detail", "version undetermined")))
        bump("medium")

    up = checks.get("upload_progress", {}).get("status")
    if up == "confirmed":
        out.append(("high", "CONFIRMED: upload_progress accepted pre-auth "
                            "session (sess file created on host)"))
        bump("high")
    elif up == "likely_exposed":
        out.append(("medium", "upload_progress reachable (both CVEs' primary "
                              "trigger)"))
        bump("medium")
    ucfg = checks.get("upload_progress_cfg", {})
    if ucfg.get("status") == "exposed":
        out.append(("medium", f"upload_progress enabled — {ucfg['detail'][:110]}"))
        bump("medium")

    fx = checks.get("session_fixation", {}).get("status")
    if fx == "confirmed":
        out.append(("high", "CONFIRMED: session fixation via POST body "
                            "(use_only_cookies bypassed)"))
        bump("high")
    elif fx == "exposed":
        out.append(("medium", "session fixation via POST body works"))
        bump("medium")

    fi = checks.get("filename_injection", {}).get("status")
    if fi == "confirmed":
        out.append(("high", "CONFIRMED: raw filename reached session storage "
                            "(Chain A primitive; patch-independent)"))
        bump("high")
    elif fi == "needs_host_check":
        out.append(("info", "filename injection probe sent — needs host-side "
                            "confirmation"))

    om = checks.get("oom_trigger", {}).get("status")
    if om == "confirmed":
        out.append(("critical", "CONFIRMED: SAPI-stage OOM signature "
                                "(CVE-2026-109618 trigger primitive)"))
        sev = "critical"
    elif om == "crash_signature":
        out.append(("critical", "CONFIRMED crash signature after OOM probe — "
                                "worker did not recover (unpatched behavior)"))
        sev = "critical"
    elif om == "likely_patched":
        out.append(("low", "OOM fingerprint points at a concrete code "
                           "location — patched delayed-OOM shape "
                           "(zend_handle_delayed_oom), not the unpatched "
                           "longjmp"))
    elif om == "partial":
        out.append(("medium", checks["oom_trigger"]["detail"]))
        bump("medium")

    hp = checks.get("host_patch_status", {}).get("status")
    if hp in ("affected", "eol"):
        out.append(("high", "HOST-CONFIRMED: " +
                    checks["host_patch_status"]["detail"][:150]))
        bump("high")
    elif hp == "patched":
        out.append(("low", "host binary/package is patched — verify running "
                           "workers were restarted after the update (they "
                           "may still serve the old build)"))

    if checks.get("sid_leak", {}).get("status") == "leak_signature":
        out.append(("critical", "heap memory disclosed via session Set-Cookie "
                                "(CVE-2026-109618 leak primitive observed)"))
        sev = "critical"

    if checks.get("serialize_handler_conflict", {}).get("status") == "exposed":
        out.append(("high", "dual serialize_handler config "
                            "(chain-C precondition met)"))
        bump("high")

    if checks.get("composer_gadget_pkgs", {}).get("status") == "exposed":
        out.append(("medium", "packages with documented POP chains present"))
        bump("medium")

    if checks.get("response_iocs", {}).get("status") == "exposed":
        out.append(("high", "exploit signatures found in ordinary responses "
                            "— investigate for active probing/exploitation"))
        bump("high")

    if checks.get("vendor_packages", {}).get("status") == "exposed":
        out.append(("high", "installed php packages below the vendor-fixed "
                            "revision — upgrade via the distro advisory"))
        bump("high")

    mit = checks.get("mitigations", {}).get("detail", "")
    if mit and "no existing" not in mit:
        out.append(("info", "existing mitigations detected: " + mit[:140]))

    if not out:
        out.append(("info", "no notable exposure found"))
    return sev, out


def verdict(checks):
    """Backward-compatible line list for the text report."""
    _sev, pairs = aggregate(checks)
    out = [line for _s, line in pairs]

    exp = []
    if checks.get("serialize_handler_conflict", {}).get("status") == "exposed":
        exp.append("dual serialize_handler config present (Chain C precondition)")
    sinks = checks.get("code_sinks", {}).get("detail", "")
    if "no unserialize" not in sinks:
        if "LFI sink" in sinks:
            exp.append("application contains LFI sink(s) (Chain A precondition)")
        if "unserialize()" in sinks:
            exp.append("application calls unserialize() (Chain B precondition)")
        if "gadget candidates:" in sinks:
            exp.append("POP gadget candidates present (Chain C weaponization)")
    out.append("Preconditions: " + ("; ".join(exp) if exp else "none confirmed"))

    # exploit-chain map (A..E from the public analysis)
    sapi = (checks.get("sapi", {}).get("detail", "") +
            checks.get("sapi_evidence", {}).get("detail", "")).lower()
    is_fpm = "fpm" in sapi or "fastcgi" in sapi
    is_mod = "mod_php" in sapi or ("apache" in sapi and "php" in sapi)
    chains = ["A: session-injection → LFI (works even patched)",
              "B: var_destroy UAF (needs userland unserialize)"]
    if is_fpm:
        chains += ["C: serialize_handler mismatch (FPM)",
                   "E: FPM stale-BG consumer (not actively probed — needs "
                   "intrusive giant-session + OOM; only passive detection "
                   "via response IoCs)"]
    if is_mod:
        chains += ["D: mod_php SAPI OOM → stale EG()"]
    if not is_fpm and not is_mod:
        chains += ["C/E need FPM", "D needs mod_php"]
    out.append("Applicable chains: " + "; ".join(chains))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="remote target URL, e.g. http://127.0.0.1:8080/app/")
    ap.add_argument("--targets", help="file with one target URL per line "
                    "(# comments allowed) — batch mode")
    ap.add_argument("--crawl", action="store_true",
                    help="recursively crawl the --target domain (same-domain "
                         "links + form endpoints; static assets and external "
                         "domains skipped) and scan every discovered page. "
                         "ON by default when --target is given")
    ap.add_argument("--no-crawl", action="store_true",
                    help="disable the default recursive crawl of --target; "
                         "scan only the given URL")
    ap.add_argument("--crawl-depth", type=int, default=3,
                    help="max link depth for --crawl (default 3)")
    ap.add_argument("--max-pages", type=int, default=50,
                    help="max pages for --crawl (default 50)")
    ap.add_argument("--path", help="local PHP project dir for code/config audit")
    ap.add_argument("--probe-path", default=None,
                    help="endpoint to probe (default: path from --target URL; "
                         "prefer one that calls session_start())")
    ap.add_argument("--confirm", action="store_true",
                    help="enable behavioral confirmation (benign triggers + "
                         "host-side verification)")
    ap.add_argument("--session-path",
                    help="session.save_path — local dir or path on remote host "
                         "(needed by --confirm for session file checks)")
    ap.add_argument("--exec-cmd",
                    help="host exec template with {cmd} placeholder, e.g. "
                         "'docker exec php-fpm sh -c \"{cmd}\"' or 'ssh host \"{cmd}\"'")
    ap.add_argument("--oom-mb", type=int, default=160,
                    help="multipart body size for the OOM fingerprint probe "
                         "(default 160MB — must exceed the typical 128M "
                         "memory_limit; chunked bodies already escalate "
                         "64→oom_mb→256MB, and >8M Content-Length bodies "
                         "may be rejected under a default post_max_size)")
    ap.add_argument("--confirm-oom", action="store_true",
                    help="force the SAPI OOM fingerprint probe even when SAPI/"
                         "version heuristics do not call for it")
    ap.add_argument("--oom-strategy",
                    choices=["auto", "chunked", "headers", "nested"],
                    default="auto",
                    help="OOM probe strategy: chunked (post_max_size bypass), "
                         "headers (part-header amplification), nested (deep "
                         "array field names); auto tries all three (default)")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    ap.add_argument("--output",
                    help="report file path; suffix picks format (.xlsx/.md/.json). "
                         "default: auto-named timestamped file under "
                         "<script_dir>/reports/ (see --cumulative)")
    ap.add_argument("--cumulative", action="store_true",
                    help="append to the shared workbook "
                         "reports/php-scan-results.xlsx instead of writing a "
                         "per-run timestamped file")
    ap.add_argument("--report-format", choices=["xlsx", "md", "json"],
                    default="xlsx",
                    help="format of the auto-named report (default xlsx)")
    ap.add_argument("--no-report", action="store_true",
                    help="skip writing any report file")
    ap.add_argument("--progress-name", default="PHP_SESSION_UPLOAD_PROGRESS",
                    help="value of session.upload_progress.name on the target "
                         "if it was renamed from the default "
                         "(local audit reports custom names)")
    ap.add_argument("--cookie",
                    help="Cookie header for authenticated probes, e.g. "
                         "'PHPSESSID=abc123; other=val' (session-id cookies are "
                         "stripped — the scanner supplies its own probe SID)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--threads", type=int, default=1,
                    help="parallel workers for batch/crawl remote scans "
                         "(default 1; raise with care — probes are per-target)")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="only print reports with severity >= medium "
                         "(reports file still gets everything)")
    ap.add_argument("--status",
                    help="only show checks with these statuses, comma-sep "
                         "(e.g. confirmed,exposed,affected) — applies to "
                         "console output and report detail rows")
    ap.add_argument("--hide-status",
                    help="hide checks with these statuses, comma-sep "
                         "(e.g. info,unknown,done)")
    ap.add_argument("--check",
                    help="only show checks whose name/description/detail "
                         "matches this regex (e.g. 'oom|upload')")
    ap.add_argument("--min-severity", choices=list(SEV), default="info",
                    help="minimum severity for verdict lines (default info)")
    ap.add_argument("--emit-rules", metavar="DIR",
                    help="write ready-to-deploy detection rules (Suricata, "
                         "ModSecurity, Sigma) to DIR, then exit unless "
                         "scan targets are also given")
    args = ap.parse_args()

    if args.status:
        FILT["status"] = {s.strip() for s in args.status.split(",") if s.strip()}
    if args.hide_status:
        FILT["hide"] = {s.strip() for s in args.hide_status.split(",")
                        if s.strip()}
    if args.check:
        try:
            FILT["check_re"] = re.compile(args.check, re.I)
        except re.error as e:
            ap.error(f"--check: bad regex: {e}")
    FILT["min_sev"] = args.min_severity

    if args.emit_rules:
        emit_rules(args.emit_rules)
    if not args.target and not args.targets and not args.path:
        if args.emit_rules:
            return 0
        ap.error("give --target/--targets and/or --path")
    if args.exec_cmd and not args.session_path:
        ap.error("--exec-cmd requires --session-path (remote session dir)")

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    reports = []

    urls = ([args.target] if args.target else [])
    if args.targets:
        urls += [l.strip() for l in open(args.targets)
                 if l.strip() and not l.strip().startswith("#")]
    if args.crawl and not args.target:
        ap.error("--crawl requires --target")
    if args.target and not args.no_crawl:
        print(f"[*] Crawling {args.target} "
              f"(depth<={args.crawl_depth}, max {args.max_pages} pages)",
              file=sys.stderr)
        try:
            pages, endpoints = crawl_site(args.target, cookie=args.cookie,
                                          max_pages=args.max_pages,
                                          max_depth=args.crawl_depth,
                                          timeout=args.timeout)
        except OSError as e:
            ap.error(f"crawl failed: {e}")
        print(f"[+] crawl done: {len(pages)} page(s), "
              f"{len(endpoints)} form endpoint(s)", file=sys.stderr)
        urls += pages + endpoints
    urls = list(dict.fromkeys(urls))
    host_ch = HostExec(session_path=args.session_path, exec_cmd=args.exec_cmd)
    if args.confirm and urls and not host_ch.available:
        print("[!] --confirm without --session-path/--exec-cmd: "
              "host-side checks will be skipped", file=sys.stderr)

    def _scan_one(url):
        pp = args.probe_path
        if pp is None:
            pp = urlparse(url if "://" in url else "http://" + url).path or "/"
        checks = RemoteScan(url, pp, args.timeout, host=host_ch,
                            confirm=args.confirm, oom_mb=args.oom_mb,
                            cookie=args.cookie,
                            force_oom=args.confirm_oom,
                            oom_strategy=args.oom_strategy,
                            progress_name=args.progress_name).run()
        return url, checks

    if args.threads > 1 and len(urls) > 1:
        scanned = {}
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(_scan_one, u): u for u in urls}
            done = 0
            for f in futs:
                u, c = f.result()
                scanned[u] = c
                done += 1
                print(f"\r[*] scanned {done}/{len(urls)}", end="",
                      file=sys.stderr, flush=True)
            print(file=sys.stderr)
        remote_results = [(u, scanned[u]) for u in urls]
    else:
        remote_results = []
        for url in urls:
            print(f"[*] Remote probe: {url}", file=sys.stderr)
            remote_results.append(_scan_one(url))

    for url, checks in remote_results:
        sev, vp = aggregate(checks)
        reports.append({"kind": "remote", "target": url, "path": None,
                        "time": ts, "checks": checks, "severity": sev,
                        "verdict": vp, "verdict_lines": verdict(checks)})
        if not args.json and (not args.quiet or SEV[sev] >= SEV["medium"]):
            print_report(f"remote: {url}", checks, sev, vp)

    if args.path:
        print(f"[*] Local audit: {args.path}", file=sys.stderr)
        checks = LocalScan(args.path).run()
        sev, vp = aggregate(checks)
        reports.append({"kind": "local", "target": None, "path": args.path,
                        "time": ts, "checks": checks, "severity": sev,
                        "verdict": vp, "verdict_lines": verdict(checks)})
        if not args.json and (not args.quiet or SEV[sev] >= SEV["medium"]):
            print_report(f"local: {args.path}", checks, sev, vp)

    if args.json:
        print(json.dumps(reports, indent=2, default=str))
    else:
        print("\nNote: this scanner measures exposure & prerequisites only.")
        print("It never sends corruption payloads. 'affected' = version/config"
              " exposure, not proof of exploitability.")

    # exit code for CI: 1 when anything high/critical was found, else 0
    rc = 1 if any(SEV.get(r["severity"], 0) >= SEV["high"] for r in reports) else 0
    if args.no_report:
        return rc
    rep_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "reports")
    if args.output:
        out = args.output
    elif args.cumulative:
        out = os.path.join(rep_dir, "php-scan-results.xlsx")
    else:
        worst = max((r["severity"] for r in reports),
                    key=lambda s: SEV.get(s, 0), default="info").upper()
        first = next((r["target"] for r in reports if r["target"]), None)
        if first:
            p = urlparse(first if "://" in first else "http://" + first)
            default_port = 443 if p.scheme == "https" else 80
            domain = p.hostname or "unknown"
            if p.port and p.port != default_port:
                domain += f"-{p.port}"
            hp = re.sub(r"[^A-Za-z0-9.-]", "_", domain)
        else:
            hp = "local"
        out = os.path.join(
            rep_dir, f"{stamp}_{hp}_{worst}.{args.report_format}")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    if out.endswith(".xlsx"):
        meta = [["掃描時間", "目標", "本地路徑", "嚴重度", "confirm 模式", "判定摘要"]]
        rows = [["掃描時間", "目標", "檢查項", "狀態", "說明", "原始細節"]]
        vrows = [["掃描時間", "目標", "嚴重度", "判定結論"]]
        for r in reports:
            tgt = r["target"] or r["path"] or "-"
            summary = r["verdict"][0][1] if r["verdict"] else ""
            meta.append([ts, tgt, r["path"] or "-", SEV_ZH.get(r["severity"], r["severity"]),
                         "是" if args.confirm else "否", summary])
            for k, c in r["checks"].items():
                if check_visible(k, c):
                    rows.append([ts, tgt, k,
                                 STATUS_ZH.get(c["status"], c["status"]),
                                 CHECK_ZH.get(k, ""), c["detail"]])
            for s, line in r["verdict"]:
                if SEV[s] >= SEV[FILT["min_sev"]]:
                    vrows.append([ts, tgt, SEV_ZH.get(s, s), line])
            if SEV["info"] >= SEV[FILT["min_sev"]]:
                for line in r["verdict_lines"]:
                    if line.startswith(("Preconditions:",
                                        "Applicable chains:")):
                        vrows.append([ts, tgt, SEV_ZH.get("info", "info"),
                                      line])
        if os.path.exists(out):
            try:
                old = load_xlsx(out)
            except (OSError, KeyError):
                old = []
            if len(old) == 3:
                meta, rows, vrows = (
                    old[0][1] + meta[1:], old[1][1] + rows[1:],
                    old[2][1] + vrows[1:])
                # pad rows to header width (schema grew across versions)
                for sheet in (meta, rows, vrows):
                    w = len(sheet[0])
                    for i, r in enumerate(sheet):
                        if len(r) < w:
                            sheet[i] = r + [""] * (w - len(r))
        write_xlsx(out, [("掃描記錄", meta, [18, 30, 30, 8, 12, 70]),
                         ("檢查明細", rows, [18, 30, 24, 12, 40, 80]),
                         ("判定", vrows, [18, 30, 8, 100])])
        print(f"\n[+] report appended: {out}", file=sys.stderr)
        return rc
    if out.endswith(".json"):
        content = json.dumps(reports, indent=2, default=str)
    else:
        lines = [f"# php-scan report — {ts}", ""]
        for r in reports:
            tgt = r["target"] or r["path"]
            lines += [f"## {r['kind']}: {tgt} — {r['severity'].upper()}", ""]
            for k, c in r["checks"].items():
                lines.append(f"- **[{c['status']}] {k}** — {c['detail']}")
            lines += ["", "### verdict", ""]
            lines += [f"- [{s.upper()}] {x}" for s, x in r["verdict"]]
            lines.append("")
        lines.append("_exposure & prerequisites only; "
                     "no corruption payloads sent._")
        content = "\n".join(lines)
    with open(out, "w") as f:
        f.write(content)
    print(f"\n[+] report written: {out}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
