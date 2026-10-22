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
import socket
import ssl
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

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
    if major < 8 or (major == 8 and minor < 2):
        return "eol", (f"PHP {major}.{minor}.{patch} is EOL — no official fix; "
                       "upgrade required (or isolate + upload_progress=Off)")
    if major == 8 and 2 <= minor <= 5:
        st = "affected" if patch < FIXED[minor] else "patched"
        return st, (f"PHP {major}.{minor}.{patch} "
                    f"{'<' if st == 'affected' else '>='} fixed 8.{minor}.{FIXED[minor]}")
    return "unknown", f"PHP {major}.{minor}.{patch} outside documented range"


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

    def file_contains(self, name, needle):
        p = self._path(name)
        if self.session_path and not self.exec_cmd:
            try:
                return needle in open(p, errors="replace").read()
            except OSError:
                return False
        out = self._run(f"grep -l {shlex.quote(needle)} {shlex.quote(p)} 2>/dev/null")
        return bool(out and p in out)


# ---------------------------------------------------------------- remote

class RemoteScan:
    def __init__(self, target, path="/", timeout=10, host=None, confirm=False,
                 oom_mb=64, cookie=None, force_oom=False):
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
        self.checks = {}

    @staticmethod
    def _strip_sid(cookie):
        parts = [p.strip() for p in cookie.split(";")
                 if p.strip() and "sess" not in p.strip().lower().split("=")[0]]
        return "; ".join(parts)

    def _cookie_line(self, extra=None):
        c = "; ".join(x for x in (extra, self.cookie) if x)
        return f"Cookie: {c}\r\n" if c else ""

    def _get(self, path, cookie=None):
        req = (f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\n"
               + self._cookie_line(cookie)
               + "Connection: close\r\n\r\n").encode()
        return http(self.host, self.port, req, tls=self.tls, timeout=self.timeout)

    def _upload(self, path, fields, filename="probe.txt"):
        b = "PHPSCAN" + uuid.uuid4().hex[:8]
        body = b""
        for n, v in fields.items():
            body += (f"--{b}\r\nContent-Disposition: form-data; "
                     f'name="{n}"\r\n\r\n{v}\r\n').encode("latin-1")
        body += (f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; "
                 f'filename="{filename}"\r\n\r\nZ\r\n--{b}--\r\n').encode("latin-1")
        req = (f"POST {path} HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Content-Type: multipart/form-data; boundary={b}\r\n"
               + self._cookie_line()
               + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
               ).encode() + body
        return http(self.host, self.port, req, tls=self.tls, timeout=self.timeout)

    def fingerprint(self):
        resp = self._get(self.probe_path)
        if not resp:
            self.checks["reachable"] = {"status": "fail", "detail": "no response"}
            return False
        head, body = split(resp)
        powered = re.search(r"X-Powered-By:\s*([^\r\n]+)", head, re.I)
        server = re.search(r"Server:\s*([^\r\n]+)", head, re.I)
        self.checks["reachable"] = {"status": "ok", "detail": head.splitlines()[0] if head else ""}
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
        # version from header or phpinfo-style body
        ver = None
        src = (powered.group(1) if powered else "") + " " + body.decode("latin1", "replace")
        m = re.search(r"PHP[/ ]?(\d+)\.(\d+)\.(\d+)", src)
        if m:
            ver = tuple(int(x) for x in m.groups())
        self.checks["php_version"] = (
            {"status": "ok", "detail": ".".join(map(str, ver))} if ver
            else {"status": "unknown", "detail": "not disclosed (expose_php may be Off)"})
        self._ver = ver
        # SAPI guess — heuristic only
        sh = (server.group(1) if server else "").lower()
        if "apache" in sh and powered and "PHP" in powered.group(1):
            self._sapi = "likely mod_php (Apache + PHP header)"
        elif "nginx" in sh or "caddy" in sh:
            self._sapi = "likely php-fpm / fastcgi"
        elif "litespeed" in sh:
            self._sapi = "LiteSpeed LSAPI (lsphp)"
        if b"fpm-fcgi" in body.lower():
            self._sapi = "php-fpm"
        self.checks["sapi"] = {"status": "info", "detail": self._sapi}
        return True

    def version_verdict(self):
        st, det = version_state(self._ver)
        self.checks["cve_affected"] = {"status": st, "detail": det}

    def upload_progress_probe(self, sid):
        """Benign: send PHP_SESSION_UPLOAD_PROGRESS with a probe SID via POST body.
        upload_progress accepts the SID without auth; we then test whether the
        fixated SID is honored on a follow-up request (session fixation)."""
        resp = self._upload(self.probe_path,
                            {self._sess_name: sid,
                             "PHP_SESSION_UPLOAD_PROGRESS": "x"})
        if not resp:
            self.checks["upload_progress"] = {"status": "unknown", "detail": "no response"}
            return
        head, _ = split(resp)
        ok = " 200" in head.split("\r\n", 1)[0] or " 302" in head.split("\r\n", 1)[0]
        # upload_progress rejecting requests usually produces a PHP warning/error
        rejected = b"upload_progress" in resp.lower() and b"disabled" in resp.lower()
        if rejected:
            self.checks["upload_progress"] = {
                "status": "not_exposed", "detail": "server reports feature disabled"}
        elif ok:
            if self.confirm and self.host_ch.available:
                if self.host_ch.file_exists(f"sess_{sid}"):
                    self.checks["upload_progress"] = {
                        "status": "confirmed",
                        "detail": f"sess_{sid} created on host — upload_progress "
                                  "accepted a session id from POST body (pre-auth)"}
                    self._fixation_confirmed = True
                    return
                self.checks["upload_progress"] = {
                    "status": "not_confirmed",
                    "detail": f"200 OK but no sess_{sid} found via host channel — "
                              "check session.save_path matches --session-path"}
            else:
                self.checks["upload_progress"] = {
                    "status": "likely_exposed",
                    "detail": "multipart with PHP_SESSION_UPLOAD_PROGRESS accepted "
                              "(confirm on host: check sess_" + sid + ")"}
        else:
            self.checks["upload_progress"] = {"status": "unknown",
                                              "detail": head.split("\r\n", 1)[0]}

    def session_fixation_probe(self, sid):
        """Send PHPSESSID in POST body, then GET with that SID as cookie.
        If the app/endpoint starts a session and honors the fixated SID
        (no replacement Set-Cookie), fixation via POST body is viable."""
        if getattr(self, "_fixation_confirmed", False):
            self.checks["session_fixation"] = {
                "status": "confirmed",
                "detail": "session file created for POST-body SID — use_only_cookies "
                          "bypassed by rfc1867 handler"}
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
                     {self._sess_name: sid, "PHP_SESSION_UPLOAD_PROGRESS": "x"},
                     filename=marker)
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

    def oom_probe(self):
        """Confirm the CVE-2026-109618 trigger primitive on mod_php:
        a single oversized multipart field forces OOM during SAPI body
        parsing — signature is 'Allowed memory size ... in Unknown on line 0'.

        INTRUSIVE: causes one memory_limit fatal error in a worker.
        Does NOT attempt corruption — no heap spray, single request only."""
        boundary = "PHPSCANOOM" + uuid.uuid4().hex[:8]
        head_part = (f"--{boundary}\r\n"
                     f'Content-Disposition: form-data; name="phpscan_data"\r\n\r\n'
                     ).encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        total = self.oom_mb * 1024 * 1024
        # Chunked encoding: no Content-Length → bypasses post_max_size
        # (documented OOM strategy in GHSA-w8hw-w9fx-j79w)
        req = (f"POST {self.probe_path} HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
               + self._cookie_line()
               + f"Transfer-Encoding: chunked\r\n"
               f"Connection: close\r\n\r\n").encode()
        s = socket.create_connection((self.host, self.port), timeout=30)
        if self.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)

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
                ssl.SSLError, OSError) as e:
            s.close()
            self.checks["oom_trigger"] = {
                "status": "inconclusive",
                "detail": f"connection cut mid-upload after {sent >> 20}MB "
                          f"({type(e).__name__}) — edge/WAF likely dropped the "
                          "chunked body; OOM fingerprint not testable remotely"}
            return
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

        body = resp.decode("latin1", "replace")
        oom = "Allowed memory size" in body
        sapi_scope = re.search(r"in\s*<?b?>?\s*Unknown", body) is not None
        if oom and sapi_scope:
            self.checks["oom_trigger"] = {
                "status": "confirmed",
                "detail": "OOM during SAPI multipart parsing observed "
                          "('in Unknown on line 0') — CVE-2026-109618 trigger "
                          "primitive present. Exploitation further requires "
                          "heap control; this probe does not attempt it."}
        elif oom:
            self.checks["oom_trigger"] = {
                "status": "partial",
                "detail": "OOM fatal fired but in user code scope — primitive "
                          "not confirmed at SAPI stage"}
        elif resp:
            status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
            self.checks["oom_trigger"] = {
                "status": "not_triggered",
                "detail": f"{status} — memory_limit not reached with "
                          f"{self.oom_mb}MB (try --oom-mb larger)"}
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

    def run(self):
        if not self.fingerprint():
            return self.checks
        self.version_verdict()
        self.mod_php_note()
        sid = "phpscan" + uuid.uuid4().hex[:20]
        self.upload_progress_probe(sid)
        self.session_fixation_probe(sid)
        self.filename_injection_probe()
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
        return self.checks


# ---------------------------------------------------------------- local

INI_FILES = ("php.ini", ".user.ini")
CONF_HINTS = re.compile(
    r"(php_value|php_flag|php_admin_value|php_admin_flag)\s+([\w.\-]+)\s+(.+)", re.I)

SINKS = [
    (re.compile(r"\bunserialize\s*\("),
     "unserialize() — object-injection sink (chain-B/C precondition)"),
    (re.compile(r"\b(include|include_once|require|require_once)\s*\(?\s*\$"),
     "include/require of variable — LFI sink (chain-A precondition)"),
    (re.compile(r"ini_set\s*\(\s*['\"]session\.serialize_handler"),
     "runtime session.serialize_handler change — chain-C enabler"),
    (re.compile(r"\bsession_set_save_handler\s*\("), "custom session save handler"),
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


class LocalScan:
    """Audit code/config of an on-disk PHP project."""

    TRACKED_KEYS = {
        "session.upload_progress.enabled", "session.serialize_handler",
        "session.use_only_cookies", "session.save_path",
        "session.upload_progress.cleanup", "session.upload_progress.min_freq",
        "memory_limit", "post_max_size", "upload_max_filesize",
        "expose_php", "disable_functions", "open_basedir",
        "allow_url_include",
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
            self._ini_notes.append(f"{src}: upload_progress disabled (good)")
        if key == "session.use_only_cookies" and val.lower() in ("0", "off"):
            self._ini_notes.append(f"{src}: use_only_cookies=0 — fixation easier")
        if key == "memory_limit":
            self._ini_notes.append(
                f"{src}: memory_limit={val} " +
                ("(OOM trigger harder — good)" if val.strip() == "-1"
                 else "(OOM reachable)"))

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
                elif lf in ("nginx.conf", "httpd.conf", "apache2.conf") or \
                        (lf.endswith(".conf") and ("pool.d" in dirpath or "fpm" in lf)):
                    websrv.append(p)
                elif f == "www.conf" or (lf.endswith(".conf") and "pool" in dirpath):
                    pools.append(p)

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
            if re.search(r"AddHandler\s+application/x-httpd-php|SetHandler.*php", txt):
                self._sapi_evidence.add(
                    f"mod_php-style handler in {os.path.relpath(p, self.root)}")

        for p in docker + comps:
            try:
                txt = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
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
            if re.search(r"fastcgi_pass|fastcgi:", txt):
                self._sapi_evidence.add(
                    f"fastcgi/php-fpm in {os.path.relpath(p, self.root)}")
            if re.search(r"php[0-9_]*_module|libphp", txt):
                self._sapi_evidence.add(
                    f"mod_php in {os.path.relpath(p, self.root)}")

        if self._settings:
            det = "\n".join(f"{k} = {v}  [{os.path.relpath(s, self.root)}]"
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

        if len(self._handlers) > 1:
            detail = "; ".join(
                f"'{h}' in {len(ps)} file(s) "
                f"({', '.join(os.path.relpath(x, self.root) for x in ps)})"
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
        if v and v[1].lower() in ("off", "0"):
            st, det = "not_exposed", f"disabled in {os.path.relpath(v[0], self.root)}"
        elif v:
            st, det = "exposed", f"enabled in {os.path.relpath(v[0], self.root)} (default anyway)"
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

    def run(self):
        self.config_audit()
        self.version_discovery()
        self.upload_progress_cfg()
        self.sink_scan()
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
}


def print_report(title, checks, sev, vp):
    print(f"\n=== php-scan report — {title} [{sev.upper()}] ===")
    for k, c in checks.items():
        print(f"  [{c['status']:>16}] {k}: {c['detail']}")
    print("--- verdict ---")
    for s, line in vp:
        print(f"  [{s.upper():>8}] {line}")


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
        for r_i, row in enumerate(rows, 1):
            x += f'<row r="{r_i}">'
            for c_i, cell in enumerate(row):
                col = ""
                n = c_i + 1
                while n:
                    n, rem = divmod(n - 1, 26)
                    col = chr(65 + rem) + col
                x += (f'<c r="{col}{r_i}" t="inlineStr" s="1"><is><t xml:space="preserve">'
                      f'{_xesc(cell)}</t></is></c>')
            x += '</row>'
        return x + '</sheetData></worksheet>'

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
                           "(Chain A filename-injection primitive persists by design)"))
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

    if checks.get("serialize_handler_conflict", {}).get("status") == "exposed":
        out.append(("high", "dual serialize_handler config "
                            "(chain-C precondition met)"))
        bump("high")

    if checks.get("composer_gadget_pkgs", {}).get("status") == "exposed":
        out.append(("medium", "packages with documented POP chains present"))
        bump("medium")

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
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="remote target URL, e.g. http://127.0.0.1:8080/app/")
    ap.add_argument("--targets", help="file with one target URL per line "
                    "(# comments allowed) — batch mode")
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
    ap.add_argument("--oom-mb", type=int, default=64,
                    help="multipart body size for the OOM fingerprint probe "
                         "(default 64MB)")
    ap.add_argument("--confirm-oom", action="store_true",
                    help="force the SAPI OOM fingerprint probe even when SAPI/"
                         "version heuristics do not call for it")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    ap.add_argument("--output",
                    help="report file path; suffix picks format (.xlsx/.md/.json). "
                         "default: <script_dir>/reports/php-scan-results.xlsx "
                         "(accumulating — each scan appends rows)")
    ap.add_argument("--no-report", action="store_true",
                    help="skip writing any report file")
    ap.add_argument("--cookie",
                    help="Cookie header for authenticated probes, e.g. "
                         "'PHPSESSID=abc123; other=val' (session-id cookies are "
                         "stripped — the scanner supplies its own probe SID)")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()

    if not args.target and not args.targets and not args.path:
        ap.error("give --target/--targets and/or --path")
    if args.exec_cmd and not args.session_path:
        ap.error("--exec-cmd requires --session-path (remote session dir)")

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    reports = []

    urls = ([args.target] if args.target else [])
    if args.targets:
        urls += [l.strip() for l in open(args.targets)
                 if l.strip() and not l.strip().startswith("#")]
    host_ch = HostExec(session_path=args.session_path, exec_cmd=args.exec_cmd)
    if args.confirm and urls and not host_ch.available:
        print("[!] --confirm without --session-path/--exec-cmd: "
              "host-side checks will be skipped", file=sys.stderr)

    for url in urls:
        print(f"[*] Remote probe: {url}", file=sys.stderr)
        pp = args.probe_path
        if pp is None:
            pp = urlparse(url if "://" in url else "http://" + url).path or "/"
        checks = RemoteScan(url, pp, args.timeout, host=host_ch,
                            confirm=args.confirm, oom_mb=args.oom_mb,
                            cookie=args.cookie,
                            force_oom=args.confirm_oom).run()
        sev, vp = aggregate(checks)
        reports.append({"kind": "remote", "target": url, "path": None,
                        "time": ts, "checks": checks, "severity": sev,
                        "verdict": vp, "verdict_lines": verdict(checks)})
        if not args.json:
            print_report(f"remote: {url}", checks, sev, vp)

    if args.path:
        print(f"[*] Local audit: {args.path}", file=sys.stderr)
        checks = LocalScan(args.path).run()
        sev, vp = aggregate(checks)
        reports.append({"kind": "local", "target": None, "path": args.path,
                        "time": ts, "checks": checks, "severity": sev,
                        "verdict": vp, "verdict_lines": verdict(checks)})
        if not args.json:
            print_report(f"local: {args.path}", checks, sev, vp)

    if args.json:
        print(json.dumps(reports, indent=2, default=str))
    else:
        print("\nNote: this scanner measures exposure & prerequisites only.")
        print("It never sends corruption payloads. 'affected' = version/config"
              " exposure, not proof of exploitability.")

    if args.no_report:
        return
    out = args.output or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "reports", "php-scan-results.xlsx")
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
                rows.append([ts, tgt, k, STATUS_ZH.get(c["status"], c["status"]),
                             CHECK_ZH.get(k, ""), c["detail"]])
            for s, line in r["verdict"]:
                vrows.append([ts, tgt, SEV_ZH.get(s, s), line])
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
        return
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


if __name__ == "__main__":
    main()
