#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: huginn_utils.py — v2.1.0
#  Shared utilities for the entire HUGINN suite.
# -----------------------------------------------------------------------------
#  What's here:
#    · Colors + logging (single source of truth)
#    · Target normalization + filename safety
#    · Atomic JSON I/O (+ optional gzip for large findings)
#    · Config loading (huginn.yaml with sane precedence)
#    · HTTP session management (pooling, retry, proxy, UA rotation)
#    · Header profiles (default.txt + per-host, session cookies, auth tokens)
#    · Sensitive header masking (safe logging / screenshots)
#    · Hop-by-hop header stripping (Burp-paste safe)
#    · Roblox CSRF token helper
#    · OOB token generation + URL building + callback polling
#    · Payload vault (base64-encoded YAML to bypass host AV)
#    · Placeholder substitution
#    · WAF / cloud / DBMS fingerprinting
#    · JSON path get/set
#    · Subprocess helpers
#    · Formatters
#
#  v2.1.0 additions:
#    · HeaderJar — session/auth header profiles with per-host resolution
#    · parse_header_block — robust HTTP/1.1 + HTTP/2 request-line handling
#    · strip_hop_by_hop — removes headers that break outgoing requests
#    · mask_header_value — safe logging of sensitive credentials
#    · get_roblox_csrf_token — X-CSRF-TOKEN bootstrap for Roblox
# =============================================================================

import os
import re
import sys
import gzip
import json
import time
import uuid
import base64
import random
import hashlib
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from shutil import which as _which
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)

# -----------------------------------------------------------------------------
#  Third-party deps
# -----------------------------------------------------------------------------
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] requests required: pip install requests pyyaml beautifulsoup4")
    sys.exit(1)

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


# =============================================================================
#  CONSTANTS
# =============================================================================
VERSION = "2.1.0"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (HUGINN; BugBounty) AppleWebKit/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 "
    "Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 "
    "Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Mobile Safari/537.36",
]

DEFAULTS = {
    "attacker_domain":   "beardedviking.org",
    "collab_host":       "oast.beardedviking.org",
    "canary_host":       "redirect.beardedviking.org",
    "canary_string":     "HUGINN-CANARY-LANDED",
    "alert_payload":     "alert(document.domain)",
    "oob_log_file":      None,
    "use_subdomain_oob": False,
    "max_workers":       8,
    "delay":             0.15,
    "timeout":           12,
    "use_browser":       False,
    "provider_filter":   None,
    "proxy":             None,
    "rotate_user_agent": False,
    "retry_transient":   True,
    "gzip_findings":     False,
}

CONFIG_SEARCH_PATHS = [
    Path("./huginn.yaml"),
    Path("./huginn.yml"),
    Path.home() / ".config" / "huginn" / "config.yaml",
    Path.home() / ".huginn.yaml",
]

TOKEN_PATTERN = re.compile(r"huginn-([a-f0-9]{16,32})", re.I)


# =============================================================================
#  HEADER CONSTANTS  (v2.1.0)
# =============================================================================
#  Headers whose values should NEVER be printed in logs or screenshots.
SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token", "proxy-authorization",
    "x-amz-security-token", "x-goog-api-key", "x-roblox-csrf",
})

#  Headers that must be stripped before sending a request. These are
#  either recomputed by the HTTP client, or hop-by-hop values that
#  mean something different per-request.
HOP_BY_HOP_HEADERS = frozenset({
    "content-length",        # must match actual body length
    "content-encoding",      # must match actual body encoding
    "transfer-encoding",     # client-managed
    "connection",            # hop-by-hop
    "keep-alive",            # hop-by-hop
    "te",                    # hop-by-hop
    "trailer",               # hop-by-hop
    "upgrade",               # hop-by-hop
    "host",                  # derived from target URL
    "accept-encoding",       # requests computes based on codecs
    "proxy-authorization",   # do not carry over
})

#  HTTP methods we recognize when parsing Burp request lines.
_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                 "OPTIONS", "CONNECT", "TRACE")

#  Request-line regex: "GET /path HTTP/1.1" or "POST /x HTTP/2" or "GET / HTTP/3"
_REQUEST_LINE_RE = re.compile(
    r"^(?:" + "|".join(_HTTP_METHODS) + r")\s+\S+\s+HTTP/\d(?:\.\d)?\s*$"
)

#  Header name validation (RFC 7230 token chars)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


# =============================================================================
#  COLORS
# =============================================================================
class C:
    R  = "\033[0m";  B  = "\033[1m";  D  = "\033[2m"
    CY = "\033[38;5;51m"; GR = "\033[38;5;46m"
    YE = "\033[38;5;226m"; RE = "\033[38;5;196m"
    MA = "\033[38;5;201m"; BL = "\033[38;5;33m"
    WH = "\033[38;5;231m"; GY = "\033[38;5;240m"


# =============================================================================
#  LOGGING
# =============================================================================
def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, level="info", tag=None):
    prefix = {
        "info":  f"{C.CY}[*]{C.R}",
        "ok":    f"{C.GR}[+]{C.R}",
        "warn":  f"{C.YE}[!]{C.R}",
        "err":   f"{C.RE}[-]{C.R}",
        "scan":  f"{C.MA}[>]{C.R}",
        "hit":   f"{C.GR}[✔]{C.R}",
        "debug": f"{C.GY}[·]{C.R}",
    }.get(level, f"{C.CY}[*]{C.R}")
    t = f"{C.GY}{ts()}{C.R} "
    tag_s = f"{C.B}{tag}{C.R} " if tag else ""
    print(f"{t}{prefix} {tag_s}{msg}", flush=True)


def section(title):
    line = "─" * 60
    print(f"\n{C.CY}┌{line}┐{C.R}")
    print(f"{C.CY}│{C.R} {C.B}{C.WH}{title}{C.R}")
    print(f"{C.CY}└{line}┘{C.R}\n")


def banner():
    print(f"""{C.CY}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██╗  ██╗██╗   ██╗ ██████╗ ██╗███╗   ██╗███╗   ██╗                 ║
║   ██║  ██║██║   ██║██╔════╝ ██║████╗  ██║████╗  ██║                 ║
║   ███████║██║   ██║██║  ███╗██║██╔██╗ ██║██╔██╗ ██║                 ║
║   ██╔══██║██║   ██║██║   ██║██║██║╚██╗██║██║╚██╗██║                 ║
║   ██║  ██║╚██████╔╝╚██████╔╝██║██║ ╚████║██║ ╚████║                 ║
║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝                 ║
║                                                                      ║
║              {C.MA}O D I N ' S   R A V E N{C.CY}                         ║
║         {C.D}Automated Recon & Vulnerability Suite{C.CY}                ║
╚══════════════════════════════════════════════════════════════════════╝
{C.R}""")


# =============================================================================
#  TIME HELPERS
# =============================================================================
def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def now_unix():
    return int(time.time())


# =============================================================================
#  TARGET NORMALIZATION
# =============================================================================
def normalize_target(target):
    target = (target or "").strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        target = "https://" + target
    p = urlparse(target)
    domain = p.netloc.split(":")[0].lower()
    scheme = p.scheme or "https"
    return domain, f"{scheme}://{p.netloc}"


def safe_filename(s):
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(s)).strip(" .")
    if len(s) > 180:
        s = s[:180] + "_" + hashlib.md5(s.encode()).hexdigest()[:6]
    return s or "_"


def get_host(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def url_extension(url):
    try:
        path = urlparse(url).path
        if "." not in path.rsplit("/", 1)[-1]:
            return ""
        return "." + path.rsplit(".", 1)[-1].lower()
    except Exception:
        return ""


# =============================================================================
#  JSON I/O
# =============================================================================
def save_json(path, data, compress=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    use_gzip = compress or path.suffix == ".gz"
    tmp = path.with_suffix(path.suffix + ".tmp")

    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")

    if use_gzip:
        with gzip.open(tmp, "wb") as f:
            f.write(payload)
    else:
        with open(tmp, "wb") as f:
            f.write(payload)

    os.replace(tmp, path)
    return path


def load_json(path):
    path = Path(path)
    if path.suffix == ".gz" or str(path).endswith(".json.gz"):
        with gzip.open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================================
#  CONFIG LOADING
# =============================================================================
def load_huginn_config(paths=None, overrides=None):
    cfg = dict(DEFAULTS)
    search = paths or CONFIG_SEARCH_PATHS
    if _yaml is None:
        log("pyyaml not installed — skipping huginn.yaml (pip install pyyaml)", "warn")
    else:
        for p in search:
            try:
                if Path(p).exists():
                    with open(p) as f:
                        data = _yaml.safe_load(f) or {}
                    if isinstance(data, dict):
                        cfg.update(data)
                    log(f"config loaded: {p}", "info")
                    break
            except Exception as e:
                log(f"config parse error ({p}): {e}", "warn")
    if overrides:
        for k, v in overrides.items():
            if v is not None:
                cfg[k] = v
    return cfg


# =============================================================================
#  OOB — TOKEN GENERATION, URL BUILDING, POLLING
# =============================================================================
def random_token(length=24):
    length = max(16, min(32, int(length)))
    return uuid.uuid4().hex[:length]


def build_oob_url(collab_host, token, path_hint="", use_subdomain=False,
                  scheme="https"):
    hint = re.sub(r"[^a-zA-Z0-9_-]", "_", (path_hint or "").strip("/"))[:64]
    if use_subdomain:
        host = f"huginn-{token}.{collab_host}"
        path = f"/{hint}" if hint else "/"
    else:
        host = collab_host
        path = f"/huginn-{token}"
        if hint:
            path += f"/{hint}"
    return f"{scheme}://{host}{path}"


class OOBPoller:
    def __init__(self, log_file=None, poll_interval=2.0, timeout=120.0):
        self.log_file = Path(log_file) if log_file else None
        self.poll_interval = float(poll_interval)
        self.timeout = float(timeout)
        self._seen = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if not self.log_file or not self.log_file.exists():
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _loop(self):
        deadline = time.time() + self.timeout
        last_size = 0
        while not self._stop.is_set() and time.time() < deadline:
            try:
                size = self.log_file.stat().st_size
                if size != last_size:
                    content = self.log_file.read_text(errors="ignore")
                    for m in TOKEN_PATTERN.finditer(content):
                        with self._lock:
                            self._seen.add(m.group(1).lower())
                    last_size = size
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def has_token(self, token):
        if not token:
            return False
        with self._lock:
            return token.lower() in self._seen

    def all_tokens(self):
        with self._lock:
            return set(self._seen)

    def ingest_text(self, text):
        added = 0
        for m in TOKEN_PATTERN.finditer(text or ""):
            with self._lock:
                self._seen.add(m.group(1).lower())
                added += 1
        return added


# =============================================================================
#  HTTP — SESSION MANAGEMENT
# =============================================================================
_SESSION = None
_SESSION_LOCK = threading.Lock()

_THROTTLE_LAST = {}
_THROTTLE_HITS = {}
_THROTTLE_LOCK = threading.Lock()

_REQUEST_COUNT = {"total": 0, "ok": 0, "err": 0}
_REQUEST_COUNT_LOCK = threading.Lock()


def get_session(proxy=None, rotate_user_agent=False):
    global _SESSION
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                s = requests.Session()
                s.headers.update(DEFAULT_HEADERS)

                if rotate_user_agent:
                    s.headers["User-Agent"] = random.choice(USER_AGENT_POOL)

                if proxy:
                    s.proxies.update({"http": proxy, "https": proxy})

                s.verify = False

                try:
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=32,
                        pool_maxsize=64,
                        max_retries=0,
                    )
                    s.mount("https://", adapter)
                    s.mount("http://", adapter)
                except Exception:
                    pass

                _SESSION = s
    return _SESSION


def reset_session():
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is not None:
            try:
                _SESSION.close()
            except Exception:
                pass
        _SESSION = None


def set_proxy(proxy_url):
    s = get_session()
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})
    else:
        s.proxies.clear()


def send_request(url, method="GET", headers=None, timeout=12,
                 allow_redirects=False, data=None, params=None, json_body=None,
                 retry=True):
    sess = get_session()

    # Merge defaults + caller headers, strip hop-by-hop
    merged_headers = dict(DEFAULT_HEADERS)
    if headers:
        merged_headers.update(headers)
    merged_headers = strip_hop_by_hop(merged_headers)

    def _attempt():
        return sess.request(
            method=method, url=url,
            headers=merged_headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            data=data, params=params, json=json_body,
        )

    try:
        resp = _attempt()
        with _REQUEST_COUNT_LOCK:
            _REQUEST_COUNT["total"] += 1
            _REQUEST_COUNT["ok"] += 1
        return resp
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout) as e:
        if retry and DEFAULTS.get("retry_transient", True):
            try:
                time.sleep(0.4)
                resp = _attempt()
                with _REQUEST_COUNT_LOCK:
                    _REQUEST_COUNT["total"] += 1
                    _REQUEST_COUNT["ok"] += 1
                return resp
            except Exception:
                pass
        with _REQUEST_COUNT_LOCK:
            _REQUEST_COUNT["total"] += 1
            _REQUEST_COUNT["err"] += 1
        return None
    except Exception:
        with _REQUEST_COUNT_LOCK:
            _REQUEST_COUNT["total"] += 1
            _REQUEST_COUNT["err"] += 1
        return None


def request_stats():
    with _REQUEST_COUNT_LOCK:
        return dict(_REQUEST_COUNT)


# =============================================================================
#  THROTTLE
# =============================================================================
def throttle(host, delay):
    if delay <= 0 or not host:
        return
    with _THROTTLE_LOCK:
        now = time.time()
        last = _THROTTLE_LAST.get(host, 0.0)
        wait = delay - (now - last)
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _THROTTLE_LAST[host] = now
        _THROTTLE_HITS[host] = _THROTTLE_HITS.get(host, 0) + 1


def throttle_stats():
    with _THROTTLE_LOCK:
        return dict(_THROTTLE_HITS)


# =============================================================================
#  URL / PARAM HELPERS
# =============================================================================
def inject_param(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if param not in qs:
        return None
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


# =============================================================================
#  JSON PATH
# =============================================================================
_JSON_PATH_RE = re.compile(r"\.([^\.\[\]]+)|\[(\d+)\]")


def parse_json_path(path):
    tokens = []
    for name, idx in _JSON_PATH_RE.findall(path or ""):
        if name:
            tokens.append(name)
        elif idx:
            tokens.append(int(idx))
    return tokens


def set_json_path(obj, path, value):
    tokens = parse_json_path(path)
    if not tokens:
        return obj
    cur = obj
    for i, key in enumerate(tokens):
        if i == len(tokens) - 1:
            try:
                cur[key] = value
            except Exception:
                pass
            return obj
        try:
            cur = cur[key]
        except Exception:
            return obj
    return obj


def get_json_path(obj, path, default=None):
    cur = obj
    for key in parse_json_path(path):
        try:
            cur = cur[key]
        except Exception:
            return default
    return cur


# =============================================================================
#  HEADER HANDLING  (v2.1.0)
# =============================================================================
#  Directory layout for header profiles:
#
#      workspace/headers/default.txt              applies to every host
#      workspace/headers/<exact-host>.txt         applies to that host only
#      workspace/headers/<parent.domain>.txt      applies to subdomains
#
#  Precedence (low -> high):
#      DEFAULT_HEADERS  <  default.txt  <  parent.domain  <  <host>
#                       <  cli_headers   <  per-request extra
# =============================================================================

def mask_header_value(name, value):
    """
    Return a safe-to-log representation of a header value.
    Sensitive headers get truncated to first/last 4 chars.
    """
    if not value:
        return ""
    low = (name or "").lower()
    if low in SENSITIVE_HEADERS:
        if len(value) <= 12:
            return "***"
        return "{}...{} ({} bytes)".format(value[:4], value[-4:], len(value))
    return value


def strip_hop_by_hop(headers):
    """
    Remove headers that would corrupt every outgoing request.
    Case-insensitive. Returns a new dict.
    """
    if not headers:
        return {}
    return {k: v for k, v in headers.items()
            if (k or "").lower() not in HOP_BY_HOP_HEADERS}


def parse_header_block(text):
    """
    Parse a raw HTTP header block into a dict.

    Handles everything a Burp paste can throw at it:
      · HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 request lines (auto-skipped)
      · Bare header blocks (no request line)
      · Comments (#) and blank lines (ignored)
      · Continuation lines (leading whitespace joined to previous header)
      · Colons inside values (only first colon splits name/value)
      · Empty values (X-Custom:)
      · Duplicate headers (last wins)
      · CRLF, LF, or CR line endings
      · Quoted values
      · Very long values (4KB+ cookies)
      · HTTP/2 pseudo-headers (:method, :path, :authority, :scheme) — dropped
    """
    headers = {}
    if not text:
        return headers

    last_name = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")

        # Blank / comment
        if not line or not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue

        # HTTP request line — HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3
        if _REQUEST_LINE_RE.match(line):
            continue

        # HTTP/2 pseudo-headers (:method, :path, :authority, :scheme) — drop
        if line.startswith(":") and ":" in line[1:]:
            continue

        # Continuation line (leading whitespace with no new colon)
        if line[0] in (" ", "\t") and last_name:
            headers[last_name] = (headers.get(last_name, "") + " " +
                                  line.strip())
            continue

        # Must have a colon
        if ":" not in line:
            continue

        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()

        # Validate header name
        if not name or not _HEADER_NAME_RE.match(name):
            continue

        # Preserve duplicate headers as concatenated (cookies, set-cookie)
        # but the general rule is last-wins
        headers[name] = value
        last_name = name

    return headers


def load_header_profile(path):
    """
    Load a single header profile from disk. Returns {} if missing/unreadable.
    """
    path = Path(path)
    if not path.exists() or not path.is_file():
        return {}
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return parse_header_block(content)
    except Exception:
        return {}


class HeaderJar:
    """
    Per-host header resolver for session cookies, auth tokens, and
    any custom headers you want sent to specific hosts.

    Thread-safe. Reload-safe.

    Usage:
        jar = HeaderJar(workspace / "headers")
        jar.load()
        merged = jar.headers_for("apis.roblox.com")
        # merged = {'Cookie': '...', 'User-Agent': '...', ...}
    """

    def __init__(self, headers_dir, cli_headers=None, log_masked=True):
        self.dir = Path(headers_dir)
        self.cli_headers = dict(cli_headers or {})
        self.log_masked = log_masked
        self._default = {}
        self._hosts = {}
        self._loaded = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def load(self):
        """(Re)load all profiles from disk. Safe to call repeatedly."""
        with self._lock:
            self._default = strip_hop_by_hop(
                load_header_profile(self.dir / "default.txt"))
            self._hosts = {}
            if self.dir.exists():
                for p in self.dir.glob("*.txt"):
                    name = p.stem.lower()
                    if name == "default":
                        continue
                    hdrs = load_header_profile(p)
                    if hdrs:
                        self._hosts[name] = strip_hop_by_hop(hdrs)
            self._loaded = True

    def reload(self):
        self.load()

    # ------------------------------------------------------------------ #
    def profiles_loaded(self):
        """Return list of (name, header_count) for logging."""
        out = []
        if self._default:
            out.append(("default", len(self._default)))
        for host, hdrs in sorted(self._hosts.items()):
            if hdrs:
                out.append((host, len(hdrs)))
        return out

    # ------------------------------------------------------------------ #
    def headers_for(self, host_or_url, extra=None):
        """
        Return the merged header dict for a host or URL.

        Precedence (low -> high):
            default.txt  <  parent.domain  <  <host>
                         <  cli_headers   <  extra

        Hop-by-hop headers are always stripped from the result.
        """
        if not self._loaded:
            self.load()

        if "://" in (host_or_url or ""):
            try:
                host = urlparse(host_or_url).netloc.lower()
            except Exception:
                host = ""
        else:
            host = (host_or_url or "").lower()

        host_noport = host.split(":")[0]

        merged = {}
        merged.update(self._default)

        # Parent-domain fallback: api.example.com -> example.com
        parts = host_noport.split(".")
        parent = ".".join(parts[-2:]) if len(parts) > 2 else None

        # Apply parent first, then exact host (so exact wins)
        if parent and parent in self._hosts:
            merged.update(self._hosts[parent])
        for key in (host_noport, host):
            if key and key in self._hosts:
                merged.update(self._hosts[key])

        merged.update(self.cli_headers)
        if extra:
            merged.update(extra)

        return strip_hop_by_hop(merged)

    # ------------------------------------------------------------------ #
    def describe(self):
        """Human-readable summary for startup logs (values masked)."""
        lines = []
        if self._default:
            lines.append("  default.txt         : {} headers".format(
                len(self._default)))
            for k in sorted(self._default):
                lines.append("      {}: {}".format(
                    k, mask_header_value(k, self._default[k])))
        for host in sorted(self._hosts):
            hdrs = self._hosts[host]
            if not hdrs:
                continue
            lines.append("  {}.txt : {} headers".format(host, len(hdrs)))
            for k in sorted(hdrs):
                lines.append("      {}: {}".format(
                    k, mask_header_value(k, hdrs[k])))
        return "\n".join(lines) if lines else "  (no header profiles loaded)"

    # ------------------------------------------------------------------ #
    def header_names_for(self, host_or_url):
        """Return sorted list of header names for auditing (no values)."""
        return sorted(self.headers_for(host_or_url).keys())


# =============================================================================
#  ROBLOX CSRF HELPER  (v2.1.0)
# =============================================================================
_ROBLOX_CSRF = {}
_ROBLOX_CSRF_LOCK = threading.Lock()


def get_roblox_csrf_token(session_headers=None, host="apis.roblox.com",
                          timeout=10):
    """
    Fetch a fresh X-CSRF-TOKEN from Roblox. Cached per host.

    Roblox returns 403 with an `x-csrf-token` response header when a
    POST is made without a valid token. We trigger that response on
    purpose, extract the token, and cache it.

    Returns the token string, or None on failure.
    """
    with _ROBLOX_CSRF_LOCK:
        cached = _ROBLOX_CSRF.get(host)
        if cached:
            return cached

    # Any endpoint that requires CSRF will do. /v1/auth/logout is reliable.
    url = "https://{}/v1/auth/logout".format(host)
    try:
        r = send_request(url, method="POST", headers=session_headers or {},
                         timeout=timeout)
    except Exception:
        return None
    if r is None:
        return None

    token = (r.headers.get("x-csrf-token") or
             r.headers.get("X-CSRF-TOKEN") or
             r.headers.get("X-Csrf-Token"))
    if token:
        with _ROBLOX_CSRF_LOCK:
            _ROBLOX_CSRF[host] = token
    return token


def reset_roblox_csrf():
    with _ROBLOX_CSRF_LOCK:
        _ROBLOX_CSRF.clear()


# =============================================================================
#  PAYLOAD VAULT
# =============================================================================
PAYLOAD_DIR = Path(__file__).parent / "payloads"


def vault_encode_all(directory=None):
    directory = Path(directory or PAYLOAD_DIR)
    if not directory.exists():
        return 0, [f"not found: {directory}"]

    yamls = sorted(directory.glob("*.yaml"))
    if not yamls:
        return 0, ["no .yaml files in payloads/"]

    encoded, errors = 0, []
    for yaml_path in yamls:
        try:
            raw = yaml_path.read_bytes()
            b64 = base64.b64encode(raw)
            wrapped = b"\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
            (yaml_path.with_suffix(".b64")).write_bytes(wrapped + b"\n")
            encoded += 1
            log(f"encoded {yaml_path.name} -> {yaml_path.with_suffix('.b64').name} "
                f"({len(raw)} -> {len(wrapped)} B)", "ok", "VAULT")
        except Exception as e:
            errors.append(f"{yaml_path.name}: {e}")
    return encoded, errors


def vault_decode_all(directory=None):
    directory = Path(directory or PAYLOAD_DIR)
    if not directory.exists():
        return 0, [f"not found: {directory}"]

    b64s = sorted(directory.glob("*.b64"))
    if not b64s:
        return 0, ["no .b64 files in payloads/"]

    decoded, errors = 0, []
    for b64_path in b64s:
        try:
            raw = b64_path.read_bytes().replace(b"\n", b"").replace(b"\r", b"")
            data = base64.b64decode(raw)
            (b64_path.with_suffix(".yaml")).write_bytes(data)
            decoded += 1
            log(f"decoded {b64_path.name} -> "
                f"{b64_path.with_suffix('.yaml').name}", "ok", "VAULT")
        except Exception as e:
            errors.append(f"{b64_path.name}: {e}")
    return decoded, errors


def vault_status(directory=None):
    directory = Path(directory or PAYLOAD_DIR)
    out = {}
    for p in sorted(list(directory.glob("*.yaml")) + list(directory.glob("*.b64"))):
        name = p.stem
        slot = out.setdefault(name, {"yaml": False, "b64": False})
        if p.suffix == ".yaml":
            slot["yaml"] = True
        elif p.suffix == ".b64":
            slot["b64"] = True
    return out


# =============================================================================
#  PAYLOAD LOADING
# =============================================================================
def load_payloads(name, directory=None):
    if _yaml is None:
        log("pyyaml missing: pip install pyyaml", "err")
        return {}

    directory = Path(directory or PAYLOAD_DIR)
    yaml_path = directory / f"{name}.yaml"
    b64_path  = directory / f"{name}.b64"

    if b64_path.exists():
        try:
            raw = b64_path.read_bytes().replace(b"\n", b"").replace(b"\r", b"")
            text = base64.b64decode(raw).decode("utf-8", errors="ignore")
            data = _yaml.safe_load(text)
            if data:
                return data
        except Exception as e:
            log(f"payload b64 decode error ({b64_path}): {e}", "warn")

    if yaml_path.exists():
        try:
            with open(yaml_path, encoding="utf-8") as f:
                return _yaml.safe_load(f) or {}
        except Exception as e:
            log(f"payload load error ({yaml_path}): {e}", "err")
            return {}

    log(f"payload file not found: {yaml_path.name} or {b64_path.name}", "warn")
    return {}


def substitute_placeholders(payload, attacker="", target="", subdomain="",
                            alert="", collab="", oob="", token="", extra=None):
    if not payload:
        return payload
    subs = {
        "{{ATTACKER}}":  attacker or "",
        "{{TARGET}}":    target or "",
        "{{SUBDOMAIN}}": subdomain or target or "",
        "{{ALERT}}":     alert or "alert(1)",
        "{{COLLAB}}":    collab or attacker or "",
        "{{OOB}}":       oob or "",
        "{{RANDOM}}":    token or "",
    }
    if extra:
        for k, v in extra.items():
            subs[f"{{{{{k}}}}}"] = str(v)
    for k, v in subs.items():
        payload = payload.replace(k, v)
    return payload


# =============================================================================
#  FINGERPRINTING (WAF / PROVIDER / DBMS)
# =============================================================================
WAF_SIGNATURES = {
    "cloudflare":  ["cloudflare"],
    "akamai":      ["akamai"],
    "sucuri":      ["sucuri"],
    "imperva":     ["imperva", "incapsula"],
    "awswaf":      ["aws waf", "awselb", "cloudfront"],
    "azurewaf":    ["azure front door", "azure waf"],
    "f5":          ["f5", "big-ip", "bigip"],
    "modsecurity": ["modsecurity", "mod_security"],
    "fastly":      ["fastly"],
    "stackpath":   ["stackpath"],
}

CLOUD_SIGNATURES = {
    "aws":          ["amazon", "aws", "cloudfront", "elb", "route53",
                     "s3.amazonaws", "elasticbeanstalk"],
    "gcp":          ["google cloud", "gcp", "googleusercontent",
                     "appspot", "google frontend"],
    "azure":        ["azure", "microsoft-iis", "front door",
                     "azurewebsites", "cloudapp.azure"],
    "digitalocean": ["digitalocean", "do-"],
    "alibaba":      ["alibaba", "aliyun"],
    "oracle":       ["oracle cloud", "oci", "oraclecloud"],
    "cloudflare":   ["cloudflare"],
    "fastly":       ["fastly"],
}

DBMS_SIGNATURES = {
    "mysql":      ["mysql", "mariadb", "phpmyadmin"],
    "postgresql": ["postgresql", "postgres", "pgsql"],
    "mssql":      ["mssql", "sql server", "asp.net", "iis"],
    "oracle":     ["oracle database", "oracle db", "oracle http server"],
    "sqlite":     ["sqlite"],
    "mongodb":    ["mongodb", "mongoose"],
}


def _match_signatures(haystack, signatures):
    hits = set()
    low = (haystack or "").lower()
    for key, needles in signatures.items():
        for needle in needles:
            if needle in low:
                hits.add(key)
                break
    return hits


def detect_waf(text_or_headers):
    hits = _match_signatures(_to_text(text_or_headers), WAF_SIGNATURES)
    return next(iter(hits)) if hits else None


def detect_provider(text_or_headers):
    hits = _match_signatures(_to_text(text_or_headers), CLOUD_SIGNATURES)
    return next(iter(hits)) if hits else None


def detect_dbms(text_or_headers):
    hits = _match_signatures(_to_text(text_or_headers), DBMS_SIGNATURES)
    return next(iter(hits)) if hits else None


def _to_text(x):
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return " ".join(f"{k}: {v}" for k, v in x.items())
    if isinstance(x, (list, tuple, set)):
        return " ".join(_to_text(i) for i in x)
    return str(x)


# =============================================================================
#  SUBPROCESS
# =============================================================================
def which(tool):
    return _which(tool)


def run_cmd(cmd, timeout=900, cwd=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=cwd)
    except Exception:
        return None


# =============================================================================
#  FORMATTERS
# =============================================================================
def format_bytes(n):
    try:
        n = float(n)
    except Exception:
        return str(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def format_duration(seconds):
    try:
        s = float(seconds)
    except Exception:
        return str(seconds)
    if s < 1:
        return f"{s * 1000:.0f}ms"
    if s < 60:
        return f"{s:.1f}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{int(m)}m {int(s)}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h {int(m)}m"


# =============================================================================
#  SELF-TEST
# =============================================================================
def _self_test():
    # --- existing assertions ---
    assert safe_filename("a/b\\c?d") == "a_b_c_d"
    assert "huginn-" in build_oob_url("x.com", "deadbeef")
    assert parse_json_path("$.a.b[0].c") == ["a", "b", 0, "c"]
    obj = {"a": {"b": [{"c": 1}]}}
    set_json_path(obj, "$.a.b[0].c", 99)
    assert obj["a"]["b"][0]["c"] == 99
    assert detect_waf("cloudflare-nginx") == "cloudflare"
    assert detect_provider("Amazon S3") == "aws"
    assert detect_dbms("PostgreSQL 15") == "postgresql"
    assert url_extension("http://x/y/z.js?v=1") == ".js"
    assert url_extension("http://x/y/z") == ""

    # --- v2.1.0: header parsing ---

    # Basic headers
    s1 = "Cookie: a=b\nX-Custom: hello\nUser-Agent: Mozilla/5.0\n"
    p1 = parse_header_block(s1)
    assert p1.get("Cookie") == "a=b"
    assert p1.get("X-Custom") == "hello"

    # HTTP/1.1 request line — skipped
    s2 = "GET /path HTTP/1.1\r\nHost: y\r\nCookie: z\r\n"
    p2 = parse_header_block(s2)
    assert p2.get("Cookie") == "z"
    assert "Host" in p2
    assert len([k for k in p2 if k.startswith("GET")]) == 0

    # HTTP/2 request line — skipped
    s3 = "POST /api/v1/events HTTP/2\nHost: apis.example.com\nCookie: c=d\n"
    p3 = parse_header_block(s3)
    assert p3.get("Cookie") == "c=d"
    assert "Host" in p3
    assert len([k for k in p3 if k.startswith("POST")]) == 0

    # HTTP/3 request line — skipped
    s4 = "GET /x HTTP/3\nCookie: a=b\n"
    p4 = parse_header_block(s4)
    assert p4.get("Cookie") == "a=b"

    # Continuation lines (RFC 7230 line folding)
    s5 = "X-Multi: part1\n part2\n part3\n"
    p5 = parse_header_block(s5)
    assert p5.get("X-Multi") == "part1 part2 part3"

    # Colon in value
    s6 = "Location: https://example.com:8443/path\n"
    p6 = parse_header_block(s6)
    assert p6.get("Location") == "https://example.com:8443/path"

    # Empty value
    s7 = "X-Empty:\nX-Spaced: value\n"
    p7 = parse_header_block(s7)
    assert p7.get("X-Empty") == ""
    assert p7.get("X-Spaced") == "value"

    # Comments and blank lines ignored
    s8 = "# comment\nCookie: a=b\n\n# another\nX-Foo: bar\n"
    p8 = parse_header_block(s8)
    assert p8.get("Cookie") == "a=b"
    assert p8.get("X-Foo") == "bar"

    # HTTP/2 pseudo-headers dropped
    s9 = ":method: POST\n:path: /x\nCookie: a=b\n"
    p9 = parse_header_block(s9)
    assert p9.get("Cookie") == "a=b"
    assert not any(k.startswith(":") for k in p9)

    # Roblox-style Burp paste (with HTTP/2, Content-Length, Content-Encoding)
    s10 = (
        "POST /experience-signals-ingest/public/v1/events/single HTTP/2\n"
        "Host: apis.roblox.com\n"
        "Cookie: .ROBLOSECURITY=abc; RBXSessionTracker=xyz\n"
        "Content-Length: 179\n"
        "Content-Encoding: gzip\n"
        "User-Agent: Mozilla/5.0\n"
        "Sec-Ch-Ua-Platform: \"Linux\"\n"
    )
    p10 = parse_header_block(s10)
    assert p10.get("Cookie", "").startswith(".ROBLOSECURITY=")
    assert p10.get("Content-Length") == "179"   # kept by parser...
    assert p10.get("User-Agent") == "Mozilla/5.0"
    assert len([k for k in p10 if k.startswith("POST")]) == 0

    # ...but stripped by HeaderJar
    stripped = strip_hop_by_hop(p10)
    assert "Content-Length" not in stripped
    assert "Content-Encoding" not in stripped
    assert "Host" not in stripped
    assert "Cookie" in stripped
    assert "User-Agent" in stripped

    # Masking
    assert mask_header_value("Cookie", "session=abc12345678").startswith("sess")
    assert mask_header_value("X-Custom", "visible").startswith("visible")
    assert mask_header_value("Authorization", "short") == "***"

    # HeaderJar precedence
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        (tdir / "default.txt").write_text("Cookie: default-cookie\nX-Default: yes\n")
        (tdir / "api.example.com.txt").write_text("X-Host: api\n")
        (tdir / "example.com.txt").write_text("X-Parent: parent\n")

        jar = HeaderJar(tdir)
        jar.load()

        # Exact host: gets default + parent + host
        h = jar.headers_for("api.example.com")
        assert h.get("Cookie") == "default-cookie"
        assert h.get("X-Default") == "yes"
        assert h.get("X-Host") == "api"
        assert h.get("X-Parent") == "parent"

        # Other subdomain: gets default + parent
        h2 = jar.headers_for("www.example.com")
        assert h2.get("Cookie") == "default-cookie"
        assert h2.get("X-Parent") == "parent"
        assert "X-Host" not in h2

        # Unrelated host: only default
        h3 = jar.headers_for("other.net")
        assert h3.get("Cookie") == "default-cookie"
        assert "X-Parent" not in h3
        assert "X-Host" not in h3

        # CLI headers win
        jar2 = HeaderJar(tdir, cli_headers={"Cookie": "cli-wins"})
        jar2.load()
        h4 = jar2.headers_for("api.example.com")
        assert h4.get("Cookie") == "cli-wins"

        # extra wins over everything
        h5 = jar2.headers_for("api.example.com", extra={"Cookie": "extra-wins"})
        assert h5.get("Cookie") == "extra-wins"

    return True


# =============================================================================
#  CLI
# =============================================================================
def _cli_headers_cmd(args):
    """Inspect a headers directory. Useful for debugging profiles."""
    hdir = Path(args.headers_dir)
    if not hdir.exists():
        log("directory not found: {}".format(hdir), "err")
        return 1

    jar = HeaderJar(hdir)
    jar.load()
    profiles = jar.profiles_loaded()

    if not profiles:
        log("no profiles found in {}".format(hdir), "warn")
        return 1

    print()
    print("{}Header profiles in {}{}".format(C.B + C.WH, hdir, C.R))
    print("{}{}{}".format(C.D, "─" * 60, C.R))
    for name, count in profiles:
        print("  {:<24} {} headers".format(name, count))
    print()

    if args.test:
        host = args.test
        print("{}Resolved headers for {}{}:{}".format(C.B, host, C.R, C.D))
        print("{}{}{}".format(C.D, "─" * 60, C.R))
        merged = jar.headers_for(host)
        if not merged:
            print("  (no headers)")
        for k in sorted(merged):
            v = mask_header_value(k, merged[k])
            print("  {}: {}".format(k, v))
        print()
    return 0


def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="huginn_utils",
        description="HUGINN shared utilities (v{})".format(VERSION),
    )
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("encode", help="Encode payloads/*.yaml -> *.b64")
    sub.add_parser("decode", help="Decode payloads/*.b64 -> *.yaml")
    sub.add_parser("vault-status", help="Show vault contents")
    sub.add_parser("self-test", help="Run internal sanity checks")

    p_h = sub.add_parser("headers", help="Inspect header profiles")
    p_h.add_argument("headers_dir",
                     help="directory containing default.txt + host.txt")
    p_h.add_argument("--test", default=None,
                     help="resolve headers for this host and print (masked)")

    args = ap.parse_args()

    if args.cmd == "encode":
        n, errs = vault_encode_all()
        log("encoded {} file(s)".format(n), "ok")
        for e in errs:
            log(e, "err")
        return 0 if not errs else 1

    if args.cmd == "decode":
        n, errs = vault_decode_all()
        log("decoded {} file(s)".format(n), "ok")
        for e in errs:
            log(e, "err")
        return 0 if not errs else 1

    if args.cmd == "vault-status":
        st = vault_status()
        print("\n{:<30} {:<8} {:<8}".format("NAME", "YAML", "B64"))
        print("-" * 50)
        for name in sorted(st):
            slot = st[name]
            print("{:<30} {:<8} {:<8}".format(
                name,
                "yes" if slot["yaml"] else "-",
                "yes" if slot["b64"] else "-",
            ))
        print()
        return 0

    if args.cmd == "self-test":
        try:
            if _self_test():
                print("huginn_utils v{} self-test: OK".format(VERSION))
            return 0
        except AssertionError as e:
            import traceback
            traceback.print_exc()
            print("self-test FAILED")
            return 1

    if args.cmd == "headers":
        return _cli_headers_cmd(args)

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(_cli())
