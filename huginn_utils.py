#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: huginn_utils.py
#  Shared utilities for the entire HUGINN suite.
# -----------------------------------------------------------------------------
#  Everything that two or more scanners need to touch lives here:
#    · colors + logging (single source of truth for terminal output)
#    · target normalization + filename safety
#    · atomic JSON I/O
#    · config loading (huginn.yaml with sane precedence)
#    · HTTP session management (connection reuse)
#    · OOB token generation + URL building + callback polling
#    · payload YAML loading + placeholder substitution
#    · WAF / cloud / DBMS fingerprinting
#    · JSON path get/set (used by every scanner that mutates bodies)
#    · misc formatters used by report generation
# =============================================================================

import os
import re
import sys
import json
import time
import uuid
import hashlib
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from shutil import which as _which
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)

# -----------------------------------------------------------------------------
#  Third-party deps — fail loudly and helpfully if missing
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
VERSION = "1.0.0"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (HUGINN; BugBounty) AppleWebKit/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

# Canonical default configuration — overridable via huginn.yaml and CLI.
DEFAULTS = {
    "attacker_domain": "beardedviking.org",
    "collab_host":     "oast.beardedviking.org",
    "canary_host":     "redirect.beardedviking.org",
    "canary_string":   "HUGINN-CANARY-LANDED",
    "alert_payload":   "alert(document.domain)",
    "oob_log_file":    None,
    "use_subdomain_oob": False,   # path-based tokens by default
    "max_workers":     8,
    "delay":           0.15,
    "timeout":         12,
    "use_browser":     False,
    "provider_filter": None,
}

CONFIG_SEARCH_PATHS = [
    Path("./huginn.yaml"),
    Path("./huginn.yml"),
    Path.home() / ".config" / "huginn" / "config.yaml",
    Path.home() / ".huginn.yaml",
]

# Token pattern shared across every receiver, poller, and payload builder.
TOKEN_PATTERN = re.compile(r"huginn-([a-f0-9]{16,32})", re.I)


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
        "info": f"{C.CY}[*]{C.R}",
        "ok":   f"{C.GR}[+]{C.R}",
        "warn": f"{C.YE}[!]{C.R}",
        "err":  f"{C.RE}[-]{C.R}",
        "scan": f"{C.MA}[>]{C.R}",
        "hit":  f"{C.GR}[✓]{C.R}",
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
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗██╗   ██╗ ██████╗ ██╗███╗   ██╗███╗   ██╗          ║
║   ██║  ██║██║   ██║██╔════╝ ██║████╗  ██║████╗  ██║          ║
║   ███████║██║   ██║██║  ███╗██║██╔██╗ ██║██╔██╗ ██║          ║
║   ██╔══██║██║   ██║██║   ██║██║██║╚██╗██║██║╚██╗██║          ║
║   ██║  ██║╚██████╔╝╚██████╔╝██║██║ ╚████║██║ ╚████║          ║
║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝          ║
║                                                              ║
║              {C.MA}O D I N ' S   R A V E N{C.CY}                         ║
║         {C.D}Automated Recon & Vulnerability Suite{C.CY}                ║
╚══════════════════════════════════════════════════════════════╝
{C.R}""")


# =============================================================================
#  TARGET NORMALIZATION
# =============================================================================
def normalize_target(target):
    """
    Accepts:  example.com | www.example.com | https://ex.com/x
    Returns:  (domain, base_url)
    """
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


# =============================================================================
#  JSON I/O
# =============================================================================
def save_json(path, data):
    """Write JSON, creating parent directories. Atomic on POSIX where possible."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================================
#  CONFIG LOADING
# =============================================================================
def load_huginn_config(paths=None, overrides=None):
    """
    Merge precedence:  DEFAULTS  <  huginn.yaml  <  overrides (dict)
    Returns a flat dict.
    """
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
    """Return a lowercase hex token of the requested length (16-32)."""
    length = max(16, min(32, int(length)))
    return uuid.uuid4().hex[:length]


def build_oob_url(collab_host, token, path_hint="", use_subdomain=False,
                  scheme="https"):
    """
    Build a unique OOB callback URL that carries a huginn token.

    Two modes:
      · Path-based (default):  https://<collab>/huginn-<token>/<hint>
        Works everywhere — no wildcard cert needed. This is what the
        shared-hosting deployment uses.

      · Subdomain-based:       https://huginn-<token>.<collab>/<hint>
        Requires a wildcard A record AND wildcard TLS on the collab host.
    """
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
    """
    Watches a local file (or the check.php endpoint's mirrored copy) for
    DNS/HTTP callbacks. Tokens are matched against the shared TOKEN_PATTERN.

    Usage:
        poller = OOBPoller("/path/to/tokens.txt", timeout=90)
        poller.start()
        ...
        if poller.has_token(tok):
            # finding confirmed
        poller.stop()
    """

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
        """Manually feed log content (useful for tests)."""
        added = 0
        for m in TOKEN_PATTERN.finditer(text or ""):
            with self._lock:
                self._seen.add(m.group(1).lower())
                added += 1
        return added


# =============================================================================
#  HTTP — SESSION MANAGEMENT + THROTTLE
# =============================================================================
_SESSION = None
_SESSION_LOCK = threading.Lock()
_THROTTLE_LAST = {}
_THROTTLE_LOCK = threading.Lock()


def get_session():
    """Return the shared requests.Session (thread-safe lazy init)."""
    global _SESSION
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                s = requests.Session()
                s.headers.update(DEFAULT_HEADERS)
                s.verify = False
                # Reasonable connection pool defaults
                try:
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=32, pool_maxsize=64, max_retries=0,
                    )
                    s.mount("https://", adapter)
                    s.mount("http://", adapter)
                except Exception:
                    pass
                _SESSION = s
    return _SESSION


def send_request(url, method="GET", headers=None, timeout=12,
                 allow_redirects=False, data=None, params=None, json_body=None):
    """Send an HTTP request via the shared session. Returns Response or None."""
    sess = get_session()
    try:
        return sess.request(
            method=method, url=url,
            headers=headers or DEFAULT_HEADERS,
            timeout=timeout, allow_redirects=allow_redirects,
            data=data, params=params, json=json_body,
        )
    except Exception:
        return None


def throttle(host, delay):
    """
    Per-host rate limiter. Call before each request to enforce a minimum
    spacing between requests to the same host. Thread-safe.
    """
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


# =============================================================================
#  URL / PARAM HELPERS
# =============================================================================
def inject_param(url, param, payload):
    """Replace <param> value with <payload>, return new URL or None."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if param not in qs:
        return None
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def get_host(url):
    """Return the netloc for throttling purposes."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


# =============================================================================
#  JSON PATH
# =============================================================================
_JSON_PATH_RE = re.compile(r"\.([^\.\[\]]+)|\[(\d+)\]")


def parse_json_path(path):
    """'$.a.b[0].c' -> ['a', 'b', 0, 'c']"""
    tokens = []
    for name, idx in _JSON_PATH_RE.findall(path or ""):
        if name:
            tokens.append(name)
        elif idx:
            tokens.append(int(idx))
    return tokens


def set_json_path(obj, path, value):
    """
    Navigate a JSON-like object by path and set the leaf.
    Returns the (possibly mutated) root object.
    """
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
#  PAYLOAD HELPERS
# =============================================================================
def load_payloads(name):
    """Load payloads/<name>.yaml → dict."""
    if _yaml is None:
        log("pyyaml missing: pip install pyyaml", "err")
        return {}
    path = Path(__file__).parent / "payloads" / f"{name}.yaml"
    if not path.exists():
        log(f"payload file not found: {path}", "warn")
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return _yaml.safe_load(f) or {}
    except Exception as e:
        log(f"payload load error ({path}): {e}", "err")
        return {}


def substitute_placeholders(payload, attacker="", target="", subdomain="",
                            alert="", collab="", oob="", token="", extra=None):
    """
    Replace every {{...}} token in a payload template.

    Centralized so every scanner uses the same substitution rules.
    """
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
    """Return the first matching WAF key, or None."""
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
#  FORMATTERS (used by report generation)
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
#  MODULE-LEVEL SANITY
# =============================================================================
def _self_test():
    """Quick self-check. Run `python -c 'import huginn_utils as h; h._self_test()'`."""
    assert safe_filename("a/b\\c?d") == "a_b_c_d"
    assert "huginn-" in build_oob_url("x.com", "deadbeef")
    assert parse_json_path("$.a.b[0].c") == ["a", "b", 0, "c"]
    obj = {"a": {"b": [{"c": 1}]}}
    set_json_path(obj, "$.a.b[0].c", 99)
    assert obj["a"]["b"][0]["c"] == 99
    assert detect_waf("cloudflare-nginx") == "cloudflare"
    assert detect_provider("Amazon S3") == "aws"
    assert detect_dbms("PostgreSQL 15") == "postgresql"
    return True


if __name__ == "__main__":
    if _self_test():
        print("huginn_utils self-test: OK")
