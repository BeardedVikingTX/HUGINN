#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: huginn_utils.py — v2.0
#  Shared utilities for the entire HUGINN suite.
# -----------------------------------------------------------------------------
#  What's here:
#    · Colors + logging (single source of truth)
#    · Target normalization + filename safety
#    · Atomic JSON I/O (+ optional gzip for large findings)
#    · Config loading (huginn.yaml with sane precedence)
#    · HTTP session management (pooling, retry, proxy, UA rotation)
#    · OOB token generation + URL building + callback polling
#    · Payload vault (base64-encoded YAML to bypass host AV)
#    · Placeholder substitution
#    · WAF / cloud / DBMS fingerprinting
#    · JSON path get/set
#    · Subprocess helpers
#    · Formatters
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
VERSION = "2.0.0"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (HUGINN; BugBounty) AppleWebKit/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

# A small pool of realistic browser UAs for rotation.
# Not exhaustive — swap in a bigger list from the anonymity module later.
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

# Canonical default configuration.
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
    # --- v2.0 additions ---
    "proxy":             None,       # e.g. "http://user:pass@host:port"
    "rotate_user_agent": False,      # random UA per session start
    "retry_transient":   True,       # retry once on connection error
    "gzip_findings":     False,      # write findings as .json.gz
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
        "info":  f"{C.CY}[*]{C.R}",
        "ok":    f"{C.GR}[+]{C.R}",
        "warn":  f"{C.YE}[!]{C.R}",
        "err":   f"{C.RE}[-]{C.R}",
        "scan":  f"{C.MA}[>]{C.R}",
        "hit":   f"{C.GR}[✓]{C.R}",
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
#  TIME HELPERS
# =============================================================================
def now_iso():
    """UTC timestamp in ISO-8601 with 'Z' suffix (matches existing findings)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def now_unix():
    return int(time.time())


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


def get_host(url):
    """Return the netloc for throttling purposes."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def url_extension(url):
    """Return the lowercase extension of the URL's path, or ''."""
    try:
        path = urlparse(url).path
        if "." not in path.rsplit("/", 1)[-1]:
            return ""
        return "." + path.rsplit(".", 1)[-1].lower()
    except Exception:
        return ""


# =============================================================================
#  JSON I/O  (+ optional gzip)
# =============================================================================
def save_json(path, data, compress=False):
    """
    Write JSON, creating parent directories. Atomic on POSIX where possible.
    If compress=True or path ends in .gz, write gzip-compressed JSON.
    """
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
    """Load JSON, transparently decompressing .gz."""
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
      · Subdomain-based:       https://huginn-<token>.<collab>/<hint>
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
    """Watches a local file for huginn-<token> lines."""

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

# Per-host throttle state
_THROTTLE_LAST = {}
_THROTTLE_HITS = {}
_THROTTLE_LOCK = threading.Lock()

# Global request counter (useful for stats)
_REQUEST_COUNT = {"total": 0, "ok": 0, "err": 0}
_REQUEST_COUNT_LOCK = threading.Lock()


def get_session(proxy=None, rotate_user_agent=False):
    """
    Return the shared requests.Session. On first call it configures:
      · Connection pooling (32 pools / 64 max)
      · verify=False (accept self-signed certs — scanning targets often use them)
      · Optional proxy from `proxy` param or DEFAULTS
      · Optional random User-Agent when rotate_user_agent=True
    """
    global _SESSION
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                s = requests.Session()

                # Headers — clone defaults so mutation is safe
                s.headers.update(DEFAULT_HEADERS)

                # Optional UA rotation
                if rotate_user_agent:
                    s.headers["User-Agent"] = random.choice(USER_AGENT_POOL)

                # Optional proxy
                if proxy:
                    s.proxies.update({"http": proxy, "https": proxy})

                s.verify = False

                try:
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=32,
                        pool_maxsize=64,
                        max_retries=0,   # we handle retry manually
                    )
                    s.mount("https://", adapter)
                    s.mount("http://", adapter)
                except Exception:
                    pass

                _SESSION = s
    return _SESSION


def reset_session():
    """Force a fresh session on the next get_session() call."""
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is not None:
            try:
                _SESSION.close()
            except Exception:
                pass
        _SESSION = None


def set_proxy(proxy_url):
    """Apply a proxy to the shared session (call reset_session() after if needed)."""
    s = get_session()
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})
    else:
        s.proxies.clear()


def send_request(url, method="GET", headers=None, timeout=12,
                 allow_redirects=False, data=None, params=None, json_body=None,
                 retry=True):
    """
    Send an HTTP request via the shared session.

    Headers are MERGED with defaults — you can override just one header
    without losing the shared UA / Accept / etc.

    On transient errors (ConnectionError / Timeout), retries once if
    `retry=True` and DEFAULTS["retry_transient"] is True.
    """
    sess = get_session()

    merged_headers = dict(DEFAULT_HEADERS)
    if headers:
        merged_headers.update(headers)

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
    """Return a snapshot of request counters."""
    with _REQUEST_COUNT_LOCK:
        return dict(_REQUEST_COUNT)


# =============================================================================
#  THROTTLE
# =============================================================================
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
        _THROTTLE_HITS[host] = _THROTTLE_HITS.get(host, 0) + 1


def throttle_stats():
    """Return {host: request_count} for hosts seen so far."""
    with _THROTTLE_LOCK:
        return dict(_THROTTLE_HITS)


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
    """Navigate a JSON-like object by path and set the leaf."""
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
#  PAYLOAD VAULT — base64 to survive shared-host malware scanners
# =============================================================================
PAYLOAD_DIR = Path(__file__).parent / "payloads"


def vault_encode_all(directory=None):
    """
    Read every .yaml in payloads/ and write a matching .b64 file.
    Returns (encoded_count, errors).
    """
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
            # Wrap at 76 chars for compatibility with scanner heuristics
            wrapped = b"\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
            (yaml_path.with_suffix(".b64")).write_bytes(wrapped + b"\n")
            encoded += 1
            log(f"encoded {yaml_path.name} -> {yaml_path.with_suffix('.b64').name} "
                f"({len(raw)} -> {len(wrapped)} B)", "ok", "VAULT")
        except Exception as e:
            errors.append(f"{yaml_path.name}: {e}")
    return encoded, errors


def vault_decode_all(directory=None):
    """
    Read every .b64 in payloads/ and write a matching .yaml file.
    Returns (decoded_count, errors).
    """
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
    """Return a dict of {name: {'yaml': bool, 'b64': bool}}."""
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
#  PAYLOAD LOADING  (vault-aware)
# =============================================================================
def load_payloads(name, directory=None):
    """
    Load payloads/<name>.yaml -> dict.

    Prefers the .b64 (base64-encoded) form when present. Falls back to
    plain .yaml for local development. This is what lets the same
    payloads/ tree survive Imunify360 on shared hosting.
    """
    if _yaml is None:
        log("pyyaml missing: pip install pyyaml", "err")
        return {}

    directory = Path(directory or PAYLOAD_DIR)
    yaml_path = directory / f"{name}.yaml"
    b64_path  = directory / f"{name}.b64"

    # 1. Prefer the encoded form (server-safe)
    if b64_path.exists():
        try:
            raw = b64_path.read_bytes().replace(b"\n", b"").replace(b"\r", b"")
            text = base64.b64decode(raw).decode("utf-8", errors="ignore")
            data = _yaml.safe_load(text)
            if data:
                return data
        except Exception as e:
            log(f"payload b64 decode error ({b64_path}): {e}", "warn")

    # 2. Fall back to plain YAML (local dev)
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
    """
    Replace every {{...}} token in a payload template.
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
    return True


# =============================================================================
#  CLI — vault subcommands
# =============================================================================
def _cli():
    """python3 huginn_utils.py <command>"""
    import argparse
    ap = argparse.ArgumentParser(
        prog="huginn_utils",
        description="HUGINN shared utilities + payload vault CLI",
    )
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("encode", help="Encode payloads/*.yaml -> *.b64")
    sub.add_parser("decode", help="Decode payloads/*.b64 -> *.yaml")
    sub.add_parser("vault-status", help="Show vault contents")
    sub.add_parser("self-test", help="Run internal sanity checks")

    args = ap.parse_args()

    if args.cmd == "encode":
        n, errs = vault_encode_all()
        log(f"encoded {n} file(s)", "ok")
        for e in errs:
            log(e, "err")
        return 0 if not errs else 1

    if args.cmd == "decode":
        n, errs = vault_decode_all()
        log(f"decoded {n} file(s)", "ok")
        for e in errs:
            log(e, "err")
        return 0 if not errs else 1

    if args.cmd == "vault-status":
        st = vault_status()
        print(f"\n{'NAME':<30} {'YAML':<8} {'B64':<8}")
        print("-" * 50)
        for name in sorted(st):
            slot = st[name]
            print(f"{name:<30} "
                  f"{'yes' if slot['yaml'] else '-':<8} "
                  f"{'yes' if slot['b64'] else '-':<8}")
        print()
        return 0

    if args.cmd == "self-test":
        if _self_test():
            print("huginn_utils self-test: OK")
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(_cli())
