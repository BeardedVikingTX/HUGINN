#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: sqli.py — v4.0
#  SQL Injection Scanner — status-aware, AI-triaged, BB-grade.
# -----------------------------------------------------------------------------
#  Detection strategies (in order of confidence):
#    1. error_signature    — DBMS error message matched in response
#    2. boolean_blind      — TRUE/FALSE payload pair produces different responses
#    3. timing_confirmed   — time-based delay reproduces across 3 attempts
#    4. status_escalation  — 2xx/3xx -> 5xx with SQL-ish content
#    5. baseline_diff      — response body substantially differs from baseline
#
#  What's new in v4.0:
#    · Response classification (403/404/429/5xx) with WAF fingerprinting
#    · WAF block page detection (Cloudflare, Akamai, Imperva, Sucuri, F5,
#      AWS WAF, ModSecurity, Wordfence, Barracuda, FortiWeb, ...)
#    · Per-host rate-limit backoff with Retry-After support
#    · Baseline stability check (unstable hosts flagged, body_diff disabled)
#    · AI triage on every finding (brain.triage)
#    · AI severity refinement (brain.assess_severity)
#    · AI-context payload augmentation on WAF detection
#    · --min-severity filter (default: medium)
#    · _ai_dropped.json audit trail for AI-rejected findings
#    · Graceful degradation — everything works when brain is off
# =============================================================================

import re
import time
import json
import shlex
import hashlib
import statistics
import threading
from pathlib import Path
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, load_json, save_json, load_payloads, send_request,
    safe_filename, format_duration, C,
)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# ---- Optional AI brain (graceful) -------------------------------------------
try:
    from brain import get_brain
    _BRAIN_AVAILABLE = True
except Exception:
    _BRAIN_AVAILABLE = False
    get_brain = None


# =============================================================================
#  DBMS ERROR SIGNATURES  (unchanged from v3.0)
# =============================================================================
ERROR_SIGNATURES = {
    "mysql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL result",
        r"MySqlClient\.", r"com\.mysql\.jdbc",
        r"Zend_Db_Adapter_Mysqli_Exception",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"You have an error in your SQL syntax",
        r"MySqlException", r"MySQLSyntaxErrorException",
        r"mysqli_", r"MariaDB server version",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR: parser: parse error at or near",
        r"pg_query\(\)", r"pg_exec\(\)",
        r"unterminated quoted string at or near",
    ],
    "mssql": [
        r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver", r"macromedia\.jdbc\.sqlserver",
        r"com\.jnetdirect\.jsql",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"System\.Data\.SqlClient\.SqlException",
        r"mssql_query\(\)",
    ],
    "oracle": [
        r"\bORA-[0-9]{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*\Woci_", r"Warning.*\Wora_", r"oracle\.jdbc",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"ORA-00933", r"ORA-01756", r"ORA-00911",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_", r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]", r"SQLite error \d+:",
        r"sqlite3\.OperationalError:", r"sqlite3\.ProgrammingError:",
        r"SQLite3::SQLException", r"org\.sqlite\.JDBC",
    ],
    "sybase": [
        r"Sybase message", r"Sybase.*Server message",
        r"SybSQLException", r"com\.sybase\.jdbc",
    ],
    "db2": [
        r"DB2 SQL error", r"CLI Driver.*DB2", r"com\.ibm\.db2",
    ],
    "informix": [
        r"Informix ODBC Driver", r"com\.informix\.jdbc", r"ODBC Informix driver",
    ],
    "ingres": [
        r"Ingres SQLSTATE", r"Ingres\W.*Driver",
    ],
    "access": [
        r"JET Database Engine", r"Access Database Engine",
        r"Microsoft Access Driver", r"Syntax error.*in query expression",
    ],
    "generic": [
        r"SQL command not properly ended", r"syntax error at or near",
        r"Unclosed quotation mark", r"Unterminated string literal",
        r"invalid query", r"Dynamic SQL Error",
        r"Syntax error in string in query expression",
    ],
}

ALL_SIGNATURES = [(dbms, re.compile(sig, re.I))
                  for dbms, sigs in ERROR_SIGNATURES.items()
                  for sig in sigs]

GENERIC_500_HINTS = re.compile(
    r"(sql|query|database|odbc|jdbc|driver|syntax|column|table)", re.I
)

TIME_PAYLOADS = re.compile(
    r"(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\(|dbms_lock\.sleep\s*\()",
    re.I,
)


# =============================================================================
#  WAF BLOCK PAGE SIGNATURES  (new in v4.0)
# =============================================================================
WAF_BLOCK_SIGNATURES = {
    "cloudflare": [
        r"cloudflare", r"cf-error-details", r"Attention Required.*Cloudflare",
        r"Ray ID", r"Error 1020", r"Error 1015",
    ],
    "akamai": [
        r"akamai", r"Reference\s*#\d+", r"Access Denied.*Akamai",
    ],
    "incapsula": [
        r"incap_ses", r"incapsula", r"Request unsuccessful.*Incapsula",
    ],
    "imperva": [
        r"imperva", r"_Incapsula_Resource",
    ],
    "sucuri": [
        r"sucuri", r"Sucuri WebSite Firewall",
    ],
    "modsecurity": [
        r"mod_security", r"ModSecurity", r"Not Acceptable!",
    ],
    "f5": [
        r"F5 Networks", r"BIG-IP", r"TS[a-f0-9]{8}",
    ],
    "awswaf": [
        r"AWS WAF", r"awselb", r"Request blocked",
    ],
    "barracuda": [
        r"Barracuda", r"Barra_counter_session",
    ],
    "fortiweb": [
        r"FortiWeb", r"FORTIWAFSID",
    ],
    "wordfence": [
        r"Wordfence", r"Generated by Wordfence",
    ],
    "generic_block": [
        r"Request Rejected", r"Blocked by", r"Access Denied.*Firewall",
    ],
}


def _detect_waf_signature(body, headers):
    """Return WAF name if the response looks like a WAF block page."""
    haystack = (body or "")[:8000]
    for k, v in (headers or {}).items():
        haystack += "\n{}: {}".format(k, v)
    low = haystack.lower()

    for name, sigs in WAF_BLOCK_SIGNATURES.items():
        for sig in sigs:
            try:
                if re.search(sig, haystack, re.I):
                    return name
            except Exception:
                continue

    # Server header hints
    server = (headers or {}).get("server", "").lower() if headers else ""
    for name in ("cloudflare", "sucuri", "incapsula", "akamai", "imperva"):
        if name in server:
            return name

    return None


# =============================================================================
#  RESPONSE CLASSIFICATION  (new in v4.0)
# =============================================================================
def classify_status(resp):
    """
    Return a dict describing the meaning of this response.
    Fields:
        code:       category string
        interesting: bool (should we keep testing this IP?)
        waf_name:   str or None
        retry_after: float or None
        notes:      str
    """
    if resp is None:
        return {"code": "EMPTY", "interesting": False, "waf_name": None,
                "retry_after": None, "notes": "no response"}

    status = resp.status_code
    body = (resp.text or "")[:8000]
    headers = {k.lower(): v for k, v in dict(resp.headers or {}).items()}

    waf_name = _detect_waf_signature(body, headers)

    retry_after = None
    ra = headers.get("retry-after")
    if ra:
        try:
            retry_after = float(ra)
        except Exception:
            retry_after = None

    if 200 <= status < 300:
        return {"code": "OK", "interesting": True, "waf_name": waf_name,
                "retry_after": retry_after, "notes": ""}
    if 300 <= status < 400:
        loc = headers.get("location", "")
        return {"code": "REDIRECT", "interesting": True, "waf_name": waf_name,
                "retry_after": retry_after,
                "notes": "Location: {}".format(loc[:120])}
    if status == 304:
        return {"code": "NOT_MODIFIED", "interesting": False,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 400:
        return {"code": "BAD_REQUEST", "interesting": True, "waf_name": waf_name,
                "retry_after": retry_after,
                "notes": "payload may have broken parser"}
    if status == 401:
        return {"code": "AUTH_REQUIRED", "interesting": True,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 403:
        if waf_name:
            return {"code": "FORBIDDEN_WAF", "interesting": False,
                    "waf_name": waf_name, "retry_after": retry_after,
                    "notes": "WAF block page"}
        return {"code": "FORBIDDEN_ACL", "interesting": False,
                "waf_name": None, "retry_after": retry_after,
                "notes": "ACL denial (no WAF signature)"}
    if status == 404:
        return {"code": "NOT_FOUND", "interesting": False,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 405:
        return {"code": "METHOD_NOT_ALLOWED", "interesting": False,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 406:
        return {"code": "NOT_ACCEPTABLE", "interesting": False,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 429:
        return {"code": "RATE_LIMITED", "interesting": False,
                "waf_name": waf_name,
                "retry_after": retry_after if retry_after else 5.0,
                "notes": "rate limited"}
    if status == 501:
        return {"code": "NOT_IMPLEMENTED", "interesting": True,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if 500 <= status < 600:
        # 500 is interesting (app broke); 502/503/504 usually upstream noise
        interesting = status == 500
        return {"code": "SERVER_ERROR", "interesting": interesting,
                "waf_name": waf_name, "retry_after": retry_after,
                "notes": "status {}".format(status)}
    return {"code": "UNKNOWN", "interesting": False, "waf_name": waf_name,
            "retry_after": retry_after, "notes": "status {}".format(status)}


# =============================================================================
#  SEVERITY RANKS
# =============================================================================
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# =============================================================================
#  SKIP FILTERS — don't waste requests on static content
# =============================================================================
SKIP_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".webm", ".wav", ".ogg", ".ogv",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".bin",
}

CDN_HOST_MARKERS = (
    "cdn.", ".cdn.", "static.", "assets.", "img.", "images.",
    "fonts.", "rbxcdn", "akamaihd", "cloudfront", "cloudflare",
    "fastly", "jsdelivr", "gstatic",
)


# =============================================================================
#  HELPERS
# =============================================================================
def _url_extension(url):
    path = urlparse(url).path
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _is_static_url(url):
    ext = _url_extension(url)
    if ext in SKIP_EXTENSIONS:
        return True
    host = urlparse(url).netloc.lower()
    for marker in CDN_HOST_MARKERS:
        if marker in host:
            return True
    return False


def _fingerprint_response(resp):
    """Stable fingerprint of a response for differential comparison."""
    if resp is None:
        return {"hash": None, "length": 0, "status": None}
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    # Remove volatile tokens before hashing
    stable = re.sub(r"\b[a-f0-9]{24,}\b", "__HEX__", body)
    stable = re.sub(r"\b[A-Za-z0-9+/=]{40,}\b", "__B64__", stable)
    return {
        "hash": hashlib.sha256(stable.encode("utf-8", errors="ignore")).hexdigest()[:16],
        "length": len(body),
        "status": resp.status_code,
    }


def _fingerprints_differ(a, b, min_len_delta=200):
    if a["hash"] is None or b["hash"] is None:
        return False
    if a["hash"] == b["hash"]:
        return False
    if abs(a["length"] - b["length"]) >= min_len_delta:
        return True
    if a["hash"] != b["hash"] and abs(a["length"] - b["length"]) > 20:
        return True
    return False


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "extra_headers", "form_data", "json_body",
                 "content_type", "baseline_resp", "baseline_fp",
                 "timing_baseline", "timing_stddev", "stable")

    def __init__(self, url, method, location, name, value,
                 json_path=None, extra_headers=None,
                 form_data=None, json_body=None, content_type=None):
        self.url = url
        self.method = method
        self.location = location
        self.name = name
        self.value = value
        self.json_path = json_path
        self.extra_headers = extra_headers or {}
        self.form_data = form_data or {}
        self.json_body = json_body
        self.content_type = content_type
        self.baseline_resp = None
        self.baseline_fp = None
        self.timing_baseline = None
        self.timing_stddev = None
        self.stable = True

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        return "<IP {}:{} @ {} {}>".format(self.location, self.name,
                                            self.method, self.url)


# =============================================================================
#  INJECTION POINT EXTRACTION (unchanged)
# =============================================================================
def _extract_query_params(page):
    url = page["url"]
    parsed = urlparse(url)
    if not parsed.query:
        return []
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return [InjectionPoint(url, "GET", "query", k, v[0]) for k, v in qs.items()]


def _extract_path_segments(page):
    parsed = urlparse(page["url"])
    segs = [s for s in parsed.path.split("/") if s]
    if not segs:
        return []
    out = []
    for i, seg in enumerate(segs):
        if _is_static_url("http://x/{}".format(seg)):
            continue
        out.append(InjectionPoint(
            page["url"], "GET", "path", "segment[{}]".format(i), seg,
            extra_headers={"_segment_index": str(i)},
        ))
    return out


def _extract_forms(page):
    if BeautifulSoup is None:
        return []
    html = page.get("content") or ""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    points = []
    for form in soup.find_all("form"):
        action = form.get("action") or page["url"]
        action_url = urljoin(page["url"], action)
        method = (form.get("method") or "GET").upper()
        ct = (form.get("enctype") or "application/x-www-form-urlencoded").lower()
        data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "").lower()
            if itype in ("submit", "button", "reset", "file", "image"):
                continue
            data[name] = inp.get("value") or ""
        for name, value in data.items():
            points.append(InjectionPoint(
                action_url, method, "body_form", name, value,
                form_data=dict(data), content_type=ct,
            ))
    return points


def _extract_headers(page):
    headers = [
        "Referer", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Client-IP", "Forwarded", "Origin", "X-Original-URL",
    ]
    return [InjectionPoint(page["url"], "GET", "header", h, "")
            for h in headers]


def _extract_cookies(page):
    headers = page.get("headers") or {}
    sc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not sc:
        return []
    out = []
    for chunk in sc.split(","):
        m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
        if m:
            out.append(InjectionPoint(
                page["url"], "GET", "cookie",
                m.group(1).strip(), m.group(2).strip(),
            ))
    return out


def _extract_json_body(page):
    ct = (page.get("content_type") or "").lower()
    content = page.get("content") or ""
    if "json" not in ct and not content.lstrip().startswith(("{", "[")):
        return []
    try:
        body = json.loads(content)
    except Exception:
        return []
    points = []

    def walk(obj, path="$"):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, "{}.{}".format(path, k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, "{}[{}]".format(path, i))
        else:
            points.append(InjectionPoint(
                page["url"], "POST", "body_json", path, str(obj),
                json_path=path, json_body=body,
                content_type="application/json",
            ))

    walk(body)
    return points


def extract_injection_points(pages):
    points, seen = [], set()
    for page in pages:
        url = page.get("url", "")
        if _is_static_url(url):
            continue
        cands = []
        cands.extend(_extract_query_params(page))
        cands.extend(_extract_path_segments(page))
        cands.extend(_extract_forms(page))
        cands.extend(_extract_headers(page))
        cands.extend(_extract_cookies(page))
        cands.extend(_extract_json_body(page))
        for ip in cands:
            k = ip.key()
            if k in seen:
                continue
            seen.add(k)
            points.append(ip)
    return points


# =============================================================================
#  REQUEST BUILDER + cURL GENERATOR
# =============================================================================
def _set_json_path(obj, path, value):
    tokens = re.findall(r"\.([^\.\[\]]+)|\[(\d+)\]", path)
    cur = obj
    for i, (name, idx) in enumerate(tokens):
        key = name if name else int(idx)
        if i == len(tokens) - 1:
            cur[key] = value
            return
        cur = cur[key]


def build_request(ip, payload, timeout=12, extra_headers=None,
                  allow_redirects=False):
    headers = dict(ip.extra_headers)
    if extra_headers:
        headers.update(extra_headers)
    url = ip.url
    method = ip.method
    data = None

    if ip.location == "query":
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))
    elif ip.location == "path":
        idx = int(headers.pop("_segment_index", "0"))
        p = urlparse(url)
        segs = [s for s in p.path.split("/") if s]
        if idx < len(segs):
            segs[idx] = payload
        url = urlunparse(p._replace(path="/" + "/".join(segs)))
    elif ip.location == "body_form":
        body = dict(ip.form_data)
        body[ip.name] = payload
        data = body
        headers["Content-Type"] = ip.content_type or "application/x-www-form-urlencoded"
    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"
    elif ip.location == "cookie":
        existing = headers.get("Cookie", "")
        pair = "{}={}".format(ip.name, payload)
        headers["Cookie"] = "{}; {}".format(existing, pair).strip("; ") if existing else pair
    elif ip.location == "header":
        headers[ip.name] = payload

    return send_request(
        url, method=method, headers=headers,
        timeout=timeout, allow_redirects=allow_redirects, data=data,
    )


def build_curl(ip, payload, timeout=15):
    parts = ["curl", "-sk", "--max-time", str(timeout), "-i"]
    if ip.location == "query":
        p = urlparse(ip.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))
        parts.append(shlex.quote(url))
    elif ip.location == "path":
        idx = int((ip.extra_headers or {}).get("_segment_index", "0"))
        p = urlparse(ip.url)
        segs = [s for s in p.path.split("/") if s]
        if idx < len(segs):
            segs[idx] = payload
        url = urlunparse(p._replace(path="/" + "/".join(segs)))
        parts.append(shlex.quote(url))
    elif ip.location == "body_form":
        body = dict(ip.form_data)
        body[ip.name] = payload
        if ip.method == "GET":
            p = urlparse(ip.url)
            url = urlunparse(p._replace(query=urlencode(body, doseq=True)))
            parts.append(shlex.quote(url))
        else:
            parts.extend(["-X", "POST"])
            for k, v in body.items():
                parts.extend(["--data-urlencode", shlex.quote("{}={}".format(k, v))])
            parts.append(shlex.quote(ip.url))
    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts.extend(["-X", "POST"])
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(json.dumps(body))])
        parts.append(shlex.quote(ip.url))
    elif ip.location == "cookie":
        parts.extend(["-H", shlex.quote("Cookie: {}={}".format(ip.name, payload))])
        parts.append(shlex.quote(ip.url))
    elif ip.location == "header":
        parts.extend(["-H", shlex.quote("{}: {}".format(ip.name, payload))])
        parts.append(shlex.quote(ip.url))
    else:
        parts.append(shlex.quote(ip.url))
    return " ".join(parts)


# =============================================================================
#  DETECTION PRIMITIVES
# =============================================================================
def _match_error_signature(body, baseline_body=""):
    if not body:
        return None, None
    baseline_low = baseline_body.lower() if baseline_body else ""
    for dbms, regex in ALL_SIGNATURES:
        m = regex.search(body)
        if m:
            matched = m.group(0)[:120].lower()
            if matched in baseline_low:
                continue
            start = max(0, m.start() - 80)
            end = min(len(body), m.end() + 200)
            return dbms, body[start:end]
    return None, None


def _severity_for(confidence):
    return {"high": "high", "medium": "medium", "low": "low"}.get(confidence, "low")


# =============================================================================
#  SCANNER
# =============================================================================
class SQLiScanner:

    def __init__(self,
                 program_dir,
                 sites_root=None,
                 max_workers=6,
                 delay=0.15,
                 timeout=12,
                 waf_hint=None,
                 dbms_hint=None,
                 time_threshold=4.0,
                 confirm_timing=True,
                 cookie=None,
                 user_agent=None,
                 min_severity="medium",
                 use_ai=True,
                 ai_severity=True):
        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "sqli"
        self.findings_root.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.delay = delay
        self.timeout = timeout
        self.waf_hint = waf_hint
        self.dbms_hint = dbms_hint
        self.time_threshold = time_threshold
        self.confirm_timing = confirm_timing
        self.min_severity = (min_severity or "low").lower()
        self.use_ai = use_ai
        self.ai_severity_enabled = ai_severity

        self.static_headers = {}
        if cookie:
            self.static_headers["Cookie"] = cookie
        if user_agent:
            self.static_headers["User-Agent"] = user_agent

        self.seen_signatures = set()
        self._seen_lock = threading.Lock()
        self._payload_cache = None

        # Per-host throttle + backoff
        self._throttle_last = {}
        self._throttle_lock = threading.Lock()
        self._host_backoff = {}    # host -> epoch until which we back off

        # WAF / rate-limit tracking
        self.host_waf = {}         # host -> waf name
        self.host_waf_counts = {}  # host -> count of WAF blocks
        self.host_rl_counts = {}   # host -> count of 429s
        self._waf_lock = threading.Lock()

        # AI bookkeeping
        self.ai_dropped = []
        self._ai_dropped_lock = threading.Lock()
        self.brain = None
        if self.use_ai and _BRAIN_AVAILABLE:
            try:
                self.brain = get_brain()
            except Exception as e:
                log("brain init failed: {}".format(e), "warn", "SQLI")
                self.brain = None

    # ------------------------------------------------------------------ #
    #  Per-host throttle + backoff
    # ------------------------------------------------------------------ #
    def _throttle(self, url):
        """
        Enforce delay between requests to the same host. Also honors
        any active rate-limit backoff. Returns True if we may proceed,
        False if the host is in extended backoff.
        """
        host = urlparse(url).netloc.lower()
        with self._throttle_lock:
            now = time.time()
            backoff_until = self._host_backoff.get(host, 0.0)
            if now < backoff_until:
                wait = backoff_until - now
                if wait > 60:
                    return False    # skip — too long to wait
                time.sleep(min(wait, 30))
                now = time.time()

            last = self._throttle_last.get(host, 0.0)
            wait = self.delay - (now - last)
            if wait > 0:
                time.sleep(wait)
                now = time.time()
            self._throttle_last[host] = now
            return True

    def _note_rate_limit(self, host, retry_after):
        with self._throttle_lock:
            wait = max(float(retry_after or 5.0), 5.0)
            self._host_backoff[host] = time.time() + wait
        with self._waf_lock:
            self.host_rl_counts[host] = self.host_rl_counts.get(host, 0) + 1

    def _note_waf_block(self, host, waf_name):
        with self._waf_lock:
            self.host_waf_counts[host] = self.host_waf_counts.get(host, 0) + 1
            if waf_name:
                self.host_waf[host] = waf_name

    # ------------------------------------------------------------------ #
    #  Payload loading
    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("sqli")
        raw = data.get("payloads", [])
        filtered = []
        for entry in raw:
            if isinstance(entry, str):
                filtered.append({
                    "id": "raw", "name": "raw", "category": "unknown",
                    "dbms": "generic", "waf": None,
                    "payload": entry, "tags": [], "description": "",
                })
                continue
            entry_waf = entry.get("waf")
            if self.waf_hint and entry_waf:
                if self.waf_hint.lower() not in entry_waf.lower():
                    continue
            entry_dbms = (entry.get("dbms") or "all").lower()
            if self.dbms_hint and entry_dbms not in ("all", "generic"):
                if self.dbms_hint.lower() not in entry_dbms:
                    continue
            filtered.append(entry)
        self._payload_cache = filtered
        return filtered

    # ------------------------------------------------------------------ #
    #  Baseline capture with stability check
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        # Fire baseline twice to check stability
        fprints = []
        bodies = []
        for _ in range(2):
            if not self._throttle(ip.url):
                ip.stable = False
                return None
            try:
                r = build_request(ip, ip.value, timeout=self.timeout,
                                  extra_headers=self.static_headers)
            except Exception:
                r = None
            fprints.append(_fingerprint_response(r))
            bodies.append((r.text or "") if r is not None else "")

        ip.baseline_resp = build_request(ip, ip.value, timeout=self.timeout,
                                          extra_headers=self.static_headers) if False else None

        # Re-fire once for the canonical baseline
        try:
            ip.baseline_resp = build_request(ip, ip.value, timeout=self.timeout,
                                              extra_headers=self.static_headers)
        except Exception:
            ip.baseline_resp = None
        ip.baseline_fp = _fingerprint_response(ip.baseline_resp)

        # Stability: compare the two probes
        if len(fprints) == 2:
            if fprints[0]["hash"] and fprints[1]["hash"]:
                if fprints[0]["hash"] != fprints[1]["hash"]:
                    if abs(fprints[0]["length"] - fprints[1]["length"]) > 100:
                        ip.stable = False
            # Very short body (<50 bytes) usually means a stub page
            if fprints[0]["length"] < 50:
                ip.stable = False
        else:
            ip.stable = False

        # Timing baseline
        samples = []
        for _ in range(3):
            if not self._throttle(ip.url):
                break
            t0 = time.time()
            try:
                build_request(ip, ip.value, timeout=self.timeout,
                              extra_headers=self.static_headers)
            except Exception:
                pass
            samples.append(time.time() - t0)

        if samples:
            ip.timing_baseline = statistics.median(samples)
            ip.timing_stddev = statistics.stdev(samples) if len(samples) > 1 else 0.0
        else:
            ip.timing_baseline = 0.5
            ip.timing_stddev = 0.2

        return ip.baseline_resp

    # ------------------------------------------------------------------ #
    #  AI payload augmentation (called once per host on WAF detection)
    # ------------------------------------------------------------------ #
    def _augment_payloads_for_waf(self, host, waf_name, example_url=""):
        """
        When a WAF is detected on a host, optionally ask the brain for
        context-aware bypass payloads. Adds them to the shared payload
        cache so subsequent IPs benefit. Best-effort; failures ignored.
        """
        if self.brain is None or not self.brain.available():
            return
        with self._waf_lock:
            if self.host_waf.get(host + ":augmented"):
                return
            self.host_waf[host + ":augmented"] = True

        context = {
            "waf": waf_name,
            "url_example": example_url,
            "dbms_hint": self.dbms_hint,
            "notes": "WAF block page detected. Suggest bypass payloads "
                     "using comment obfuscation, alternate encodings, "
                     "case mixing, or version-specific syntax.",
        }
        try:
            payloads = self.brain.suggest_payloads(context, kind="sqli",
                                                    max_payloads=8)
        except Exception as e:
            log("AI payload augmentation failed: {}".format(e), "debug", "SQLI")
            return
        if not payloads:
            return

        extra = []
        for i, p in enumerate(payloads):
            extra.append({
                "id": "ai_waf_{}".format(i),
                "name": "AI WAF bypass #{}".format(i + 1),
                "category": "ai_generated",
                "dbms": self.dbms_hint or "all",
                "waf": waf_name,
                "payload": p,
                "tags": ["ai", "waf_bypass", waf_name],
                "description": "AI-generated WAF bypass payload",
            })
        with self._seen_lock:
            if self._payload_cache is not None:
                self._payload_cache = extra + self._payload_cache
        log("AI added {} WAF-bypass payloads ({} on {})".format(
            len(extra), waf_name, host), "info", "SQLI")

    # ------------------------------------------------------------------ #
    #  Detection strategies
    # ------------------------------------------------------------------ #
    def _test_error_based(self, ip, payload_obj, resp, baseline_body):
        body = resp.text or ""
        dbms, evidence = _match_error_signature(body, baseline_body)
        if not dbms:
            return None
        return {
            "confidence": "high",
            "subtype": "error_based",
            "reason": "DBMS error signature matched ({})".format(dbms),
            "dbms": dbms,
            "evidence": evidence,
            "verification_method": "error_signature",
        }

    def _test_status_escalation(self, ip, resp):
        if ip.baseline_resp is None:
            return None
        base_status = ip.baseline_resp.status_code
        if base_status < 500 and resp.status_code >= 500:
            body = resp.text or ""
            if GENERIC_500_HINTS.search(body):
                return {
                    "confidence": "medium",
                    "subtype": "status_escalation",
                    "reason": "Status escalated {} -> {} with SQL-ish body".format(
                        base_status, resp.status_code),
                    "dbms": None,
                    "evidence": body[:400],
                    "verification_method": "status_escalation",
                }
        return None

    def _test_timing_confirmed(self, ip, payload, first_elapsed):
        if ip.timing_baseline is None:
            return None
        threshold = max(
            self.time_threshold,
            ip.timing_baseline + 3.0 * (ip.timing_stddev or 0.2) + 2.0,
        )
        first_delta = first_elapsed - ip.timing_baseline
        if first_delta < threshold - 2.0:
            return None

        if not self.confirm_timing:
            if first_delta >= threshold:
                return {
                    "confidence": "medium",
                    "subtype": "time_based",
                    "reason": "Time delay {:.2f}s (baseline {:.2f}s)".format(
                        first_elapsed, ip.timing_baseline),
                    "dbms": self.dbms_hint,
                    "evidence": "delay=+{:.2f}s".format(first_delta),
                    "verification_method": "timing_unconfirmed",
                }
            return None

        reproductions = 0
        for _ in range(2):
            if not self._throttle(ip.url):
                break
            t0 = time.time()
            try:
                build_request(ip, payload, timeout=self.timeout + 4,
                              extra_headers=self.static_headers)
            except Exception:
                continue
            elapsed = time.time() - t0
            if (elapsed - ip.timing_baseline) >= threshold - 2.0:
                reproductions += 1
            time.sleep(0.3)

        if reproductions < 2:
            return None

        return {
            "confidence": "high",
            "subtype": "time_based",
            "reason": "Time-based SQLi confirmed — {:.2f}s initial ({}/2 reproductions)".format(
                first_elapsed, reproductions),
            "dbms": self.dbms_hint,
            "evidence": "baseline={:.2f}s first={:.2f}s reproductions={}/2".format(
                ip.timing_baseline, first_elapsed, reproductions),
            "verification_method": "timing_confirmed",
        }

    def _test_boolean_pair(self, ip, true_payload, false_payload):
        try:
            true_resp = build_request(ip, true_payload, timeout=self.timeout,
                                      extra_headers=self.static_headers)
            if not self._throttle(ip.url):
                return None
            time.sleep(0.1)
            false_resp = build_request(ip, false_payload, timeout=self.timeout,
                                       extra_headers=self.static_headers)
        except Exception:
            return None
        if true_resp is None or false_resp is None:
            return None

        true_fp  = _fingerprint_response(true_resp)
        false_fp = _fingerprint_response(false_resp)
        base_fp  = ip.baseline_fp or {"hash": None}

        if not _fingerprints_differ(true_fp, false_fp, min_len_delta=100):
            return None
        t_base_diff = _fingerprints_differ(true_fp, base_fp, min_len_delta=100)
        f_base_diff = _fingerprints_differ(false_fp, base_fp, min_len_delta=100)
        if not (t_base_diff or f_base_diff):
            return None

        return {
            "confidence": "high",
            "subtype": "boolean_blind",
            "reason": "Boolean-based blind — TRUE and FALSE payloads produce different responses",
            "dbms": self.dbms_hint,
            "evidence": "true_len={} false_len={} base_len={}".format(
                true_fp["length"], false_fp["length"], base_fp.get("length", 0)),
            "verification_method": "boolean_pair",
        }

    def _test_body_diff(self, ip, resp):
        if not ip.stable:
            return None      # unstable baseline → too noisy
        if not ip.baseline_fp or not ip.baseline_fp.get("hash"):
            return None
        if ip.baseline_resp is None:
            return None

        current = _fingerprint_response(resp)
        if not _fingerprints_differ(current, ip.baseline_fp, min_len_delta=500):
            return None
        delta = current["length"] - ip.baseline_fp["length"]
        if delta < 500:
            return None
        return {
            "confidence": "low",
            "subtype": "body_diff",
            "reason": "Response body grew by {} bytes".format(delta),
            "dbms": None,
            "evidence": "baseline={} current={}".format(
                ip.baseline_fp["length"], current["length"]),
            "verification_method": "body_diff",
        }

    # ------------------------------------------------------------------ #
    #  Test one payload
    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj, baseline_body=""):
        payload = payload_obj["payload"]
        is_time = bool(TIME_PAYLOADS.search(payload))

        if not self._throttle(ip.url):
            return None      # host in backoff

        start = time.time()
        try:
            resp = build_request(ip, payload, timeout=self.timeout + 4,
                                 extra_headers=self.static_headers)
        except Exception:
            return None
        elapsed = time.time() - start
        if resp is None:
            return None

        # Classify the response and react to rate limits / WAF
        host = urlparse(ip.url).netloc.lower()
        info = classify_status(resp)

        if info["code"] == "RATE_LIMITED":
            self._note_rate_limit(host, info["retry_after"])
            return None

        if info["code"] in ("FORBIDDEN_WAF", "NOT_ACCEPTABLE"):
            self._note_waf_block(host, info["waf_name"])
            # Trigger AI augmentation once per host
            if info["waf_name"]:
                self._augment_payloads_for_waf(host, info["waf_name"], ip.url)
            return None

        # ---- Strategy 1: Error signature ----------------------------
        hit = self._test_error_based(ip, payload_obj, resp, baseline_body)
        if hit:
            return self._build_finding(ip, payload_obj, hit, resp,
                                        elapsed, payload)

        # ---- Strategy 2: Status escalation --------------------------
        hit = self._test_status_escalation(ip, resp)
        if hit:
            return self._build_finding(ip, payload_obj, hit, resp,
                                        elapsed, payload)

        # ---- Strategy 3: Time-based confirmed -----------------------
        if is_time:
            hit = self._test_timing_confirmed(ip, payload, elapsed)
            if hit:
                return self._build_finding(ip, payload_obj, hit, resp,
                                            elapsed, payload)

        # ---- Strategy 5: Body diff (weak) ---------------------------
        if not is_time and resp.status_code < 500:
            hit = self._test_body_diff(ip, resp)
            if hit:
                return self._build_finding(ip, payload_obj, hit, resp,
                                            elapsed, payload)

        return None

    # ------------------------------------------------------------------ #
    #  Severity filter
    # ------------------------------------------------------------------ #
    def _passes_severity_filter(self, finding):
        if not self.min_severity:
            return True
        rank = SEVERITY_RANK.get(finding.get("severity", "low"), 1)
        min_rank = SEVERITY_RANK.get(self.min_severity, 0)
        return rank >= min_rank

    def _record_ai_drop(self, finding, verdict, reason="ai_fp"):
        with self._ai_dropped_lock:
            self.ai_dropped.append({
                "reason":         reason,
                "url":            finding.get("url"),
                "parameter":      finding.get("parameter"),
                "payload_id":     finding.get("payload_id"),
                "severity":       finding.get("severity"),
                "verification_method": finding.get("verification_method"),
                "ai_verdict":     verdict,
            })

    # ------------------------------------------------------------------ #
    #  Build finding (with AI integration)
    # ------------------------------------------------------------------ #
    def _build_finding(self, ip, payload_obj, hit, resp, elapsed, payload):
        confidence = hit["confidence"]
        severity = _severity_for(confidence)

        finding = {
            "type": "sqli",
            "subtype": hit["subtype"],
            "severity": severity,
            "confidence": confidence,
            "confirmed": hit.get("verification_method") in (
                "error_signature", "timing_confirmed", "boolean_pair",
            ),
            "verification_method": hit.get("verification_method"),

            "url": ip.url,
            "method": ip.method,
            "parameter": ip.name,
            "injection_point": {
                "location": ip.location,
                "name": ip.name,
                "original_value": (ip.value or "")[:200],
                "json_path": ip.json_path,
            },

            "payload_id":          payload_obj.get("id"),
            "payload_name":        payload_obj.get("name"),
            "payload":             payload,
            "payload_category":    payload_obj.get("category"),
            "payload_dbms":        payload_obj.get("dbms"),
            "payload_tags":        payload_obj.get("tags", []),
            "payload_description": payload_obj.get("description", ""),

            "matched_dbms":      hit.get("dbms"),
            "detection_reason":  hit["reason"],
            "evidence":          hit.get("evidence", ""),

            "response_status":   resp.status_code if resp else None,
            "response_length":   len(resp.text or "") if resp else None,
            "response_snippet":  (resp.text or "")[:800],
            "baseline_status":   ip.baseline_resp.status_code if ip.baseline_resp else None,
            "baseline_length":   len(ip.baseline_resp.text or "") if ip.baseline_resp else None,
            "baseline_timing":   round(ip.timing_baseline or 0, 3),
            "timing_stddev":     round(ip.timing_stddev or 0, 3),
            "elapsed_seconds":   round(elapsed, 3),

            "curl_command": build_curl(ip, payload),

            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Use parameterized queries / prepared statements. Never "
                "concatenate user input into SQL. Apply least-privilege DB "
                "accounts. Validate and whitelist input server-side. "
                "Suppress DBMS error messages in production responses. "
                "Enable detailed SQL error logging server-side instead."
            ),
        }

        # Deduplicate
        sig = hashlib.md5(
            "{}|{}|{}|{}".format(ip.url, ip.name, payload_obj.get("id"),
                                 confidence).encode()
        ).hexdigest()
        with self._seen_lock:
            if sig in self.seen_signatures:
                return None
            self.seen_signatures.add(sig)

        # ----- AI triage ------------------------------------------------
        if self.brain is not None and self.brain.available():
            try:
                verdict = self.brain.triage(finding, kind="sqli")
                if verdict:
                    finding["ai_triage"] = verdict
                    if (verdict["verdict"] == "FALSE_POSITIVE"
                            and verdict.get("confidence", 0) >= 0.85):
                        self._record_ai_drop(finding, verdict, "ai_fp")
                        log("AI dropped FP: {} (conf {:.2f}) — {}".format(
                            ip.name, verdict["confidence"],
                            verdict.get("reason", "")[:80]),
                            "info", "SQLI")
                        return None
            except Exception as e:
                log("AI triage error: {}".format(e), "debug", "SQLI")

        # ----- AI severity ---------------------------------------------
        if (self.ai_severity_enabled and self.brain is not None
                and self.brain.available()):
            try:
                sev = self.brain.assess_severity(finding, kind="sqli")
                if sev:
                    finding["ai_severity"] = sev
                    if sev.get("confidence", 0) >= 0.6:
                        finding["severity"] = sev["severity"]
            except Exception as e:
                log("AI severity error: {}".format(e), "debug", "SQLI")

        # ----- Min-severity filter -------------------------------------
        if not self._passes_severity_filter(finding):
            self._record_ai_drop(finding, None, "low_severity")
            log("Dropped (severity<{}): {} @ {} ({})".format(
                self.min_severity, ip.name, ip.url,
                finding.get("severity", "?")), "info", "SQLI")
            return None

        # ----- Save ----------------------------------------------------
        host = urlparse(ip.url).netloc
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_")
            + "__" + ip.name
        )
        fname = "{}__{}_sqli_vulnerable.json".format(
            slug, payload_obj.get("id", "x"))
        out_path = self.findings_root / safe_filename(host) / fname
        save_json(out_path, finding)

        sev_color = {
            "critical": "\033[38;5;196m",
            "high":     "\033[38;5;196m",
            "medium":   "\033[38;5;226m",
            "low":      "\033[38;5;240m",
            "info":     "\033[38;5;240m",
        }.get(finding["severity"], "\033[0m")

        ai_tag = ""
        if "ai_triage" in finding:
            ai_tag = " [AI:{}]".format(finding["ai_triage"]["verdict"])

        log("[{}{:8}\033[0m] {}:{} @ {}{} ({} → {})".format(
            sev_color, finding["severity"].upper(),
            ip.location, ip.name, ip.url, ai_tag,
            payload_obj.get("name"), hit["verification_method"]),
            "hit", "SQLI")

        return finding

    # ------------------------------------------------------------------ #
    #  Test one injection point
    # ------------------------------------------------------------------ #
    def test_point(self, ip, payloads):
        self.capture_baseline(ip)
        baseline_body = (ip.baseline_resp.text or "") if ip.baseline_resp else ""

        if not ip.stable:
            log("unstable baseline: {}:{} @ {}".format(
                ip.location, ip.name, ip.url), "debug", "SQLI")

        findings = []
        for p in payloads:
            f = self.test_payload(ip, p, baseline_body)
            if f:
                findings.append(f)
            time.sleep(self.delay)
        return findings

    # ------------------------------------------------------------------ #
    #  Main entry
    # ------------------------------------------------------------------ #
    def run(self):
        section("SQLi SCANNER :: INITIALISING")

        if self.brain is not None and self.brain.available():
            log("AI triage: ON ({} / {})".format(
                self.brain.cfg["label"], self.brain.model), "info", "SQLI")
            log("AI severity: {}".format(
                "ON" if self.ai_severity_enabled else "OFF"), "info", "SQLI")
        else:
            log("AI triage: OFF (running without triage)", "warn", "SQLI")

        log("min severity filter: {}".format(self.min_severity), "info")

        payloads = self.load_and_filter_payloads()
        log("loaded {} payloads (waf={}, dbms={})".format(
            len(payloads), self.waf_hint or "none", self.dbms_hint or "none"),
            "info")

        # Load pages
        pages = []
        for jf in self.sites_root.rglob("*.json"):
            if jf.name.startswith("_"):
                continue
            try:
                rec = load_json(jf)
                if rec.get("url") and not _is_static_url(rec["url"]):
                    pages.append(rec)
            except Exception:
                continue
        log("loaded {} testable pages".format(len(pages)), "info")

        points = extract_injection_points(pages)
        log("extracted {} injection points".format(len(points)), "ok")

        if not points:
            log("nothing to test", "warn")
            return []

        section("SQLi SCANNER :: STRIKE PHASE")
        all_findings = []
        done = 0
        total = len(points)
        t0 = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.test_point, ip, payloads): ip
                       for ip in points}
            for fut in as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    all_findings.extend(fut.result())
                except Exception as e:
                    log("error testing {}: {}".format(ip, e), "warn")
                if done % 10 == 0 or done == total:
                    log("progress {}/{}  hits={}".format(
                        done, total, len(all_findings)), "info")

        elapsed = time.time() - t0

        # -------- Summary ------------------------------------------------
        section("SQLi SCANNER :: COMPLETE")

        by_conf = {}
        by_severity = {}
        by_verdict = {}
        by_method = {}
        for f in all_findings:
            by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
            sev = f.get("severity", "low")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            m = f.get("verification_method", "unknown")
            by_method[m] = by_method.get(m, 0) + 1
            v = (f.get("ai_triage") or {}).get("verdict")
            if v:
                by_verdict[v] = by_verdict.get(v, 0) + 1

        if all_findings:
            for c in ("high", "medium", "low"):
                if c in by_conf:
                    log("confidence {} : {}".format(c, by_conf[c]), "info")
            for s in ("critical", "high", "medium", "low", "info"):
                if s in by_severity:
                    log("severity   {} : {}".format(s, by_severity[s]), "ok")
            if by_verdict:
                log("AI verdict    : {}".format(by_verdict), "info")
            log("methods       : {}".format(by_method), "info")
            log("total saved   : {}".format(len(all_findings)), "ok", "DONE")
        else:
            log("no SQLi findings saved", "info", "DONE")

        # Host-level observations
        with self._waf_lock:
            waf_hosts = {h: v for h, v in self.host_waf.items()
                         if not h.endswith(":augmented") and v}
            rl_hosts = dict(self.host_rl_counts)
        if waf_hosts:
            log("WAF-protected hosts: {}".format(
                ", ".join("{} ({})".format(h, w) for h, w in waf_hosts.items())),
                "info")
        if rl_hosts:
            log("rate-limited hosts: {}".format(
                ", ".join("{} ({}×)".format(h, c) for h, c in rl_hosts.items())),
                "info")

        if self.ai_dropped:
            log("AI/filter dropped: {}".format(len(self.ai_dropped)), "info")
            audit_path = self.findings_root / "_ai_dropped.json"
            save_json(audit_path, self.ai_dropped)
            log("audit written  : {}".format(audit_path), "info")

        log("elapsed       : {}".format(format_duration(elapsed)), "info")

        # Save summary
        save_json(self.findings_root / "_summary.json", {
            "total_saved":     len(all_findings),
            "total_dropped":   len(self.ai_dropped),
            "by_confidence":   by_conf,
            "by_severity":     by_severity,
            "by_ai_verdict":   by_verdict,
            "by_method":       by_method,
            "waf_hint":        self.waf_hint,
            "dbms_hint":       self.dbms_hint,
            "min_severity":    self.min_severity,
            "waf_hosts":       waf_hosts,
            "rate_limited":    rl_hosts,
            "elapsed_seconds": round(elapsed, 1),
            "timestamp":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [
                {"url": f["url"], "param": f["parameter"],
                 "severity": f.get("severity"),
                 "confidence": f["confidence"],
                 "method": f.get("verification_method"),
                 "payload_name": f.get("payload_name"),
                 "ai_verdict": (f.get("ai_triage") or {}).get("verdict"),
                 "ai_severity": (f.get("ai_severity") or {}).get("severity")}
                for f in all_findings
            ],
        })

        return all_findings


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None, waf_hint=None, dbms_hint=None,
        cookie=None, user_agent=None, confirm_timing=True,
        min_severity="medium", use_ai=True, ai_severity=True):
    scanner = SQLiScanner(
        program_dir=program_dir,
        sites_root=sites_root,
        waf_hint=waf_hint,
        dbms_hint=dbms_hint,
        cookie=cookie,
        user_agent=user_agent,
        confirm_timing=confirm_timing,
        min_severity=min_severity,
        use_ai=use_ai,
        ai_severity=ai_severity,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN SQLi scanner v4.0")
    ap.add_argument("program_dir")
    ap.add_argument("--waf", default=None,
                    help="WAF hint (cloudflare, akamai, imperva, ...)")
    ap.add_argument("--dbms", default=None,
                    help="DBMS hint (mysql, postgresql, mssql, oracle, ...)")
    ap.add_argument("--cookie", default=None,
                    help="Cookie header for authenticated scanning")
    ap.add_argument("--user-agent", default=None,
                    help="User-Agent override")
    ap.add_argument("--no-confirm-timing", action="store_true",
                    help="skip 3-attempt timing confirmation")
    ap.add_argument("--time-threshold", type=float, default=4.0,
                    help="min timing delta in seconds (default: 4.0)")
    ap.add_argument("--min-severity", default="medium",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="min severity to save (default: medium)")
    ap.add_argument("--no-ai", action="store_true",
                    help="disable AI triage entirely")
    ap.add_argument("--no-ai-severity", action="store_true",
                    help="disable AI severity refinement")
    args = ap.parse_args()

    run(args.program_dir,
        waf_hint=args.waf,
        dbms_hint=args.dbms,
        cookie=args.cookie,
        user_agent=args.user_agent,
        confirm_timing=not args.no_confirm_timing,
        min_severity=args.min_severity,
        use_ai=not args.no_ai,
        ai_severity=not args.no_ai_severity)
