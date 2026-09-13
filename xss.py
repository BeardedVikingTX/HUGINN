#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: xss.py
#  The Ultimate Cross-Site Scripting Scanner — 2026 Edition
# -----------------------------------------------------------------------------
#  Detection pipeline:
#    1. Send a marker into every injectable parameter
#    2. Detect where it reflected (HTML body / attr / JS string / CSS / etc.)
#    3. Dispatch only payloads whose context matches (plus polyglots)
#    4. For each payload, verify via:
#         · payload_survival   — payload survives unmodified in a live context
#         · dangerous_markup   — <script>, onerror=, javascript:, etc. present
#         · oob_callback       — token appears in oast.beardedviking.org check
#         · browser_dialog     — Playwright observed alert/confirm/prompt
#    5. Emit a fully self-contained finding with cURL for reproduction
#
#  Injection transports:
#    · Query params · POST form bodies · JSON bodies · Cookies · Headers
#    · Path segments · HTTP parameter pollution
# =============================================================================

import re
import json
import time
import uuid
import shlex
import hashlib
import threading
from pathlib import Path
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, load_json, save_json, load_payloads, send_request,
    safe_filename, C,
    random_token, build_oob_url,        # per-payload OOB URL builder
)

try:
    import requests
except ImportError:
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# =============================================================================
#  CONSTANTS
# =============================================================================

DEFAULT_ATTACKER = "beardedviking.org"
DEFAULT_COLLAB   = "oast.beardedviking.org"
DEFAULT_ALERT    = "alert(document.domain)"

# Dangerous patterns — presence in body (unescaped) is a strong indicator
DANGEROUS_PATTERNS = [
    (re.compile(r"<script[\s>]", re.I), "script_tag"),
    (re.compile(r"</script\s*>", re.I), "script_close"),
    (re.compile(r"\bon[a-z]+\s*=\s*(?:[\"'])?[^\s>]+", re.I), "event_handler"),
    (re.compile(r"(?:href|src|action|data|formaction)\s*=\s*[\"']?\s*javascript:",
                re.I), "javascript_uri"),
    (re.compile(r"[\"']\s*javascript\s*:", re.I), "javascript_uri_quoted"),
    (re.compile(r"<svg[^>]*onload\s*=", re.I), "svg_onload"),
    (re.compile(r"<svg[^>]*>", re.I), "svg_tag"),
    (re.compile(r"<math[^>]*>", re.I), "mathml_tag"),
    (re.compile(r"(?:href|src|action)\s*=\s*[\"']?\s*data:text/html",
                re.I), "data_html_uri"),
    (re.compile(r"<(?:iframe|object|embed|meta)[\s>]", re.I), "dangerous_tag"),
    (re.compile(r"\{\{[^}]*(?:constructor|eval|alert|onerror)[^}]*\}\}",
                re.I), "template_injection"),
]

# Event handler names commonly used in XSS
EVENT_HANDLER_NAMES = {
    "onerror", "onload", "onclick", "onmouseover", "onmouseenter",
    "onfocus", "onblur", "onsubmit", "onchange", "oninput",
    "onanimationstart", "onanimationend", "onbegin", "ontoggle",
    "onpopstate", "onhashchange", "onpageshow", "onfocusin",
    "onpointerover", "oncontentvisibilityautostatechange",
    "onbeforetoggle", "onbeforematch", "onreadystatechange", "onscroll",
}

# Context families for payload routing
ATTR_FAMILY   = {"attribute_double", "attribute_single", "attribute_unquoted"}
JS_STR_FAMILY = {"js_string_single", "js_string_double", "js_string_template"}

# Categories that always apply regardless of context
UNIVERSAL_CATEGORIES = {"polyglots"}

# Categories that only make sense with certain transports
FILE_UPLOAD_CATEGORY = "file_upload"
HEADER_CATEGORY      = "header_injection"

# Contexts that can't be injected into
SAFE_CONTEXTS = {"not_reflected", "unknown_encoded"}


# =============================================================================
#  HELPERS
# =============================================================================
def _substitute(payload, attacker, alert_payload, target):
    """Fallback substitution for non-OOB placeholders."""
    return (payload
            .replace("{{ATTACKER}}", attacker)
            .replace("{{TARGET}}", target)
            .replace("{{ALERT}}", alert_payload))


def _make_marker():
    """Unique marker unlikely to appear naturally in a response."""
    return f"HU9INN_{uuid.uuid4().hex[:12]}_MARK"


def _count_unescaped(text, char):
    """Count occurrences of `char` not preceded by a backslash."""
    n = 0
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == char:
            n += 1
        i += 1
    return n


def _find_marker(body, marker):
    """Locate the marker in the body. Returns (index, encoding, snippet)."""
    if not body or not marker:
        return -1, None, ""

    idx = body.find(marker)
    if idx != -1:
        return idx, "raw", body[max(0, idx - 80): idx + len(marker) + 80]

    encoded_forms = [
        marker.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
        marker.replace("<", "&#60;").replace(">", "&#62;"),
        marker.replace("<", "&#x3c;").replace(">", "&#x3e;"),
    ]
    for form in encoded_forms:
        idx = body.find(form)
        if idx != -1:
            return idx, "html_encoded", body[max(0, idx - 80): idx + len(form) + 80]

    url_enc = quote(marker, safe="")
    idx = body.find(url_enc)
    if idx != -1:
        return idx, "url_encoded", body[max(0, idx - 80): idx + len(url_enc) + 80]

    return -1, None, ""


def _response_snippet(body, needle, window=160):
    """Return a ~320 char window around the first occurrence of `needle`."""
    if not body or not needle:
        return ""
    idx = body.find(needle)
    if idx == -1:
        return body[:window * 2]
    return body[max(0, idx - window): idx + len(needle) + window]


# =============================================================================
#  CONTEXT DETECTION
# =============================================================================
def detect_context(html, marker_idx):
    if marker_idx < 0:
        return "not_reflected"

    before = html[:marker_idx].lower()
    before_orig = html[:marker_idx]

    # HTML comment
    if before.rfind("<!--") > before.rfind("-->"):
        return "html_comment"

    # <script> block
    last_script_open  = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        js_before = before_orig[last_script_open + len("<script"):]
        gt_idx = js_before.find(">")
        if gt_idx != -1:
            js_before = js_before[gt_idx + 1:]
        return _classify_js_context(js_before)

    # <style> block
    if before.rfind("<style") > before.rfind("</style"):
        return "css"

    # <textarea>
    if before.rfind("<textarea") > before.rfind("</textarea"):
        return "textarea"

    # <title>
    if before.rfind("<title") > before.rfind("</title"):
        return "title"

    # <noscript>
    if before.rfind("<noscript") > before.rfind("</noscript"):
        return "noscript"

    # Inside a tag (attribute context)
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        return _classify_attribute_context(before_orig[last_lt:])

    return "html_body"


def _classify_js_context(js_before):
    single = _count_unescaped(js_before, "'")
    double = _count_unescaped(js_before, '"')
    tick   = _count_unescaped(js_before, "`")

    if tick % 2 == 1:
        return "js_string_template"
    if single % 2 == 1 and double % 2 == 0:
        return "js_string_single"
    if double % 2 == 1 and single % 2 == 0:
        return "js_string_double"
    if single % 2 == 1 and double % 2 == 1:
        last_sq = js_before.rfind("'")
        last_dq = js_before.rfind('"')
        return "js_string_single" if last_sq > last_dq else "js_string_double"
    return "js_code"


def _classify_attribute_context(tag_fragment):
    last_eq = tag_fragment.rfind("=")
    if last_eq == -1:
        return "attribute_unquoted"
    rest = tag_fragment[last_eq + 1:]
    if not rest:
        return "attribute_unquoted"
    first = rest.lstrip()[:1]
    if first == '"':  return "attribute_double"
    if first == "'":  return "attribute_single"
    return "attribute_unquoted"


# =============================================================================
#  DANGEROUS MARKUP ANALYSIS
# =============================================================================
def detect_dangerous_markup(body):
    if not body:
        return []
    hits, seen = [], set()
    for regex, name in DANGEROUS_PATTERNS:
        m = regex.search(body)
        if m and name not in seen:
            seen.add(name)
            hits.append({"pattern": name, "match": m.group(0)[:120]})
    return hits


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "json_body", "form_data", "extra_headers",
                 "baseline_resp", "reflection")

    def __init__(self, url, method, location, name, value,
                 json_path=None, json_body=None, form_data=None,
                 extra_headers=None):
        self.url = url
        self.method = method
        self.location = location
        self.name = name
        self.value = value
        self.json_path = json_path
        self.json_body = json_body
        self.form_data = form_data
        self.extra_headers = extra_headers or {}
        self.baseline_resp = None
        self.reflection = None

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        return f"<IP {self.location}:{self.name} @ {self.method} {self.url}>"


# =============================================================================
#  INJECTION POINT EXTRACTION
# =============================================================================
def _extract_query_params(page):
    p = urlparse(page["url"])
    if not p.query:
        return []
    qs = parse_qs(p.query, keep_blank_values=True)
    return [InjectionPoint(page["url"], "GET", "query", k, v[0])
            for k, v in qs.items()]


def _extract_path_segments(page):
    p = urlparse(page["url"])
    segs = [s for s in p.path.split("/") if s]
    if not segs:
        return []
    return [InjectionPoint(page["url"], "GET", "path",
                           f"segment[{i}]", seg,
                           extra_headers={"_segment_index": str(i)})
            for i, seg in enumerate(segs)]


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
        data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            if inp.has_attr("type") and inp["type"].lower() in ("submit", "button"):
                continue
            data[name] = inp.get("value") or ""
        for name, value in data.items():
            points.append(InjectionPoint(
                action_url, method, "body_form", name, value,
                form_data=dict(data),
            ))
    return points


def _extract_headers(page):
    headers = ["Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
               "X-Real-IP", "Origin", "X-Original-URL"]
    return [InjectionPoint(page["url"], "GET", "header", h, "")
            for h in headers]


def _extract_cookies(page):
    hdrs = page.get("headers") or {}
    sc = hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or ""
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
            ))

    walk(body)
    return points


def extract_injection_points(pages):
    points, seen = [], set()
    for page in pages:
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
#  REQUEST BUILDER + CURL GENERATOR
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
                  allow_redirects=True):
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
        body = dict(ip.form_data or {})
        body[ip.name] = payload
        if method == "GET":
            p = urlparse(url)
            url = urlunparse(p._replace(query=urlencode(body, doseq=True)))
        else:
            data = body
            headers.setdefault("Content-Type",
                               "application/x-www-form-urlencoded")

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        data = json.dumps(body)
        headers.setdefault("Content-Type", "application/json")

    elif ip.location == "cookie":
        existing = headers.get("Cookie", "")
        pair = f"{ip.name}={payload}"
        headers["Cookie"] = f"{existing}; {pair}".strip("; ") if existing else pair

    elif ip.location == "header":
        headers[ip.name] = payload

    return send_request(url, method=method, headers=headers,
                        timeout=timeout, allow_redirects=allow_redirects,
                        data=data)


def build_curl(ip, payload, timeout=15):
    """
    Build a copy-pasteable cURL command that reproduces the finding.
    Uses shlex.quote() for shell safety; the URL is already percent-encoded.
    """
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
        body = dict(ip.form_data or {})
        body[ip.name] = payload
        if ip.method == "GET":
            p = urlparse(ip.url)
            url = urlunparse(p._replace(query=urlencode(body, doseq=True)))
            parts.append(shlex.quote(url))
        else:
            parts.extend(["-X", "POST"])
            for k, v in body.items():
                parts.extend(["--data-urlencode", shlex.quote(f"{k}={v}")])
            parts.append(shlex.quote(ip.url))

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts.extend(["-X", "POST"])
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(json.dumps(body))])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "cookie":
        parts.extend(["-H", shlex.quote(f"Cookie: {ip.name}={payload}")])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "header":
        parts.extend(["-H", shlex.quote(f"{ip.name}: {payload}")])
        parts.append(shlex.quote(ip.url))

    else:
        parts.append(shlex.quote(ip.url))

    return " ".join(parts)


# =============================================================================
#  OOB POLLERS — LOCAL FILE + REMOTE CHECK.PHP
# =============================================================================
class LocalOOBPoller:
    """Watches a local file for huginn-<token> lines."""

    def __init__(self, log_file, poll_interval=2.0, timeout=120.0):
        self.log_file = Path(log_file)
        self.poll_interval = poll_interval
        self.timeout = timeout
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
                    for m in re.finditer(r"huginn-([a-f0-9]{16,32})", content):
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


class RemoteOOBPoller:
    """
    Polls https://oast.beardedviking.org/check.php?list=1 for tokens.
    Preferred when running against shared hosting.
    """

    def __init__(self, base_url, poll_interval=4.0, timeout=180.0, verify=False):
        self.base_url = base_url.rstrip("/")
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.verify = verify
        self._seen = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if requests is None:
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
        endpoint = f"{self.base_url}/check.php?list=1"
        while not self._stop.is_set() and time.time() < deadline:
            try:
                r = requests.get(endpoint, timeout=6, verify=self.verify)
                if r.status_code == 200:
                    data = r.json()
                    toks = data.get("tokens", {})
                    if isinstance(toks, dict):
                        with self._lock:
                            for tok in toks.keys():
                                self._seen.add(tok.lower())
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


# =============================================================================
#  PLAYWRIGHT BROWSER VERIFICATION (optional)
# =============================================================================
def _verify_with_playwright(url, timeout_ms=6000):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    result = {"executed": False, "dialogs": [], "console": [], "url": url}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()

            def _on_dialog(dialog):
                result["executed"] = True
                result["dialogs"].append({
                    "type": dialog.type,
                    "message": dialog.message,
                })
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            def _on_console(msg):
                result["console"].append({"type": msg.type, "text": msg.text})

            page.on("dialog", _on_dialog)
            page.on("console", _on_console)

            try:
                page.goto(url, timeout=timeout_ms, wait_until="load")
                page.wait_for_timeout(400)
            except Exception:
                pass

            browser.close()
    except Exception:
        return None

    return result


# =============================================================================
#  SCANNER
# =============================================================================
class XSSScanner:

    def __init__(self,
                 program_dir,
                 sites_root=None,
                 attacker_domain=DEFAULT_ATTACKER,
                 collab_host=DEFAULT_COLLAB,
                 alert_payload=DEFAULT_ALERT,
                 target_domain=None,
                 max_workers=8,
                 delay=0.15,
                 timeout=12,
                 use_browser=False,
                 oob_log_file=None,
                 oob_base_url=None,
                 oob_timeout=120.0):
        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "xss"
        self.findings_root.mkdir(parents=True, exist_ok=True)

        self.attacker_domain = attacker_domain
        self.collab_host     = collab_host or DEFAULT_COLLAB
        self.alert_payload   = alert_payload
        self.target_domain   = target_domain or ""
        self.max_workers     = max_workers
        self.delay           = delay
        self.timeout         = timeout
        self.use_browser     = use_browser

        self.seen_signatures = set()
        self._payloads = None

        # ---- OOB poller selection ---------------------------------------
        self.oob_poller = None
        if oob_base_url:
            self.oob_poller = RemoteOOBPoller(oob_base_url, timeout=oob_timeout)
        elif oob_log_file:
            self.oob_poller = LocalOOBPoller(oob_log_file, timeout=oob_timeout)

    # ------------------------------------------------------------------ #
    #  Payload loading & per-payload OOB substitution
    # ------------------------------------------------------------------ #
    def load_payloads(self):
        data = load_payloads("xss")
        raw = data.get("payloads", [])
        ctx_target = self.target_domain or "target.invalid"
        out = []

        for entry in raw:
            if isinstance(entry, str):
                out.append({
                    "id": "raw", "name": "raw", "category": "unknown",
                    "context": "html_body",
                    "payload": _substitute(entry, self.attacker_domain,
                                           self.alert_payload, ctx_target),
                    "tags": [], "_token": None, "_oob_url": None,
                })
                continue

            entry = dict(entry)
            token    = random_token()
            hint     = entry.get("id", "xss")
            oob_url  = build_oob_url(self.collab_host, token,
                                     path_hint=hint, use_subdomain=False)
            oob_host = urlparse(oob_url).netloc
            oob_ws   = oob_url.replace("https://", "wss://")

            p = entry["payload"]
            p = (p.replace("{{OOB}}",      oob_url)
                  .replace("{{OOB_HOST}}", oob_host)
                  .replace("{{OOB_WS}}",   oob_ws))
            p = _substitute(p, self.attacker_domain,
                            self.alert_payload, ctx_target)

            entry["payload"]   = p
            entry["_token"]    = token
            entry["_oob_url"]  = oob_url
            out.append(entry)

        self._payloads = out
        return out

    # ------------------------------------------------------------------ #
    #  Payload routing
    # ------------------------------------------------------------------ #
    def filter_payloads_for_context(self, ctx, ip):
        """
        Two-stage filter: context must match AND transport must be capable.
        """
        if ctx in SAFE_CONTEXTS:
            return []

        selected = []
        for entry in self._payloads:
            category = entry.get("category", "")
            p_ctx    = entry.get("context", "")

            # ---- Transport filtering ------------------------------------
            # file_upload payloads only fire in file upload context;
            # sending them as a query param won't produce a result.
            if category == FILE_UPLOAD_CATEGORY:
                # Allow them against form fields (best-effort)
                if ip.location not in ("body_form", "body_json"):
                    continue

            # header_injection payloads are only worth sending against
            # header/cookie injection points (or as form values that
            # later get logged — allow form fields too)
            if category == HEADER_CATEGORY:
                if ip.location not in ("header", "cookie", "body_form",
                                       "body_json", "query"):
                    continue

            # ---- Context matching --------------------------------------
            if category in UNIVERSAL_CATEGORIES:
                selected.append(entry); continue

            if p_ctx == ctx:
                selected.append(entry); continue

            if p_ctx in ATTR_FAMILY and ctx in ATTR_FAMILY:
                selected.append(entry); continue

            if p_ctx in JS_STR_FAMILY and ctx in JS_STR_FAMILY:
                selected.append(entry); continue

            if ctx == "html_body" and p_ctx in ("html_body", "multi", "any", ""):
                selected.append(entry); continue

            if ctx.startswith("dom_") and p_ctx.startswith("dom_"):
                selected.append(entry); continue

            if ctx.startswith("csp_") and p_ctx.startswith("csp_"):
                selected.append(entry); continue

            # Blind payloads apply wherever a sink might render
            if category == "blind":
                selected.append(entry); continue

            # Encoding / WAF / filter bypass payloads apply broadly
            if category in ("encoding", "waf_bypass", "filter_bypass",
                            "context_breaks"):
                if ctx in ("html_body", "attribute_double", "attribute_single",
                           "attribute_unquoted", "js_code", "unknown"):
                    selected.append(entry); continue

            # CSTI / PP payloads are context-agnostic within their family
            if category in ("csti", "prototype_pollution"):
                if ctx in ("html_body", "attribute_double", "attribute_single",
                           "attribute_unquoted", "js_code", "unknown"):
                    selected.append(entry); continue

        return selected

    # ------------------------------------------------------------------ #
    #  Baseline + reflection probe
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        try:
            ip.baseline_resp = build_request(ip, ip.value, timeout=self.timeout)
        except Exception:
            ip.baseline_resp = None

    def probe_reflection(self, ip):
        marker = _make_marker()
        try:
            resp = build_request(ip, marker, timeout=self.timeout)
        except Exception:
            return None
        if resp is None:
            return None
        body = resp.text or ""
        idx, encoding, snippet = _find_marker(body, marker)
        if idx < 0:
            return None

        context = detect_context(body, idx) if encoding == "raw" else encoding
        ip.reflection = {
            "marker": marker,
            "encoding": encoding,
            "context": context,
            "snippet": snippet,
        }
        return ip.reflection

    # ------------------------------------------------------------------ #
    #  Verification
    # ------------------------------------------------------------------ #
    def _verify(self, ip, payload_obj, resp):
        """
        Multi-signal verification. Returns a hit dict or None.

        Priority order:
          1. payload_survival  — the exact payload appears unmodified
          2. dangerous_markup  — <script>, onerror=, javascript: present
          3. reflection        — raw chars survive in dangerous context
        """
        if resp is None:
            return None

        body = resp.text or ""
        payload = payload_obj["payload"]

        # ---- 1. Exact payload survival --------------------------------
        # Only check when the payload is fully present (some payloads get
        # partially mangled by the target's HTML rendering).
        # We trim trailing whitespace because some servers do.
        trimmed = payload.strip()
        if trimmed and trimmed in body:
            # Now check it landed in a dangerous context
            dangerous = detect_dangerous_markup(body)
            ctx = (ip.reflection or {}).get("context", "unknown")
            return {
                "verification_method": "payload_survival",
                "severity": "critical" if dangerous else "high",
                "reason": f"Payload survived unmodified in {ctx} context",
                "evidence": _response_snippet(body, trimmed),
                "dangerous": dangerous,
                "payload_found": True,
            }

        # ---- 2. Dangerous markup ---------------------------------------
        dangerous = detect_dangerous_markup(body)
        if dangerous:
            top_patterns = {d["pattern"] for d in dangerous}
            critical_set = {"script_tag", "javascript_uri",
                            "javascript_uri_quoted"}
            sev = "critical" if top_patterns & critical_set else "high"
            return {
                "verification_method": "dangerous_markup",
                "severity": sev,
                "reason": f"Dangerous markup present: {sorted(top_patterns)}",
                "evidence": dangerous[0]["match"],
                "dangerous": dangerous,
                "payload_found": False,
            }

        # ---- 3. Reflection heuristic -----------------------------------
        if ip.reflection:
            ctx = ip.reflection.get("context", "")
            enc = ip.reflection.get("encoding", "")
            if enc == "raw" and ctx in (ATTR_FAMILY | JS_STR_FAMILY |
                                        {"html_body"}):
                return {
                    "verification_method": "reflection",
                    "severity": "medium",
                    "reason": f"Raw chars reflect in {ctx} (no execution yet)",
                    "evidence": ip.reflection["snippet"][:200],
                    "dangerous": [],
                    "payload_found": False,
                }

        return None

    # ------------------------------------------------------------------ #
    #  Test one payload
    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj):
        try:
            resp = build_request(ip, payload_obj["payload"],
                                 timeout=self.timeout)
        except Exception:
            return None

        hit = self._verify(ip, payload_obj, resp)

        # OOB verification for blind payloads
        oob_confirmed = False
        if (not hit or hit.get("verification_method") != "payload_survival"):
            if (self.oob_poller and payload_obj.get("category") == "blind"
                    and payload_obj.get("_token")):
                # Give the target a moment to fire the callback
                time.sleep(0.4)
                if self.oob_poller.has_token(payload_obj["_token"]):
                    oob_confirmed = True
                    if not hit:
                        hit = {
                            "verification_method": "oob_callback",
                            "severity": "confirmed",
                            "reason": "Out-of-band callback received",
                            "evidence": payload_obj.get("_oob_url", ""),
                            "dangerous": [],
                            "payload_found": False,
                        }
                    else:
                        hit["verification_method"] = "oob_callback"
                        hit["severity"] = "confirmed"

        if not hit:
            return None

        return self._build_finding(ip, payload_obj, hit, resp,
                                   oob_confirmed=oob_confirmed)

    # ------------------------------------------------------------------ #
    #  Finding construction
    # ------------------------------------------------------------------ #
    def _build_finding(self, ip, payload_obj, hit, resp, browser_verified=None,
                       oob_confirmed=False):
        severity = hit["severity"]
        payload  = payload_obj["payload"]

        finding = {
            "type": "xss",
            "subtype": self._subtype(payload_obj),
            "severity": severity,
            "confirmed": hit.get("verification_method") in
                         ("payload_survival", "oob_callback", "browser_dialog"),
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
            "reflection": ip.reflection,

            "payload_id":          payload_obj.get("id"),
            "payload_name":        payload_obj.get("name"),
            "payload":             payload,
            "payload_category":    payload_obj.get("category"),
            "payload_context":     payload_obj.get("context"),
            "payload_tags":        payload_obj.get("tags", []),
            "payload_description": payload_obj.get("description", ""),
            "payload_references":  payload_obj.get("references", []),

            "detection_reason":  hit["reason"],
            "evidence":          hit.get("evidence", ""),
            "dangerous_markup":  hit.get("dangerous", []),
            "response_status":   resp.status_code if resp else None,
            "response_length":   len(resp.text or "") if resp else None,
            "response_snippet":  _response_snippet(resp.text or "",
                                                   payload[:40] if payload else ""),

            "curl_command": build_curl(ip, payload),

            "attacker_domain": self.attacker_domain,
            "collab_host":     self.collab_host,
            "target_domain":   self.target_domain,
            "oob_url":         payload_obj.get("_oob_url"),
            "oob_token":       payload_obj.get("_token"),
            "oob_confirmed":   oob_confirmed,
            "browser_verified": browser_verified,

            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Encode all user-controlled data on output according to the "
                "context it lands in (HTML body → HTML entity encoding; "
                "attribute → attribute encoding; JavaScript string → JS string "
                "encoding; URL → URL encoding; CSS → CSS escaping). Prefer "
                "context-aware templating engines. Apply a strict Content "
                "Security Policy (no unsafe-inline, no unsafe-eval). Sanitize "
                "HTML with a maintained library (DOMPurify, bleach) when rich "
                "text is required. Never pass untrusted data into DOM sinks "
                "like innerHTML, document.write, or eval."
            ),
        }

        # Dedup by URL+param+payload_id
        sig = hashlib.md5(
            f"{ip.url}|{ip.name}|{payload_obj.get('id')}".encode()
        ).hexdigest()
        if sig in self.seen_signatures:
            return None
        self.seen_signatures.add(sig)

        # Persist
        host = urlparse(ip.url).netloc
        slug = safe_filename((urlparse(ip.url).path or "/").replace("/", "_")
                             or "_root")
        fname = (f"{slug}__{safe_filename(ip.name)}__"
                 f"{payload_obj.get('id','x')}_xss_vulnerable.json")
        out_path = self.findings_root / safe_filename(host) / fname
        save_json(out_path, finding)

        sev_color = {
            "confirmed": "\033[38;5;46m",
            "critical":  "\033[38;5;196m",
            "high":      "\033[38;5;208m",
            "medium":    "\033[38;5;226m",
            "low":       "\033[38;5;240m",
        }.get(severity, "\033[0m")

        log(
            f"[{sev_color}{severity.upper():8}\033[0m] "
            f"{ip.location}:{ip.name} @ {ip.url} "
            f"({payload_obj.get('name')} → {hit.get('verification_method')})",
            "hit", "XSS",
        )
        return finding

    @staticmethod
    def _subtype(payload_obj):
        cat = payload_obj.get("category", "")
        return {
            "basic":                "reflected_basic",
            "event_handlers":       "reflected_event_handler",
            "html5_tags":           "reflected_html5",
            "svg_vectors":          "reflected_svg",
            "mathml_vectors":       "namespace_confusion",
            "polyglots":            "polyglot",
            "filter_bypass":        "filter_bypass",
            "encoding":             "encoded_payload",
            "context_breaks":       "context_escape",
            "waf_bypass":           "waf_bypass",
            "csp_bypass":           "csp_bypass",
            "mxss":                 "mutation_xss",
            "dom_based":            "dom_based",
            "framework_specific":   "framework_specific",
            "csti":                 "client_side_template_injection",
            "prototype_pollution":  "prototype_pollution",
            "file_upload":          "file_upload_xss",
            "header_injection":     "header_injection_xss",
            "namespace_confusion":  "namespace_confusion",
            "modern":               "modern_vector",
            "legacy":               "legacy_vector",
            "blind":                "blind_xss",
        }.get(cat, "reflected_xss")

    # ------------------------------------------------------------------ #
    #  Process one injection point
    # ------------------------------------------------------------------ #
    def test_point(self, ip):
        self.capture_baseline(ip)
        reflection = self.probe_reflection(ip)
        if not reflection:
            return []

        ctx = reflection["context"]
        if ctx in SAFE_CONTEXTS:
            return []

        log(f"reflection [{ctx}] at {ip.location}:{ip.name} @ {ip.url}",
            "ok", "PROBE")

        payloads = self.filter_payloads_for_context(ctx, ip)
        if not payloads:
            return []

        log(f"  → {len(payloads)} payloads applicable", "info")

        findings = []
        for p in payloads:
            f = self.test_payload(ip, p)
            if f:
                findings.append(f)
            time.sleep(self.delay)
        return findings

    # ------------------------------------------------------------------ #
    #  Browser verification pass
    # ------------------------------------------------------------------ #
    def verify_findings_with_browser(self, findings):
        if not self.use_browser or not findings:
            return findings

        log(f"browser verification pass over {len(findings)} candidates", "info")

        candidates = []
        for f in findings:
            ip = InjectionPoint(
                f["url"], f["method"], f["injection_point"]["location"],
                f["injection_point"]["name"], f["injection_point"]["original_value"],
                json_path=f["injection_point"].get("json_path"),
            )
            url = self._build_verification_url(ip, f["payload"])
            if url:
                candidates.append((f, url))

        for f, url in candidates:
            result = _verify_with_playwright(url)
            if result is None:
                log("playwright not installed — skipping browser verification",
                    "warn")
                return findings
            if result.get("executed"):
                f["browser_verified"] = result
                f["severity"] = "confirmed"
                f["confirmed"] = True
                f["verification_method"] = "browser_dialog"
                f["detection_reason"] += " | BROWSER CONFIRMED"
                log(f"browser confirmed XSS at {url}", "hit", "XSS-BROWSER")

        return findings

    def _build_verification_url(self, ip, payload):
        try:
            if ip.location == "query":
                p = urlparse(ip.url)
                qs = parse_qs(p.query, keep_blank_values=True)
                qs[ip.name] = [payload]
                return urlunparse(p._replace(query=urlencode(qs, doseq=True)))
            if ip.location == "body_form" and ip.method == "GET":
                p = urlparse(ip.url)
                qs = parse_qs(p.query, keep_blank_values=True)
                qs[ip.name] = [payload]
                return urlunparse(p._replace(query=urlencode(qs, doseq=True)))
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    #  Main entry
    # ------------------------------------------------------------------ #
    def run(self):
        section("XSS SCANNER :: INITIALISING")
        log(f"attacker : {self.attacker_domain}")
        log(f"collab   : {self.collab_host}")
        log(f"alert    : {self.alert_payload}")
        log(f"browser  : {'enabled' if self.use_browser else 'disabled'}")
        log(f"OOB      : {'enabled' if self.oob_poller else 'disabled'}")

        self.load_payloads()
        log(f"loaded {len(self._payloads)} payloads", "info")

        if self.oob_poller and self.oob_poller.start():
            log("OOB poller started", "ok")

        pages = []
        for jf in self.sites_root.rglob("*.json"):
            if jf.name.startswith("_"):
                continue
            try:
                rec = load_json(jf)
                if rec.get("url"):
                    pages.append(rec)
            except Exception:
                continue
        log(f"loaded {len(pages)} crawled pages", "info")

        points = extract_injection_points(pages)
        log(f"extracted {len(points)} injection points", "ok")
        if not points:
            log("nothing to test", "warn")
            if self.oob_poller:
                self.oob_poller.stop()
            return []

        section("XSS SCANNER :: STRIKE PHASE")
        all_findings = []
        done, total = 0, len(points)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.test_point, ip): ip for ip in points}
            for fut in as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    all_findings.extend(fut.result())
                except Exception as e:
                    log(f"error testing {ip}: {e}", "warn")
                if done % 20 == 0 or done == total:
                    log(f"progress {done}/{total}  hits={len(all_findings)}",
                        "info")

        # Browser verification
        if self.use_browser and all_findings:
            all_findings = self.verify_findings_with_browser(all_findings)

        # OOB drain
        if self.oob_poller:
            log("waiting for final OOB callbacks…", "info")
            time.sleep(min(15, self.oob_poller.timeout))
            self.oob_poller.stop()

        # -------- Summary ------------------------------------------------
        section("XSS SCANNER :: COMPLETE")
        if all_findings:
            by_sev  = {}
            by_ctx  = {}
            by_ver  = {}
            for f in all_findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
                r = f.get("reflection") or {}
                c = r.get("context", "unknown")
                by_ctx[c] = by_ctx.get(c, 0) + 1
                v = f.get("verification_method", "unknown")
                by_ver[v] = by_ver.get(v, 0) + 1
            for s in ("confirmed", "critical", "high", "medium", "low"):
                if s in by_sev:
                    log(f"{s:10} : {by_sev[s]}", "ok")
            log(f"verification methods: {by_ver}", "info")
            log(f"total findings: {len(all_findings)}", "ok", "DONE")
        else:
            log("no XSS findings", "info", "DONE")

        save_json(self.findings_root / "_summary.json", {
            "total": len(all_findings),
            "by_severity": {s: sum(1 for f in all_findings if f["severity"] == s)
                            for s in ("confirmed", "critical", "high",
                                      "medium", "low")},
            "by_subtype":   self._summarize(all_findings, "subtype"),
            "by_context":   self._summarize_reflection_context(all_findings),
            "by_category":  self._summarize(all_findings, "payload_category"),
            "by_verification": self._summarize(all_findings, "verification_method"),
            "attacker_domain": self.attacker_domain,
            "collab_host":     self.collab_host,
            "alert_payload":   self.alert_payload,
            "browser_used":    self.use_browser,
            "oob_enabled":     bool(self.oob_poller),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [
                {"url": f["url"], "param": f["parameter"],
                 "severity": f["severity"], "subtype": f["subtype"],
                 "context": (f.get("reflection") or {}).get("context"),
                 "verification": f.get("verification_method"),
                 "payload_name": f["payload_name"]}
                for f in all_findings
            ],
        })
        return all_findings

    @staticmethod
    def _summarize(findings, key):
        out = {}
        for f in findings:
            k = f.get(key) or "unknown"
            out[k] = out.get(k, 0) + 1
        return out

    @staticmethod
    def _summarize_reflection_context(findings):
        out = {}
        for f in findings:
            r = f.get("reflection") or {}
            c = r.get("context", "unknown")
            out[c] = out.get(c, 0) + 1
        return out


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None,
        attacker_domain=DEFAULT_ATTACKER,
        collab_host=DEFAULT_COLLAB,
        alert_payload=DEFAULT_ALERT,
        target_domain=None,
        use_browser=False,
        oob_log_file=None,
        oob_base_url=None):
    """
    oob_base_url : e.g. "https://oast.beardedviking.org" — polls check.php?list=1
    oob_log_file : local log file for interactsh-client style polling
    """
    scanner = XSSScanner(
        program_dir=program_dir,
        sites_root=sites_root,
        attacker_domain=attacker_domain,
        collab_host=collab_host,
        alert_payload=alert_payload,
        target_domain=target_domain,
        use_browser=use_browser,
        oob_log_file=oob_log_file,
        oob_base_url=oob_base_url,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN XSS scanner")
    ap.add_argument("program_dir")
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--collab",   default=DEFAULT_COLLAB,
                    help="OOB receiver host (default: oast.beardedviking.org)")
    ap.add_argument("--alert",    default=DEFAULT_ALERT)
    ap.add_argument("--target",   default=None)
    ap.add_argument("--browser",  action="store_true")
    ap.add_argument("--oob-log",  default=None,
                    help="local collaborator log file (interactsh)")
    ap.add_argument("--oob-url",  default=None,
                    help="remote OOB base URL, e.g. https://oast.beardedviking.org")
    args = ap.parse_args()
    run(args.program_dir,
        attacker_domain=args.attacker,
        collab_host=args.collab,
        alert_payload=args.alert,
        target_domain=args.target,
        use_browser=args.browser,
        oob_log_file=args.oob_log,
        oob_base_url=args.oob_url)
