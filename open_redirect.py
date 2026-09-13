#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: open_redirect.py
#  The Ultimate Open Redirect Scanner — 2026 Edition
# -----------------------------------------------------------------------------
#  Detection pipeline:
#    1. Inject payload into every reachable parameter
#    2. Analyse the immediate response for:
#         · Location header pointing at attacker/canary    →  follow chain
#         · Location header with scheme abuse (js:, data:) →  high severity
#         · Location header with cloud metadata           →  critical (SSRF)
#         · <meta refresh> in body                        →  medium
#         · JS location assignment in body                →  medium
#         · Canary string in body                         →  CONFIRMED
#         · Raw attacker/canary reflection                →  low
#    3. For chain-verifiable hits, follow the Location and read the
#       HUGINN-CANARY-LANDED string from the final response body.
#    4. For async/out-of-band hits, poll check.php on the canary host.
#    5. Emit a self-contained finding: URL, payload, evidence, response
#       snippet, and a copy-pasteable cURL command for reproduction.
#
#  Injection transports:
#    · Query params    · POST form bodies  · JSON bodies
#    · Cookies         · HTTP headers      · Path segments
#    · HTTP parameter pollution (HPP)
# =============================================================================

import re
import json
import time
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
    random_token, build_oob_url,
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

DEFAULT_ATTACKER     = "beardedviking.org"
DEFAULT_CANARY_HOST  = "redirect.beardedviking.org"
DEFAULT_CANARY_STR   = "HUGINN-CANARY-LANDED"
DEFAULT_CANARY_CHECK = "https://redirect.beardedviking.org/check.php"
DEFAULT_COLLAB_HOST  = "oast.beardedviking.org"

# Cloud metadata markers → escalation to "critical"
METADATA_MARKERS = [
    "ami-id", "instance-id", "iam/security-credentials",
    "computemetadata", "metadata-flavor",
    "opc/v1/instance", "metadata/v1",
    "latest/meta-data",
]

# Headers worth fuzzing (independent of payload category)
FUZZABLE_HEADERS = [
    "Referer", "Referrer", "User-Agent", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Client-IP", "Forwarded", "Origin", "Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Http-Method-Override",
    "X-Wap-Profile", "X-Callback-Url", "X-Auth-Token",
]

# Scheme-abuse prefixes — detection uses these as needles
SCHEME_NEEDLES = [
    "javascript:", "data:", "vbscript:", "file:", "blob:",
    "chrome://", "about:", "intent://", "tel:", "sms:", "ftp:",
]

# Category → routing family (controls how payloads are sent)
ROUTE_HEADER_CATEGORY = "header_based"
ROUTE_COOKIE_CATEGORY = "cookie_based"
ROUTE_HPP_CATEGORY    = "parameter_pollution"
ROUTE_CLIENT_CATEGORY = "client_side"

# =============================================================================
#  IN-BODY REDIRECT EXTRACTION
# =============================================================================
RE_META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*'
    r'["\']?[^"\'>]*url\s*=\s*([^"\'>\s]+)',
    re.I,
)
RE_META_REFRESH_ALT = re.compile(
    r'<meta[^>]+content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'>\s]+)',
    re.I,
)
JS_REDIRECT_PATTERNS = [
    re.compile(r'location\s*\.\s*href\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'location\s*\.\s*replace\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'location\s*\.\s*assign\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'window\s*\.\s*location\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'document\s*\.\s*location\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'location\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'meta\s*\(\s*["\']refresh["\']\s*,\s*["\'][^"\']*url=([^"\']+)', re.I),
]


# =============================================================================
#  HELPERS
# =============================================================================
def _build_query_string(params):
    """
    Build a query string, preserving percent-encoded values as-is.
    urllib.urlencode() would double-encode '%2f' → '%252f', breaking
    whitespace/encoding payloads. We only encode the KEY, not the value.
    """
    pairs = []
    for k, v in params.items():
        if isinstance(v, list):
            for item in v:
                pairs.append(f"{quote(str(k), safe='')}={item}")
        else:
            pairs.append(f"{quote(str(k), safe='')}={v}")
    return "&".join(pairs)


def _substitute_placeholders(payload, attacker, target, canary_host,
                             canary_url, oob_url, token):
    """Swap every HUGINN placeholder in a payload template."""
    return (payload
            .replace("{{ATTACKER}}",   attacker)
            .replace("{{TARGET}}",     target)
            .replace("{{SUBDOMAIN}}",  target)
            .replace("{{CANARY}}",     canary_host)
            .replace("{{CANARY_URL}}", canary_url)
            .replace("{{OOB}}",        oob_url)
            .replace("{{RANDOM}}",     f"huginn-{token}")
            .replace("{{ALERT}}",      "alert(document.domain)"))


def _parse_header_payload(payload):
    """Parse 'H1: v1|H2: v2' or 'H1: v1' → dict."""
    if "|" in payload:
        out = {}
        for chunk in payload.split("|"):
            if ":" not in chunk:
                return None
            name, _, val = chunk.partition(":")
            out[name.strip()] = val.strip()
        return out or None
    if ":" in payload:
        name, _, val = payload.partition(":")
        return {name.strip(): val.strip()}
    return None


def _parse_cookie_payload(payload):
    if "=" not in payload:
        return None
    name, _, val = payload.partition("=")
    return {name.strip(): val.strip()}


def _is_attacker_target(value, attacker_domain, canary_host):
    """Does value reference the attacker or canary host?"""
    if not value:
        return False
    v = value.lower()
    decoded = unquote(v)
    for needle in (attacker_domain.lower(), canary_host.lower()):
        if needle in v or needle in decoded:
            return True
        if "//" + needle in v or "//" + needle in decoded:
            return True
    return False


def _is_scheme_abuse(value):
    if not value:
        return None
    v = value.strip().lower()
    for scheme in SCHEME_NEEDLES:
        if v.startswith(scheme):
            return scheme
    return None


def _is_metadata_url(value):
    if not value:
        return False
    v = value.lower()
    if "169.254.169.254" in v or "100.100.100.200" in v:
        return True
    return any(m in v for m in METADATA_MARKERS)


def _extract_body_redirects(body):
    """Extract (vector, url) tuples from meta-refresh and JS redirects."""
    if not body:
        return []
    out = []
    for m in RE_META_REFRESH.finditer(body):
        out.append(("meta_refresh", m.group(1)))
    for m in RE_META_REFRESH_ALT.finditer(body):
        out.append(("meta_refresh", m.group(1)))
    for pat in JS_REDIRECT_PATTERNS:
        for m in pat.finditer(body):
            out.append(("js_redirect", m.group(1)))
    # dedup
    seen, uniq = set(), []
    for vec, url in out:
        key = (vec, url)
        if key not in seen:
            seen.add(key)
            uniq.append(key)
    return uniq


def _response_snippet(body, needle, window=180):
    """Return a ~360 char window around the first occurrence of `needle`."""
    if not body:
        return ""
    if not needle:
        return body[:window * 2]
    idx = body.lower().find(needle.lower())
    if idx == -1:
        return body[:window * 2]
    return body[max(0, idx - window): idx + len(needle) + window]


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "json_body", "form_data", "extra_headers",
                 "baseline")

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
        self.baseline = None

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        return f"<IP {self.location}:{self.name} @ {self.method} {self.url}>"


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


def _extract_path_segments(page):
    url = page["url"]
    parsed = urlparse(url)
    segs = [s for s in parsed.path.split("/") if s]
    if not segs:
        return []
    return [InjectionPoint(
        url, "GET", "path", f"segment[{i}]", seg,
        extra_headers={"_segment_index": str(i)},
    ) for i, seg in enumerate(segs)]


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
            if inp.has_attr("type") and inp["type"].lower() in ("submit", "button", "file"):
                continue
            data[name] = inp.get("value") or ""
        for name, value in data.items():
            points.append(InjectionPoint(
                action_url, method, "body_form", name, value,
                form_data=dict(data),
            ))
    return points


def _extract_headers(page):
    return [InjectionPoint(page["url"], "GET", "header", h, "")
            for h in FUZZABLE_HEADERS]


def _extract_cookies(page):
    headers = page.get("headers") or {}
    sc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not sc:
        return []
    points = []
    for chunk in sc.split(","):
        m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
        if m:
            points.append(InjectionPoint(
                page["url"], "GET", "cookie",
                m.group(1).strip(), m.group(2).strip(),
            ))
    return points


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
#  REQUEST + CURL BUILDERS
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


def build_request(ip, payload, timeout=12, allow_redirects=False):
    headers = dict(ip.extra_headers)
    url = ip.url
    data = None
    method = ip.method

    if ip.location == "query":
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        # Use raw-substitution query builder to preserve %XX
        qs_string = _build_query_string(qs)
        url = urlunparse(p._replace(query=qs_string))

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
            url = urlunparse(p._replace(query=_build_query_string(body)))
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
    """Build a copy-pasteable cURL for a finding."""
    parts = ["curl", "-sk", "--max-time", str(timeout), "-i"]

    if ip.location == "query":
        p = urlparse(ip.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=_build_query_string(qs)))
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
            url = urlunparse(p._replace(query=_build_query_string(body)))
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
#  REMOTE CANARY POLLER
# =============================================================================
class RemoteCanaryPoller:
    """
    Polls check.php on the canary host for async confirmation. Every token
    the scanner sends gets tracked; if it appears in the canary log, the
    corresponding finding is upgraded to confirmed.
    """

    def __init__(self, check_url, poll_interval=4.0, timeout=180.0,
                 verify=False):
        self.check_url = check_url.rstrip("/")
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
        endpoint = f"{self.check_url}?list=1"
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
#  DETECTION
# =============================================================================
def _detect_in_response(resp, payload_obj, attacker_domain, canary_host,
                        canary_string, needle):
    """
    Analyse a single response. Returns list of dicts:
        {"vector": str, "value": str, "severity": str}
    """
    hits = []
    if resp is None:
        return hits

    body = resp.text or ""
    location = (resp.headers.get("Location") or
                resp.headers.get("location") or "").strip()

    # ---- 1. Location header -------------------------------------------------
    if location:
        # Chain to our infrastructure
        if _is_attacker_target(location, attacker_domain, canary_host):
            hits.append({
                "vector": "location_header",
                "value": location,
                "severity": "high",
            })
        # Scheme abuse in Location
        scheme = _is_scheme_abuse(location)
        if scheme and scheme in payload_obj["payload"].lower():
            hits.append({
                "vector": "location_header_scheme",
                "value": location,
                "severity": "high",
            })
        # Cloud metadata
        if _is_metadata_url(location):
            hits.append({
                "vector": "location_header_metadata",
                "value": location,
                "severity": "critical",
            })

    # ---- 2. Meta refresh / JS redirect -------------------------------------
    for vec, url_val in _extract_body_redirects(body):
        if _is_attacker_target(url_val, attacker_domain, canary_host):
            hits.append({
                "vector": vec,
                "value": url_val,
                "severity": "medium",
            })
        if _is_metadata_url(url_val):
            hits.append({
                "vector": f"{vec}_metadata",
                "value": url_val,
                "severity": "critical",
            })

    # ---- 3. Canary string landed -------------------------------------------
    if canary_string and canary_string.lower() in body.lower():
        hits.append({
            "vector": "canary_landed",
            "value": canary_string,
            "severity": "confirmed",
        })

    # ---- 4. Raw reflection (weakest signal) --------------------------------
    if not hits and needle and needle in body.lower():
        hits.append({
            "vector": "reflection",
            "value": needle,
            "severity": "low",
        })

    return hits


# =============================================================================
#  SCANNER
# =============================================================================
class OpenRedirectScanner:

    def __init__(self,
                 program_dir,
                 sites_root=None,
                 attacker_domain=DEFAULT_ATTACKER,
                 canary_host=DEFAULT_CANARY_HOST,
                 canary_string=DEFAULT_CANARY_STR,
                 collab_host=DEFAULT_COLLAB_HOST,
                 canary_check_url=DEFAULT_CANARY_CHECK,
                 target_domain=None,
                 max_workers=8,
                 delay=0.15,
                 timeout=12,
                 verify_chain=True):
        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "open_redirect"
        self.findings_root.mkdir(parents=True, exist_ok=True)

        self.attacker_domain = attacker_domain
        self.canary_host     = canary_host
        self.canary_string   = canary_string
        self.collab_host     = collab_host
        self.canary_check_url = canary_check_url
        self.target_domain   = target_domain or ""
        self.max_workers     = max_workers
        self.delay           = delay
        self.timeout         = timeout
        self.verify_chain    = verify_chain

        self.seen_signatures = set()
        self._payloads = None
        self._tokens_by_id = {}       # payload_id → token
        self.poller = RemoteCanaryPoller(canary_check_url)

    # ------------------------------------------------------------------ #
    #  Payload loading
    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("open_redirect")
        raw = data.get("payloads", [])
        ctx_target = self.target_domain or "target.invalid"
        out = []

        for entry in raw:
            if isinstance(entry, str):
                token = random_token()
                canary_url = f"https://{self.canary_host}/huginn-{token}/raw"
                oob_url = build_oob_url(self.collab_host, token,
                                        path_hint="openredir")
                p = _substitute_placeholders(
                    entry, self.attacker_domain, ctx_target,
                    self.canary_host, canary_url, oob_url, token,
                )
                out.append({
                    "id": "raw", "name": "raw", "category": "unknown",
                    "payload": p, "tags": [], "description": "",
                    "_token": token, "_canary_url": canary_url,
                })
                continue

            entry = dict(entry)
            token = random_token()
            canary_url = f"https://{self.canary_host}/huginn-{token}/{entry['id']}"
            oob_url = build_oob_url(self.collab_host, token,
                                    path_hint=entry["id"])

            entry["payload"] = _substitute_placeholders(
                entry["payload"], self.attacker_domain, ctx_target,
                self.canary_host, canary_url, oob_url, token,
            )
            entry["_token"] = token
            entry["_canary_url"] = canary_url
            self._tokens_by_id[entry["id"]] = token
            out.append(entry)

        self._payloads = out
        return out

    # ------------------------------------------------------------------ #
    #  Baseline
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        try:
            ip.baseline = build_request(ip, ip.value, timeout=self.timeout)
        except Exception:
            ip.baseline = None

    # ------------------------------------------------------------------ #
    #  Chain verification
    # ------------------------------------------------------------------ #
    def _verify_chain(self, location_url):
        """Follow the Location and read the canary string from the final body."""
        if not location_url:
            return None
        try:
            resp = send_request(location_url, timeout=self.timeout,
                                allow_redirects=True)
        except Exception:
            return None
        if resp is None:
            return None
        body = resp.text or ""
        return {
            "landed_at": resp.url,
            "final_status": resp.status_code,
            "canary_found": bool(
                self.canary_string and
                self.canary_string.lower() in body.lower()
            ),
            "snippet": _response_snippet(body, self.canary_string),
        }

    # ------------------------------------------------------------------ #
    #  Test one payload against one injection point
    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj):
        payload = payload_obj["payload"]
        category = payload_obj.get("category", "unknown")
        token = payload_obj.get("_token")
        needle = self.attacker_domain

        # ---- Route special categories -----------------------------------
        if category == ROUTE_HEADER_CATEGORY:
            parsed = _parse_header_payload(payload)
            if not parsed:
                return None
            try:
                resp = send_request(ip.url, method="GET", headers=parsed,
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                return None
            hits = _detect_in_response(resp, payload_obj,
                                       self.attacker_domain, self.canary_host,
                                       self.canary_string, needle)
            if not hits:
                return None
            return self._build_finding(ip, payload_obj, hits, resp,
                                       extra={"injected_headers": parsed})

        if category == ROUTE_COOKIE_CATEGORY:
            parsed = _parse_cookie_payload(payload)
            if not parsed:
                return None
            cookie_hdr = "; ".join(f"{k}={v}" for k, v in parsed.items())
            try:
                resp = send_request(ip.url, method="GET",
                                    headers={"Cookie": cookie_hdr},
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                return None
            hits = _detect_in_response(resp, payload_obj,
                                       self.attacker_domain, self.canary_host,
                                       self.canary_string, needle)
            if not hits:
                return None
            return self._build_finding(ip, payload_obj, hits, resp,
                                       extra={"injected_cookies": parsed})

        if category == ROUTE_HPP_CATEGORY:
            # Payload IS the query string — append to base URL
            p = urlparse(ip.url)
            base = urlunparse(p._replace(query=""))
            target_url = base + (payload if payload.startswith("?") else "?" + payload)
            try:
                resp = send_request(target_url, method="GET",
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                return None
            hits = _detect_in_response(resp, payload_obj,
                                       self.attacker_domain, self.canary_host,
                                       self.canary_string, needle)
            if not hits:
                return None
            return self._build_finding(ip, payload_obj, hits, resp,
                                       extra={"hpp_url": target_url})

        # ---- Standard transport -----------------------------------------
        try:
            resp = build_request(ip, payload, timeout=self.timeout,
                                 allow_redirects=False)
        except Exception:
            return None
        if resp is None:
            return None

        hits = _detect_in_response(resp, payload_obj,
                                   self.attacker_domain, self.canary_host,
                                   self.canary_string, needle)
        if not hits:
            return None

        return self._build_finding(ip, payload_obj, hits, resp)

    # ------------------------------------------------------------------ #
    #  Finding construction
    # ------------------------------------------------------------------ #
    def _build_finding(self, ip, payload_obj, hits, resp, extra=None):
        order = {"confirmed": 4, "critical": 3, "high": 2, "medium": 1, "low": 0}
        best = max(hits, key=lambda h: order.get(h["severity"], -1))
        severity = best["severity"]
        confirmed = False

        # ---- Chain verification ----------------------------------------
        chain = None
        if self.verify_chain:
            loc = (resp.headers.get("Location") or
                   resp.headers.get("location") or "").strip()
            if loc and _is_attacker_target(loc, self.attacker_domain,
                                           self.canary_host):
                chain = self._verify_chain(loc)
                if chain and chain.get("canary_found"):
                    severity = "confirmed"
                    confirmed = True
                    hits.append({
                        "vector": "canary_landed_after_chain",
                        "value": chain.get("landed_at", ""),
                        "severity": "confirmed",
                    })

        # ---- Async token confirmation ----------------------------------
        token = payload_obj.get("_token")
        if not confirmed and token and self.poller.has_token(token):
            confirmed = True
            severity = "confirmed"
            hits.append({
                "vector": "canary_token_logged",
                "value": token,
                "severity": "confirmed",
            })

        # ---- If already confirmed via body canary -----------------------
        if any(h["vector"] == "canary_landed" for h in hits):
            confirmed = True

        # ---- Assemble finding -------------------------------------------
        response_body = resp.text or ""
        response_location = (resp.headers.get("Location") or
                             resp.headers.get("location") or "").strip()

        finding = {
            "type": "open_redirect",
            "subtype": self._subtype_from_hits(hits),
            "severity": severity,
            "confirmed": confirmed,
            "verification_method": self._verification_method(hits, chain),

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
            "payload":             payload_obj["payload"],
            "payload_category":    payload_obj.get("category"),
            "payload_tags":        payload_obj.get("tags", []),
            "payload_description": payload_obj.get("description", ""),
            "payload_references":  payload_obj.get("references", []),
            "payload_expected":    payload_obj.get("expected"),

            "detection_vectors": hits,
            "chain": chain,

            "response_status":   resp.status_code,
            "response_location": response_location,
            "response_length":   len(response_body),
            "response_snippet":  _response_snippet(
                response_body,
                self.canary_string if confirmed else self.attacker_domain,
            ),

            "baseline_status": ip.baseline.status_code if ip.baseline else None,

            "curl_command": build_curl(ip, payload_obj["payload"]),

            "attacker_domain":  self.attacker_domain,
            "canary_host":      self.canary_host,
            "canary_url":       payload_obj.get("_canary_url"),
            "oob_token":        token,
            "target_domain":    self.target_domain,

            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Never trust user input as a redirect destination. Enforce "
                "a strict allow-list of permitted hosts and paths. Reject "
                "protocol-relative URLs (//), backslashes, and non-http(s) "
                "schemes. If a redirect parameter must exist, map it to an "
                "internal ID rather than accepting a URL. Also validate the "
                "Host, Referer, and X-Forwarded-* headers server-side."
            ),
        }
        if extra:
            finding["injection_extra"] = extra

        # ---- Dedup ------------------------------------------------------
        sig = hashlib.md5(
            f"{ip.url}|{ip.name}|{payload_obj.get('id')}|{severity}".encode()
        ).hexdigest()
        if sig in self.seen_signatures:
            return None
        self.seen_signatures.add(sig)

        # ---- Persist ----------------------------------------------------
        host = urlparse(ip.url).netloc
        slug = safe_filename((urlparse(ip.url).path or "/").replace("/", "_")
                             or "_root")
        fname = (f"{slug}__{safe_filename(ip.name)}__"
                 f"{payload_obj.get('id','x')}_openredirect.json")
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
            f"[{sev_color}{severity.upper():9}\033[0m] "
            f"{ip.location}:{ip.name} @ {ip.url} "
            f"({payload_obj.get('name')} → {hits[0]['vector']})",
            "hit", "REDIR",
        )
        return finding

    @staticmethod
    def _subtype_from_hits(hits):
        vecs = {h["vector"] for h in hits}
        if any("metadata" in v for v in vecs):       return "ssrf_via_redirect"
        if any("scheme" in v for v in vecs):         return "scheme_abuse"
        if any(v.startswith("js_") for v in vecs):   return "client_side_js_redirect"
        if any(v == "meta_refresh" for v in vecs):   return "client_side_meta_refresh"
        if any(v == "location_header" for v in vecs):return "server_side_redirect"
        if any("canary" in v for v in vecs):         return "confirmed_redirect"
        if any(v == "reflection" for v in vecs):     return "unvalidated_reflection"
        return "unknown"

    @staticmethod
    def _verification_method(hits, chain):
        vecs = {h["vector"] for h in hits}
        if "canary_landed_after_chain" in vecs:      return "chain_follow"
        if "canary_landed" in vecs:                  return "body_canary"
        if "canary_token_logged" in vecs:            return "async_token"
        if any(v == "location_header" for v in vecs):return "location_header"
        if any(v.startswith("js_") for v in vecs):   return "js_redirect"
        if any(v == "meta_refresh" for v in vecs):   return "meta_refresh"
        return "reflection"

    # ------------------------------------------------------------------ #
    #  Test one injection point
    # ------------------------------------------------------------------ #
    def test_point(self, ip, payloads):
        self.capture_baseline(ip)
        findings = []
        for p in payloads:
            f = self.test_payload(ip, p)
            if f:
                findings.append(f)
            time.sleep(self.delay)
        return findings

    # ------------------------------------------------------------------ #
    #  Main entry
    # ------------------------------------------------------------------ #
    def run(self):
        section("OPEN REDIRECT SCANNER :: INITIALISING")
        log(f"attacker    : {self.attacker_domain}")
        log(f"canary host : {self.canary_host}")
        log(f"canary check: {self.canary_check_url}")

        payloads = self.load_and_filter_payloads()
        log(f"loaded {len(payloads)} payloads", "info")

        if self.poller.start():
            log("canary poller started", "ok")
        else:
            log("canary poller unavailable — async confirmation disabled",
                "warn")

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
            self.poller.stop()
            return []

        section("OPEN REDIRECT SCANNER :: STRIKE PHASE")
        all_findings = []
        done, total = 0, len(points)

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
                if done % 25 == 0 or done == total:
                    log(f"progress {done}/{total}  hits={len(all_findings)}",
                        "info")

        # Let the poller drain
        if self.poller:
            log("waiting for final canary callbacks…", "info")
            time.sleep(min(15, self.poller.timeout))
            self.poller.stop()

        # Second pass — recheck findings whose tokens may have arrived
        for f in all_findings:
            tok = f.get("oob_token")
            if tok and not f.get("confirmed") and self.poller.has_token(tok):
                f["confirmed"] = True
                if f["severity"] != "confirmed":
                    f["severity"] = "confirmed"
                f["verification_method"] = "async_token_post_scan"
                f.setdefault("detection_vectors", []).append({
                    "vector": "canary_token_logged_post_scan",
                    "value": tok,
                    "severity": "confirmed",
                })
                save_json(
                    self.findings_root
                    / safe_filename(urlparse(f["url"]).netloc)
                    / (safe_filename(
                        (urlparse(f["url"]).path or "/").replace("/", "_")
                        or "_root") + "__" +
                       safe_filename(f["parameter"]) + "__" +
                       str(f["payload_id"]) + "_openredirect.json"),
                    f,
                )

        # -------- Summary ------------------------------------------------
        section("OPEN REDIRECT SCANNER :: COMPLETE")
        confirmed = [f for f in all_findings if f.get("confirmed")]
        if all_findings:
            by_sev = {}
            for f in all_findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            for s in ("confirmed", "critical", "high", "medium", "low"):
                if s in by_sev:
                    log(f"{s:10} : {by_sev[s]}", "ok")
            log(f"CONFIRMED    : {len(confirmed)}", "ok", "DONE")
            log(f"total        : {len(all_findings)}", "info")
        else:
            log("no open redirect findings", "info", "DONE")

        save_json(self.findings_root / "_summary.json", {
            "total": len(all_findings),
            "confirmed": len(confirmed),
            "by_severity": {s: sum(1 for f in all_findings if f["severity"] == s)
                            for s in ("confirmed", "critical", "high",
                                      "medium", "low")},
            "by_subtype": self._summarize(all_findings, "subtype"),
            "by_verification": self._summarize(all_findings, "verification_method"),
            "attacker_domain": self.attacker_domain,
            "canary_host":     self.canary_host,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [
                {"url":        f["url"],
                 "param":      f["parameter"],
                 "severity":   f["severity"],
                 "subtype":    f["subtype"],
                 "confirmed":  f.get("confirmed", False),
                 "vector":     (f["detection_vectors"][0]["vector"]
                                if f.get("detection_vectors") else None),
                 "payload_id": f["payload_id"]}
                for f in all_findings
            ],
            "confirmed_findings": [
                {"url":        f["url"],
                 "param":      f["parameter"],
                 "severity":   f["severity"],
                 "subtype":    f["subtype"],
                 "curl":       f["curl_command"]}
                for f in confirmed
            ],
        })

        # Write a "confirmed only" index for quick triage
        if confirmed:
            save_json(self.findings_root / "_confirmed.json", {
                "count": len(confirmed),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "findings": confirmed,
            })

        return all_findings

    @staticmethod
    def _summarize(findings, key):
        out = {}
        for f in findings:
            k = f.get(key) or "unknown"
            out[k] = out.get(k, 0) + 1
        return out


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None,
        attacker_domain=DEFAULT_ATTACKER,
        canary_host=DEFAULT_CANARY_HOST,
        canary_string=DEFAULT_CANARY_STR,
        collab_host=DEFAULT_COLLAB_HOST,
        canary_check_url=DEFAULT_CANARY_CHECK,
        target_domain=None):
    scanner = OpenRedirectScanner(
        program_dir=program_dir,
        sites_root=sites_root,
        attacker_domain=attacker_domain,
        canary_host=canary_host,
        canary_string=canary_string,
        collab_host=collab_host,
        canary_check_url=canary_check_url,
        target_domain=target_domain,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN Open Redirect scanner")
    ap.add_argument("program_dir")
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--canary",   default=DEFAULT_CANARY_HOST)
    ap.add_argument("--canary-string", default=DEFAULT_CANARY_STR)
    ap.add_argument("--canary-check",  default=DEFAULT_CANARY_CHECK,
                    help="URL of the canary check.php")
    ap.add_argument("--collab",   default=DEFAULT_COLLAB_HOST)
    ap.add_argument("--target",   default=None)
    args = ap.parse_args()
    run(args.program_dir,
        attacker_domain=args.attacker,
        canary_host=args.canary,
        canary_string=args.canary_string,
        collab_host=args.collab,
        canary_check_url=args.canary_check,
        target_domain=args.target)
