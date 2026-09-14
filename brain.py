#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: brain.py — v2.0
#  Provider-agnostic LLM interface for every scanner in the suite.
# -----------------------------------------------------------------------------
#  SCANNER COMPATIBILITY MATRIX
#  ---------------------------------------------------------------------------
#    sqli.py           → triage(kind="sqli"), assess_severity, explain_finding
#    xss.py            → triage(kind="xss"), assess_severity, explain_finding
#    ssrf.py           → triage(kind="ssrf"), assess_severity, explain_finding
#    rce.py            → triage(kind="rce"), assess_severity, explain_finding
#    idor.py           → triage(kind="idor"), assess_severity, explain_finding
#    open_redirect.py  → triage(kind="open_redirect"), assess_severity
#    path_traversal.py → triage(kind="path_traversal"), assess_severity
#    burp_to_sites.py  → recon_page(page), classify_page(page)
#    report.py         → explain_finding, assess_severity
#    orchestrator.py   → suggest_next, suggest_payloads, deduplicate, warmup
#
#  ---------------------------------------------------------------------------
#  Provider states:
#    full   — a cloud API key is present AND chat-capable
#    local  — Ollama is reachable on localhost:11434
#    off    — nothing available; every method returns None
#  ---------------------------------------------------------------------------
#  What's new in v2.0:
#    · rce triage profile added
#    · SCANNER_METADATA registry (per-scanner field schemas)
#    · triage_batch / assess_severity / explain_finding / suggest_payloads
#    · deduplicate / warmup / stats
#    · Retry-After header handling on 429 responses
#    · Kind-aware finding compaction
# =============================================================================

# from __future__ import annotations  # disabled for Python 3.6 (shared host)

import json
import os
import re
import sys
import time
import hashlib
import threading
from pathlib import Path

from huginn_utils import log, section, C, load_json, save_json, now_iso

try:
    import requests
except ImportError:
    print("[!] requests is required: pip install requests")
    sys.exit(2)

BRAIN_VERSION = "2.0.0"


# =============================================================================
#  .env LOADER
# =============================================================================
def _load_dotenv_inline(path):
    if not path.exists():
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass

_env_file = Path(__file__).parent / ".env"
try:
    from dotenv import load_dotenv
    load_dotenv(_env_file)
except ImportError:
    _load_dotenv_inline(_env_file)


# =============================================================================
#  PROVIDER REGISTRY
# =============================================================================
PROVIDERS = {
    "ollama": {
        "label":         "Ollama (local)",
        "key_envs":      [],
        "url_env":       "OLLAMA_BASE_URL",
        "model_env":     "OLLAMA_MODEL",
        "default_url":   "http://localhost:11434",
        "default_model": "qwen2.5:14b-instruct",
        "models_path":   "/api/tags",
        "chat_path":     "/v1/chat/completions",
        "probe_path":    "/api/tags",
        "kind":          "local",
        "cost_per_mtok": (0.0, 0.0),
    },
    "deepseek": {
        "label":         "DeepSeek",
        "key_envs":      ["DEEPSEEK_API_KEY"],
        "url_env":       "DEEPSEEK_BASE_URL",
        "model_env":     "DEEPSEEK_MODEL",
        "default_url":   "https://api.deepseek.com",
        "default_model": "deepseek-flash",
        "models_path":   "/v1/models",
        "chat_path":     "/v1/chat/completions",
        "probe_path":    "/v1/models",
        "kind":          "cloud",
        "cost_per_mtok": (0.14, 0.28),
    },
    "groq": {
        "label":         "Groq",
        "key_envs":      ["GROQ_API_KEY"],
        "url_env":       "GROQ_BASE_URL",
        "model_env":     "GROQ_MODEL",
        "default_url":   "https://api.groq.com/openai/v1",
        "default_model": "llama-3.1-8b-instant",
        "models_path":   "/models",
        "chat_path":     "/chat/completions",
        "probe_path":    "/models",
        "kind":          "cloud",
        "cost_per_mtok": (0.05, 0.08),
    },
    "huggingface": {
        "label":         "HuggingFace",
        "key_envs":      ["HUGGINGFACE_API_KEY", "HF_TOKEN",
                          "HUGGINGFACEHUB_API_TOKEN"],
        "url_env":       "HUGGINGFACE_BASE_URL",
        "model_env":     "HUGGINGFACE_MODEL",
        "default_url":   "https://router.huggingface.co/v1",
        "default_model": "meta-llama/Llama-3.1-8B-Instruct",
        "models_path":   "/models",
        "chat_path":     "/chat/completions",
        "probe_path":    "/models",
        "kind":          "cloud",
        "cost_per_mtok": (0.10, 0.20),
    },
}

DEFAULT_PRIORITY = ["ollama", "deepseek", "groq", "huggingface"]

# Single source of truth for what a "kind" is
VALID_SCANNERS = frozenset({
    "sqli", "xss", "ssrf", "rce", "idor",
    "open_redirect", "path_traversal",
})


# =============================================================================
#  SCANNER METADATA — per-scanner field schemas
# =============================================================================
#  These drive kind-aware compaction: the brain pulls the right fields into
#  the LLM prompt based on which scanner produced the finding.
#
#  To add a new scanner:
#    1. Add its slug to VALID_SCANNERS
#    2. Add a TRIAGE_PROFILES entry
#    3. Add a SCANNER_METADATA entry here
#  Nothing else in this file needs to change.
# =============================================================================
SCANNER_METADATA = {
    "sqli": {
        "label": "SQL Injection",
        "extra_fields": [
            "matched_dbms", "injection_point",
            "baseline_timing", "timing_stddev", "elapsed_seconds",
        ],
    },
    "xss": {
        "label": "Cross-Site Scripting",
        "extra_fields": [
            "reflection_context", "execution_confirmed",
            "browser_used", "dom_snapshot",
            "content_type", "encoding", "payload_context",
        ],
    },
    "ssrf": {
        "label": "Server-Side Request Forgery",
        "extra_fields": [
            "oob_hit", "callback_host", "internal_ip",
            "internal_response", "protocol", "port",
            "redirect_chain", "baseline_timing",
        ],
    },
    "rce": {
        "label": "Remote Code Execution",
        "extra_fields": [
            "command", "output", "oob_hit", "callback_host",
            "baseline_timing", "elapsed_seconds",
            "shell_type", "os_guess",
        ],
    },
    "idor": {
        "label": "Insecure Direct Object Reference",
        "extra_fields": [
            "resource_id", "baseline_id",
            "unauthorized_data", "baseline_snippet",
            "target_user", "access_control",
            "response_diff_bytes", "is_sequential_id",
        ],
    },
    "open_redirect": {
        "label": "Open Redirect",
        "extra_fields": [
            "redirect_target", "location_header",
            "redirect_type", "is_attacker_domain",
            "redirect_chain", "status_code",
        ],
    },
    "path_traversal": {
        "label": "Path Traversal / LFI",
        "extra_fields": [
            "file_target", "file_content_found",
            "signature_matched", "os_guess",
            "traversal_depth", "null_byte_used",
        ],
    },
}


# =============================================================================
#  TRIAGE PROFILES — per-scanner system prompts
# =============================================================================
_TRIAGE_OUTPUT_RULES = (
    "\n\nRespond with ONLY a JSON object. No markdown, no code fences, no "
    "prose. Format:\n"
    '{"verdict": "REAL" | "FALSE_POSITIVE" | "UNCERTAIN", '
    '"confidence": <float 0.0-1.0>, "reason": "<one sentence>"}\n\n'
    "Rules:\n"
    "- REAL: evidence clearly indicates a genuine vulnerability.\n"
    "- FALSE_POSITIVE: normal error, generic 403/404, WAF block, baseline "
    "noise, or verification_method that does not confirm exploitation.\n"
    "- UNCERTAIN: cannot decide from evidence alone; manual review needed.\n"
    "- Never explain outside the JSON. Never add fields."
)

TRIAGE_PROFILES = {
    "generic": {
        "system": (
            "You are HUGINN's security-finding triage engine. You receive "
            "structured JSON from automated scanners and decide whether the "
            "finding is a real vulnerability or a false positive."
        ),
        "focus": (
            "Check: does the evidence actually demonstrate exploitation, or "
            "does it show normal application behaviour? Is the baseline "
            "sufficiently different from the payload response?"
        ),
    },
    "sqli": {
        "system": (
            "You are HUGINN's SQL injection triage engine. You review SQLi "
            "findings from automated scanners and reject false positives."
        ),
        "focus": (
            "SQLi-specific checks:\n"
            "- error_signature: does the matched error come from the payload, "
            "not from the baseline response?\n"
            "- timing_confirmed: was the delay >3x baseline stddev and "
            "reproduced multiple times?\n"
            "- boolean_pair: do TRUE and FALSE responses differ meaningfully "
            "in length or content, and differ from baseline?\n"
            "- status_escalation: 5xx with SQL-ish body counts as weak; "
            "5xx without SQL-ish content is a false positive.\n"
            "- body_diff: response growth alone is NOT SQLi evidence. Mark "
            "UNCERTAIN at best unless other signals corroborate.\n"
            "A generic 403, 404, or WAF block page is a FALSE POSITIVE."
        ),
    },
    "xss": {
        "system": (
            "You are HUGINN's XSS triage engine. You review cross-site "
            "scripting findings and reject false positives."
        ),
        "focus": (
            "XSS-specific checks:\n"
            "- Is the payload reflected unescaped in an executable context "
            "(HTML body, attribute, script block, event handler)?\n"
            "- Reflection in a JSON response with Content-Type: application/"
            "json is not XSS unless the response is rendered as HTML.\n"
            "- Payload inside an HTML-encoded context (&lt; &gt; &amp;) is "
            "NOT XSS.\n"
            "- Reflection in a 404 page with no browser execution context is "
            "a FALSE POSITIVE.\n"
            "- If the scanner used a headless browser and JS executed, that "
            "is REAL with high confidence."
        ),
    },
    "ssrf": {
        "system": (
            "You are HUGINN's SSRF triage engine. You review server-side "
            "request forgery findings and reject false positives."
        ),
        "focus": (
            "SSRF-specific checks:\n"
            "- Did an out-of-band callback actually arrive at the collab "
            "host, or is the finding based on response timing only?\n"
            "- A response that echoes back the payload URL in a JSON/HTML "
            "field is NOT SSRF.\n"
            "- Internal IP access confirmed by response body content is REAL.\n"
            "- Timing-only signals are UNCERTAIN at best.\n"
            "- A 200 OK with no callback and no internal content is a FALSE "
            "POSITIVE."
        ),
    },
    "rce": {
        "system": (
            "You are HUGINN's remote code execution triage engine. You "
            "review RCE and command-injection findings from automated "
            "scanners and reject false positives."
        ),
        "focus": (
            "RCE-specific checks:\n"
            "- output_based: does the response contain command output? "
            "Signatures: 'uid=' from id, 'PING' from ping, 'total' from ls, "
            "'Directory of' from dir, Windows error codes from cmd.\n"
            "- timing_confirmed: was the delay >=3x baseline stddev and "
            "reproduced across attempts?\n"
            "- oob_based: did a callback actually arrive at the collab host? "
            "Is the timestamp consistent with the payload send?\n"
            "- Reflection of shell metacharacters (';', '|', '`', '$(') in "
            "the page body WITHOUT command output is NOT RCE.\n"
            "- 5xx errors caused by semicolons/pipes alone are weak signals — "
            "mark UNCERTAIN unless output or OOB is present.\n"
            "- Blind injection returning only 'ok' or 'error' is weak; "
            "require timing or OOB confirmation for REAL.\n"
            "- A generic 403/404 or WAF block page is a FALSE POSITIVE."
        ),
    },
    "idor": {
        "system": (
            "You are HUGINN's IDOR / broken-access-control triage engine."
        ),
        "focus": (
            "IDOR checks:\n"
            "- Does the response actually return another user's data?\n"
            "- A different resource ID returning 403/404 is NOT IDOR.\n"
            "- A response that differs from baseline only in a user-ID "
            "string is weak evidence.\n"
            "- Confirmed unauthorised data retrieval (another user's PII, "
            "orders, private objects) is REAL.\n"
            "- Sequential integer IDs on unauthenticated endpoints are "
            "strong IDOR candidates.\n"
            "- Numeric-ID substitution that returns identical content is a "
            "FALSE POSITIVE."
        ),
    },
    "open_redirect": {
        "system": (
            "You are HUGINN's open-redirect triage engine. You review "
            "redirect findings and reject false positives."
        ),
        "focus": (
            "Open-redirect checks:\n"
            "- Does the Location header point to an attacker-controlled host?\n"
            "- Redirects to the same domain, to a whitelisted host, or to "
            "relative paths are NOT open redirects.\n"
            "- A meta-refresh or JS-based redirect to an attacker host IS a "
            "real open redirect.\n"
            "- HTTP 302 to a hardcoded login page is a FALSE POSITIVE.\n"
            "- Redirect chains that end on the original domain are NOT "
            "exploitable."
        ),
    },
    "path_traversal": {
        "system": (
            "You are HUGINN's path-traversal / LFI triage engine."
        ),
        "focus": (
            "Path-traversal checks:\n"
            "- Does the response contain actual file content (root:x:0:0 in "
            "/etc/passwd, [extensions] in win.ini, etc.)?\n"
            "- Reflected payload without file content is NOT traversal.\n"
            "- Error messages mentioning filenames without content leakage "
            "are UNCERTAIN.\n"
            "- A 200 OK returning the requested page (SPA routing) is a "
            "FALSE POSITIVE.\n"
            "- Known file signatures (SHA/MD5 of standard files) confirm "
            "REAL with high confidence."
        ),
    },
}

DEFAULT_TRIAGE = "generic"


# =============================================================================
#  PAGE-LEVEL PROMPTS (for burp_to_sites)
# =============================================================================
CLASSIFY_SYSTEM = (
    "You are HUGINN's page classifier. Given a fetched page's metadata, "
    "decide if it is worth deep scanning.\n\n"
    'Respond with ONLY a JSON object: {"interesting": true|false, '
    '"kind": "<login|api|admin|form|static|error|other>", '
    '"reason": "<one sentence>"}\n\n'
    "Rules:\n"
    "- interesting=true for: login portals, admin panels, API endpoints, "
    "forms with parameters, search pages, file uploads, user profiles.\n"
    "- interesting=false for: marketing pages, static content, obvious 404s, "
    "WAF block pages, empty redirects, plain HTML with no inputs.\n"
    "- Never explain outside the JSON."
)

RECON_SYSTEM = (
    "You are HUGINN's page reconnaissance analyst. Given metadata and a "
    "body preview of a fetched URL, produce structured intelligence for a "
    "bug bounty hunter.\n\n"
    "Respond with ONLY a JSON object. No markdown, no prose. Format:\n"
    "{\n"
    '  "interesting": true | false,\n'
    '  "kind": "login|api|admin|form|static|error|other",\n'
    '  "priority": "high|medium|low",\n'
    '  "confidence": <float 0.0-1.0>,\n'
    '  "attack_surface": ["<short concrete observation>", ...],\n'
    '  "suggested_scanners": ["sqli","xss",...],\n'
    '  "notes": "<2-3 sentences from an ethical hacker perspective>",\n'
    '  "reason": "<one sentence>"\n'
    "}\n\n"
    "Known scanners: sqli, xss, ssrf, rce, idor, open_redirect, "
    "path_traversal.\n\n"
    "Rules:\n"
    "- interesting=false for marketing pages, static content, obvious 404s, "
    "WAF block pages, empty redirects.\n"
    "- attack_surface: concrete observations only (param names, form fields, "
    "missing security headers, exposed version strings, auth patterns). "
    "Maximum 5 items. Empty list if none.\n"
    "- suggested_scanners: only from the known list above. Pick scanners "
    "genuinely worth running against THIS page based on what you see.\n"
    "- notes: what YOU would try first as an attacker, and why. Be specific "
    "to what you observe, not generic.\n"
    "- Never explain outside the JSON. Never add fields."
)


# =============================================================================
#  HIGH-LEVEL PROMPTS (for advanced helpers)
# =============================================================================
PAYLOAD_SYSTEM = (
    "You are HUGINN's payload advisor. Given a target context and a "
    "vulnerability class, propose the most promising payloads to try next.\n\n"
    "Respond with ONLY a JSON object. No markdown. Format:\n"
    '{"payloads": ["<payload>", ...], "rationale": "<one sentence>"}\n\n'
    "Rules:\n"
    "- Maximum 10 payloads.\n"
    "- Every payload must be a self-contained string.\n"
    "- Prefer payloads that test for confirmation, not just detection.\n"
    "- Vary encoding and obfuscation if a WAF is suspected.\n"
    "- Never explain outside the JSON."
)

SEVERITY_SYSTEM = (
    "You are HUGINN's severity assessor. Given a confirmed vulnerability "
    "finding, assign a realistic severity.\n\n"
    "Respond with ONLY a JSON object. No markdown. Format:\n"
    "{\n"
    '  "severity": "critical|high|medium|low|info",\n'
    '  "confidence": <float 0.0-1.0>,\n'
    '  "impact": "<one sentence describing attacker capability>",\n'
    '  "cvss_estimate": <float 0.0-10.0 or null>,\n'
    '  "reason": "<one sentence>"\n'
    "}\n\n"
    "Rules:\n"
    "- critical: unauthenticated RCE, mass PII exfil, full auth bypass\n"
    "- high: authenticated RCE, single-user PII exfil, SQLi with data access\n"
    "- medium: SSRF with limited scope, stored XSS, IDOR of sensitive data\n"
    "- low: reflected XSS with user interaction, open redirect, path leak\n"
    "- info: version disclosure, missing headers, non-sensitive files\n"
    "- Never explain outside the JSON."
)

EXPLAIN_SYSTEM = (
    "You are HUGINN's report writer. Given a confirmed vulnerability "
    "finding, produce a concise, submission-ready explanation.\n\n"
    "Respond with ONLY a JSON object. No markdown. Format:\n"
    "{\n"
    '  "summary": "<one-line title>",\n'
    '  "impact": "<2-3 sentences on what an attacker could do>",\n'
    '  "remediation": "<2-3 sentences on how to fix>",\n'
    '  "references": ["<url>", ...]\n'
    "}\n\n"
    "Rules:\n"
    "- Be specific to the observed evidence, not generic.\n"
    "- References: OWASP, CWE, CVE where applicable. Maximum 3.\n"
    "- Never explain outside the JSON."
)

DEDUP_SYSTEM = (
    "You are HUGINN's finding deduplicator. Given a list of findings from "
    "the same scanner, identify which describe the same underlying issue.\n\n"
    "Respond with ONLY a JSON object. No markdown. Format:\n"
    '{"clusters": [\n'
    '  {"representative_idx": <int>, "duplicate_idxs": [<int>, ...], '
    '"reason": "<one sentence>"}\n'
    "]}\n\n"
    "Rules:\n"
    "- Findings are the same if: same parameter name, same vulnerability "
    "type, and evidence that a scanner would consider one issue.\n"
    "- Do not merge findings across different parameters or URL paths.\n"
    "- Every index must appear in exactly one cluster (as representative or "
    "duplicate).\n"
    "- Never explain outside the JSON."
)


# =============================================================================
#  CAPABILITY CACHE
# =============================================================================
_CAPABILITY_FILE = Path(__file__).parent / ".brain_capabilities.json"
_CAPABILITY_TTL = float(os.environ.get("BRAIN_CAPABILITY_TTL", "3600"))


class CapabilityCache:
    """Disk-backed, TTL'd record of which providers are usable."""

    def __init__(self, path=None, ttl=None):
        self.path = Path(path or _CAPABILITY_FILE)
        self.ttl = float(ttl if ttl is not None else _CAPABILITY_TTL)
        self._data = self._load()
        self._lock = threading.Lock()

    def _load(self):
        try:
            if self.path.exists():
                with open(self.path, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = str(self.path) + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp, str(self.path))
        except Exception:
            pass

    def get(self, slug):
        with self._lock:
            entry = self._data.get(slug)
            if not entry:
                return None
            age = time.time() - float(entry.get("checked_at", 0))
            if age > self.ttl:
                return None
            entry = dict(entry)
            entry["age_s"] = round(age, 1)
            return entry

    def put(self, slug, usable, reason, model=None, base_url=None,
            model_ids=None):
        with self._lock:
            self._data[slug] = {
                "usable":     bool(usable),
                "reason":     str(reason)[:200],
                "model":      model,
                "base_url":   base_url,
                "model_ids":  (model_ids or [])[:200],
                "checked_at": time.time(),
            }
            self._save()

    def invalidate(self, slug):
        with self._lock:
            self._data.pop(slug, None)
            self._save()

    def clear(self):
        with self._lock:
            self._data = {}
            self._save()

    def snapshot(self):
        with self._lock:
            return dict(self._data)


# =============================================================================
#  BUDGET
# =============================================================================
class BudgetExceeded(Exception):
    pass


class Budget:
    def __init__(self, max_calls=500, max_tokens=200_000,
                 max_seconds=1800.0, max_cost_usd=0.50):
        self.max_calls = int(max_calls)
        self.max_tokens = int(max_tokens)
        self.max_seconds = float(max_seconds)
        self.max_cost_usd = float(max_cost_usd)
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.cost_usd = 0.0
        self.started_at = time.time()
        self._lock = threading.Lock()

    def check(self, est_tokens=1000, est_cost=0.0):
        with self._lock:
            if self.calls + 1 > self.max_calls:
                raise BudgetExceeded("call limit ({})".format(self.max_calls))
            if self.tokens_in + self.tokens_out + est_tokens > self.max_tokens:
                raise BudgetExceeded("token limit ({})".format(self.max_tokens))
            if time.time() - self.started_at > self.max_seconds:
                raise BudgetExceeded("time limit ({})".format(self.max_seconds))
            if self.cost_usd + est_cost > self.max_cost_usd:
                raise BudgetExceeded("cost limit (${})".format(self.max_cost_usd))

    def record(self, tokens_in=0, tokens_out=0, cost_usd=0.0):
        with self._lock:
            self.calls += 1
            self.tokens_in += int(tokens_in or 0)
            self.tokens_out += int(tokens_out or 0)
            self.cost_usd += float(cost_usd or 0.0)

    def snapshot(self):
        with self._lock:
            return {
                "calls":       self.calls,
                "max_calls":   self.max_calls,
                "tokens_in":   self.tokens_in,
                "tokens_out":  self.tokens_out,
                "max_tokens":  self.max_tokens,
                "cost_usd":    round(self.cost_usd, 6),
                "max_cost":    self.max_cost_usd,
                "elapsed_s":   round(time.time() - self.started_at, 1),
                "max_seconds": self.max_seconds,
            }


# =============================================================================
#  TRIAGE CACHE
# =============================================================================
class TriageCache:
    def __init__(self, max_size=1000):
        self._d = {}
        self._order = []
        self._max = max_size
        self._lock = threading.Lock()

    def key(self, finding, kind):
        raw = "|".join([kind] + [str(finding.get(k, "")) for k in (
            "type", "subtype", "url", "parameter", "payload_id", "payload",
            "verification_method", "detection_reason",
        )])
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:32]

    def get(self, k):
        with self._lock:
            return self._d.get(k)

    def put(self, k, v):
        with self._lock:
            if k not in self._d:
                self._order.append(k)
            self._d[k] = v
            while len(self._order) > self._max:
                old = self._order.pop(0)
                self._d.pop(old, None)


# =============================================================================
#  BRAIN
# =============================================================================
class Brain:
    """Provider-agnostic LLM interface for every HUGINN scanner."""

    def __init__(self, priority=None, mode=None, force_refresh=False):
        self._lock = threading.Lock()
        self.mode = "off"
        self.provider = None
        self.cfg = None
        self.base_url = None
        self.model = None
        self.key = None
        self.models = []

        self.budget = Budget(
            max_calls=int(os.environ.get("BRAIN_MAX_CALLS", "500")),
            max_tokens=int(os.environ.get("BRAIN_MAX_TOKENS", "200000")),
            max_seconds=float(os.environ.get("BRAIN_MAX_SECONDS", "1800")),
            max_cost_usd=float(os.environ.get("BRAIN_MAX_COST_USD", "0.50")),
        )
        self.cache = TriageCache()
        self.cap = CapabilityCache()

        # Per-method call counters for stats()
        self._method_calls = {}
        self._method_lock = threading.Lock()

        self._priority = priority or [
            p.strip().lower()
            for p in os.environ.get(
                "BRAIN_PRIORITY", ",".join(DEFAULT_PRIORITY)
            ).split(",") if p.strip()
        ]
        self._mode_hint = (mode or os.environ.get("BRAIN_MODE", "auto")).lower()

        self._detect(force=force_refresh)

    # ------------------------------------------------------------------ #
    #  Detection & probing
    # ------------------------------------------------------------------ #
    def _detect(self, force=False):
        if not force and self.provider:
            return

        mode = self._mode_hint
        priority = list(self._priority)

        if mode == "off":
            self.mode = "off"
            self.provider = None
            return
        if mode == "local":
            priority = [p for p in priority if PROVIDERS[p]["kind"] == "local"]
        elif mode == "full":
            priority = [p for p in priority if PROVIDERS[p]["kind"] == "cloud"]

        for slug in priority:
            cfg = PROVIDERS.get(slug)
            if not cfg:
                continue
            result = self._probe(slug, cfg, force=force)
            if result["usable"]:
                self._apply_active(slug, cfg, result)
                return

        self.mode = "off"
        self.provider = None

    def _apply_active(self, slug, cfg, result):
        with self._lock:
            self.provider = slug
            self.cfg = cfg
            self.mode = "local" if cfg["kind"] == "local" else "full"
            self.base_url = result.get("base_url")
            self.model = result.get("model")
            self.key = result.get("key")
            self.models = result.get("model_ids") or []

    def _probe(self, slug, cfg, force=False):
        # 0. Cache lookup
        if not force:
            cached = self.cap.get(slug)
            if cached is not None:
                return {
                    "usable":    cached.get("usable", False),
                    "reason":    cached.get("reason", "cached"),
                    "model":     cached.get("model"),
                    "base_url":  cached.get("base_url"),
                    "key":       self._key_for(cfg),
                    "model_ids": cached.get("model_ids") or [],
                    "from_cache": True,
                }

        # 1. Key check
        key = self._key_for(cfg)
        if cfg["kind"] == "cloud" and not key:
            self.cap.put(slug, False, "no API key")
            return {"usable": False, "reason": "no API key", "model": None,
                    "base_url": None, "key": None, "model_ids": []}

        # 2. Base URL + models endpoint
        base_url = os.environ.get(cfg["url_env"], cfg["default_url"]).rstrip("/")
        url = base_url + cfg["probe_path"]
        headers = {}
        if key:
            headers["Authorization"] = "Bearer " + key

        probe_timeout = float(os.environ.get("BRAIN_PROBE_TIMEOUT", "10"))
        try:
            r = requests.get(url, headers=headers, timeout=probe_timeout)
        except Exception as e:
            reason = "{}: {}".format(type(e).__name__, str(e)[:80])
            log("probe {}: {}".format(slug, reason), "debug", "BRAIN")
            self.cap.put(slug, False, reason)
            return {"usable": False, "reason": reason, "model": None,
                    "base_url": base_url, "key": key, "model_ids": []}

        if r.status_code != 200:
            reason = "models HTTP {}".format(r.status_code)
            log("probe {}: {}".format(slug, reason), "debug", "BRAIN")
            self.cap.put(slug, False, reason)
            return {"usable": False, "reason": reason, "model": None,
                    "base_url": base_url, "key": key, "model_ids": []}

        # 3. Model selection
        model = os.environ.get(cfg["model_env"], cfg["default_model"]).strip()
        model_ids = self._parse_model_ids(slug, cfg, r)
        if model_ids and model not in model_ids:
            fallback = self._pick_fallback(slug, model_ids)
            if fallback:
                model = fallback

        # 4. Chat capability check
        do_chat = os.environ.get("BRAIN_PROBE_CHAT", "1") == "1"
        if cfg["kind"] == "local":
            do_chat = os.environ.get("BRAIN_PROBE_CHAT_LOCAL", "0") == "1"

        if do_chat:
            ok, reason = self._chat_capability_check(
                slug, cfg, base_url, key, model)
            if not ok:
                log("probe {}: chat failed: {}".format(slug, reason),
                    "debug", "BRAIN")
                self.cap.put(slug, False, reason, model=model,
                             base_url=base_url, model_ids=model_ids)
                return {"usable": False, "reason": reason, "model": model,
                        "base_url": base_url, "key": key,
                        "model_ids": model_ids}

        self.cap.put(slug, True, "ok", model=model, base_url=base_url,
                     model_ids=model_ids)
        return {"usable": True, "reason": "ok", "model": model,
                "base_url": base_url, "key": key, "model_ids": model_ids}

    def _chat_capability_check(self, slug, cfg, base_url, key, model):
        url = base_url + cfg["chat_path"]
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = "Bearer " + key

        body = {
            "model":       model,
            "messages":    [{"role": "user", "content": "ping"}],
            "max_tokens":  4,
            "temperature": 0.0,
            "stream":      False,
        }
        timeout = float(os.environ.get("BRAIN_CHAT_PROBE_TIMEOUT", "20"))
        try:
            r = requests.post(url, headers=headers,
                              data=json.dumps(body), timeout=timeout)
        except Exception as e:
            return False, "{}: {}".format(type(e).__name__, str(e)[:80])

        if r.status_code == 200:
            return True, "ok"

        msg = ""
        try:
            payload = r.json()
            if isinstance(payload, dict):
                err = payload.get("error")
                if isinstance(err, dict):
                    msg = err.get("message", "")
                elif isinstance(err, str):
                    msg = err
                if not msg:
                    msg = payload.get("message", "")
        except Exception:
            pass
        if not msg:
            msg = r.text[:100]

        return False, "HTTP {} {}".format(r.status_code, msg.strip()[:120])

    @staticmethod
    def _key_for(cfg):
        for env in cfg["key_envs"]:
            v = os.environ.get(env, "").strip()
            if v:
                return v
        return None

    @staticmethod
    def _parse_model_ids(slug, cfg, resp):
        try:
            data = resp.json()
        except Exception:
            return []
        ids = []
        if slug == "ollama":
            for m in data.get("models", []) or []:
                name = m.get("name") or m.get("model")
                if name:
                    ids.append(name)
        else:
            for m in data.get("data", []) or []:
                mid = m.get("id")
                if mid:
                    ids.append(mid)
        return ids

    @staticmethod
    def _pick_fallback(slug, ids):
        preferred = {
            "ollama":      ["qwen2.5:14b-instruct", "llama3.1:8b",
                            "qwen2.5:7b", "llama3.2:3b"],
            "deepseek":    ["deepseek-flash", "deepseek-chat",
                            "deepseek-reasoner"],
            "groq":        ["llama-3.1-8b-instant", "llama-3.3-70b-versatile",
                            "gemma2-9b-it"],
            "huggingface": [],
        }.get(slug, [])
        for p in preferred:
            if p in ids:
                return p
        for needle in ("instruct", "chat", "flash", "instant", "mini"):
            for i in ids:
                if needle in i.lower():
                    return i
        return ids[0] if ids else None

    # ------------------------------------------------------------------ #
    #  Public API — availability
    # ------------------------------------------------------------------ #
    def available(self):
        return self.mode != "off" and self.provider is not None

    def available_providers(self, force=False):
        """Return list of slugs currently usable. Uses capability cache."""
        out = []
        for slug in self._priority:
            cfg = PROVIDERS.get(slug)
            if not cfg:
                continue
            r = self._probe(slug, cfg, force=force)
            if r["usable"]:
                out.append(slug)
        return out

    def warmup(self, force=True):
        """
        Pre-probe every provider and populate the capability cache.
        Call once at the start of a session to avoid per-call probe delays.

        Returns:
            {slug: {"usable": bool, "reason": str, "model": str,
                    "latency_ms": int}}
        """
        out = {}
        for slug in self._priority:
            cfg = PROVIDERS.get(slug)
            if not cfg:
                continue
            t0 = time.time()
            r = self._probe(slug, cfg, force=force)
            dt = (time.time() - t0) * 1000
            out[slug] = {
                "usable":     r["usable"],
                "reason":     r["reason"],
                "model":      r.get("model"),
                "latency_ms": int(dt),
            }
        # Re-detect with fresh cache
        self._detect(force=False)
        return out

    def refresh(self, force=True):
        with self._lock:
            self.provider = None
        self._detect(force=force)

    # ------------------------------------------------------------------ #
    #  Public API — chat
    # ------------------------------------------------------------------ #
    def chat(self, messages, max_tokens=512, temperature=0.2,
             json_mode=False, timeout=45, _retry=0):
        if not self.available():
            return None
        try:
            self.budget.check(est_tokens=max_tokens)
        except BudgetExceeded as e:
            log("brain budget exceeded: {}".format(e), "warn", "BRAIN")
            return None

        self._bump_method("chat")

        url = self.base_url + self.cfg["chat_path"]
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key

        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        try:
            r = requests.post(url, headers=headers,
                              data=json.dumps(body), timeout=timeout)
        except Exception as e:
            log("brain chat error ({}): {}: {}".format(
                self.provider, type(e).__name__, e), "warn", "BRAIN")
            if _retry < 1:
                return self._failover(messages, max_tokens, temperature,
                                      json_mode, timeout, _retry)
            return None

        if r.status_code != 200:
            log("brain chat HTTP {} ({}): {}".format(
                r.status_code, self.provider, r.text[:160]),
                "warn", "BRAIN")

            # Respect Retry-After on 429
            if r.status_code == 429:
                ra = r.headers.get("Retry-After") or r.headers.get("retry-after")
                try:
                    wait = min(float(ra), 30.0) if ra else 2.0
                except Exception:
                    wait = 2.0
                log("rate limited; sleeping {:.1f}s".format(wait),
                    "info", "BRAIN")
                time.sleep(wait)

            # Demote and retry on transient/auth errors
            if r.status_code in (401, 402, 403, 429, 500, 502, 503, 504):
                if _retry < 1:
                    self.cap.invalidate(self.provider)
                    self.cap.put(self.provider, False,
                                 "chat HTTP {}".format(r.status_code))
                    return self._failover(messages, max_tokens, temperature,
                                          json_mode, timeout, _retry)
            return None

        try:
            data = r.json()
        except Exception:
            return None

        usage = data.get("usage") or {}
        tin = usage.get("prompt_tokens", 0) or 0
        tout = usage.get("completion_tokens", 0) or 0
        self.budget.record(tin, tout, self._estimate_cost(tin, tout))

        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            return None

    def _failover(self, messages, max_tokens, temperature, json_mode,
                  timeout, _retry):
        old = self.provider
        self.refresh(force=False)
        if not self.available() or self.provider == old:
            return None
        log("brain failover: {} -> {}".format(old, self.provider),
            "info", "BRAIN")
        return self.chat(messages, max_tokens, temperature, json_mode,
                         timeout, _retry=_retry + 1)

    def _estimate_cost(self, tin, tout):
        rates = self.cfg.get("cost_per_mtok", (0.0, 0.0)) if self.cfg else (0.0, 0.0)
        return (tin / 1_000_000.0) * rates[0] + (tout / 1_000_000.0) * rates[1]

    def _bump_method(self, name):
        with self._method_lock:
            self._method_calls[name] = self._method_calls.get(name, 0) + 1

    # ------------------------------------------------------------------ #
    #  Public API — triage (single & batch)
    # ------------------------------------------------------------------ #
    def triage(self, finding, kind=None):
        """
        Triage a single finding.

        Returns dict or None:
            {"verdict": "REAL|FALSE_POSITIVE|UNCERTAIN",
             "confidence": 0.0-1.0,
             "reason": "...",
             "kind": "sqli",
             "provider": "groq",
             "model": "...",
             "timestamp": "..."}
        """
        if not self.available():
            return None

        kind = (kind or finding.get("type") or DEFAULT_TRIAGE).lower()
        if kind not in VALID_SCANNERS:
            kind = DEFAULT_TRIAGE

        profile = TRIAGE_PROFILES.get(kind, TRIAGE_PROFILES[DEFAULT_TRIAGE])

        ck = self.cache.key(finding, kind)
        cached = self.cache.get(ck)
        if cached:
            return cached

        system_prompt = profile["system"] + "\n\n" + profile["focus"] + _TRIAGE_OUTPUT_RULES
        compact = self._compact_finding(finding, kind)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": json.dumps(compact, indent=2)},
        ]
        self._bump_method("triage")
        raw = self.chat(messages, max_tokens=256, temperature=0.0,
                        json_mode=True)
        if not raw:
            return None

        parsed = self._parse_json_reply(raw)
        if not parsed or "verdict" not in parsed:
            log("brain triage parse failed; raw={!r}".format(raw[:160]),
                "warn", "BRAIN")
            return None

        verdict = str(parsed.get("verdict", "")).upper().strip()
        if verdict not in ("REAL", "FALSE_POSITIVE", "UNCERTAIN"):
            verdict = "UNCERTAIN"

        result = {
            "verdict":    verdict,
            "confidence": float(parsed.get("confidence", 0.5) or 0.5),
            "reason":     str(parsed.get("reason", ""))[:280],
            "kind":       kind,
            "provider":   self.provider,
            "model":      self.model,
            "timestamp":  now_iso(),
        }
        self.cache.put(ck, result)
        return result

    def triage_batch(self, findings, kind=None, max_workers=2):
        """
        Triage a list of findings concurrently.

        Returns:
            list of (index, finding, verdict_or_None) sorted by index.
            If brain is off, verdicts are all None.
        """
        if not self.available():
            return [(i, f, None) for i, f in enumerate(findings)]

        results = [None] * len(findings)
        sem = threading.Semaphore(max(1, max_workers))

        def worker(i, f):
            with sem:
                try:
                    results[i] = self.triage(f, kind=kind)
                except Exception as e:
                    log("batch triage error idx={}: {}: {}".format(
                        i, type(e).__name__, e), "warn", "BRAIN")
                    results[i] = None

        threads = []
        for i, f in enumerate(findings):
            t = threading.Thread(target=worker, args=(i, f))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return [(i, findings[i], results[i]) for i in range(len(findings))]

    # ------------------------------------------------------------------ #
    #  Public API — page intelligence (for burp_to_sites)
    # ------------------------------------------------------------------ #
    def classify_page(self, page):
        """Quick binary interesting/not-interesting classification."""
        if not self.available():
            return None
        meta = {
            "url":            page.get("url"),
            "status":         page.get("status"),
            "content_type":   page.get("content_type"),
            "content_length": page.get("content_length"),
            "title":          (page.get("title") or "")[:200],
            "params":         page.get("params", []),
            "has_form":       "<form" in (page.get("content") or "").lower(),
            "body_head":      (page.get("content") or "")[:1200],
        }
        messages = [
            {"role": "system", "content": CLASSIFY_SYSTEM},
            {"role": "user",   "content": json.dumps(meta, indent=2)},
        ]
        self._bump_method("classify_page")
        raw = self.chat(messages, max_tokens=128, temperature=0.0,
                        json_mode=True)
        if not raw:
            return None
        parsed = self._parse_json_reply(raw)
        if not isinstance(parsed, dict) or "interesting" not in parsed:
            return None
        return {
            "interesting": bool(parsed.get("interesting")),
            "kind":        str(parsed.get("kind", "other"))[:32],
            "reason":      str(parsed.get("reason", ""))[:200],
            "provider":    self.provider,
            "model":       self.model,
        }

    def recon_page(self, page, force=False):
        """Rich page reconnaissance. See module docstring for schema."""
        if not self.available():
            return None

        url = page.get("url") or ""
        status = page.get("status")
        ctype = (page.get("content_type") or "").split(";")[0].strip()
        clen = page.get("content_length")

        ck = "recon:" + hashlib.sha256(
            "{}|{}|{}|{}".format(url, status, ctype, clen).encode(
                "utf-8", errors="ignore")
        ).hexdigest()[:32]
        if not force:
            cached = self.cache.get(ck)
            if cached:
                return cached

        body = (page.get("content") or "")[:3000]
        meta = {
            "url":            url,
            "status":         status,
            "content_type":   ctype,
            "content_length": clen,
            "title":          (page.get("title") or "")[:200],
            "params":         page.get("params", []),
            "cookies":        list((page.get("cookies") or {}).keys())[:10],
            "has_form":       "<form" in body.lower(),
            "body_head":      body,
        }

        messages = [
            {"role": "system", "content": RECON_SYSTEM},
            {"role": "user",   "content": json.dumps(meta, indent=2)},
        ]
        self._bump_method("recon_page")
        raw = self.chat(messages, max_tokens=512, temperature=0.2,
                        json_mode=True)
        if not raw:
            return None

        parsed = self._parse_json_reply(raw)
        if not isinstance(parsed, dict) or "interesting" not in parsed:
            log("recon parse failed for {}; raw={!r}".format(
                url[:80], raw[:160]), "warn", "BRAIN")
            return None

        priority = str(parsed.get("priority", "medium")).lower().strip()
        if priority not in ("high", "medium", "low"):
            priority = "medium"

        surface = parsed.get("attack_surface") or []
        if not isinstance(surface, list):
            surface = []
        surface = [str(x)[:200] for x in surface][:5]

        scanners = parsed.get("suggested_scanners") or []
        if not isinstance(scanners, list):
            scanners = []
        scanners = [s for s in scanners
                    if isinstance(s, str) and s.lower() in VALID_SCANNERS][:6]

        result = {
            "interesting":        bool(parsed.get("interesting")),
            "kind":               str(parsed.get("kind", "other"))[:32],
            "priority":           priority,
            "confidence":         float(parsed.get("confidence", 0.5) or 0.5),
            "attack_surface":     surface,
            "suggested_scanners": scanners,
            "notes":              str(parsed.get("notes", ""))[:600],
            "reason":             str(parsed.get("reason", ""))[:280],
            "provider":           self.provider,
            "model":              self.model,
            "timestamp":          now_iso(),
        }
        self.cache.put(ck, result)
        return result

    # ------------------------------------------------------------------ #
    #  Public API — orchestration helpers
    # ------------------------------------------------------------------ #
    def suggest_next(self, context):
        """Free-form next-action suggestions. Returns list of strings or None."""
        if not self.available():
            return None
        messages = [
            {"role": "system",
             "content": ("You are HUGINN's orchestration advisor. Given the "
                         "current scan state, suggest the highest-value next "
                         "actions. Respond with ONLY a JSON array of short "
                         "strings (1-5 items). No markdown.")},
            {"role": "user", "content": json.dumps(context, indent=2)},
        ]
        self._bump_method("suggest_next")
        raw = self.chat(messages, max_tokens=200, temperature=0.3,
                        json_mode=True)
        if not raw:
            return None
        parsed = self._parse_json_reply(raw)
        if isinstance(parsed, list):
            return [str(x)[:200] for x in parsed][:5]
        if isinstance(parsed, dict) and isinstance(parsed.get("actions"), list):
            return [str(x)[:200] for x in parsed["actions"]][:5]
        return None

    def suggest_payloads(self, context, kind="sqli", max_payloads=10):
        """
        Context-aware payload suggestions for a stuck scanner.

        context example:
            {
              "url": "https://t/x?id=1",
              "method": "GET",
              "parameter": "id",
              "waf_hint": "cloudflare",
              "dbms_hint": "mysql",
              "baseline_status": 200,
              "baseline_content_type": "text/html",
              "tried_payloads": ["'", "' OR 1=1--"],
              "response_snippet": "...",
              "notes": "WAF blocked obvious quotes"
            }

        Returns list of payload strings, or None.
        """
        if not self.available():
            return None
        if kind not in VALID_SCANNERS:
            kind = "sqli"

        user_body = {
            "vulnerability_class": kind,
            "context":             context,
            "max_payloads":        int(max_payloads),
        }
        messages = [
            {"role": "system", "content": PAYLOAD_SYSTEM},
            {"role": "user",   "content": json.dumps(user_body, indent=2)},
        ]
        self._bump_method("suggest_payloads")
        raw = self.chat(messages, max_tokens=400, temperature=0.4,
                        json_mode=True)
        if not raw:
            return None
        parsed = self._parse_json_reply(raw)
        if not isinstance(parsed, dict):
            return None
        payloads = parsed.get("payloads") or []
        if not isinstance(payloads, list):
            return None
        return [str(p) for p in payloads if isinstance(p, str)][:max_payloads]

    def assess_severity(self, finding, kind=None):
        """
        Refine severity of a CONFIRMED finding. Returns dict or None.

        Returns:
            {"severity": "critical|high|medium|low|info",
             "confidence": 0.0-1.0,
             "impact": "...",
             "cvss_estimate": float_or_None,
             "reason": "...",
             "provider": "...",
             "model": "..."}
        """
        if not self.available():
            return None
        kind = (kind or finding.get("type") or DEFAULT_TRIAGE).lower()
        if kind not in VALID_SCANNERS:
            kind = DEFAULT_TRIAGE

        compact = self._compact_finding(finding, kind)
        messages = [
            {"role": "system", "content": SEVERITY_SYSTEM},
            {"role": "user",   "content": json.dumps(compact, indent=2)},
        ]
        self._bump_method("assess_severity")
        raw = self.chat(messages, max_tokens=256, temperature=0.0,
                        json_mode=True)
        if not raw:
            return None
        parsed = self._parse_json_reply(raw)
        if not isinstance(parsed, dict):
            return None

        severity = str(parsed.get("severity", "medium")).lower().strip()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        cvss = parsed.get("cvss_estimate")
        try:
            cvss = float(cvss) if cvss is not None else None
            if cvss is not None and (cvss < 0.0 or cvss > 10.0):
                cvss = None
        except Exception:
            cvss = None

        return {
            "severity":      severity,
            "confidence":    float(parsed.get("confidence", 0.5) or 0.5),
            "impact":        str(parsed.get("impact", ""))[:280],
            "cvss_estimate": cvss,
            "reason":        str(parsed.get("reason", ""))[:280],
            "provider":      self.provider,
            "model":         self.model,
        }

    def explain_finding(self, finding, kind=None):
        """
        Generate a human-readable explanation for reports.
        Returns dict or None.
        """
        if not self.available():
            return None
        kind = (kind or finding.get("type") or DEFAULT_TRIAGE).lower()
        if kind not in VALID_SCANNERS:
            kind = DEFAULT_TRIAGE

        compact = self._compact_finding(finding, kind)
        messages = [
            {"role": "system", "content": EXPLAIN_SYSTEM},
            {"role": "user",   "content": json.dumps(compact, indent=2)},
        ]
        self._bump_method("explain_finding")
        raw = self.chat(messages, max_tokens=512, temperature=0.2,
                        json_mode=True)
        if not raw:
            return None
        parsed = self._parse_json_reply(raw)
        if not isinstance(parsed, dict):
            return None

        refs = parsed.get("references") or []
        if not isinstance(refs, list):
            refs = []
        refs = [str(r)[:200] for r in refs if isinstance(r, str)][:3]

        return {
            "summary":     str(parsed.get("summary", ""))[:200],
            "impact":      str(parsed.get("impact", ""))[:600],
            "remediation": str(parsed.get("remediation", ""))[:600],
            "references":  refs,
            "provider":    self.provider,
            "model":       self.model,
        }

    def deduplicate(self, findings, kind=None, max_items=50):
        """
        Cluster similar findings. Returns list of clusters or None.

        Each cluster:
            {"representative_idx": int,
             "duplicate_idxs": [int, ...],
             "reason": "..."}

        If fewer than 2 findings, returns [[single cluster]] trivially.
        If brain is off, returns None.
        """
        if not self.available() or len(findings) < 2:
            return None

        sample = findings[:max_items]
        compact_list = []
        for i, f in enumerate(sample):
            c = self._compact_finding(f, kind)
            c["_idx"] = i
            compact_list.append(c)

        messages = [
            {"role": "system", "content": DEDUP_SYSTEM},
            {"role": "user",   "content": json.dumps(compact_list, indent=2)},
        ]
        self._bump_method("deduplicate")
        raw = self.chat(messages, max_tokens=1024, temperature=0.0,
                        json_mode=True)
        if not raw:
            return None
        parsed = self._parse_json_reply(raw)
        if not isinstance(parsed, dict):
            return None
        clusters = parsed.get("clusters") or []
        if not isinstance(clusters, list):
            return None

        out = []
        for cl in clusters:
            if not isinstance(cl, dict):
                continue
            rep = cl.get("representative_idx")
            dups = cl.get("duplicate_idxs") or []
            if not isinstance(rep, int) or rep < 0 or rep >= len(sample):
                continue
            dups = [d for d in dups
                    if isinstance(d, int) and 0 <= d < len(sample) and d != rep]
            out.append({
                "representative_idx": rep,
                "duplicate_idxs":     dups,
                "reason":             str(cl.get("reason", ""))[:200],
            })
        return out

    def embed(self, texts):
        """RAG stub. Returns None until an embedder is wired in."""
        return None

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _compact_finding(f, kind=None):
        """Kind-aware compaction: pull the fields that matter for this scanner."""
        kind = (kind or f.get("type") or "generic").lower()

        compact = {
            "type":                f.get("type"),
            "subtype":             f.get("subtype"),
            "url":                 f.get("url"),
            "method":              f.get("method"),
            "parameter":           f.get("parameter"),
            "verification_method": f.get("verification_method"),
            "detection_reason":    f.get("detection_reason"),
            "evidence":            (f.get("evidence") or "")[:500],
            "response_status":     f.get("response_status"),
            "baseline_status":     f.get("baseline_status"),
            "response_length":     f.get("response_length"),
            "baseline_length":     f.get("baseline_length"),
            "response_snippet":    (f.get("response_snippet") or "")[:800],
            "payload":             (f.get("payload") or "")[:300],
        }

        meta = SCANNER_METADATA.get(kind, {})
        for field in meta.get("extra_fields", []):
            val = f.get(field)
            if val is None:
                continue
            if isinstance(val, str):
                compact[field] = val[:400]
            elif isinstance(val, (dict, list)):
                # Serialize but bound the size
                try:
                    s = json.dumps(val)
                    compact[field] = s[:400] if len(s) > 400 else val
                except Exception:
                    compact[field] = str(val)[:200]
            else:
                compact[field] = val

        return compact

    @staticmethod
    def _parse_json_reply(raw):
        if not raw:
            return None
        s = raw.strip()

        # Strip ```json ... ``` fences
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)

        # Try direct parse
        try:
            return json.loads(s)
        except Exception:
            pass

        # Try stripping trailing commas
        s2 = re.sub(r",(\s*[}\]])", r"\1", s)
        try:
            return json.loads(s2)
        except Exception:
            pass

        # Fallback: grab first {...} or [...]
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                try:
                    return json.loads(re.sub(r",(\s*[}\]])", r"\1", m.group(0)))
                except Exception:
                    pass
        m = re.search(r"\[.*\]", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------ #
    #  Diagnostics
    # ------------------------------------------------------------------ #
    def status(self):
        return {
            "version":  BRAIN_VERSION,
            "mode":     self.mode,
            "provider": self.provider,
            "label":    self.cfg["label"] if self.cfg else None,
            "base_url": self.base_url,
            "model":    self.model,
            "models":   self.models,
            "budget":   self.budget.snapshot(),
        }

    def stats(self):
        """Return detailed session statistics including per-method call counts."""
        with self._method_lock:
            methods = dict(self._method_calls)
        return {
            "version":        BRAIN_VERSION,
            "provider":       self.provider,
            "mode":           self.mode,
            "budget":         self.budget.snapshot(),
            "methods":        methods,
            "capabilities":   self.cap.snapshot(),
        }


# =============================================================================
#  SINGLETON
# =============================================================================
_BRAIN = None
_BRAIN_LOCK = threading.Lock()


def get_brain(priority=None, mode=None, refresh=False):
    global _BRAIN
    with _BRAIN_LOCK:
        if _BRAIN is None:
            _BRAIN = Brain(priority=priority, mode=mode)
        elif refresh:
            _BRAIN.refresh()
        return _BRAIN


# =============================================================================
#  CLI
# =============================================================================
def _cmd_status():
    b = get_brain()
    st = b.status()
    print()
    print("{}HUGINN :: brain status{}".format(C.CY + C.B, C.R))
    print("{}{}{}".format(C.D, "─" * 60, C.R))
    print("  version   : {}".format(st.get("version", "?")))
    mode_color = {"full": C.GR, "local": C.CY, "off": C.RE}.get(st["mode"], C.R)
    print("  mode      : {}{}{}".format(mode_color, st["mode"].upper(), C.R))
    print("  provider  : {}".format(st["provider"] or "—"))
    print("  label     : {}".format(st["label"] or "—"))
    print("  base_url  : {}".format(st["base_url"] or "—"))
    print("  model     : {}".format(st["model"] or "—"))
    print("  models    : {} known".format(len(st["models"])))
    bud = st["budget"]
    print()
    print("  budget    : calls {}/{}  tokens {}/{}  cost ${:.4f}/${}".format(
        bud["calls"], bud["max_calls"],
        bud["tokens_in"] + bud["tokens_out"], bud["max_tokens"],
        bud["cost_usd"], bud["max_cost"]))
    print()
    return 0 if st["mode"] != "off" else 1


def _cmd_providers():
    b = get_brain()
    force = os.environ.get("BRAIN_PROBE_FORCE", "") == "1"

    print()
    print("{}HUGINN :: provider capability matrix{}".format(C.CY + C.B, C.R))
    print("{}{}{}".format(C.D, "─" * 90, C.R))
    print("  {:<14} {:<10} {:<10} {:<44} {}".format(
        "provider", "reachable", "usable", "reason", "model"))
    print("{}{}{}".format(C.D, "─" * 90, C.R))

    for slug in b._priority:
        cfg = PROVIDERS.get(slug)
        if not cfg:
            continue
        r = b._probe(slug, cfg, force=force)
        reach = "yes" if r.get("base_url") else "no"
        usable = "yes" if r["usable"] else "no"
        reason = r["reason"][:42]
        model = (r.get("model") or "—")[:40]
        color = C.GR if r["usable"] else C.RE
        print("  {:<14} {:<10} {}{:<10}{} {:<44} {}".format(
            slug, reach, color, usable, C.R, reason, model))
    print()
    print("{}({}) Capability cache: {}".format(
        C.D, "forced re-probe" if force else "using cache",
        b.cap.path))
    print("Set BRAIN_PROBE_FORCE=1 to force a fresh probe.{}".format(C.R))
    print()
    return 0 if b.available() else 1


def _cmd_warmup():
    b = get_brain()
    print()
    print("{}HUGINN :: brain warmup{}".format(C.CY + C.B, C.R))
    print("{}{}{}".format(C.D, "─" * 70, C.R))
    results = b.warmup(force=True)
    for slug, r in results.items():
        icon = "{}✓{}".format(C.GR, C.R) if r["usable"] else "{}✗{}".format(C.RE, C.R)
        print("  {} {:<14} {:>6} ms   {}   {}".format(
            icon, slug, r["latency_ms"],
            (r["model"] or "—")[:36], r["reason"][:40]))
    print()
    print("  active provider: {}{}{}".format(
        C.B, b.provider or "—", C.R))
    print()
    return 0 if b.available() else 1


def _cmd_test():
    b = get_brain()
    if not b.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    log("using {} ({})".format(b.cfg["label"], b.model), "info", "BRAIN")
    reply = b.chat(
        [{"role": "user", "content": "Reply with exactly: HUGINN-BRAIN-OK"}],
        max_tokens=32, temperature=0.0)
    if not reply:
        log("no reply", "err", "BRAIN")
        return 1
    log("reply: {}".format(reply.strip()[:120]), "ok", "BRAIN")
    return 0


def _cmd_models():
    b = get_brain()
    if not b.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    section("Models on {}".format(b.cfg["label"]))
    for m in b.models:
        print("  · {}".format(m))
    return 0


def _cmd_triage(path, kind=None):
    b = get_brain()
    if not b.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    try:
        finding = load_json(path)
    except Exception as e:
        log("cannot read {}: {}".format(path, e), "err")
        return 1
    verdict = b.triage(finding, kind=kind)
    if not verdict:
        log("triage returned nothing", "warn", "BRAIN")
        return 1
    print()
    print("{}verdict   :{} {}".format(C.B, C.R, verdict["verdict"]))
    print("{}confidence:{} {:.2f}".format(C.B, C.R, verdict["confidence"]))
    print("{}reason    :{} {}".format(C.B, C.R, verdict["reason"]))
    print("{}profile   :{} {}".format(C.B, C.R, verdict["kind"]))
    print("{}provider  :{} {} ({})".format(C.B, C.R,
        verdict["provider"], verdict["model"]))
    print()
    return 0


def _cmd_explain(path, kind=None):
    b = get_brain()
    if not b.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    try:
        finding = load_json(path)
    except Exception as e:
        log("cannot read {}: {}".format(path, e), "err")
        return 1
    exp = b.explain_finding(finding, kind=kind)
    if not exp:
        log("explain returned nothing", "warn", "BRAIN")
        return 1
    print()
    print("{}summary    :{} {}".format(C.B, C.R, exp["summary"]))
    print("{}impact     :{} {}".format(C.B, C.R, exp["impact"]))
    print("{}remediation:{} {}".format(C.B, C.R, exp["remediation"]))
    if exp["references"]:
        print("{}references :{}".format(C.B, C.R))
        for r in exp["references"]:
            print("  · {}".format(r))
    print()
    return 0


def _cmd_severity(path, kind=None):
    b = get_brain()
    if not b.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    try:
        finding = load_json(path)
    except Exception as e:
        log("cannot read {}: {}".format(path, e), "err")
        return 1
    sev = b.assess_severity(finding, kind=kind)
    if not sev:
        log("severity assessment returned nothing", "warn", "BRAIN")
        return 1
    print()
    print("{}severity   :{} {}".format(C.B, C.R, sev["severity"]))
    print("{}confidence :{} {:.2f}".format(C.B, C.R, sev["confidence"]))
    print("{}impact     :{} {}".format(C.B, C.R, sev["impact"]))
    if sev["cvss_estimate"] is not None:
        print("{}cvss       :{} {:.1f}".format(C.B, C.R, sev["cvss_estimate"]))
    print("{}reason     :{} {}".format(C.B, C.R, sev["reason"]))
    print()
    return 0


def _cmd_stats():
    b = get_brain()
    st = b.stats()
    print()
    print("{}HUGINN :: brain session stats{}".format(C.CY + C.B, C.R))
    print("{}{}{}".format(C.D, "─" * 60, C.R))
    print("  version  : {}".format(st["version"]))
    print("  provider : {}".format(st["provider"] or "—"))
    print("  mode     : {}".format(st["mode"]))
    print()
    bud = st["budget"]
    print("  calls    : {}/{}".format(bud["calls"], bud["max_calls"]))
    print("  tokens   : in={} out={} total={}/{}".format(
        bud["tokens_in"], bud["tokens_out"],
        bud["tokens_in"] + bud["tokens_out"], bud["max_tokens"]))
    print("  cost     : ${:.4f}/${}".format(bud["cost_usd"], bud["max_cost"]))
    print("  elapsed  : {}s".format(bud["elapsed_s"]))
    print()
    if st["methods"]:
        print("  per-method calls:")
        for name, count in sorted(st["methods"].items()):
            print("    {:<20} {}".format(name, count))
    print()
    return 0


def _cmd_reset_cache():
    b = get_brain()
    b.cap.clear()
    log("capability cache cleared", "ok", "BRAIN")
    return 0


def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="brain",
        description="HUGINN brain v{} — provider-agnostic LLM interface".format(
            BRAIN_VERSION),
    )
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("status",        help="show active provider / budget")
    sub.add_parser("providers",     help="capability matrix for all providers")
    sub.add_parser("warmup",        help="force-probe all providers and cache")
    sub.add_parser("test",          help="send a hello message")
    sub.add_parser("models",        help="list models for the active provider")
    sub.add_parser("stats",         help="session stats and per-method counts")
    sub.add_parser("reset-cache",   help="clear the capability cache")
    sub.add_parser("version",       help="print brain version")
    sub.add_parser("reset",         help="clear singleton")

    p_t = sub.add_parser("triage", help="triage a finding JSON file")
    p_t.add_argument("file")
    p_t.add_argument("--kind", default=None,
                     help="force scanner profile (sqli|xss|ssrf|rce|idor|"
                          "open_redirect|path_traversal)")

    p_e = sub.add_parser("explain", help="explain a finding for a report")
    p_e.add_argument("file")
    p_e.add_argument("--kind", default=None)

    p_s = sub.add_parser("severity", help="assess severity of a finding")
    p_s.add_argument("file")
    p_s.add_argument("--kind", default=None)

    args = ap.parse_args()
    if args.cmd == "status":       return _cmd_status()
    if args.cmd == "providers":    return _cmd_providers()
    if args.cmd == "warmup":       return _cmd_warmup()
    if args.cmd == "test":         return _cmd_test()
    if args.cmd == "models":       return _cmd_models()
    if args.cmd == "stats":        return _cmd_stats()
    if args.cmd == "reset-cache":  return _cmd_reset_cache()
    if args.cmd == "version":
        print("HUGINN brain v{}".format(BRAIN_VERSION))
        return 0
    if args.cmd == "triage":       return _cmd_triage(args.file, args.kind)
    if args.cmd == "explain":      return _cmd_explain(args.file, args.kind)
    if args.cmd == "severity":     return _cmd_severity(args.file, args.kind)
    if args.cmd == "reset":
        global _BRAIN
        with _BRAIN_LOCK:
            _BRAIN = None
        log("brain singleton cleared", "ok")
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    try:
        sys.exit(_cli())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
