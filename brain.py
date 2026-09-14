#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: brain.py — v1.1
#  Provider-agnostic LLM interface with scanner-aware triage.
# -----------------------------------------------------------------------------
#  What's new in v1.1:
#    · import requests FIX (the whole reason status showed OFF)
#    · Non-silent probe / chat errors (logged, never swallowed)
#    · TRIAGE_PROFILES — per-scanner system prompts
#    · classify_page() — for burp_to_sites post-fetch tagging
#    · available_providers() — for multi-provider consensus
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

# ---- .env support (dotenv if present, inline fallback otherwise) ------------
def _load_dotenv_inline(path):
    """Minimal .env parser. Doesn't overwrite existing env vars."""
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


# =============================================================================
#  TRIAGE PROFILES  — per-scanner system prompts
# =============================================================================
#  Each profile has:
#    system  : the base instructions
#    focus   : scanner-specific things the model should check
#
#  The `kind` argument to triage() picks the profile. If omitted, the brain
#  looks at finding["type"] and falls back to "generic".
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
            "- HTTP 302 to a hardcoded login page is a FALSE POSITIVE."
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
            "FALSE POSITIVE."
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
            "orders, private objects) is REAL."
        ),
    },
}

DEFAULT_TRIAGE = "generic"

# Page classification (for burp_to_sites post-fetch tagging)
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
    """
    Provider-agnostic LLM interface with scanner-aware triage.
    Never raises. Callers should check `available()` first.
    """

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

        self._priority = priority or [
            p.strip().lower()
            for p in os.environ.get(
                "BRAIN_PRIORITY", ",".join(DEFAULT_PRIORITY)
            ).split(",") if p.strip()
        ]
        self._mode_hint = (mode or os.environ.get("BRAIN_MODE", "auto")).lower()

        self._detect(force=force_refresh)

    # ------------------------------------------------------------------ #
    #  Detection
    # ------------------------------------------------------------------ #
    def _detect(self, force=False):
        if not force and self.provider:
            return
        mode = self._mode_hint
        priority = self._priority
        if mode == "off":
            self.mode = "off"; self.provider = None; return
        if mode == "local":
            priority = [p for p in priority if PROVIDERS[p]["kind"] == "local"]
        elif mode == "full":
            priority = [p for p in priority if PROVIDERS[p]["kind"] == "cloud"]

        for slug in priority:
            cfg = PROVIDERS.get(slug)
            if not cfg:
                continue
            if self._probe(slug, cfg):
                self.provider = slug
                self.cfg = cfg
                self.mode = "local" if cfg["kind"] == "local" else "full"
                return
        self.mode = "off"
        self.provider = None

    def _probe(self, slug, cfg):
        key = None
        for env in cfg["key_envs"]:
            v = os.environ.get(env, "").strip()
            if v:
                key = v
                break
        if cfg["kind"] == "cloud" and not key:
            return False

        base_url = os.environ.get(cfg["url_env"], cfg["default_url"]).rstrip("/")
        url = base_url + cfg["probe_path"]
        headers = {}
        if key:
            headers["Authorization"] = "Bearer " + key

        probe_timeout = float(os.environ.get("BRAIN_PROBE_TIMEOUT", "10"))
        try:
            r = requests.get(url, headers=headers, timeout=probe_timeout)
        except Exception as e:
            log("probe {} failed: {}: {}".format(slug, type(e).__name__, e),
                "debug", "BRAIN")
            return False
        if r.status_code != 200:
            log("probe {} HTTP {}".format(slug, r.status_code),
                "debug", "BRAIN")
            return False

        model = os.environ.get(cfg["model_env"], cfg["default_model"]).strip()
        model_ids = self._parse_model_ids(slug, cfg, r)
        if model_ids and model not in model_ids:
            fallback = self._pick_fallback(slug, model_ids)
            if fallback:
                model = fallback

        with self._lock:
            self.base_url = base_url
            self.model = model
            self.key = key
            self.models = model_ids
        return True

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
    #  Public API
    # ------------------------------------------------------------------ #
    def available(self):
        return self.mode != "off" and self.provider is not None

    def available_providers(self):
        """Return list of slugs currently usable. Useful for consensus."""
        out = []
        for slug in self._priority:
            cfg = PROVIDERS.get(slug)
            if cfg and self._probe(slug, cfg):
                out.append(slug)
        return out

    def refresh(self):
        with self._lock:
            self.provider = None
        self._detect(force=True)

    def chat(self, messages, max_tokens=512, temperature=0.2,
             json_mode=False, timeout=45):
        if not self.available():
            return None
        try:
            self.budget.check(est_tokens=max_tokens)
        except BudgetExceeded as e:
            log("brain budget exceeded: {}".format(e), "warn", "BRAIN")
            return None

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
            return None

        if r.status_code != 200:
            log("brain chat HTTP {} ({}): {}".format(
                r.status_code, self.provider, r.text[:200]),
                "warn", "BRAIN")
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

    def _estimate_cost(self, tin, tout):
        rates = self.cfg.get("cost_per_mtok", (0.0, 0.0)) if self.cfg else (0.0, 0.0)
        return (tin / 1_000_000.0) * rates[0] + (tout / 1_000_000.0) * rates[1]

    # ------------------------------------------------------------------ #
    #  Triage
    # ------------------------------------------------------------------ #
    def triage(self, finding, kind=None):
        """
        Triage a scanner finding.

        kind: "sqli" | "xss" | "ssrf" | "open_redirect" | "path_traversal"
              | "idor" | "generic" | None (auto-detect from finding["type"])

        Returns dict or None if brain off / budget exceeded / parse failed.
        """
        if not self.available():
            return None

        kind = (kind or finding.get("type") or DEFAULT_TRIAGE).lower()
        profile = TRIAGE_PROFILES.get(kind, TRIAGE_PROFILES[DEFAULT_TRIAGE])

        ck = self.cache.key(finding, kind)
        cached = self.cache.get(ck)
        if cached:
            return cached

        system_prompt = profile["system"] + "\n\n" + profile["focus"] + _TRIAGE_OUTPUT_RULES
        compact = self._compact_finding(finding)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": json.dumps(compact, indent=2)},
        ]
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

    # ------------------------------------------------------------------ #
    #  Page classification (for burp_to_sites)
    # ------------------------------------------------------------------ #
    def classify_page(self, page):
        """
        Given a fetched page record, decide if it's worth deep scanning.
        Returns {"interesting": bool, "kind": str, "reason": str} or None.
        """
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

    def suggest_next(self, context):
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

    def embed(self, texts):
        """RAG stub. Returns None until an embedder is wired in."""
        return None

    # ------------------------------------------------------------------ #
    #  Internals
    # ------------------------------------------------------------------ #
    @staticmethod
    def _compact_finding(f):
        return {
            "type":                f.get("type"),
            "subtype":             f.get("subtype"),
            "url":                 f.get("url"),
            "method":              f.get("method"),
            "parameter":           f.get("parameter"),
            "payload":             (f.get("payload") or "")[:300],
            "verification_method": f.get("verification_method"),
            "detection_reason":    f.get("detection_reason"),
            "evidence":            (f.get("evidence") or "")[:500],
            "response_status":     f.get("response_status"),
            "baseline_status":     f.get("baseline_status"),
            "response_length":     f.get("response_length"),
            "baseline_length":     f.get("baseline_length"),
            "response_snippet":    (f.get("response_snippet") or "")[:800],
            # xss / ssrf / open_redirect specific fields, if present
            "reflection_context":  f.get("reflection_context"),
            "redirect_target":     f.get("redirect_target"),
            "oob_hit":             f.get("oob_hit"),
        }

    @staticmethod
    def _parse_json_reply(raw):
        if not raw:
            return None
        s = raw.strip()
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
        try:
            return json.loads(s)
        except Exception:
            pass
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        m = re.search(r"\[.*\]", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        return None

    def status(self):
        return {
            "mode":     self.mode,
            "provider": self.provider,
            "label":    self.cfg["label"] if self.cfg else None,
            "base_url": self.base_url,
            "model":    self.model,
            "models":   self.models,
            "budget":   self.budget.snapshot(),
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
#  CLI (unchanged from v1.0, plus a quick smoke test)
# =============================================================================
def _cmd_status():
    b = get_brain()
    st = b.status()
    print()
    print("{}HUGINN :: brain status{}".format(C.CY + C.B, C.R))
    print("{}{}{}".format(C.D, "─" * 60, C.R))
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


def _cli():
    import argparse
    ap = argparse.ArgumentParser(prog="brain")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status", help="show provider / budget status")
    sub.add_parser("test",   help="send a hello message")
    sub.add_parser("models", help="list models for the active provider")
    sub.add_parser("providers", help="list all currently usable providers")
    p_t = sub.add_parser("triage", help="triage a finding JSON file")
    p_t.add_argument("file")
    p_t.add_argument("--kind", default=None,
                     help="force scanner profile (sqli|xss|ssrf|...)")
    sub.add_parser("reset",  help="clear singleton")

    args = ap.parse_args()
    if args.cmd == "status":    return _cmd_status()
    if args.cmd == "test":      return _cmd_test()
    if args.cmd == "models":    return _cmd_models()
    if args.cmd == "providers":
        b = get_brain()
        for s in b.available_providers():
            print("  + {}".format(s))
        return 0
    if args.cmd == "triage":    return _cmd_triage(args.file, args.kind)
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
