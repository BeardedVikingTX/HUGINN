#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: brain.py — v1.0
#  Provider-agnostic LLM interface.
# -----------------------------------------------------------------------------
#  Design goals:
#    · One interface, many providers (Ollama, DeepSeek, Groq, HuggingFace)
#    · Auto-detect what's available at startup; fall back gracefully
#    · NEVER raise — if no provider is usable, callers get None and continue
#    · Budget-aware — cap calls / tokens / seconds / USD per session
#    · Thread-safe — scanners use ThreadPoolExecutor
#    · Cache identical triage calls to avoid paying twice
#
#  States:
#    full   — a cloud API key is present and reachable
#    local  — Ollama is reachable on localhost:11434
#    off    — nothing available; AI hooks become no-ops
#
#  Provider priority (override via BRAIN_PRIORITY in .env):
#    ollama, deepseek, groq, huggingface
#
#  Usage:
#    from brain import get_brain
#    brain = get_brain()
#    if brain.available():
#        verdict = brain.triage(finding)
#        if verdict and verdict["verdict"] == "FALSE_POSITIVE":
#            return
#
#  CLI:
#    python3 brain.py status           # show what's available
#    python3 brain.py test             # send a hello message
#    python3 brain.py triage FILE      # triage a finding JSON
#    python3 brain.py models           # list models for the active provider
# =============================================================================

from __future__ import annotations

import json
import os
import re
import sys
import time
import hashlib
import threading
from pathlib import Path

from huginn_utils import log, section, C, load_json, save_json, now_iso

# ---- .env support -----------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

try:
    import requests
except ImportError:
    print("[!] requests is required: pip install requests")
    sys.exit(2)


# =============================================================================
#  PROVIDER REGISTRY
# =============================================================================
PROVIDERS = {
    "ollama": {
        "label":         "Ollama (local)",
        "key_envs":      [],                               # no key needed
        "url_env":       "OLLAMA_BASE_URL",
        "model_env":     "OLLAMA_MODEL",
        "default_url":   "http://localhost:11434",
        "default_model": "qwen2.5:14b-instruct",
        "models_path":   "/api/tags",                      # native Ollama
        "chat_path":     "/v1/chat/completions",           # OpenAI-compat shim
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

# Triage system prompt — tight, format-locked, no room for prose.
TRIAGE_SYSTEM = (
    "You are HUGINN's triage engine. You analyze security-scanner findings "
    "and decide whether they are real vulnerabilities or false positives.\n\n"
    "Respond with ONLY a JSON object. No markdown, no code fences, no "
    "explanation outside the JSON. Format:\n"
    '{"verdict": "REAL" | "FALSE_POSITIVE" | "UNCERTAIN", '
    '"confidence": <float 0.0-1.0>, "reason": "<one sentence>"}\n\n'
    "Rules:\n"
    "- REAL: evidence clearly indicates a genuine vulnerability.\n"
    "- FALSE_POSITIVE: normal error page, generic 403/404, WAF block, or "
    "detector matched baseline noise.\n"
    "- UNCERTAIN: needs manual review; you cannot decide from the evidence.\n"
    "- Never explain outside the JSON. Never add fields. Never wrap in prose."
)

SUGGEST_SYSTEM = (
    "You are HUGINN's orchestration advisor. Given the current scan state, "
    "suggest the highest-value next actions.\n\n"
    "Respond with ONLY a JSON array of short strings (1-5 items). "
    "No markdown, no explanation."
)


# =============================================================================
#  BUDGET
# =============================================================================
class BudgetExceeded(Exception):
    pass


class Budget:
    """Per-session budget for LLM calls."""

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
                raise BudgetExceeded(f"call limit ({self.max_calls})")
            if self.tokens_in + self.tokens_out + est_tokens > self.max_tokens:
                raise BudgetExceeded(f"token limit ({self.max_tokens})")
            if time.time() - self.started_at > self.max_seconds:
                raise BudgetExceeded(f"time limit ({self.max_seconds}s)")
            if self.cost_usd + est_cost > self.max_cost_usd:
                raise BudgetExceeded(f"cost limit (${self.max_cost_usd})")

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
#  TRIAGE CACHE  (bounded LRU-ish)
# =============================================================================
class TriageCache:
    def __init__(self, max_size=1000):
        self._d = {}
        self._order = []
        self._max = max_size
        self._lock = threading.Lock()

    def key(self, finding):
        raw = "|".join(str(finding.get(k, "")) for k in (
            "type", "subtype", "url", "parameter", "payload_id", "payload",
            "verification_method", "detection_reason",
        ))
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
    Provider-agnostic LLM interface.

    Never raises. Callers should check `available()` before using, but
    even if they don't, every method returns None on failure.
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
            if self._probe(slug, cfg):
                self.provider = slug
                self.cfg = cfg
                self.mode = "local" if cfg["kind"] == "local" else "full"
                return

        self.mode = "off"
        self.provider = None

    def _probe(self, slug, cfg):
        """Return True if this provider is usable right now."""
        # 1. Key check (cloud providers only)
        key = None
        for env in cfg["key_envs"]:
            v = os.environ.get(env, "").strip()
            if v:
                key = v
                break
        if cfg["kind"] == "cloud" and not key:
            return False

        # 2. Base URL
        base_url = os.environ.get(cfg["url_env"], cfg["default_url"]).rstrip("/")

        # 3. Probe
        url = f"{base_url}{cfg['probe_path']}"
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        try:
            r = requests.get(url, headers=headers, timeout=3)
        except Exception:
            return False
        if r.status_code != 200:
            return False

        # 4. Model selection
        model = os.environ.get(cfg["model_env"], cfg["default_model"]).strip()
        model_ids = self._parse_model_ids(slug, cfg, r)

        # Ollama: /api/tags shape is {"models":[{"name": "..."}]}
        # Cloud: /v1/models shape is {"data":[{"id": "..."}]}
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

    def refresh(self):
        with self._lock:
            self.provider = None
        self._detect(force=True)

    def chat(self, messages, max_tokens=512, temperature=0.2,
             json_mode=False, timeout=45):
        """
        Low-level chat. Returns the assistant's string, or None on any error.
        Honors the session budget.
        """
        if not self.available():
            return None
        try:
            self.budget.check(est_tokens=max_tokens)
        except BudgetExceeded as e:
            log(f"brain budget exceeded: {e}", "warn", "BRAIN")
            return None

        url = f"{self.base_url}{self.cfg['chat_path']}"
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"

        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if json_mode:
            # OpenAI-compatible response_format
            body["response_format"] = {"type": "json_object"}

        try:
            r = requests.post(url, headers=headers,
                              data=json.dumps(body), timeout=timeout)
        except Exception as e:
            log(f"brain chat error ({self.provider}): {e}", "warn", "BRAIN")
            return None

        if r.status_code != 200:
            log(f"brain chat HTTP {r.status_code} ({self.provider}): "
                f"{r.text[:200]}", "warn", "BRAIN")
            return None

        try:
            data = r.json()
        except Exception:
            return None

        usage = data.get("usage") or {}
        tin = usage.get("prompt_tokens", 0) or 0
        tout = usage.get("completion_tokens", 0) or 0
        cost = self._estimate_cost(tin, tout)
        self.budget.record(tokens_in=tin, tokens_out=tout, cost_usd=cost)

        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            return None

    def _estimate_cost(self, tin, tout):
        rates = self.cfg.get("cost_per_mtok", (0.0, 0.0)) if self.cfg else (0.0, 0.0)
        return (tin / 1_000_000.0) * rates[0] + (tout / 1_000_000.0) * rates[1]

    # ------------------------------------------------------------------ #
    #  High-level helpers
    # ------------------------------------------------------------------ #
    def triage(self, finding):
        """
        Ask the brain whether a finding is REAL / FALSE_POSITIVE / UNCERTAIN.

        Returns:
            {"verdict": "...", "confidence": 0-1, "reason": "...",
             "provider": "...", "model": "..."}
        or None if the brain is off, budget exceeded, or parsing failed.
        """
        if not self.available():
            return None

        ck = self.cache.key(finding)
        cached = self.cache.get(ck)
        if cached:
            return cached

        compact = self._compact_finding(finding)
        messages = [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user",   "content": json.dumps(compact, indent=2)},
        ]
        raw = self.chat(messages, max_tokens=256, temperature=0.0,
                        json_mode=True)
        if not raw:
            return None

        parsed = self._parse_json_reply(raw)
        if not parsed or "verdict" not in parsed:
            log(f"brain triage parse failed; raw={raw[:160]!r}",
                "warn", "BRAIN")
            return None

        verdict = str(parsed.get("verdict", "")).upper().strip()
        if verdict not in ("REAL", "FALSE_POSITIVE", "UNCERTAIN"):
            verdict = "UNCERTAIN"

        result = {
            "verdict":    verdict,
            "confidence": float(parsed.get("confidence", 0.5) or 0.5),
            "reason":     str(parsed.get("reason", ""))[:280],
            "provider":   self.provider,
            "model":      self.model,
            "timestamp":  now_iso(),
        }
        self.cache.put(ck, result)
        return result

    def suggest_next(self, context):
        """Return a list of suggested next actions, or None."""
        if not self.available():
            return None
        messages = [
            {"role": "system", "content": SUGGEST_SYSTEM},
            {"role": "user",   "content": json.dumps(context, indent=2)},
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
        """
        Stub for RAG. Returns None until a local embedder or a cloud
        embedding provider is wired in. Callers must handle None.
        """
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
        }

    @staticmethod
    def _parse_json_reply(raw):
        """Strip fences, extract first JSON object/array, parse."""
        if not raw:
            return None
        s = raw.strip()
        # Strip ```json ... ``` fences
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
        try:
            return json.loads(s)
        except Exception:
            pass
        # Fallback: grab first {...} or [...]
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

    # ------------------------------------------------------------------ #
    #  Diagnostics
    # ------------------------------------------------------------------ #
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
#  CLI
# =============================================================================
def _cmd_status():
    brain = get_brain()
    st = brain.status()

    print()
    print(f"{C.CY}{C.B}HUGINN :: brain status{C.R}")
    print(f"{C.D}{'─' * 60}{C.R}")

    mode_color = {
        "full":  C.GR,
        "local": C.CY,
        "off":   C.RE,
    }.get(st["mode"], C.R)

    print(f"  mode      : {mode_color}{st['mode'].upper()}{C.R}")
    print(f"  provider  : {st['provider'] or '—'}")
    print(f"  label     : {st['label'] or '—'}")
    print(f"  base_url  : {st['base_url'] or '—'}")
    print(f"  model     : {st['model'] or '—'}")
    print(f"  models    : {len(st['models'])} known")

    b = st["budget"]
    print()
    print(f"  budget    : calls {b['calls']}/{b['max_calls']}  "
          f"tokens {b['tokens_in'] + b['tokens_out']}/{b['max_tokens']}  "
          f"cost ${b['cost_usd']:.4f}/${b['max_cost']}")
    print()

    if st["mode"] == "off":
        print(f"{C.YE}No provider available. Scanners will run without AI.{C.R}")
        print(f"{C.D}  · Start Ollama, or set DEEPSEEK_API_KEY / GROQ_API_KEY / "
              f"HUGGINGFACE_API_KEY{C.R}")
        print(f"{C.D}  · Force off explicitly with BRAIN_MODE=off{C.R}")
        print()

    return 0 if st["mode"] != "off" else 1


def _cmd_test():
    brain = get_brain()
    if not brain.available():
        log("brain is off — no provider available", "warn", "BRAIN")
        return 1
    log(f"using {brain.cfg['label']} ({brain.model})", "info", "BRAIN")
    reply = brain.chat(
        [{"role": "user",
          "content": "Reply with exactly: HUGINN-BRAIN-OK"}],
        max_tokens=32, temperature=0.0,
    )
    if not reply:
        log("no reply", "err", "BRAIN")
        return 1
    log(f"reply: {reply.strip()[:120]}", "ok", "BRAIN")
    log(f"budget: {brain.budget.snapshot()}", "info", "BRAIN")
    return 0


def _cmd_models():
    brain = get_brain()
    if not brain.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    section(f"Models on {brain.cfg['label']}")
    for m in brain.models:
        print(f"  · {m}")
    return 0


def _cmd_triage(path):
    brain = get_brain()
    if not brain.available():
        log("brain is off", "warn", "BRAIN")
        return 1
    try:
        finding = load_json(path)
    except Exception as e:
        log(f"cannot read {path}: {e}", "err")
        return 1
    verdict = brain.triage(finding)
    if not verdict:
        log("triage returned nothing", "warn", "BRAIN")
        return 1
    print()
    print(f"{C.B}verdict   :{C.R} {verdict['verdict']}")
    print(f"{C.B}confidence:{C.R} {verdict['confidence']:.2f}")
    print(f"{C.B}reason    :{C.R} {verdict['reason']}")
    print(f"{C.B}provider  :{C.R} {verdict['provider']} ({verdict['model']})")
    print()
    return 0


def _cli():
    import argparse
    ap = argparse.ArgumentParser(prog="brain",
                                 description="HUGINN brain CLI")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status", help="show provider / budget status")
    sub.add_parser("test",   help="send a hello message")
    sub.add_parser("models", help="list models for the active provider")
    p_t = sub.add_parser("triage", help="triage a finding JSON file")
    p_t.add_argument("file")
    sub.add_parser("reset",  help="clear the singleton (for testing)")

    args = ap.parse_args()
    if args.cmd == "status":
        return _cmd_status()
    if args.cmd == "test":
        return _cmd_test()
    if args.cmd == "models":
        return _cmd_models()
    if args.cmd == "triage":
        return _cmd_triage(args.file)
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
