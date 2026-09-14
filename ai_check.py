#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUGINN :: ai_check.py

Verify LLM provider connectivity, enumerate available models, and
prove end-to-end chat completion works.

Providers (auto-detected from environment / .env):
  • DeepSeek      DEEPSEEK_API_KEY
  • Groq          GROQ_API_KEY
  • Hugging Face  HUGGINGFACE_API_KEY  (also accepts HF_TOKEN,
                                        HUGGINGFACEHUB_API_TOKEN)

Usage:
    python3 ai_check.py                     # test every provider with a key
    python3 ai_check.py --quick             # key + reachability only
    python3 ai_check.py --models            # key + model list only
    python3 ai_check.py -p groq             # restrict to one provider
    python3 ai_check.py -p groq,deepseek    # restrict to a subset
    python3 ai_check.py --json              # emit machine-readable JSON only
    python3 ai_check.py --no-color          # disable ANSI colors
    python3 ai_check.py -v                  # verbose (print every model ID)

Exit codes:
    0  all tested providers passed
    1  at least one provider failed or was partial
    2  no provider keys found / fatal error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# --- .env support (optional) -------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    # Not fatal - we can run against exported env vars only.
    pass

try:
    import requests
except ImportError:
    print("[!] 'requests' is required. Install with: pip install requests")
    sys.exit(2)


# =============================================================================
#  PROVIDER REGISTRY
# =============================================================================
PROVIDERS = {
    "deepseek": {
        "label":         "DeepSeek",
        "key_envs":      ["DEEPSEEK_API_KEY"],
        "url_env":       "DEEPSEEK_BASE_URL",
        "model_env":     "DEEPSEEK_MODEL",
        "default_url":   "https://api.deepseek.com",
        "default_model": "deepseek-chat",
        "models_path":   "/v1/models",
        "chat_path":     "/v1/chat/completions",
        "docs":          "https://platform.deepseek.com/api_keys",
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
        "docs":          "https://console.groq.com/keys",
    },
    "huggingface": {
        "label":         "Hugging Face",
        "key_envs":      ["HUGGINGFACE_API_KEY",
                          "HF_TOKEN",
                          "HUGGINGFACEHUB_API_TOKEN"],
        "url_env":       "HUGGINGFACE_BASE_URL",
        "model_env":     "HUGGINGFACE_MODEL",
        "default_url":   "https://router.huggingface.co/v1",
        "default_model": "meta-llama/Llama-3.1-8B-Instruct",
        "models_path":   "/models",
        "chat_path":     "/chat/completions",
        "docs":          "https://huggingface.co/settings/tokens",
    },
}


# =============================================================================
#  OUTPUT
# =============================================================================
COLOR = True
QUIET = False


class C:
    R  = "\033[0m";  B  = "\033[1m";  D  = "\033[2m"
    CY = "\033[38;5;51m"; GR = "\033[38;5;46m"
    YE = "\033[38;5;226m"; RE = "\033[38;5;196m"
    MA = "\033[38;5;201m"; GY = "\033[38;5;240m"
    WH = "\033[38;5;255m"


def _disable_color():
    for attr in list(vars(C)):
        if attr.startswith("_"):
            continue
        setattr(C, attr, "")


def _p(*a, **kw):
    if not QUIET:
        print(*a, **kw)


def hr():           _p(f"{C.D}{'─' * 66}{C.R}")
def ok(msg):        _p(f"{C.GR}[+]{C.R} {msg}")
def info(msg):      _p(f"{C.CY}[*]{C.R} {msg}")
def warn(msg):      _p(f"{C.YE}[!]{C.R} {msg}")
def err(msg):       _p(f"{C.RE}[-]{C.R} {msg}")
def dim(msg):       _p(f"{C.D}{msg}{C.R}")


# =============================================================================
#  UTILITIES
# =============================================================================
def resolve_key(cfg):
    """Return (env_name, value) for the first populated key env var."""
    for env in cfg["key_envs"]:
        val = os.environ.get(env, "").strip()
        if val:
            return env, val
    return None, None


def mask_key(k):
    if not k:
        return ""
    if len(k) <= 12:
        return "***"
    return f"{k[:7]}...{k[-4:]}"


def http_get(url, key, timeout=10):
    t0 = time.time()
    try:
        r = requests.get(url,
                         headers={"Authorization": f"Bearer {key}",
                                  "Accept": "application/json"},
                         timeout=timeout)
        return r, time.time() - t0, None
    except requests.exceptions.RequestException as e:
        return None, time.time() - t0, e


def http_post_json(url, key, body, timeout=30):
    t0 = time.time()
    try:
        r = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            data=json.dumps(body),
            timeout=timeout,
        )
        return r, time.time() - t0, None
    except requests.exceptions.RequestException as e:
        return None, time.time() - t0, e


def pick_fallback(ids, slug):
    preferred = {
        "deepseek":    ["deepseek-chat", "deepseek-flash", "deepseek-reasoner"],
        "groq":        ["llama-3.1-8b-instant", "llama-3.3-70b-versatile",
                        "gemma2-9b-it", "mixtral-8x7b-32768"],
        "huggingface": [],
    }.get(slug, [])
    for p in preferred:
        if p in ids:
            return p
    for needle in ("chat", "instruct", "flash", "instant", "versatile", "mini"):
        for i in ids:
            if needle in i.lower():
                return i
    return ids[0]


def _col(plain, colored, width):
    """Pad `colored` string to visible width based on `plain` length."""
    return colored + " " * max(0, width - len(plain))


# =============================================================================
#  CHAT / TRIAGE TESTS
# =============================================================================
def test_completion(base_url, cfg, key, model):
    url  = f"{base_url}{cfg['chat_path']}"
    body = {
        "model": model,
        "messages": [
            {"role": "system",
             "content": "You are HUGINN's analysis engine. "
                        "Reply in one short sentence."},
            {"role": "user",
             "content": "Confirm you are online and ready to assist "
                        "with security research."},
        ],
        "max_tokens":  64,
        "temperature": 0.2,
        "stream":      False,
    }
    r, dt, ex = http_post_json(url, key, body, timeout=30)
    if ex:
        return None, dt, ex, None
    if r is None:
        return None, dt, RuntimeError("no response"), None
    if r.status_code != 200:
        return r, dt, None, None
    try:
        return r, dt, None, r.json()
    except Exception as e:
        return r, dt, e, None


def test_triage(base_url, cfg, key, model):
    finding = {
        "url":                "https://example.com/search",
        "parameter":          "q",
        "payload":            "'; EXEC('SELECT 0x61646d696e')-- ",
        "response_snippet":   "<h1>403</h1><p>Access to this resource on "
                              "the server is denied!</p>",
        "verification_method": "body_diff",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system",
             "content": ('You are HUGINN\'s triage engine. Reply with only: '
                         '"REAL" or "FALSE_POSITIVE", then a colon, then a '
                         'one-line reason.')},
            {"role": "user", "content": json.dumps(finding, indent=2)},
        ],
        "max_tokens":  64,
        "temperature": 0.0,
        "stream":      False,
    }
    r, dt, ex = http_post_json(
        f"{base_url}{cfg['chat_path']}", key, body, timeout=30
    )
    if ex or r is None or r.status_code != 200:
        return None, dt, ex
    try:
        data = r.json()
    except Exception:
        return None, dt, None
    reply = ((data.get("choices") or [{}])[0]
             .get("message", {}).get("content", "").strip())
    return reply or None, dt, None


# =============================================================================
#  PER-PROVIDER FLOW
# =============================================================================
def check_provider(slug, cfg, opts):
    res = {
        "provider":             slug,
        "label":                cfg["label"],
        "key_present":          False,
        "key_source":           None,
        "key_masked":           None,
        "base_url":             None,
        "reachable":            False,
        "status_code":          None,
        "models_latency_s":     None,
        "models_count":         0,
        "models":               [],
        "test_model":           None,
        "completion_ok":        False,
        "completion_latency_s": None,
        "usage":                {},
        "triage_ok":            False,
        "triage_verdict":       None,
        "errors":               [],
        "status":               "unknown",   # ok | partial | fail | missing_key
    }

    _p()
    _p(f"{C.CY}{C.B}▸ {cfg['label']}{C.R}  {C.GY}({slug}){C.R}")
    hr()

    # ----- API key -----------------------------------------------------------
    key_env, key = resolve_key(cfg)
    if not key:
        err(f"no API key set (looked for: {', '.join(cfg['key_envs'])})")
        dim(f"    get one at: {cfg['docs']}")
        res["status"] = "missing_key"
        return res

    res["key_present"] = True
    res["key_source"]  = key_env
    res["key_masked"]  = mask_key(key)
    ok(f"API key: {res['key_masked']}  (from {key_env})")

    # ----- Base URL ----------------------------------------------------------
    base_url = os.environ.get(cfg["url_env"], cfg["default_url"]).rstrip("/")
    res["base_url"] = base_url
    info(f"Base URL: {base_url}")

    # ----- Models endpoint (soft-fail unless auth is broken) ----------------
    models_url = f"{base_url}{cfg['models_path']}"
    r, dt, ex = http_get(models_url, key, timeout=10)
    res["models_latency_s"] = round(dt, 3)

    if ex:
        err(f"connection failed: {ex}")
        res["errors"].append(str(ex))
        res["status"] = "fail"
        return res

    res["status_code"] = r.status_code
    ids = []

    if r.status_code == 401:
        err("API key rejected (HTTP 401 Unauthorized)")
        res["errors"].append("401 unauthorized")
        res["status"] = "fail"
        return res
    if r.status_code == 403:
        err("forbidden (HTTP 403) - key may lack required scope")
        res["errors"].append("403 forbidden")
        res["status"] = "fail"
        return res

    if r.status_code == 200:
        res["reachable"] = True
        ok(f"reachable  ({res['models_latency_s'] * 1000:.0f} ms)")
        try:
            payload = r.json()
        except Exception:
            payload = {}
        models = payload.get("data", []) if isinstance(payload, dict) else []
        ids = [m.get("id") for m in models
               if isinstance(m, dict) and m.get("id")]
        res["models"]       = ids
        res["models_count"] = len(ids)

        if ids:
            info(f"{len(ids)} model(s) available")
            show_n = len(ids) if opts.verbose else min(10, len(ids))
            for mid in ids[:show_n]:
                _p(f"    {C.GY}·{C.R} {mid}")
            if show_n < len(ids):
                dim(f"    … +{len(ids) - show_n} more (use -v to list all)")
        else:
            warn("no models returned by /models endpoint")
    else:
        warn(f"models endpoint returned HTTP {r.status_code} "
             f"- chat test will still be attempted")
        res["errors"].append(f"models http {r.status_code}")

    if opts.models_only:
        res["status"] = "ok" if ids else "partial"
        return res

    # ----- Model selection ---------------------------------------------------
    configured = os.environ.get(cfg["model_env"], cfg["default_model"]).strip()
    test_model = configured
    if ids and configured not in ids:
        warn(f"configured model '{configured}' not in catalog")
        test_model = pick_fallback(ids, slug)
        warn(f"falling back to '{test_model}'")
    res["test_model"] = test_model
    info(f"test model: {test_model}")

    if opts.quick:
        res["status"] = "ok"
        return res

    # ----- Chat completion ---------------------------------------------------
    _p()
    info(f"chat completion  →  {test_model}")
    r, dt, ex, data = test_completion(base_url, cfg, key, test_model)
    res["completion_latency_s"] = round(dt, 3)

    if ex:
        err(f"completion error: {ex}")
        res["errors"].append(f"completion: {ex}")
        res["status"] = "partial"
        return res

    if r is None or r.status_code != 200:
        code    = r.status_code if r is not None else "?"
        snippet = r.text[:300] if r is not None else ""
        err(f"completion failed (HTTP {code})")
        if snippet:
            dim(f"    {snippet}")
        res["errors"].append(f"completion http {code}")
        res["status"] = "partial"
        return res

    if data is None:
        err("completion returned unparseable payload")
        res["status"] = "partial"
        return res

    choice  = (data.get("choices") or [{}])[0]
    content = (choice.get("message") or {}).get("content", "").strip()
    usage   = data.get("usage", {}) or {}

    res["completion_ok"] = True
    res["usage"] = {
        "prompt_tokens":     usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens":      usage.get("total_tokens"),
    }
    ok(f"completion ok  ({res['completion_latency_s'] * 1000:.0f} ms)")
    _p(f"    {C.WH}{content}{C.R}")
    if usage:
        dim(f"    tokens: in={usage.get('prompt_tokens', '?')}  "
            f"out={usage.get('completion_tokens', '?')}  "
            f"total={usage.get('total_tokens', '?')}")

    # ----- Triage dry-run ----------------------------------------------------
    _p()
    info("triage dry-run  →  sample false-positive finding")
    reply, tdt, tex = test_triage(base_url, cfg, key, test_model)
    if tex or not reply:
        warn("triage dry-run skipped (endpoint refused or empty reply)")
        res["status"] = "ok"
        return res

    res["triage_ok"]      = True
    res["triage_verdict"] = reply
    ok(f"verdict: {C.B}{reply}{C.R}")
    res["status"] = "ok"
    return res


# =============================================================================
#  SUMMARY
# =============================================================================
def print_summary(results):
    if QUIET:
        return
    _p()
    _p(f"{C.CY}{C.B}Summary{C.R}")
    hr()
    header = (f"{'Provider':<14} {'Key':<6} {'HTTP':<6} {'Models':<8} "
              f"{'Chat':<6} {'Latency':<12} {'Tokens':<8}")
    _p(f"{C.B}{header}{C.R}")
    _p(f"{C.D}{'─' * 66}{C.R}")

    for r in results:
        if r["status"] == "missing_key":
            _p(f"{r['label']:<14} "
               f"{C.RE}✗{C.R}      "
               f"{'—':<6} {'—':<8} {'—':<6} {'—':<12} {'—':<8}")
            continue

        key_p = "✓" if r["key_present"] else "✗"
        key_c = f"{C.GR}{key_p}{C.R}" if r["key_present"] else f"{C.RE}{key_p}{C.R}"

        http_p = str(r["status_code"]) if r["status_code"] else "—"
        mod_p  = str(r["models_count"])

        if r["completion_ok"]:
            chat_p, chat_c = "✓", f"{C.GR}✓{C.R}"
        elif r["reachable"]:
            chat_p, chat_c = "—", f"{C.YE}—{C.R}"
        else:
            chat_p, chat_c = "✗", f"{C.RE}✗{C.R}"

        if r["completion_latency_s"] is not None:
            lat_p = f"{r['completion_latency_s'] * 1000:.0f} ms"
        elif r["models_latency_s"] is not None:
            lat_p = f"{r['models_latency_s'] * 1000:.0f} ms"
        else:
            lat_p = "—"

        tok_p = "—"
        if r["usage"] and r["usage"].get("total_tokens") is not None:
            tok_p = str(r["usage"]["total_tokens"])

        row = (
            f"{r['label']:<14} "
            f"{_col(key_p,  key_c,  6)} "
            f"{_col(http_p, http_p, 6)} "
            f"{_col(mod_p,  mod_p,  8)} "
            f"{_col(chat_p, chat_c, 6)} "
            f"{_col(lat_p,  lat_p,  12)} "
            f"{_col(tok_p,  tok_p,  8)}"
        )
        _p(row)

    _p(f"{C.D}{'─' * 66}{C.R}")


# =============================================================================
#  MAIN
# =============================================================================
def main():
    global QUIET

    ap = argparse.ArgumentParser(
        description="HUGINN :: multi-provider LLM connectivity check",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--quick",    action="store_true",
                    help="skip chat completion test")
    ap.add_argument("--models",   action="store_true",
                    help="only list models (skip chat completion)")
    ap.add_argument("-p", "--provider", default="",
                    help="comma-separated provider slugs "
                         "(default: all configured)")
    ap.add_argument("--json",     action="store_true",
                    help="emit machine-readable JSON only")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI colors")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every model ID")
    args = ap.parse_args()

    if args.json:
        QUIET = True
    if args.no_color or args.json:
        _disable_color()

    opts = argparse.Namespace(
        quick=args.quick,
        models_only=args.models,
        verbose=args.verbose,
    )

    # ----- Provider selection -----------------------------------------------
    requested = [s.strip().lower() for s in args.provider.split(",") if s.strip()]
    if requested:
        unknown = [s for s in requested if s not in PROVIDERS]
        if unknown:
            print(f"[!] unknown provider(s): {', '.join(unknown)}",
                  file=sys.stderr)
            print(f"    known: {', '.join(PROVIDERS.keys())}",
                  file=sys.stderr)
            sys.exit(2)
        slugs = requested
    else:
        slugs = list(PROVIDERS.keys())

    # ----- Banner ------------------------------------------------------------
    _p()
    _p(f"{C.CY}{C.B}HUGINN :: LLM Provider Connectivity Check{C.R}")
    hr()
    _p(f"{C.D}providers: "
       f"{', '.join(PROVIDERS[s]['label'] for s in slugs)}{C.R}")

    # ----- Run ---------------------------------------------------------------
    results = [check_provider(slug, PROVIDERS[slug], opts) for slug in slugs]

    # ----- Summary -----------------------------------------------------------
    print_summary(results)

    tested  = [r for r in results if r["status"] != "missing_key"]
    ok_list = [r for r in tested  if r["status"] == "ok"]
    partial = [r for r in tested  if r["status"] == "partial"]
    failed  = [r for r in tested  if r["status"] == "fail"]

    # ----- No keys case ------------------------------------------------------
    if not tested:
        err("no provider API keys found in environment")
        _p()
        _p(f"{C.D}  1. Copy .env.example to .env")
        all_envs = sorted({e for cfg in PROVIDERS.values()
                           for e in cfg["key_envs"]})
        _p(f"  2. Add at least one of: {', '.join(all_envs)}")
        _p(f"  3. Re-run: python3 ai_check.py{C.R}")
        if args.json:
            print(json.dumps({"results": results,
                              "verdict": "no_keys"}, indent=2))
        sys.exit(2)

    # ----- JSON output -------------------------------------------------------
    if args.json:
        print(json.dumps({
            "results": results,
            "verdict": {
                "tested":  len(tested),
                "ok":      len(ok_list),
                "partial": len(partial),
                "failed":  len(failed),
                "skipped": len(results) - len(tested),
            },
        }, indent=2, default=str))
    else:
        _p()
        if len(ok_list) == len(tested):
            _p(f"{C.GR}{C.B}✓ all {len(tested)} tested provider(s) are live."
               f"{C.R}")
        elif ok_list or partial:
            _p(f"{C.YE}{C.B}⚠ {len(ok_list)} ok, {len(partial)} partial, "
               f"{len(failed)} failed  (of {len(tested)} tested).{C.R}")
        else:
            _p(f"{C.RE}{C.B}✗ all {len(tested)} tested provider(s) failed."
               f"{C.R}")
        _p()

    sys.exit(1 if (failed or partial) else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        sys.exit(130)
