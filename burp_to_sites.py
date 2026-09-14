#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUGINN :: burp_to_sites.py — v3.1

Convert a plain list of URLs (exported from Burp Suite, or curated by hand)
into the sites/<host>/<slug>.json workspace format that HUGINN's scanners
consume.

NEW in v3.1:
  · Session headers — reads workspace/headers/default.txt + per-host
    overrides; every fetch is authenticated automatically
  · Per-JSON "_fetch" block — audit trail of auth state and header names
  · Per-JSON "_ai" block — provider, model, duration, timestamp, success
  · --no-auth flag to disable header profiles for a single run

NEW in v3.0:
  · AI page reconnaissance (--ai) — per-URL ethical-hacker analysis
  · Resume mode — skip URLs already fetched (--refresh to force)
  · AI backfill — add ai_recon to an existing workspace without refetching
  · Priority index — writes _ai_recon_index.json with scan order
  · Graceful degradation — works with or without brain.py

Smart filtering:
  · Presets for common workflows (bugbounty, strict, api-only, none)
  · Host include/exclude regexes
  · Path include/exclude regexes
  · Automatic tracking-parameter stripping
  · CDN / static-asset skip by default

Usage:
    # Basic import (no AI, but headers/ profiles are used if present)
    python3 burp_to_sites.py urls.txt workspace/

    # With AI reconnaissance on every fetched URL
    python3 burp_to_sites.py urls.txt workspace/ --ai

    # Skip header profiles for one run (pure unauthenticated)
    python3 burp_to_sites.py urls.txt workspace/ --no-auth

    # Custom header profile directory
    python3 burp_to_sites.py urls.txt workspace/ --headers-dir ./my_headers

    # Gentle on free-tier rate limits
    python3 burp_to_sites.py urls.txt workspace/ --ai --ai-workers 1

    # Refetch everything (ignore existing files)
    python3 burp_to_sites.py urls.txt workspace/ --refresh

Environment:
    BRAIN_MODE=off           Disable AI even if --ai is passed
    BRAIN_PRIORITY=...       Provider priority for the brain
    BRAIN_MAX_CALLS=...      Session budget
"""
import argparse
import hashlib
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

from huginn_utils import (
    log, section, save_json, load_json, send_request,
    safe_filename, format_duration, C, now_iso,
)

# ---- Optional HeaderJar (requires huginn_utils >= 2.1.0) --------------------
try:
    from huginn_utils import HeaderJar, mask_header_value
    _HEADER_JAR_AVAILABLE = True
except ImportError:
    _HEADER_JAR_AVAILABLE = False
    HeaderJar = None
    mask_header_value = None

# ---- Optional AI brain -------------------------------------------------------
try:
    from brain import get_brain
    _BRAIN_AVAILABLE = True
except Exception as _e:
    _BRAIN_AVAILABLE = False
    _BRAIN_IMPORT_ERR = str(_e)
    get_brain = None


# =============================================================================
#  PRESETS
# =============================================================================
PRESETS = {
    "bugbounty": {
        "description": "Balanced — skips CDNs, static assets, third-party hosts (DEFAULT)",
        "exclude_host": (
            r"(rbxcdn|akamai|cloudfront|cloudflare|fastly|"
            r"cdn\.|\.cdn\.|static\.|assets\.|img\.|images\.|fonts\.|"
            r"analytics\.|tracking\.|telemetry\.|beacon\.|"
            r"\.googleapis\.com|\.gstatic\.com|\.jsdelivr\.net|"
            r"\.cloudflare\.com|\.newrelic\.com|\.datadoghq\.com|"
            r"\.sentry\.io|\.segment\.(io|com)|\.mixpanel\.com)"
        ),
        "exclude_path": (
            r"\.(js|mjs|css|map|png|jpg|jpeg|gif|svg|webp|ico|"
            r"woff|woff2|ttf|otf|eot|mp4|webm|mp3|wav|ogg|"
            r"pdf|zip|tar|gz|7z|rar|exe|dll|bin)$"
        ),
    },
    "strict": {
        "description": "Paranoid — only API-like endpoints, no static content",
        "include_path": (
            r"/(api|v[0-9]+|graphql|rest|oauth|auth|admin|"
            r"user|account|billing|payment|login|session)"
        ),
        "exclude_path": (
            r"\.(js|mjs|css|map|png|jpg|jpeg|gif|svg|webp|ico|"
            r"woff|woff2|ttf|otf|eot)$"
        ),
    },
    "api-only": {
        "description": "Only /api/ /v1/ /graphql paths",
        "include_path": r"/(api|v[0-9]+|graphql|rest)/",
    },
    "none": {
        "description": "No automatic filtering — raw import",
    },
}

STATIC_EXTENSIONS = re.compile(
    r"\.(js|mjs|css|map|png|jpg|jpeg|gif|svg|webp|ico|bmp|"
    r"woff|woff2|ttf|otf|eot|mp4|webm|mp3|wav|ogg|ogv|"
    r"pdf|zip|tar|gz|7z|rar|exe|dll|so|bin)$",
    re.I,
)


# =============================================================================
#  TRACKING PARAMS
# =============================================================================
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_reader", "utm_vis", "utm_user",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "mc_eid", "mc_cid",
    "_ga", "_gl", "yclid", "igshid", "twclid", "ttclid",
    "ref", "referrer", "source",
    "cache_buster", "_", "cb", "ts", "timestamp", "_t", "_ts",
    "v", "ver", "version",
}


# =============================================================================
#  CONFIG
# =============================================================================
MAX_BODY_BYTES   = 500_000
FETCH_TIMEOUT    = 20
DEFAULT_DELAY    = 0.25
DEFAULT_WORKERS  = 8
DEFAULT_AI_WORKERS = 2
PROGRESS_EVERY   = 25

# Headers we consider "authenticated" for auditing purposes
AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token",
    "proxy-authorization", "x-amz-security-token", "x-goog-api-key",
}


# =============================================================================
#  URL NORMALIZATION
# =============================================================================
def normalize_url(url):
    try:
        p = urlparse(url)
    except Exception:
        return None

    p = p._replace(fragment="")

    if p.query:
        qs = parse_qs(p.query, keep_blank_values=True)
        cleaned = {k: v for k, v in qs.items()
                   if k.lower() not in TRACKING_PARAMS}
        new_query = urlencode(cleaned, doseq=True) if cleaned else ""
        p = p._replace(query=new_query)

    return urlunparse(p)


def parse_url_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith(("GET ", "POST ", "PUT ", "DELETE ",
                         "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ")):
        parts = line.split(" ", 2)
        if len(parts) >= 2:
            line = parts[1]
        else:
            return None

    if not line.startswith(("http://", "https://")):
        if "." in line.split("/")[0]:
            line = "https://" + line
        else:
            return None

    return line


def load_urls(path, filter_pattern=None, include_host=None,
              exclude_host=None, include_path=None, exclude_path=None):
    urls = []
    seen = set()

    rx_filter    = re.compile(filter_pattern) if filter_pattern else None
    rx_inc_host  = re.compile(include_host)   if include_host else None
    rx_exc_host  = re.compile(exclude_host)   if exclude_host else None
    rx_inc_path  = re.compile(include_path)   if include_path else None
    rx_exc_path  = re.compile(exclude_path)   if exclude_path else None

    stats = {
        "read": 0, "invalid": 0, "filtered_url": 0,
        "filtered_host": 0, "filtered_path": 0,
        "dupes": 0, "kept": 0,
    }

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            stats["read"] += 1
            line = parse_url_line(raw)
            if not line:
                stats["invalid"] += 1
                continue

            line = normalize_url(line)
            if not line:
                stats["invalid"] += 1
                continue

            if rx_filter and not rx_filter.search(line):
                stats["filtered_url"] += 1
                continue

            try:
                parsed = urlparse(line)
            except Exception:
                stats["invalid"] += 1
                continue

            host = parsed.netloc.lower()
            path_l = parsed.path.lower()

            if rx_inc_host and not rx_inc_host.search(host):
                stats["filtered_host"] += 1
                continue
            if rx_exc_host and rx_exc_host.search(host):
                stats["filtered_host"] += 1
                continue

            if rx_inc_path and not rx_inc_path.search(path_l):
                stats["filtered_path"] += 1
                continue
            if rx_exc_path and rx_exc_path.search(path_l):
                stats["filtered_path"] += 1
                continue

            if line in seen:
                stats["dupes"] += 1
                continue
            seen.add(line)
            urls.append(line)
            stats["kept"] += 1

    return urls, stats


# =============================================================================
#  SLUG GENERATOR
# =============================================================================
def slug_for_url(url):
    parsed = urlparse(url)
    path_part = parsed.path.strip("/").replace("/", "_") or "index"
    if parsed.query:
        qs_slug = "_".join(
            "{}={}".format(k, v[0]) for k, v in sorted(parse_qs(parsed.query).items())
        )
        path_part = "{}__{}".format(path_part, qs_slug)
    slug = safe_filename(path_part)
    if slug.startswith("_"):
        slug = "p" + slug
    if len(slug) > 180:
        slug = slug[:170] + "_" + hashlib.md5(url.encode()).hexdigest()[:6]
    return slug


def is_static_url(url):
    try:
        p = urlparse(url)
    except Exception:
        return False
    if STATIC_EXTENSIONS.search(p.path):
        return True
    host = p.netloc.lower()
    for marker in ("cdn.", ".cdn.", "static.", "assets.",
                   "img.", "images.", "fonts.", "jsdelivr",
                   "gstatic", "googleapis"):
        if marker in host:
            return True
    return False


# =============================================================================
#  HTTP FETCH
# =============================================================================
def _categorize_error(exc_type_name, msg):
    m = (msg or "").lower()
    if "timeout" in m or "timed out" in m:
        return "timeout"
    if "name or service not known" in m or "nodename" in m or "getaddrinfo" in m:
        return "dns"
    if "ssl" in m or "certificate" in m:
        return "tls"
    if "connection refused" in m:
        return "refused"
    if "connection reset" in m:
        return "reset"
    return "exception:{}".format(exc_type_name)


def describe_fetch_headers(merged_headers):
    """
    Return (authenticated: bool, sorted_header_names: list).
    Only header NAMES are returned — never values.
    """
    if not merged_headers:
        return False, []
    names = sorted(merged_headers.keys())
    authenticated = any(n.lower() in AUTH_HEADER_NAMES for n in names)
    return authenticated, names


def fetch_page(url, timeout=FETCH_TIMEOUT, extra_headers=None):
    """Fetch a URL, return (record, error_reason)."""
    try:
        r = send_request(url, timeout=timeout, allow_redirects=True,
                         headers=extra_headers)
    except Exception as e:
        return None, _categorize_error(type(e).__name__, str(e))

    if r is None:
        return None, "no_response"

    try:
        body = r.text or ""
    except Exception:
        body = ""

    if len(body) > MAX_BODY_BYTES:
        body = body[:MAX_BODY_BYTES]

    cookies = {}
    sc = r.headers.get("Set-Cookie") or r.headers.get("set-cookie") or ""
    if sc:
        for chunk in sc.split(","):
            m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
            if m:
                cookies[m.group(1).strip()] = m.group(2).strip()

    title = ""
    mt = re.search(r"<title[^>]*>([^<]{1,300})</title>", body, re.I)
    if mt:
        title = mt.group(1).strip()

    parsed = urlparse(url)
    try:
        clen = len(r.content or b"")
    except Exception:
        clen = len(body)

    return {
        "url":            url,
        "status":         r.status_code,
        "method":         "GET",
        "content_type":   r.headers.get("Content-Type", ""),
        "content_length": clen,
        "title":          title,
        "params":         list(parse_qs(parsed.query).keys()),
        "headers":        dict(r.headers),
        "cookies":        cookies,
        "content":        body,
        "_source":        "burp",
        "_fetched_at":    now_iso(),
    }, None


def placeholder_page(url):
    parsed = urlparse(url)
    return {
        "url":            url,
        "status":         200,
        "method":         "GET",
        "content_type":   "text/html",
        "content_length": 0,
        "title":          "",
        "params":         list(parse_qs(parsed.query).keys()),
        "headers":        {},
        "cookies":        {},
        "content":        "",
        "_source":        "burp_placeholder",
        "_note":          "no content captured — scanners will test URL params only",
        "_fetched_at":    now_iso(),
    }


# =============================================================================
#  THREAD-SAFE STATS
# =============================================================================
class FetchStats:
    def __init__(self, total):
        self.total       = total
        self.written     = 0
        self.failed      = 0
        self.skipped     = 0
        self.refreshed   = 0
        self.ai_done     = 0
        self.ai_failed   = 0
        self.ai_skipped  = 0
        self.ai_interesting = 0
        self.ai_by_kind       = {}
        self.ai_by_priority   = {}
        self.ai_scanner_hits  = {}
        self.error_reasons    = {}
        self.authenticated    = 0
        self.unauthenticated  = 0
        self.started_at  = time.time()
        self._lock       = threading.Lock()

    def bump(self, field, n=1):
        with self._lock:
            setattr(self, field, getattr(self, field, 0) + n)

    def record_error(self, reason):
        with self._lock:
            self.error_reasons[reason] = self.error_reasons.get(reason, 0) + 1

    def record_auth(self, authenticated):
        with self._lock:
            if authenticated:
                self.authenticated += 1
            else:
                self.unauthenticated += 1

    def record_ai(self, recon):
        with self._lock:
            self.ai_done += 1
            if recon.get("interesting"):
                self.ai_interesting += 1
            kind = recon.get("kind", "other")
            self.ai_by_kind[kind] = self.ai_by_kind.get(kind, 0) + 1
            pri = recon.get("priority", "medium")
            self.ai_by_priority[pri] = self.ai_by_priority.get(pri, 0) + 1
            for s in recon.get("suggested_scanners", []):
                self.ai_scanner_hits[s] = self.ai_scanner_hits.get(s, 0) + 1

    def snapshot(self):
        with self._lock:
            return {
                "total":             self.total,
                "written":           self.written,
                "failed":            self.failed,
                "skipped":           self.skipped,
                "refreshed":         self.refreshed,
                "authenticated":     self.authenticated,
                "unauthenticated":   self.unauthenticated,
                "ai_done":           self.ai_done,
                "ai_failed":         self.ai_failed,
                "ai_skipped":        self.ai_skipped,
                "ai_interesting":    self.ai_interesting,
                "ai_by_kind":        dict(self.ai_by_kind),
                "ai_by_priority":    dict(self.ai_by_priority),
                "ai_scanner_hits":   dict(self.ai_scanner_hits),
                "error_reasons":     dict(self.error_reasons),
                "elapsed_s":         round(time.time() - self.started_at, 1),
            }


# =============================================================================
#  PER-HOST THROTTLE
# =============================================================================
class HostThrottle:
    def __init__(self, delay):
        self.delay = delay
        self._last = {}
        self._lock = threading.Lock()

    def wait(self, host):
        if self.delay <= 0 or not host:
            return
        with self._lock:
            now = time.time()
            last = self._last.get(host, 0.0)
            w = self.delay - (now - last)
            if w > 0:
                time.sleep(w)
                now = time.time()
            self._last[host] = now


# =============================================================================
#  WORKER
# =============================================================================
def fetch_worker(url, workspace, used_slugs, used_slugs_lock, throttle,
                 header_jar, fallback_headers, no_fetch, refresh,
                 brain, ai_semaphore, ai_force, ai_skip_static,
                 stats, out_lock, quiet):
    """
    Process a single URL. Returns:
        (url, status_code_or_0, outcome)
    where outcome ∈ {"ok", "placeholder", "skipped", "error:<reason>"}
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    host_dir = workspace / "sites" / safe_filename(host)
    try:
        host_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        stats.record_error("mkdir:{}".format(type(e).__name__))
        return url, 0, "error:mkdir"

    slug = slug_for_url(url)
    with used_slugs_lock:
        host_slugs = used_slugs.setdefault(host, {})
        if slug in host_slugs:
            h = hashlib.md5(url.encode()).hexdigest()[:6]
            slug = "{}_{}".format(slug, h)
        host_slugs[slug] = url

    out_path = host_dir / "{}.json".format(slug)

    # ----- Resume ---------------------------------------------------------
    record = None
    needs_save = False
    if out_path.exists() and not refresh:
        try:
            record = load_json(out_path)
            needs_ai = (brain is not None and brain.available()
                        and "ai_recon" not in record)
            if not needs_ai:
                stats.bump("skipped")
                return url, record.get("status", 0), "skipped"
        except Exception:
            record = None

    # ----- Fetch ----------------------------------------------------------
    if record is None:
        # Resolve headers for this specific URL
        if header_jar is not None:
            merged_headers = header_jar.headers_for(url)
        else:
            merged_headers = dict(fallback_headers or {})

        authenticated, header_names = describe_fetch_headers(merged_headers)

        if no_fetch:
            record = placeholder_page(url)
            outcome = "placeholder"
        else:
            throttle.wait(host)
            record, err = fetch_page(url, extra_headers=merged_headers)
            if record is None:
                stats.record_error(err or "unknown")
                return url, 0, "error:{}".format(err or "unknown")
            outcome = "ok"

        # Attach the _fetch audit block
        record["_fetch"] = {
            "authenticated": authenticated,
            "header_names":  header_names,
            "timestamp":     now_iso(),
        }
        stats.record_auth(authenticated)

        if refresh and out_path.exists():
            stats.bump("refreshed")
        needs_save = True

    # ----- AI recon -------------------------------------------------------
    if brain is not None and brain.available() and ai_semaphore is not None:
        skip_ai = False
        if ai_skip_static and is_static_url(url):
            skip_ai = True
            stats.bump("ai_skipped")

        if not skip_ai and not ai_force and "ai_recon" in record:
            skip_ai = True
            stats.bump("ai_skipped")

        if not skip_ai:
            ai_t0 = time.time()
            recon = None
            try:
                with ai_semaphore:
                    recon = brain.recon_page(record, force=ai_force)
                ai_ok = recon is not None
            except Exception as e:
                ai_ok = False
                if not quiet:
                    log("AI recon error for {}: {}: {}".format(
                        url[:80], type(e).__name__, e), "warn")
            ai_duration_ms = int((time.time() - ai_t0) * 1000)

            # Always write the _ai audit block when we attempted
            record["_ai"] = {
                "enabled":     True,
                "ok":          ai_ok,
                "provider":    brain.provider,
                "model":       brain.model,
                "model_label": brain.cfg["label"] if brain.cfg else None,
                "duration_ms": ai_duration_ms,
                "timestamp":   now_iso(),
            }

            if ai_ok:
                record["ai_recon"] = recon
                stats.record_ai(recon)
            else:
                stats.bump("ai_failed")
            needs_save = True
        else:
            # Skipped — leave existing _ai block alone, or write a stub
            if "_ai" not in record:
                record["_ai"] = {
                    "enabled":   True,
                    "ok":        "ai_recon" in record,
                    "provider":  brain.provider,
                    "model":     brain.model,
                    "model_label": brain.cfg["label"] if brain.cfg else None,
                    "skipped":   True,
                    "timestamp": now_iso(),
                }
                needs_save = True
    else:
        # Brain off — write an explicit disabled marker if not present
        if "_ai" not in record:
            record["_ai"] = {
                "enabled":   False,
                "timestamp": now_iso(),
            }
            needs_save = True

    # ----- Save -----------------------------------------------------------
    if needs_save:
        try:
            with out_lock:
                save_json(out_path, record)
            stats.bump("written")
        except Exception as e:
            stats.record_error("save:{}".format(type(e).__name__))
            return url, record.get("status", 0), "error:save"

    return url, record.get("status", 0), outcome if record else "ok"


# =============================================================================
#  STATISTICS DISPLAY
# =============================================================================
def print_host_stats(urls, top=25):
    hosts = {}
    for u in urls:
        try:
            h = urlparse(u).netloc.lower()
        except Exception:
            continue
        hosts[h] = hosts.get(h, 0) + 1

    sorted_hosts = sorted(hosts.items(), key=lambda x: -x[1])

    print()
    print("{}  {:<52} {:>6}{}".format(C.B + C.WH, "HOST", "URLS", C.R))
    print("{}  {}{}".format(C.D, "─" * 60, C.R))
    for host, count in sorted_hosts[:top]:
        h = host[:50] + ".." if len(host) > 52 else host
        print("  {:<52} {:>6}".format(h, count))
    if len(sorted_hosts) > top:
        remaining = sum(c for _, c in sorted_hosts[top:])
        print("  {}... and {} more hosts ({} URLs){}".format(
            C.D, len(sorted_hosts) - top, remaining, C.R))
    print("{}  {}{}".format(C.D, "─" * 60, C.R))
    print("  {:<52} {:>6}".format("TOTAL", len(urls)))
    print()


def print_path_stats(urls, top=15):
    paths = {}
    for u in urls:
        try:
            p = urlparse(u).path
        except Exception:
            continue
        segments = [s for s in p.split("/") if s]
        bucket = "/" + segments[0] if segments else "/"
        paths[bucket] = paths.get(bucket, 0) + 1

    sorted_paths = sorted(paths.items(), key=lambda x: -x[1])

    print()
    print("{}  {:<52} {:>6}{}".format(C.B + C.WH, "PATH PREFIX", "URLS", C.R))
    print("{}  {}{}".format(C.D, "─" * 60, C.R))
    for prefix, count in sorted_paths[:top]:
        p = prefix[:50] + ".." if len(prefix) > 52 else prefix
        print("  {:<52} {:>6}".format(p, count))
    print()


def print_ai_summary(stats, brain):
    snap = stats.snapshot()
    if snap["ai_done"] == 0 and snap["ai_failed"] == 0 and snap["ai_skipped"] == 0:
        return

    section("AI RECON SUMMARY")
    log("analyzed      : {} pages".format(snap["ai_done"]), "ok")
    if snap["ai_interesting"]:
        pct = 100.0 * snap["ai_interesting"] / max(1, snap["ai_done"])
        log("interesting   : {} ({:.0f}%)".format(
            snap["ai_interesting"], pct), "info")
    if snap["ai_skipped"]:
        log("skipped       : {} (static or cached)".format(
            snap["ai_skipped"]), "info")
    if snap["ai_failed"]:
        log("failed        : {}".format(snap["ai_failed"]), "warn")

    if snap["ai_by_kind"]:
        kinds = sorted(snap["ai_by_kind"].items(), key=lambda x: -x[1])
        log("by kind       : " + "  ".join(
            "{}={}".format(k, v) for k, v in kinds[:8]), "info")

    if snap["ai_by_priority"]:
        pri = snap["ai_by_priority"]
        log("by priority   : high={} medium={} low={}".format(
            pri.get("high", 0), pri.get("medium", 0),
            pri.get("low", 0)), "info")

    if snap["ai_scanner_hits"]:
        scanners = sorted(snap["ai_scanner_hits"].items(), key=lambda x: -x[1])
        log("scanner hints : " + "  ".join(
            "{}={}".format(s, n) for s, n in scanners[:8]), "info")

    if brain is not None:
        b = brain.budget.snapshot()
        log("brain calls   : {}  tokens {}/{}  cost ${:.4f}".format(
            b["calls"],
            b["tokens_in"] + b["tokens_out"],
            b["max_tokens"],
            b["cost_usd"]), "info")


def write_ai_index(workspace, results):
    index = {
        "generated_at": now_iso(),
        "total":        len(results),
        "pages":        [],
    }

    priority_rank = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda r: (
        priority_rank.get(r.get("priority", "low"), 3),
        0 if r.get("interesting") else 1,
        r.get("url", ""),
    ))

    for r in results:
        index["pages"].append({
            "url":                r["url"],
            "kind":               r["kind"],
            "priority":           r["priority"],
            "interesting":        r["interesting"],
            "confidence":         r["confidence"],
            "attack_surface":     r["attack_surface"],
            "suggested_scanners": r["suggested_scanners"],
            "notes":              r["notes"],
        })

    save_json(workspace / "_ai_recon_index.json", index)
    return len(index["pages"])


# =============================================================================
#  ARGPARSE
# =============================================================================
def build_parser():
    ap = argparse.ArgumentParser(
        description="Burp URLs → HUGINN workspace (auth-aware, AI-optional)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Presets:
  bugbounty  Skips CDNs, static assets, third-party hosts (DEFAULT)
  strict     Only API-like endpoints, no static content
  api-only   Only /api/ /v1/ /graphql paths
  none       No automatic filtering — raw import

Header profiles:
  workspace/headers/default.txt            applies to every host
  workspace/headers/<host>.txt             applies to that host only
  Supported formats: raw header lines, or a full Burp request block.

Examples:
  python3 burp_to_sites.py urls.txt workspace/
  python3 burp_to_sites.py urls.txt workspace/ --ai
  python3 burp_to_sites.py urls.txt workspace/ --ai --ai-workers 1
  python3 burp_to_sites.py urls.txt workspace/ --no-auth
  python3 burp_to_sites.py urls.txt workspace/ --headers-dir ./sessions/prod
  python3 burp_to_sites.py urls.txt workspace/ --refresh
  python3 burp_to_sites.py urls.txt workspace/ --dry-run
  python3 burp_to_sites.py urls.txt workspace/ --stats-only
""",
    )
    ap.add_argument("urls_file", help="text file with one URL per line")
    ap.add_argument("workspace", help="workspace directory to create")

    # Filtering
    ap.add_argument("--preset", choices=list(PRESETS.keys()),
                    default="bugbounty",
                    help="filtering preset (default: bugbounty)")
    ap.add_argument("--filter", default=None,
                    help="URL-level regex filter")
    ap.add_argument("--include-host", default=None,
                    help="only keep URLs whose host matches this regex")
    ap.add_argument("--exclude-host", default=None,
                    help="drop URLs whose host matches this regex")
    ap.add_argument("--include-path", default=None,
                    help="only keep URLs whose path matches this regex")
    ap.add_argument("--exclude-path", default=None,
                    help="drop URLs whose path matches this regex")
    ap.add_argument("--no-cdn", action="store_true",
                    help="add common CDN exclusion pattern")

    # Behavior
    ap.add_argument("--no-fetch", action="store_true",
                    help="skip fetching; register URLs with empty content")
    ap.add_argument("--refresh", action="store_true",
                    help="refetch even if a site JSON already exists")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be imported; no fetch, no write")
    ap.add_argument("--stats-only", action="store_true",
                    help="show host/path statistics and exit")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help="per-host delay between requests (default {})".format(
                        DEFAULT_DELAY))
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help="concurrent fetch workers (default {})".format(
                        DEFAULT_WORKERS))
    ap.add_argument("--timeout", type=int, default=FETCH_TIMEOUT,
                    help="request timeout in seconds (default {})".format(
                        FETCH_TIMEOUT))
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="suppress per-URL logs; show only progress and summary")

    # Authentication
    ap.add_argument("--headers-dir", default=None,
                    help="directory with header profiles "
                         "(default: <workspace>/headers)")
    ap.add_argument("--no-auth", action="store_true",
                    help="ignore header profiles entirely (unauthenticated)")
    ap.add_argument("--cookie", default=None,
                    help="Cookie header value (CLI override, merged last)")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header (repeatable): 'Name: value'")

    # AI
    ap.add_argument("--ai", action="store_true",
                    help="run AI page reconnaissance on every fetched URL")
    ap.add_argument("--ai-workers", type=int, default=DEFAULT_AI_WORKERS,
                    help="concurrent AI recon calls (default {})".format(
                        DEFAULT_AI_WORKERS))
    ap.add_argument("--ai-force", action="store_true",
                    help="ignore cached AI recon and re-run")
    ap.add_argument("--ai-skip-static", action="store_true",
                    help="skip AI recon on obvious static/CDN URLs")

    return ap


def merge_preset_filters(args):
    preset = PRESETS.get(args.preset, {})
    result = {
        "filter":       args.filter,
        "include_host": args.include_host,
        "exclude_host": args.exclude_host,
        "include_path": args.include_path,
        "exclude_path": args.exclude_path,
    }
    for key in ("include_host", "exclude_host",
                "include_path", "exclude_path"):
        if result[key] is None and key in preset:
            result[key] = preset[key]

    if args.no_cdn:
        cdn_rx = (
            r"(cdn\.|\.cdn\.|akamai|cloudfront|cloudflare|fastly|"
            r"\.googleapis\.com|\.gstatic\.com|\.jsdelivr\.net)"
        )
        if result["exclude_host"]:
            result["exclude_host"] = "({})|({})".format(
                result["exclude_host"], cdn_rx)
        else:
            result["exclude_host"] = cdn_rx

    return result


def parse_extra_headers(cookie, header_list):
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    for h in header_list:
        if ":" in h:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    return headers


# =============================================================================
#  PROGRESS REPORTER
# =============================================================================
class ProgressReporter:
    def __init__(self, stats, total, quiet=False):
        self.stats = stats
        self.total = total
        self.quiet = quiet
        self._lock = threading.Lock()
        self._last_report = 0

    def tick(self):
        if self.quiet:
            return
        with self._lock:
            done = (self.stats.written + self.stats.failed +
                    self.stats.skipped)
            if done - self._last_report >= PROGRESS_EVERY or done == self.total:
                self._last_report = done
                elapsed = time.time() - self.stats.started_at
                rate = done / elapsed if elapsed > 0 else 0
                eta = (self.total - done) / rate if rate > 0 else 0
                log("progress {}/{}  ok={} fail={} skip={}  ~{:.0f}/s  ETA {}".format(
                    done, self.total,
                    self.stats.written, self.stats.failed, self.stats.skipped,
                    rate, format_duration(eta)),
                    "info", "PROG")


# =============================================================================
#  MAIN
# =============================================================================
def main():
    ap = build_parser()
    args = ap.parse_args()

    urls_file = Path(args.urls_file)
    if not urls_file.exists():
        log("URLs file not found: {}".format(urls_file), "err")
        sys.exit(1)

    workspace = Path(args.workspace)
    preset_info = PRESETS.get(args.preset, {})
    if preset_info.get("description"):
        log("preset : {} — {}".format(args.preset,
                                       preset_info["description"]), "info")

    filters = merge_preset_filters(args)

    # ---- Load & filter --------------------------------------------------
    section("LOADING & FILTERING")
    try:
        urls, stats_load = load_urls(
            urls_file,
            filter_pattern=filters["filter"],
            include_host=filters["include_host"],
            exclude_host=filters["exclude_host"],
            include_path=filters["include_path"],
            exclude_path=filters["exclude_path"],
        )
    except Exception as e:
        log("failed to load URLs: {}: {}".format(type(e).__name__, e), "err")
        sys.exit(1)

    if not urls:
        log("no URLs matched the filters", "err")
        log("stats: {}".format(stats_load), "info")
        sys.exit(1)

    log("read {} lines from {}".format(stats_load["read"], urls_file.name),
        "info")
    if stats_load["invalid"]:      log("  {} invalid".format(stats_load["invalid"]), "info")
    if stats_load["filtered_url"]: log("  {} filtered by URL regex".format(stats_load["filtered_url"]), "info")
    if stats_load["filtered_host"]:log("  {} filtered by host".format(stats_load["filtered_host"]), "info")
    if stats_load["filtered_path"]:log("  {} filtered by path".format(stats_load["filtered_path"]), "info")
    if stats_load["dupes"]:        log("  {} duplicates removed".format(stats_load["dupes"]), "info")
    log("kept {} unique URLs".format(stats_load["kept"]), "ok")

    print_host_stats(urls)
    if args.stats_only:
        print_path_stats(urls)
        return

    if args.dry_run:
        section("DRY RUN — no fetch, no write")
        log("would fetch {} URLs into {}".format(len(urls), workspace), "info")
        if args.ai:
            log("would run AI recon on fetched pages", "info")
        print_path_stats(urls)
        return

    # ---- Prepare workspace ----------------------------------------------
    try:
        (workspace / "sites").mkdir(parents=True, exist_ok=True)
        (workspace / "findings").mkdir(parents=True, exist_ok=True)
        (workspace / "recon").mkdir(parents=True, exist_ok=True)
        (workspace / "headers").mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log("cannot create workspace: {}: {}".format(type(e).__name__, e), "err")
        sys.exit(1)

    # ---- Header profiles (session cookies, auth tokens, etc.) ----------
    section("AUTHENTICATION")
    cli_headers = parse_extra_headers(args.cookie, args.header)

    if args.no_auth:
        log("--no-auth set: skipping header profiles", "warn")
        header_jar = None
        fallback_headers = cli_headers
    elif not _HEADER_JAR_AVAILABLE:
        log("HeaderJar not available in huginn_utils — "
            "upgrade to v2.1.0 or apply the merge patch", "warn")
        log("continuing with CLI headers only (if any)", "info")
        header_jar = None
        fallback_headers = cli_headers
    else:
        headers_dir = (Path(args.headers_dir) if args.headers_dir
                       else (workspace / "headers"))
        try:
            header_jar = HeaderJar(headers_dir, cli_headers=cli_headers)
            header_jar.load()
        except Exception as e:
            log("failed to load header profiles: {}: {}".format(
                type(e).__name__, e), "warn")
            header_jar = None
            fallback_headers = cli_headers
        else:
            profiles = header_jar.profiles_loaded()
            if profiles:
                log("header profiles loaded from {}".format(headers_dir), "ok")
                for line in header_jar.describe().splitlines():
                    log(line, "info", "HEADERS")
                if cli_headers:
                    log("+ {} CLI header(s) merged last".format(len(cli_headers)),
                        "info")
            else:
                log("no header profiles found in {}".format(headers_dir), "info")
                if cli_headers:
                    log("using {} CLI header(s)".format(len(cli_headers)), "info")
                else:
                    log("unauthenticated fetch — scanners may miss bugs",
                        "warn")
            fallback_headers = cli_headers

    # ---- AI brain setup -------------------------------------------------
    section("AI SETUP")
    brain = None
    ai_semaphore = None

    if args.ai:
        if not _BRAIN_AVAILABLE:
            log("--ai requested but brain.py is not importable: {}".format(
                _BRAIN_IMPORT_ERR), "warn")
            log("continuing without AI", "info")
        else:
            try:
                brain = get_brain()
            except Exception as e:
                log("brain init failed: {}: {}".format(
                    type(e).__name__, e), "warn")
                brain = None

            if brain is not None and not brain.available():
                log("--ai requested but brain is OFF (no usable provider)",
                    "warn")
                brain = None

            if brain is not None:
                log("AI recon: ON ({} / {})".format(
                    brain.cfg["label"], brain.model), "info")
                log("AI workers: {}  (throttled for rate limits)".format(
                    args.ai_workers), "info")
                if args.ai_skip_static:
                    log("AI skip-static: ON", "info")
                if args.ai_force:
                    log("AI force: ON (ignoring cache)", "info")
                ai_semaphore = threading.Semaphore(max(1, args.ai_workers))
    else:
        log("AI recon: OFF (use --ai to enable)", "info")

    # ---- Write import metadata -----------------------------------------
    try:
        save_json(workspace / "_burp_import.json", {
            "source_file":      str(urls_file),
            "preset":           args.preset,
            "filters_applied":  {k: v for k, v in filters.items() if v},
            "load_stats":       stats_load,
            "total_urls":       len(urls),
            "auth": {
                "enabled":      header_jar is not None,
                "headers_dir":  (str(Path(args.headers_dir))
                                 if args.headers_dir
                                 else str(workspace / "headers")),
                "profiles":     (header_jar.profiles_loaded()
                                 if header_jar is not None else []),
                "cli_header_names": sorted(cli_headers.keys()),
                "no_auth_flag": args.no_auth,
            },
            "ai_enabled":       brain is not None,
            "ai_provider":      brain.provider if brain else None,
            "ai_model":         brain.model if brain else None,
            "ai_workers":       args.ai_workers if brain else None,
            "refresh":          args.refresh,
            "no_fetch":         args.no_fetch,
            "timestamp":        now_iso(),
        })
    except Exception as e:
        log("failed to write import metadata: {}: {}".format(
            type(e).__name__, e), "warn")

    # ---- Fetch ----------------------------------------------------------
    if args.no_fetch:
        section("REGISTERING (no fetch)")
        log("registering {} URLs without fetching".format(len(urls)), "info")
    else:
        section("FETCHING")
        log("fetching {} URLs (workers={}, delay={}s/host)".format(
            len(urls), args.workers, args.delay), "info")

    used_slugs = {}
    used_slugs_lock = threading.Lock()
    throttle = HostThrottle(args.delay)
    stats = FetchStats(total=len(urls))
    out_lock = threading.Lock()
    progress = ProgressReporter(stats, len(urls), quiet=args.quiet)

    ai_results = []
    ai_results_lock = threading.Lock()

    t0 = time.time()

    def handle_result(url, status, outcome):
        if outcome == "skipped":
            pass
        elif outcome.startswith("error:"):
            reason = outcome.split(":", 1)[1] if ":" in outcome else "unknown"
            if not args.quiet:
                log("  ✗ [{}] {}".format(reason, url[:110]), "warn")
        else:
            if not args.quiet:
                log("  [{}] {}".format(status, url[:110]), "ok",
                    urlparse(url).netloc)
        progress.tick()

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {}
            for u in urls:
                fut = pool.submit(
                    fetch_worker, u, workspace, used_slugs, used_slugs_lock,
                    throttle, header_jar, fallback_headers,
                    args.no_fetch, args.refresh,
                    brain, ai_semaphore, args.ai_force, args.ai_skip_static,
                    stats, out_lock, args.quiet,
                )
                futures[fut] = u

            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    _, status, outcome = fut.result()
                except Exception as e:
                    stats.bump("failed")
                    stats.record_error("worker:{}".format(type(e).__name__))
                    if not args.quiet:
                        log("  ✗ worker crash for {}: {}: {}".format(
                            url[:80], type(e).__name__, e), "warn")
                    progress.tick()
                    continue

                if outcome != "skipped" and outcome.startswith("error:"):
                    stats.bump("failed")
                handle_result(url, status, outcome)

                # Collect AI recon for priority index
                if brain is not None and brain.available():
                    try:
                        parsed = urlparse(url)
                        host = parsed.netloc.lower()
                        slug = slug_for_url(url)
                        fpath = (workspace / "sites" / safe_filename(host)
                                 / "{}.json".format(slug))
                        if not fpath.exists():
                            host_slugs = used_slugs.get(host, {})
                            for s, u2 in host_slugs.items():
                                if u2 == url:
                                    fpath = (workspace / "sites"
                                             / safe_filename(host)
                                             / "{}.json".format(s))
                                    break
                        if fpath.exists():
                            rec = load_json(fpath)
                            ar = rec.get("ai_recon")
                            if ar:
                                ar2 = dict(ar)
                                ar2["url"] = url
                                with ai_results_lock:
                                    ai_results.append(ar2)
                    except Exception:
                        pass

    except KeyboardInterrupt:
        print()
        log("interrupted — partial workspace preserved", "warn")

    elapsed = time.time() - t0

    # ---- Summary --------------------------------------------------------
    snap = stats.snapshot()

    section("SUMMARY")
    log("workspace     : {}".format(workspace), "ok")
    log("unique hosts  : {}".format(
        len(set(urlparse(u).netloc for u in urls))), "info")
    log("pages written : {}".format(snap["written"]), "ok")
    if snap["skipped"]:
        log("pages skipped : {} (already existed)".format(
            snap["skipped"]), "info")
    if snap["refreshed"]:
        log("pages refreshed: {}".format(snap["refreshed"]), "info")
    if snap["failed"]:
        log("pages failed  : {}".format(snap["failed"]), "warn")

    if snap["authenticated"] or snap["unauthenticated"]:
        log("authenticated : {}  |  unauthenticated : {}".format(
            snap["authenticated"], snap["unauthenticated"]), "info")

    if snap["error_reasons"]:
        reasons = sorted(snap["error_reasons"].items(), key=lambda x: -x[1])
        log("error breakdown: " + "  ".join(
            "{}={}".format(r, n) for r, n in reasons[:6]), "info")

    log("elapsed       : {}".format(format_duration(elapsed)), "info")

    # AI summary
    if brain is not None:
        print_ai_summary(stats, brain)

    # Priority index
    if ai_results:
        try:
            n = write_ai_index(workspace, ai_results)
            log("priority index: {} pages  ({})".format(
                n, workspace / "_ai_recon_index.json"), "ok")
        except Exception as e:
            log("failed to write priority index: {}: {}".format(
                type(e).__name__, e), "warn")

    # ---- Save final stats ----------------------------------------------
    try:
        final_meta = load_json(workspace / "_burp_import.json")
    except Exception:
        final_meta = {}
    final_meta["final_stats"] = snap
    final_meta["completed_at"] = now_iso()
    try:
        save_json(workspace / "_burp_import.json", final_meta)
    except Exception:
        pass

    # ---- Next steps -----------------------------------------------------
    print()
    print("{}Next steps:{}".format(C.D, C.R))
    print()
    if ai_results:
        print("  {}AI priority index written to:{}{}".format(
            C.CY, C.R, workspace / "_ai_recon_index.json"))
        print("  {}High-priority pages (scan these first):{}".format(C.D, C.R))
        high = [r for r in ai_results if r.get("priority") == "high"][:5]
        for r in high:
            print("    · {} [{}]".format(r.get("url", "")[:80],
                                          ",".join(r.get("suggested_scanners", []))))
        print()

    print("  python3 sqli.py           {}".format(workspace))
    print("  python3 xss.py            {} --browser".format(workspace))
    print("  python3 ssrf.py           {}".format(workspace))
    print("  python3 open_redirect.py  {}".format(workspace))
    print("  python3 path_traversal.py {}".format(workspace))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
        sys.exit(130)
