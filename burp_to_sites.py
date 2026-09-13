#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUGINN :: burp_to_sites.py — v2.0

Convert a plain list of URLs (exported from Burp Suite, or curated by hand)
into the sites/<host>/<slug>.json workspace format that HUGINN's scanners
consume.

Smart filtering:
  · Presets for common workflows (bugbounty, strict, api-only, none)
  · Host include/exclude regexes
  · Path include/exclude regexes
  · Automatic tracking-parameter stripping
  · CDN / static-asset skip by default

Usage:
    # Recommended: bugbounty preset (skips CDNs and static assets)
    python burp_to_sites.py urls.txt output/workspace

    # Only *.roblox.com hosts
    python burp_to_sites.py urls.txt output/workspace \\
        --include-host "\\.roblox\\.com$"

    # Preview without fetching
    python burp_to_sites.py urls.txt output/workspace --dry-run

    # Stats only — see what you're working with
    python burp_to_sites.py urls.txt output/workspace --stats-only

    # Authenticated fetch
    python burp_to_sites.py urls.txt output/workspace \\
        --cookie "session=abc123" \\
        --header "Authorization: Bearer xyz"
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
    log, section, save_json, send_request, safe_filename, C,
)


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


# =============================================================================
#  TRACKING PARAMS — stripped from URLs before dedup
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
MAX_BODY_BYTES = 500_000
FETCH_TIMEOUT = 20
DEFAULT_DELAY = 0.25
DEFAULT_WORKERS = 8


# =============================================================================
#  URL NORMALIZATION
# =============================================================================
def normalize_url(url):
    """Strip tracking params and fragments."""
    try:
        p = urlparse(url)
    except Exception:
        return None

    p = p._replace(fragment="")

    if p.query:
        qs = parse_qs(p.query, keep_blank_values=True)
        # Strip tracking params (case-insensitive)
        cleaned = {k: v for k, v in qs.items() if k.lower() not in TRACKING_PARAMS}
        new_query = urlencode(cleaned, doseq=True) if cleaned else ""
        p = p._replace(query=new_query)

    return urlunparse(p)


def parse_url_line(line):
    """Parse a single line from a Burp export or URL list."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Strip Burp "METHOD URL HTTP/1.1" format
    if line.startswith(("GET ", "POST ", "PUT ", "DELETE ",
                         "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ")):
        parts = line.split(" ", 2)
        if len(parts) >= 2:
            line = parts[1]
        else:
            return None

    # Normalize scheme-less URLs
    if not line.startswith(("http://", "https://")):
        if "." in line.split("/")[0]:
            line = "https://" + line
        else:
            return None

    return line


def load_urls(path, filter_pattern=None, include_host=None,
              exclude_host=None, include_path=None, exclude_path=None):
    """
    Load, normalize, dedupe, and filter URLs.
    Returns (urls, stats_dict).
    """
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
            path = parsed.path.lower()

            if rx_inc_host and not rx_inc_host.search(host):
                stats["filtered_host"] += 1
                continue
            if rx_exc_host and rx_exc_host.search(host):
                stats["filtered_host"] += 1
                continue

            if rx_inc_path and not rx_inc_path.search(path):
                stats["filtered_path"] += 1
                continue
            if rx_exc_path and rx_exc_path.search(path):
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
            f"{k}={v[0]}" for k, v in sorted(parse_qs(parsed.query).items())
        )
        path_part = f"{path_part}__{qs_slug}"
    slug = safe_filename(path_part)
    if slug.startswith("_"):
        slug = "p" + slug
    if len(slug) > 180:
        slug = slug[:170] + "_" + hashlib.md5(url.encode()).hexdigest()[:6]
    return slug


# =============================================================================
#  FETCH
# =============================================================================
def fetch_page(url, timeout=FETCH_TIMEOUT, extra_headers=None):
    """Fetch a URL and return (record, error)."""
    try:
        r = send_request(url, timeout=timeout, allow_redirects=True,
                         headers=extra_headers)
    except Exception as e:
        return None, f"exception:{type(e).__name__}"
    if r is None:
        return None, "no_response"

    body = r.text or ""
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
    return {
        "url": url,
        "status": r.status_code,
        "method": "GET",
        "content_type": r.headers.get("Content-Type", ""),
        "content_length": len(r.content or b""),
        "title": title,
        "params": list(parse_qs(parsed.query).keys()),
        "headers": dict(r.headers),
        "cookies": cookies,
        "content": body,
        "_source": "burp",
    }, None


def placeholder_page(url):
    parsed = urlparse(url)
    return {
        "url": url, "status": 200, "method": "GET",
        "content_type": "text/html", "content_length": 0,
        "title": "", "params": list(parse_qs(parsed.query).keys()),
        "headers": {}, "cookies": {}, "content": "",
        "_source": "burp_placeholder",
        "_note": "no content captured — scanners will test URL params only",
    }


# =============================================================================
#  STATISTICS DISPLAY
# =============================================================================
def print_host_stats(urls, top=25):
    hosts = {}
    for u in urls:
        h = urlparse(u).netloc.lower()
        hosts[h] = hosts.get(h, 0) + 1

    sorted_hosts = sorted(hosts.items(), key=lambda x: -x[1])

    print()
    print(f"{C.B}{C.WH}  {'HOST':<52} {'URLS':>6}{C.R}")
    print(f"{C.D}  {'─' * 60}{C.R}")
    for host, count in sorted_hosts[:top]:
        h = host[:50] + ".." if len(host) > 52 else host
        print(f"  {h:<52} {count:>6}")
    if len(sorted_hosts) > top:
        remaining = sum(c for _, c in sorted_hosts[top:])
        print(f"  {C.D}... and {len(sorted_hosts) - top} more hosts ({remaining} URLs){C.R}")
    print(f"{C.D}  {'─' * 60}{C.R}")
    print(f"  {'TOTAL':<52} {len(urls):>6}")
    print()


def print_path_stats(urls, top=15):
    paths = {}
    for u in urls:
        p = urlparse(u).path
        segments = [s for s in p.split("/") if s]
        bucket = "/" + segments[0] if segments else "/"
        paths[bucket] = paths.get(bucket, 0) + 1

    sorted_paths = sorted(paths.items(), key=lambda x: -x[1])

    print()
    print(f"{C.B}{C.WH}  {'PATH PREFIX':<52} {'URLS':>6}{C.R}")
    print(f"{C.D}  {'─' * 60}{C.R}")
    for prefix, count in sorted_paths[:top]:
        p = prefix[:50] + ".." if len(prefix) > 52 else prefix
        print(f"  {p:<52} {count:>6}")
    print()


# =============================================================================
#  PER-HOST THROTTLE
# =============================================================================
class HostThrottle:
    def __init__(self, delay):
        self.delay = delay
        self._last = {}
        self._lock = threading.Lock()

    def wait(self, host):
        if self.delay <= 0:
            return
        with self._lock:
            now = time.time()
            last = self._last.get(host, 0.0)
            w = self.delay - (now - last)
            if w > 0:
                time.sleep(w)
            self._last[host] = time.time()


# =============================================================================
#  FETCH WORKER
# =============================================================================
def fetch_worker(url, workspace, used_slugs, used_slugs_lock, throttle,
                 extra_headers, no_fetch):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    host_dir = workspace / "sites" / safe_filename(host)
    host_dir.mkdir(parents=True, exist_ok=True)

    slug = slug_for_url(url)
    with used_slugs_lock:
        host_slugs = used_slugs.setdefault(host, {})
        if slug in host_slugs:
            h = hashlib.md5(url.encode()).hexdigest()[:6]
            slug = f"{slug}__{h}"
        host_slugs[slug] = url

    if no_fetch:
        save_json(host_dir / f"{slug}.json", placeholder_page(url))
        return url, 200, "placeholder"

    throttle.wait(host)
    record, err = fetch_page(url, extra_headers=extra_headers)
    if record is None:
        return url, 0, err or "unknown"

    save_json(host_dir / f"{slug}.json", record)
    return url, record["status"], "ok"


# =============================================================================
#  ARGPARSE
# =============================================================================
def build_parser():
    ap = argparse.ArgumentParser(
        description="Burp URLs → HUGINN workspace (smart filtering)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Presets:
  bugbounty  Skips CDNs, static assets, third-party hosts (DEFAULT)
  strict     Only API-like endpoints, no static content
  api-only   Only /api/ /v1/ /graphql paths
  none       No automatic filtering — raw import

Examples:
  python burp_to_sites.py urls.txt output/workspace
  python burp_to_sites.py urls.txt output/workspace --include-host "\\.roblox\\.com$"
  python burp_to_sites.py urls.txt output/workspace --dry-run
  python burp_to_sites.py urls.txt output/workspace --stats-only
  python burp_to_sites.py urls.txt output/workspace --cookie "session=abc"
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
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be imported; do not fetch or write")
    ap.add_argument("--stats-only", action="store_true",
                    help="show host/path statistics and exit")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help=f"per-host delay between requests (default {DEFAULT_DELAY}s)")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help=f"concurrent fetch workers (default {DEFAULT_WORKERS})")
    ap.add_argument("--timeout", type=int, default=FETCH_TIMEOUT,
                    help=f"request timeout in seconds (default {FETCH_TIMEOUT})")

    # Authentication
    ap.add_argument("--cookie", default=None,
                    help="Cookie header value for authenticated fetches")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header (repeatable): 'Name: value'")

    return ap


def merge_preset_filters(args):
    """Apply preset values where the user didn't explicitly override."""
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
            result["exclude_host"] = f"({result['exclude_host']})|({cdn_rx})"
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
#  MAIN
# =============================================================================
def main():
    ap = build_parser()
    args = ap.parse_args()

    urls_file = Path(args.urls_file)
    if not urls_file.exists():
        log(f"URLs file not found: {urls_file}", "err")
        sys.exit(1)

    workspace = Path(args.workspace)
    preset_info = PRESETS.get(args.preset, {})
    if preset_info.get("description"):
        log(f"preset : {args.preset} — {preset_info['description']}", "info")

    filters = merge_preset_filters(args)

    # ---- Load & filter --------------------------------------------------
    section("LOADING & FILTERING")
    urls, stats = load_urls(
        urls_file,
        filter_pattern=filters["filter"],
        include_host=filters["include_host"],
        exclude_host=filters["exclude_host"],
        include_path=filters["include_path"],
        exclude_path=filters["exclude_path"],
    )

    if not urls:
        log("no URLs matched the filters", "err")
        log(f"stats: {stats}", "info")
        sys.exit(1)

    log(f"read {stats['read']} lines from {urls_file.name}", "info")
    if stats["invalid"]:      log(f"  {stats['invalid']} invalid", "info")
    if stats["filtered_url"]: log(f"  {stats['filtered_url']} filtered by URL regex", "info")
    if stats["filtered_host"]:log(f"  {stats['filtered_host']} filtered by host", "info")
    if stats["filtered_path"]:log(f"  {stats['filtered_path']} filtered by path", "info")
    if stats["dupes"]:        log(f"  {stats['dupes']} duplicates removed", "info")
    log(f"kept {stats['kept']} unique URLs", "ok")

    print_host_stats(urls)
    if args.stats_only:
        print_path_stats(urls)
        return

    if args.dry_run:
        section("DRY RUN — no fetch, no write")
        log(f"would fetch {len(urls)} URLs into {workspace}", "info")
        print_path_stats(urls)
        return

    # ---- Prepare workspace ----------------------------------------------
    (workspace / "sites").mkdir(parents=True, exist_ok=True)
    (workspace / "findings").mkdir(parents=True, exist_ok=True)
    (workspace / "recon").mkdir(parents=True, exist_ok=True)

    extra_headers = parse_extra_headers(args.cookie, args.header)
    save_json(workspace / "_burp_import.json", {
        "source_file": str(urls_file),
        "preset": args.preset,
        "filters_applied": {k: v for k, v in filters.items() if v},
        "stats": stats,
        "total_urls": len(urls),
        "has_auth": bool(extra_headers),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # ---- Fetch ----------------------------------------------------------
    section("FETCHING" if not args.no_fetch else "REGISTERING (no fetch)")
    if args.no_fetch:
        log(f"registering {len(urls)} URLs without fetching", "info")
    else:
        log(f"fetching {len(urls)} URLs "
            f"(workers={args.workers}, delay={args.delay}s/host)", "info")

    used_slugs = {}
    used_slugs_lock = threading.Lock()
    throttle = HostThrottle(args.delay)

    written = 0
    failed = 0
    written_lock = threading.Lock()
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(fetch_worker, u, workspace, used_slugs,
                        used_slugs_lock, throttle, extra_headers,
                        args.no_fetch): u
            for u in urls
        }
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                _, status, reason = fut.result()
            except Exception as e:
                with written_lock:
                    failed += 1
                log(f"  ✗ {url[:100]} ({e})", "warn")
                continue

            with written_lock:
                if reason in ("ok", "placeholder"):
                    written += 1
                    host = urlparse(url).netloc
                    log(f"  [{status}] {url[:110]}", "ok", host)
                else:
                    failed += 1
                    log(f"  ✗ {url[:100]} ({reason})", "warn")

    elapsed = time.time() - t0

    # ---- Summary --------------------------------------------------------
    section("SUMMARY")
    log(f"workspace     : {workspace}", "ok")
    log(f"unique hosts  : {len(set(urlparse(u).netloc for u in urls))}", "info")
    log(f"pages written : {written}", "ok")
    if failed:
        log(f"pages failed  : {failed}", "warn")
    log(f"elapsed       : {elapsed:.1f}s", "info")

    print()
    print(f"{C.D}Now run individual scanners against this workspace:{C.R}")
    print()
    print(f"  python sqli.py           {workspace}")
    print(f"  python xss.py            {workspace} --browser")
    print(f"  python ssrf.py           {workspace}")
    print(f"  python open_redirect.py  {workspace}")
    print(f"  python path_traversal.py {workspace}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
        sys.exit(130)
