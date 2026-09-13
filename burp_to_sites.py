#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUGINN :: burp_to_sites.py

Convert a plain list of URLs (exported from Burp Suite, or curated by hand)
into the sites/<host>/<slug>.json workspace format that HUGINN's scanners
consume.

Usage:
    # From a Burp "Copy URLs" export
    python burp_to_sites.py urls.txt output/my_workspace

    # Skip the network fetch (uses placeholder content)
    # — useful when you already have responses cached elsewhere
    python burp_to_sites.py urls.txt output/my_workspace --no-fetch

    # Include only URLs matching a pattern
    python burp_to_sites.py urls.txt output/my_workspace --filter "/api/"
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Reuse HUGINN's shared session (keeps cookies, connection pooling)
from huginn_utils import (
    log, section, save_json, send_request, safe_filename, C,
)


# =============================================================================
#  CONFIG
# =============================================================================
MAX_BODY_BYTES    = 500_000   # cap so we don't write multi-MB JSON files
FETCH_TIMEOUT     = 20
DEFAULT_DELAY     = 0.25      # between requests (be polite to the target)


# =============================================================================
#  URL PARSING
# =============================================================================
def load_urls(path, filter_pattern=None):
    """
    Read a text file, extract every line that looks like a URL.
    Filters out comments (#) and blanks. Optional regex filter.
    """
    urls = []
    seen = set()
    rx = re.compile(filter_pattern) if filter_pattern else None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            # Burp sometimes exports "METHOD URL HTTP/1.1" — strip the prefix
            if line.startswith(("GET ", "POST ", "PUT ", "DELETE ",
                                 "PATCH ", "HEAD ", "OPTIONS ")):
                parts = line.split(" ", 2)
                line = parts[1] if len(parts) >= 2 else line

            # Normalise scheme-less URLs
            if not line.startswith(("http://", "https://")):
                if "." in line.split("/")[0]:
                    line = "https://" + line
                else:
                    continue

            if rx and not rx.search(line):
                continue

            if line in seen:
                continue
            seen.add(line)
            urls.append(line)

    return urls


# =============================================================================
#  SLUG GENERATOR  (same logic as crawl.py)
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
    # Prefix if URL itself starts with _ so metadata filter doesn't eat it
    if slug.startswith("_"):
        slug = "p" + slug
    return slug


# =============================================================================
#  FETCH  (optional)
# =============================================================================
def fetch_page(url, timeout=FETCH_TIMEOUT):
    """
    Fetch a URL and return a page record in the format scanners expect.
    Returns None on failure.
    """
    try:
        r = send_request(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None
    if r is None:
        return None

    body = r.text or ""
    if len(body) > MAX_BODY_BYTES:
        body = body[:MAX_BODY_BYTES]

    # Parse cookies out of Set-Cookie
    cookies = {}
    sc = r.headers.get("Set-Cookie") or r.headers.get("set-cookie") or ""
    if sc:
        for chunk in sc.split(","):
            m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
            if m:
                cookies[m.group(1).strip()] = m.group(2).strip()

    # Extract title (crude — scanners don't need BeautifulSoup-precise)
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
    }


def placeholder_page(url):
    """
    Build a page record without fetching. Useful when you already have the
    response captured elsewhere and just want the URL registered.
    """
    parsed = urlparse(url)
    return {
        "url": url,
        "status": 200,
        "method": "GET",
        "content_type": "text/html",
        "content_length": 0,
        "title": "",
        "params": list(parse_qs(parsed.query).keys()),
        "headers": {},
        "cookies": {},
        "content": "",
        "_source": "burp_placeholder",
        "_note": "no content captured — scanners will test URL params only",
    }


# =============================================================================
#  MAIN
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="Burp URLs → HUGINN sites/ workspace")
    ap.add_argument("urls_file", help="text file with one URL per line")
    ap.add_argument("workspace", help="workspace directory to create")
    ap.add_argument("--no-fetch", action="store_true",
                    help="skip fetching; register URLs with empty content")
    ap.add_argument("--filter", default=None,
                    help="only include URLs matching this regex")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help=f"delay between requests (default {DEFAULT_DELAY}s)")
    args = ap.parse_args()

    urls_file = Path(args.urls_file)
    if not urls_file.exists():
        log(f"URLs file not found: {urls_file}", "err")
        sys.exit(1)

    workspace = Path(args.workspace)
    sites_root = workspace / "sites"
    sites_root.mkdir(parents=True, exist_ok=True)
    (workspace / "findings").mkdir(parents=True, exist_ok=True)
    (workspace / "recon").mkdir(parents=True, exist_ok=True)

    # ---- Load URLs ------------------------------------------------------
    urls = load_urls(urls_file, args.filter)
    if not urls:
        log("no URLs found in input file", "err")
        sys.exit(1)

    log(f"loaded {len(urls)} unique URLs", "ok")

    # ---- Group by host --------------------------------------------------
    by_host = {}
    for u in urls:
        host = urlparse(u).netloc.lower()
        if not host:
            continue
        by_host.setdefault(host, []).append(u)

    log(f"{len(by_host)} unique hosts", "ok")

    # ---- Fetch + write --------------------------------------------------
    section("FETCHING" if not args.no_fetch else "REGISTERING (no fetch)")

    total_written = 0
    total_failed = 0
    used_slugs = {}       # host → {slug: url}

    for host, host_urls in by_host.items():
        host_dir = sites_root / safe_filename(host)
        host_dir.mkdir(parents=True, exist_ok=True)
        used_slugs[host] = {}

        log(f"{host}: {len(host_urls)} URLs", "scan", host)

        for url in host_urls:
            slug = slug_for_url(url)

            # Handle slug collisions by appending a short hash
            if slug in used_slugs[host]:
                import hashlib
                h = hashlib.md5(url.encode()).hexdigest()[:6]
                slug = f"{slug}__{h}"
            used_slugs[host][slug] = url

            if args.no_fetch:
                record = placeholder_page(url)
            else:
                record = fetch_page(url)
                if record is None:
                    log(f"  ✗ {url[:100]}", "warn")
                    total_failed += 1
                    time.sleep(args.delay)
                    continue

            out_path = host_dir / f"{slug}.json"
            save_json(out_path, record)
            total_written += 1

            status = record.get("status", "?")
            log(f"  [{status}] {url[:110]}", "ok", host)

            if not args.no_fetch:
                time.sleep(args.delay)

    # ---- Summary --------------------------------------------------------
    section("SUMMARY")
    log(f"workspace     : {workspace}", "ok")
    log(f"hosts         : {len(by_host)}", "info")
    log(f"pages written : {total_written}", "ok")
    if total_failed:
        log(f"pages failed  : {total_failed}", "warn")

    print()
    print(f"{C.D}Now run individual scanners against this workspace:{C.R}")
    print()
    print(f"  python sqli.py          {workspace}")
    print(f"  python xss.py           {workspace} --browser")
    print(f"  python ssrf.py          {workspace}")
    print(f"  python open_redirect.py {workspace}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
        sys.exit(130)
