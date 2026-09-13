#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: crawl.py — v3.0 (multi-engine + 403 bypass)
# -----------------------------------------------------------------------------
#  Engines (best-effort, chained):
#    1. Katana            — ProjectDiscovery's fast JS-aware crawler
#    2. Crawl4AI          — Playwright-backed, JS-heavy sites, async
#    3. Firecrawl         — API-based, clean markdown, schema extraction
#    4. Python BFS        — last-resort fallback, always works
#
#  Plus:
#    · Sensitive-file discovery (config/.env/.git/backups) with 403 bypass
#    · Content-hash dedup, skip-reason diagnostics
#    · Per-host + global aggregation
# =============================================================================

import re
import os
import json
import time
import base64
import hashlib
import asyncio
import threading
from pathlib import Path
from urllib.parse import (urlparse, urljoin, urlunparse, parse_qs,
                          urlencode, quote)
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, save_json, load_json, run_cmd, which, send_request,
    safe_filename, throttle, get_host, C,
)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# ---- Optional engine imports ------------------------------------------------
try:
    from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, BrowserConfig
    HAS_CRAWL4AI = True
except ImportError:
    HAS_CRAWL4AI = False

try:
    from firecrawl import Firecrawl
    HAS_FIRECRAWL = True
except ImportError:
    HAS_FIRECRAWL = False


# =============================================================================
#  CONSTANTS
# =============================================================================

KEEP_STATUS = {
    200, 201, 202, 203, 204,
    301, 302, 303, 307, 308,
    401, 403, 405,
    500, 501, 502, 503,
}

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico",
    ".tiff", ".tif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".m4a", ".m4v", ".wav", ".ogg", ".ogv", ".webm",
    ".avi", ".mov", ".wmv", ".flv", ".mkv",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".dmg",
    ".apk", ".ipa", ".deb", ".rpm",
    ".sql", ".db", ".sqlite", ".sqlite3",
    ".map", ".css",
}

KEEP_CONTENT_TYPES = (
    "text/html", "application/xhtml",
    "application/json", "application/ld+json",
    "application/xml", "text/xml",
    "text/plain", "application/javascript", "text/javascript",
    "application/x-javascript",
    "",
)

MAX_DEPTH        = 4
MAX_PAGES_HOST   = 5000
MAX_BODY_BYTES   = 200_000
HASH_SAMPLE_SIZE = 10_000

KATANA_DEPTH       = 4
KATANA_CONCURRENCY = 5
KATANA_RATE_LIMIT  = 30
KATANA_TIMEOUT     = 15
KATANA_MAX_SECONDS = 900     # hard cap so katana can't eat 35 minutes

CRAWL4AI_TIMEOUT   = 25      # per-page seconds
CRAWL4AI_MAX_PAGES = 100     # per-host cap on deep-crawl
FIRECRAWL_LIMIT    = 200     # per-domain page cap
FIRECRAWL_TIMEOUT  = 30      # poll interval seconds

HOST_WORKERS           = 3
FETCH_WORKERS_PER_HOST = 3
FETCH_TIMEOUT          = 30
DEFAULT_DELAY          = 0.4

NON_HTML_CT = ("application/json", "text/plain", "application/javascript",
               "text/javascript", "application/xml", "text/xml")


# =============================================================================
#  403 BYPASS PAYLOADS FOR SENSITIVE FILES
# =============================================================================
#  Files worth probing for on every live host. Each is a (path, category)
#  tuple. Categories route the file's content through different detectors.
SENSITIVE_FILES = [
    ("/.env",              "env"),
    ("/.env.local",        "env"),
    ("/.env.production",   "env"),
    ("/.env.backup",       "env"),
    ("/.env.bak",          "env"),
    ("/.env.old",          "env"),
    ("/.env.dev",          "env"),
    ("/.env.staging",      "env"),
    ("/config.php",        "config"),
    ("/config.json",       "config"),
    ("/config.yaml",       "config"),
    ("/config.yml",        "config"),
    ("/config.xml",        "config"),
    ("/configuration.php", "config"),
    ("/settings.py",       "config"),
    ("/wp-config.php",     "wordpress"),
    ("/wp-config.php.bak", "wordpress"),
    ("/.git/config",       "git"),
    ("/.git/HEAD",         "git"),
    ("/.gitignore",        "git"),
    ("/.git/",             "git"),
    ("/.svn/entries",      "svn"),
    ("/.htaccess",         "apache"),
    ("/.htpasswd",         "apache"),
    ("/web.config",        "iis"),
    ("/phpinfo.php",       "phpinfo"),
    ("/info.php",          "phpinfo"),
    ("/server-status",     "apache"),
    ("/server-info",       "apache"),
    ("/backup.sql",        "backup"),
    ("/backup.zip",        "backup"),
    ("/backup.tar.gz",     "backup"),
    ("/db.sql",            "backup"),
    ("/dump.sql",          "backup"),
    ("/database.sql",      "backup"),
    ("/composer.json",     "deps"),
    ("/package.json",      "deps"),
    ("/yarn.lock",         "deps"),
    ("/composer.lock",     "deps"),
    ("/Dockerfile",        "docker"),
    ("/docker-compose.yml","docker"),
    ("/.dockerignore",     "docker"),
    ("/Procfile",          "heroku"),
    ("/manifest.json",     "pwa"),
    ("/robots.txt",        "meta"),
    ("/sitemap.xml",       "meta"),
]

#  Path mutation techniques for 403 bypass
BYPASS_MUTATIONS = [
    # (description, transform_function)
    ("identity",         lambda p: p),
    ("trailing-dot",     lambda p: p + "."),
    ("trailing-slash",   lambda p: p + "/"),
    ("double-slash",     lambda p: p.replace("/", "//", 1)),
    ("dot-slash",        lambda p: "/./" + p.lstrip("/")),
    ("double-encoded",   lambda p: p.replace("/", "%252f").replace(".", "%252e")),
    ("encoded-dot",      lambda p: p.replace(".", "%2e")),
    ("uppercase",        lambda p: p.upper()),
    ("case-mixed",       lambda p: "/" + p.lstrip("/").swapcase()),
    ("trailing-space",   lambda p: p + "%20"),
    ("trailing-tab",     lambda p: p + "%09"),
    ("trailing-newline", lambda p: p + "%0a"),
    ("trailing-null",    lambda p: p + "%00"),
    ("double-dot-slash", lambda p: "/.." + p),
    ("dot-dot-semi",     lambda p: "/..;/" + p.lstrip("/")),
]

#  Headers to send when 403 is hit
BYPASS_HEADERS = [
    {"X-Original-URL":      "{path}"},
    {"X-Rewrite-URL":       "{path}"},
    {"X-Forwarded-For":     "127.0.0.1"},
    {"X-Forwarded-Host":    "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP":    "127.0.0.1"},
    {"X-Remote-IP":         "127.0.0.1"},
    {"X-Remote-Addr":       "127.0.0.1"},
    {"X-Client-IP":         "127.0.0.1"},
    {"X-Host":              "127.0.0.1"},
    {"X-Forwarded-Server":  "127.0.0.1"},
    {"X-HTTP-Method-Override": "GET"},
    {"Referer":             "{base}"},
]

#  Content markers that mean we actually hit the file (not a soft 200 page)
HIT_MARKERS = {
    "env":      [re.compile(r"^[A-Z_]{3,}\s*=", re.M)],
    "config":   [re.compile(r"<\?php", re.I),
                 re.compile(r"^\s*[\w]+\s*[:=]\s", re.M)],
    "wordpress":[re.compile(r"DB_NAME|DB_PASSWORD|table_prefix", re.I)],
    "git":      [re.compile(r"\[core\]", re.I),
                 re.compile(r"^ref:\s+refs/heads/", re.M)],
    "svn":      [re.compile(r"<entry", re.I)],
    "apache":   [re.compile(r"<IfModule|<Directory|AuthType|Require\s+", re.I)],
    "iis":      [re.compile(r"<configuration|<system\.web", re.I)],
    "phpinfo":  [re.compile(r"<title>phpinfo\(\)|PHP Version", re.I)],
    "backup":   [re.compile(r"INSERT INTO|CREATE TABLE|-- MySQL dump", re.I)],
    "deps":     [re.compile(r'"(name|version|dependencies)"\s*:', re.I)],
    "docker":   [re.compile(r"FROM\s+\w+|version\s*:", re.I)],
    "heroku":   [re.compile(r"web:\s+\w+", re.I)],
    "pwa":      [re.compile(r'"name"\s*:\s*"', re.I)],
    "meta":     [re.compile(r"User-agent|<\?xml|<urlset", re.I)],
}


# =============================================================================
#  URL FILTERING
# =============================================================================
def _url_extension(url):
    path = urlparse(url).path
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _should_skip_url(url):
    if not url:
        return True
    low = url.lower()
    if low.startswith(("mailto:", "tel:", "javascript:", "data:",
                       "file:", "blob:")):
        return True
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    cache_busters = {"_", "v", "ver", "version", "ts", "t",
                     "timestamp", "cache", "rand", "random", "_t"}
    if qs and set(qs.keys()).issubset(cache_busters):
        return True
    ext = _url_extension(url)
    if ext in SKIP_EXTENSIONS:
        return True
    return False


def _content_type_ok(ct):
    if not ct:
        return True
    return any(c in ct.lower() for c in KEEP_CONTENT_TYPES)


# =============================================================================
#  ROBOTS / SITEMAP
# =============================================================================
def _parse_robots(base_url):
    out = {"disallow": [], "allow": [], "sitemaps": []}
    r = send_request(urljoin(base_url, "/robots.txt"), timeout=10)
    if r is None or r.status_code != 200:
        return out
    for line in (r.text or "").splitlines():
        line = line.strip()
        if line.startswith("#") or not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "disallow" and val:
            out["disallow"].append(val)
        elif key == "allow" and val:
            out["allow"].append(val)
        elif key == "sitemap" and val:
            out["sitemaps"].append(val)
    return out


def _parse_sitemap(sitemap_url, max_urls=5000):
    urls = []
    seen = set()

    def _walk(u, depth=0):
        if depth > 3 or len(urls) >= max_urls or u in seen:
            return
        seen.add(u)
        r = send_request(u, timeout=10)
        if r is None or r.status_code != 200:
            return
        try:
            root = ET.fromstring(r.content)
        except Exception:
            return
        tag = root.tag.split("}")[-1]
        if tag == "sitemapindex":
            for loc in root.iter():
                if loc.tag.split("}")[-1] == "loc" and loc.text:
                    _walk(loc.text.strip(), depth + 1)
        elif tag == "urlset":
            for loc in root.iter():
                if loc.tag.split("}")[-1] == "loc" and loc.text:
                    urls.append(loc.text.strip())
                    if len(urls) >= max_urls:
                        return

    _walk(sitemap_url)
    return urls


def _seed_from_robots_and_sitemap(base_url):
    discovered = set()
    robots = _parse_robots(base_url)
    for path in robots["disallow"]:
        if path in ("/", "/*") or len(path) < 2:
            continue
        discovered.add(urljoin(base_url, path.rstrip("*").rstrip("$")))
    sitemap_urls = list(robots["sitemaps"])
    for guess in ("sitemap.xml", "sitemap_index.xml", "sitemap-index.xml",
                  "sitemap/sitemap.xml", "sitemap1.xml", "sitemap.txt"):
        sitemap_urls.append(urljoin(base_url, guess))
    for sm in sitemap_urls[:6]:
        try:
            found = _parse_sitemap(sm)
            if found:
                log(f"sitemap {sm} → {len(found)} URLs", "info", "SEED")
                discovered.update(found)
                break
        except Exception:
            continue
    return discovered


# =============================================================================
#  ENGINE 1 — KATANA (single batch)
# =============================================================================
def katana_crawl_once(all_seeds, out_dir, timeout=KATANA_MAX_SECONDS):
    if not which("katana"):
        return []

    log(f"katana crawling {len(all_seeds)} seeds "
        f"(c={KATANA_CONCURRENCY}, rl={KATANA_RATE_LIMIT}, "
        f"max={KATANA_MAX_SECONDS}s)…", "scan", "KATANA")

    seeds_file = out_dir / "_katana_seeds.txt"
    seeds_file.write_text("\n".join(all_seeds) + "\n")

    r = run_cmd([
        "katana",
        "-list", str(seeds_file),
        "-jsonl", "-silent", "-no-color",
        "-d", str(KATANA_DEPTH),
        "-jc",
        "-kf", "robotstxt,sitemapxml",   # narrow scope — was "all"
        "-xhr",
        "-c", str(KATANA_CONCURRENCY),
        "-timeout", str(KATANA_TIMEOUT),
        "-rl", str(KATANA_RATE_LIMIT),
        "-retry", "1",
    ], timeout=timeout)

    urls = []
    if r and r.stdout:
        for line in r.stdout.splitlines():
            try:
                obj = json.loads(line)
                url = (obj.get("request", {}).get("endpoint")
                       or obj.get("url"))
                method = obj.get("request", {}).get("method", "GET")
                if url:
                    urls.append({"url": url, "method": method,
                                 "_source": "katana"})
            except Exception:
                pass
    log(f"katana returned {len(urls)} URLs total", "ok", "KATANA")
    return urls


# =============================================================================
#  ENGINE 2 — CRAWL4AI (async, Playwright, JS-heavy)
# =============================================================================
def _crawl4ai_worker(seed_urls, out_dir):
    """
    Run Crawl4AI synchronously for a list of seeds.
    Returns list of dicts: {url, method, html, markdown, links, _source}
    """
    async def _run():
        results = []
        try:
            browser_cfg = BrowserConfig(headless=True, verbose=False)
            run_cfg = CrawlerRunConfig(
                page_timeout=CRAWL4AI_TIMEOUT * 1000,
                wait_until="domcontentloaded",
                word_count_threshold=10,
                exclude_external_links=True,
                exclude_social_media_links=True,
            )
            async with AsyncWebCrawler(config=browser_cfg) as crawler:
                for seed in seed_urls[:CRAWL4AI_MAX_PAGES]:
                    try:
                        r = await crawler.arun(url=seed, config=run_cfg)
                        if r and r.success:
                            results.append({
                                "url": r.url or seed,
                                "method": "GET",
                                "html": (r.html or "")[:MAX_BODY_BYTES],
                                "markdown": (r.markdown or "")[:MAX_BODY_BYTES],
                                "links": r.links or {},
                                "_source": "crawl4ai",
                            })
                    except Exception as e:
                        log(f"crawl4ai {seed}: {e}", "warn", "CRAWL4AI")
        except Exception as e:
            log(f"crawl4ai engine failed: {e}", "warn", "CRAWL4AI")
        return results

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        log(f"crawl4ai loop error: {e}", "warn", "CRAWL4AI")
        return []


def crawl4ai_crawl(all_seeds):
    if not HAS_CRAWL4AI:
        return []
    log(f"crawl4ai probing {min(len(all_seeds), CRAWL4AI_MAX_PAGES)} seeds…",
        "scan", "CRAWL4AI")
    results = _crawl4ai_worker(all_seeds, None)
    log(f"crawl4ai returned {len(results)} pages", "ok", "CRAWL4AI")
    return results


# =============================================================================
#  ENGINE 3 — FIRECRAWL (API-based, needs internet to api.firecrawl.dev)
# =============================================================================
def firecrawl_crawl(all_seeds, out_dir):
    """
    Firecrawl is API-based: send the seed list, get clean pages back.
    Uses start_crawl + poll to avoid blocking on a single long call.
    """
    if not HAS_FIRECRAWL:
        return []

    api_key = os.environ.get("FIRECRAWL_API_KEY")
    log(f"firecrawl starting ({len(all_seeds)} seeds)…", "scan", "FIRECRAWL")

    try:
        if api_key:
            client = Firecrawl(api_key=api_key)
        else:
            # Free tier, no key required
            client = Firecrawl()

        # Firecrawl crawls one URL at a time and discovers links.
        # We give it the primary (first) seed to keep scope tight.
        primary = all_seeds[0] if all_seeds else None
        if not primary:
            return []

        docs = client.crawl(
            url=primary,
            limit=FIRECRAWL_LIMIT,
            scrape_options={"formats": ["markdown", "html"]},
        )

        results = []
        data = getattr(docs, "data", None) or []
        for doc in data:
            md = getattr(doc, "markdown", "") or ""
            html = getattr(doc, "html", "") or ""
            meta = getattr(doc, "metadata", None) or {}
            url = (meta.get("sourceURL")
                   or meta.get("url")
                   or getattr(doc, "url", None))
            if url:
                results.append({
                    "url": url,
                    "method": "GET",
                    "html": html[:MAX_BODY_BYTES],
                    "markdown": md[:MAX_BODY_BYTES],
                    "links": {},
                    "_source": "firecrawl",
                })

        log(f"firecrawl returned {len(results)} pages", "ok", "FIRECRAWL")
        return results
    except Exception as e:
        log(f"firecrawl error: {e}", "warn", "FIRECRAWL")
        return []


# =============================================================================
#  ENGINE 4 — PYTHON BFS FALLBACK
# =============================================================================
def python_crawl(seed_urls, domain):
    if BeautifulSoup is None:
        return []
    results = []
    seen = set()
    lock = threading.Lock()

    def _fetch_links(url):
        if _should_skip_url(url):
            return []
        r = send_request(url, timeout=15, allow_redirects=True)
        if r is None:
            return []
        ct = (r.headers.get("Content-Type") or "").lower()
        if "text/html" not in ct:
            return []
        try:
            soup = BeautifulSoup(r.text, "html.parser")
        except Exception:
            return []
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(url, href).split("#")[0]
            if domain in urlparse(full).netloc:
                links.add(full)
        return list(links)

    queue = list(seed_urls)
    depth = {u: 0 for u in seed_urls}

    while queue and len(results) < MAX_PAGES_HOST * 3:
        batch = queue[:16]
        queue = queue[16:]
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(_fetch_links, u): u for u in batch}
            for fut in as_completed(futures):
                parent = futures[fut]
                parent_depth = depth.get(parent, 0)
                try:
                    links = fut.result()
                except Exception:
                    continue
                for link in links:
                    with lock:
                        if link in seen:
                            continue
                        seen.add(link)
                        results.append({"url": link, "method": "GET",
                                        "_source": "python"})
                        if parent_depth + 1 <= MAX_DEPTH:
                            depth[link] = parent_depth + 1
                            queue.append(link)
    return results


# =============================================================================
#  EXTRACTION
# =============================================================================
RE_JS_ENDPOINT = re.compile(r"""["']([/][a-zA-Z0-9_\-./?&=%{}:]*?)["']""", re.X)
RE_JS_FETCH = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete)|\.ajax)\s*\(\s*["']([^"']+)["']""",
    re.I)
RE_JS_PATH = re.compile(
    r"""["'](/(?:api|v[0-9]+|graphql|rest)/[^"']{2,120})["']""", re.I)


def extract_forms(soup, page_url):
    forms = []
    if soup is None:
        return forms
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        method = (form.get("method") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            ftype = (inp.get("type") or "").lower()
            if ftype in ("submit", "button", "reset", "image"):
                continue
            fields.append({
                "name": name,
                "type": ftype or inp.name,
                "value": inp.get("value", ""),
            })
        if fields:
            forms.append({
                "action": action_url,
                "method": method,
                "fields": fields,
                "page_url": page_url,
            })
    return forms


def extract_js_endpoints(html):
    if not html:
        return []
    endpoints = set()
    for m in RE_JS_FETCH.finditer(html):
        u = m.group(1).strip()
        if u and not u.startswith(("data:", "javascript:", "#")):
            endpoints.add(u)
    for m in RE_JS_PATH.finditer(html):
        u = m.group(1).strip()
        if u:
            endpoints.add(u)
    for m in RE_JS_ENDPOINT.finditer(html):
        u = m.group(1).strip()
        if len(u) < 3 or u in ("//", "/**/"):
            continue
        if any(u.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
            continue
        endpoints.add(u)
    return sorted(endpoints)


def extract_links(soup, page_url, domain):
    links = set()
    if soup is None:
        return []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urljoin(page_url, href).split("#")[0]
        if domain in urlparse(full).netloc:
            links.add(full)
    return list(links)


# =============================================================================
#  FETCH + STORE
# =============================================================================
def _content_hash(body_bytes):
    if not body_bytes:
        return ""
    return hashlib.sha256(body_bytes[:HASH_SAMPLE_SIZE]).hexdigest()


def _slug_for_url(url):
    """
    FIXED: the old version returned '_' for root URLs and '_api_v1_users'
    for any path starting with /, which caused EVERY stored file to start
    with '_' and every scanner to skip it via the metadata filter.
    """
    parsed = urlparse(url)
    # Strip leading/trailing slashes, replace inner ones, default to 'index'
    path_part = parsed.path.strip("/").replace("/", "_") or "index"
    if parsed.query:
        qs_slug = "_".join(f"{k}={v[0]}"
                           for k, v in sorted(parse_qs(parsed.query).items()))
        path_part = f"{path_part}__{qs_slug}"
    slug = safe_filename(path_part)
    # If a legitimate URL path itself starts with '_', prefix so the
    # metadata-skip filter doesn't eat it.
    if slug.startswith("_"):
        slug = "p" + slug
    return slug


def _parse_cookies(headers):
    sc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    out = {}
    if not sc:
        return out
    for chunk in sc.split(","):
        m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    return out


def fetch_and_store(page, site_dir, seen_hashes, seen_hashes_lock,
                    delay=DEFAULT_DELAY):
    """
    Fetch + store a single page. Returns the record, or a `_skip` dict.
    Accepts `page` dicts that already contain pre-fetched content from
    Crawl4AI/Firecrawl — those skip the HTTP fetch step.
    """
    url = page["url"]
    method = page.get("method", "GET")
    pre_html = page.get("html")
    pre_md   = page.get("markdown")

    if _should_skip_url(url):
        return {"_skip": True, "url": url, "reason": "url_filter"}

    host = get_host(url)
    throttle(host, delay)

    # ---- If engine already returned content, use it ---------------------
    if pre_html is not None:
        body_text = pre_html
        status = 200
        ct = "text/html; charset=utf-8"
        headers = {}
        body_bytes = body_text.encode("utf-8", errors="ignore")
    else:
        try:
            r = send_request(url, method=method, timeout=FETCH_TIMEOUT,
                             allow_redirects=True)
        except Exception as e:
            return {"_skip": True, "url": url, "reason": f"exception:{e}"}

        if r is None:
            return {"_skip": True, "url": url, "reason": "no_response"}
        if r.status_code not in KEEP_STATUS:
            return {"_skip": True, "url": url,
                    "reason": f"status:{r.status_code}"}

        ct = (r.headers.get("Content-Type") or "").lower()
        if not _content_type_ok(ct):
            return {"_skip": True, "url": url,
                    "reason": f"content_type:{ct}"}

        body_bytes = r.content or b""
        body_text = r.text or ""
        status = r.status_code
        headers = dict(r.headers)

    # ---- Content-hash dedup (HTML only) --------------------------------
    content_hash = None
    if "text/html" in ct:
        content_hash = _content_hash(body_bytes)
        with seen_hashes_lock:
            if content_hash in seen_hashes:
                return {"_skip": True, "url": url,
                        "reason": "content_dedup",
                        "hash": content_hash}
            seen_hashes.add(content_hash)

    # ---- Extract --------------------------------------------------------
    soup = None
    title = ""
    forms = []
    endpoints = []
    links = []
    if "text/html" in ct and BeautifulSoup:
        try:
            soup = BeautifulSoup(body_text, "html.parser")
            title_tag = soup.title
            title = title_tag.get_text(strip=True) if title_tag else ""
            forms = extract_forms(soup, url)
            endpoints = extract_js_endpoints(body_text)
            links = extract_links(soup, url, urlparse(url).netloc)
        except Exception:
            pass

    parsed = urlparse(url)
    record = {
        "url": url,
        "status": status,
        "method": method,
        "content_type": ct,
        "content_length": len(body_bytes),
        "content_hash": content_hash,
        "title": title,
        "params": list(parse_qs(parsed.query).keys()),
        "headers": headers,
        "cookies": _parse_cookies(headers),
        "forms": forms,
        "js_endpoints": endpoints,
        "out_links": links[:200],
        "content": body_text[:MAX_BODY_BYTES],
        "crawl_source": page.get("_source", "http"),
    }
    if pre_md:
        record["markdown"] = pre_md[:MAX_BODY_BYTES]

    slug = _slug_for_url(url)
    fname = f"{slug}.json"
    out_path = site_dir / fname
    if out_path.exists():
        fname = (f"{slug}__{content_hash[:6] if content_hash else int(time.time())}.json")
        out_path = site_dir / fname

    save_json(out_path, record)
    return record


# =============================================================================
#  SENSITIVE-FILE DISCOVERY + 403 BYPASS
# =============================================================================
def _content_is_hit(body, category):
    """Return (True, marker) if the response looks like the real file."""
    if not body:
        return False, None
    for rx in HIT_MARKERS.get(category, []):
        m = rx.search(body)
        if m:
            return True, m.group(0)[:80]
    return False, None


def _probe_one_file(base_url, path, category, host, out_dir):
    """
    Try every BYPASS_MUTATIONS technique against one sensitive path.
    On a hit (200 + content matches the file category), save it.
    """
    hits = []
    base = base_url.rstrip("/")

    for desc, transform in BYPASS_MUTATIONS:
        mutated = transform(path)
        target = base + mutated
        try:
            r = send_request(target, timeout=10, allow_redirects=False)
        except Exception:
            continue
        if r is None:
            continue
        # Only consider a hit if we got real content
        if r.status_code not in (200, 206):
            continue
        is_hit, marker = _content_is_hit(r.text or "", category)
        if not is_hit:
            continue
        hits.append({
            "path": path,
            "category": category,
            "bypass_technique": desc,
            "url": target,
            "status": r.status_code,
            "content_length": len(r.content or b""),
            "marker": marker,
            "snippet": (r.text or "")[:800],
        })
        break  # one successful bypass per path is enough

    # ---- If nothing worked, try header-based bypasses -------------------
    if not hits:
        target = base + path
        for hdr_template in BYPASS_HEADERS:
            hdrs = {k: v.format(path=path, base=base)
                    for k, v in hdr_template.items()}
            try:
                r = send_request(target, headers=hdrs, timeout=10,
                                 allow_redirects=False)
            except Exception:
                continue
            if r is None or r.status_code not in (200, 206):
                continue
            is_hit, marker = _content_is_hit(r.text or "", category)
            if not is_hit:
                continue
            hits.append({
                "path": path,
                "category": category,
                "bypass_technique": f"header:{list(hdrs.keys())[0]}",
                "url": target,
                "status": r.status_code,
                "content_length": len(r.content or b""),
                "marker": marker,
                "snippet": (r.text or "")[:800],
            })
            break

    if hits:
        for h in hits:
            # Save the exposed file with a clear name
            safe = safe_filename(path.replace("/", "_").replace(".", "_"))
            save_json(out_dir / f"_EXPOSED_{safe}.json", h)
        log(f"EXPOSED  {path}  ({hits[0]['bypass_technique']})", "hit", "403BYP")
    return hits


def probe_sensitive_files(host, scheme, out_dir, delay=DEFAULT_DELAY):
    """
    Probe every path in SENSITIVE_FILES against one host.
    Returns a list of hits.
    """
    base_url = f"{scheme}://{host}"
    log(f"probing {len(SENSITIVE_FILES)} sensitive paths on {host}…",
        "scan", "403BYP")

    all_hits = []
    for path, category in SENSITIVE_FILES:
        # Skip the trivially-public ones (robots/sitemap) — already crawled
        if category == "meta":
            continue
        throttle(host, delay)
        try:
            hits = _probe_one_file(base_url, path, category, host, out_dir)
            all_hits.extend(hits)
        except Exception as e:
            log(f"probe error {path}: {e}", "warn", "403BYP")

    if all_hits:
        log(f"{len(all_hits)} sensitive file(s) exposed on {host}",
            "hit", "403BYP")
    return all_hits


# =============================================================================
#  PER-HOST ORCHESTRATOR
# =============================================================================
def crawl_host(host, seed_urls, engine_urls, sites_root,
               delay=DEFAULT_DELAY, probe_files=True):
    site_dir = sites_root / safe_filename(host)
    site_dir.mkdir(parents=True, exist_ok=True)

    # ---- Build the fetch queue ------------------------------------------
    discovered = []

    # 1. Seeds first (highest priority)
    for u in seed_urls:
        discovered.append({"url": u, "method": "GET", "_source": "seed"})

    # 2. Engine-discovered URLs (Katana, Crawl4AI, Firecrawl)
    for e in (engine_urls or []):
        discovered.append(e)

    # 3. robots.txt + sitemap.xml seeds
    robots_seeds = set()
    for seed in seed_urls[:3]:
        try:
            robots_seeds.update(_seed_from_robots_and_sitemap(seed))
        except Exception:
            continue
    for u in robots_seeds:
        discovered.append({"url": u, "method": "GET", "_source": "robots"})

    # ---- Dedup pre-fetch ------------------------------------------------
    seen_urls = set()
    deduped = []
    for d in discovered:
        u = d["url"]
        if u in seen_urls:
            continue
        seen_urls.add(u)
        deduped.append(d)
        if len(deduped) >= MAX_PAGES_HOST:
            break

    log(f"{host}: {len(deduped)} URLs to fetch", "scan", host)

    # ---- Parallel fetch -------------------------------------------------
    seen_hashes = set()
    seen_hashes_lock = threading.Lock()
    stored = []
    deduped_count = 0
    skip_reasons = {}

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS_PER_HOST) as pool:
        futures = {
            pool.submit(fetch_and_store, p, site_dir,
                        seen_hashes, seen_hashes_lock, delay): p
            for p in deduped
        }
        for fut in as_completed(futures):
            try:
                rec = fut.result()
                if rec is None:
                    continue
                if rec.get("_skip"):
                    reason = rec.get("reason", "unknown")
                    skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                    if reason == "content_dedup":
                        deduped_count += 1
                    continue
                stored.append(rec)
                status = rec["status"]
                if status in (200, 403, 401, 500):
                    src = rec.get("crawl_source", "http")
                    log(f"[{status}] ({src}) {rec['url'][:100]}",
                        "ok", host)
            except Exception as e:
                skip_reasons[f"thread_error:{e}"] = \
                    skip_reasons.get(f"thread_error:{e}", 0) + 1

    # ---- Sensitive-file probe (403 bypass) ------------------------------
    file_hits = []
    if probe_files:
        scheme = "https"
        for s in seed_urls:
            parsed = urlparse(s)
            if parsed.scheme:
                scheme = parsed.scheme
                break
        try:
            file_hits = probe_sensitive_files(host, scheme, site_dir, delay)
        except Exception as e:
            log(f"file-probe error on {host}: {e}", "warn", host)

    # ---- Aggregate per-host artifacts -----------------------------------
    endpoints = sorted({e for r in stored for e in (r.get("js_endpoints") or [])})
    forms_flat = [f for r in stored for f in (r.get("forms") or [])]
    params_seen = sorted({p for r in stored for p in (r.get("params") or [])})
    statuses = {}
    for r in stored:
        statuses[str(r["status"])] = statuses.get(str(r["status"]), 0) + 1

    save_json(site_dir / "_forms.json", {
        "host": host, "count": len(forms_flat), "forms": forms_flat,
    })
    save_json(site_dir / "_endpoints.json", {
        "host": host, "count": len(endpoints), "endpoints": endpoints,
    })
    save_json(site_dir / "_host_summary.json", {
        "host": host,
        "pages_stored": len(stored),
        "pages_deduped": deduped_count,
        "skip_reasons": skip_reasons,
        "status_distribution": statuses,
        "unique_params": params_seen,
        "unique_endpoints": len(endpoints),
        "unique_forms": len(forms_flat),
        "sensitive_file_hits": len(file_hits),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    return {
        "host": host,
        "stored": stored,
        "endpoints": endpoints,
        "forms": forms_flat,
        "params": params_seen,
        "deduped": deduped_count,
        "statuses": statuses,
        "skipped": skip_reasons,
        "sensitive_file_hits": file_hits,
    }


# =============================================================================
#  ORCHESTRATOR
# =============================================================================
def run(program_dir, httpx_file, probe_files=True):
    section("PHASE 3 :: CRAWLING")
    httpx_data = load_json(httpx_file)
    domain = httpx_data["domain"]
    sites_root = Path(program_dir) / "sites"
    sites_root.mkdir(parents=True, exist_ok=True)

    # ---- Build per-host seed lists --------------------------------------
    host_seeds = {}
    all_seeds = []
    for entry in httpx_data.get("results", []):
        u = entry.get("url") or entry.get("input")
        sc = entry.get("status_code")
        if not u or sc in (0, None):
            continue
        if not u.startswith("http"):
            u = f"https://{u}"
        if _should_skip_url(u):
            continue
        host = get_host(u)
        host_seeds.setdefault(host, []).append(u)
        all_seeds.append(u)

    if not host_seeds:
        log("no live seeds to crawl", "warn")
        return

    log(f"{len(host_seeds)} hosts to crawl, {len(all_seeds)} seed URLs", "info")

    # ---- ENGINE RUNS (best-effort, chained) -----------------------------
    t_start = time.time()
    engine_urls = []

    # 1. Katana — fast, JS-aware, best first pass
    try:
        katana_urls = katana_crawl_once(all_seeds, sites_root)
        engine_urls.extend(katana_urls)
    except Exception as e:
        log(f"katana engine failed: {e}", "warn", "KATANA")

    # 2. Crawl4AI — JS-heavy pages katana can't reach
    if HAS_CRAWL4AI:
        try:
            c4ai = crawl4ai_crawl(all_seeds[:CRAWL4AI_MAX_PAGES])
            engine_urls.extend(c4ai)
        except Exception as e:
            log(f"crawl4ai engine failed: {e}", "warn", "CRAWL4AI")
    else:
        log("crawl4ai not installed — install with: pip install crawl4ai",
            "info", "CRAWL4AI")

    # 3. Firecrawl — clean markdown, schema extraction (API)
    if HAS_FIRECRAWL:
        try:
            fc = firecrawl_crawl(all_seeds, sites_root)
            engine_urls.extend(fc)
        except Exception as e:
            log(f"firecrawl engine failed: {e}", "warn", "FIRECRAWL")
    else:
        log("firecrawl not installed — install with: pip install firecrawl-py",
            "info", "FIRECRAWL")

    # 4. Python BFS — always works, catches what the others missed
    try:
        py_urls = python_crawl(all_seeds, domain)
        for p in py_urls:
            p["_source"] = "python"
        engine_urls.extend(py_urls)
    except Exception as e:
        log(f"python BFS failed: {e}", "warn", "PYBFS")

    log(f"engines returned {len(engine_urls)} total URLs to fetch", "info")

    # ---- Bucket engine results by host ----------------------------------
    engine_by_host = {}
    for item in engine_urls:
        h = get_host(item["url"])
        engine_by_host.setdefault(h, []).append(item)

    # ---- Crawl hosts ----------------------------------------------------
    all_results = []
    with ThreadPoolExecutor(max_workers=HOST_WORKERS) as pool:
        futures = {
            pool.submit(crawl_host, host, seeds,
                        engine_by_host.get(host, []),
                        sites_root, DEFAULT_DELAY, probe_files): host
            for host, seeds in host_seeds.items()
        }
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                all_results.append(fut.result())
            except Exception as e:
                log(f"host crawl failed ({host}): {e}", "warn", host)

    elapsed = time.time() - t_start

    # ---- Global aggregation ---------------------------------------------
    all_endpoints = sorted({e for r in all_results for e in r["endpoints"]})
    all_forms     = [f for r in all_results for f in r["forms"]]
    all_params    = sorted({p for r in all_results for p in r["params"]})
    all_file_hits = [h for r in all_results for h in r.get("sensitive_file_hits", [])]
    total_stored  = sum(len(r["stored"]) for r in all_results)
    total_deduped = sum(r["deduped"] for r in all_results)
    total_skipped = {}
    for r in all_results:
        for reason, count in (r.get("skipped") or {}).items():
            total_skipped[reason] = total_skipped.get(reason, 0) + count

    index = {r["host"]: [p["url"] for p in r["stored"]] for r in all_results}
    save_json(sites_root / "_index.json", {
        "domain": domain,
        "hosts": len(all_results),
        "total_pages": total_stored,
        "total_deduped": total_deduped,
        "total_skipped": total_skipped,
        "total_sensitive_hits": len(all_file_hits),
        "by_host": index,
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    save_json(sites_root / "_endpoints.json", {
        "domain": domain, "count": len(all_endpoints),
        "endpoints": all_endpoints,
    })
    save_json(sites_root / "_forms.json", {
        "domain": domain, "count": len(all_forms), "forms": all_forms,
    })
    save_json(sites_root / "_parameters.json", {
        "domain": domain, "count": len(all_params),
        "parameters": all_params,
    })

    # ---- Sensitive-file index (high value: this is what gets paid) ------
    if all_file_hits:
        save_json(sites_root / "_sensitive_files.json", {
            "domain": domain,
            "count": len(all_file_hits),
            "hits": all_file_hits,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        log(f"{len(all_file_hits)} EXPOSED SENSITIVE FILE(S) → "
            f"_sensitive_files.json", "hit", "403BYP")

    # ---- Summary log ----------------------------------------------------
    log(f"crawled {len(all_results)} hosts in {elapsed:.1f}s", "ok", "DONE")
    log(f"stored {total_stored} pages (deduped {total_deduped})", "ok", "DONE")

    if total_skipped:
        log(f"skip breakdown: {total_skipped}", "info", "DONE")

    log(f"{len(all_endpoints)} unique JS endpoints discovered", "info")
    log(f"{len(all_forms)} forms discovered", "info")
    log(f"{len(all_params)} unique params discovered", "info")
    log(f"artifacts → {sites_root}", "ok", "SAVE")


# =============================================================================
#  ENTRY
# =============================================================================
if __name__ == "__main__":
    import sys
    from huginn_utils import normalize_target
    if len(sys.argv) < 3:
        print("usage: crawl.py <program_dir> <httpx_json> [--no-file-probe]")
        sys.exit(1)
    probe = "--no-file-probe" not in sys.argv
    run(sys.argv[1], sys.argv[2], probe_files=probe)
