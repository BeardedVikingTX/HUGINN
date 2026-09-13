#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: subdomains.py
#  The Colossal Beast — Subdomain Enumeration + HTTP Probing
# -----------------------------------------------------------------------------
#  Pipeline:
#    Phase 1  MULTI-SOURCE ENUMERATION
#      · subfinder       (passive + active)
#      · amass           (passive mode)
#      · assetfinder     (cert + public sources)
#      · crt.sh          (certificate transparency)
#      · certspotter     (CT API)
#      · chaos           (ProjectDiscovery public dataset, needs key)
#      · github-subdomains (GitHub code search, needs token)
#      · gau + waybackurls (historical URL extraction)
#      · alterx + gotator (permutation/alteration)
#      · dnsx            (bruteforce against provided wordlist)
#
#    Phase 2  WILDCARD DETECTION
#      · Probe random subdomains to detect *.domain wildcards
#      · Filter wildcard-resolved entries from the result set
#
#    Phase 3  DNS RESOLUTION (dnsx)
#      · Filter out dead hosts before HTTP probing (10x faster)
#      · Capture CNAME chains for cloud-provider fingerprinting
#
#    Phase 4  HTTP PROBING (httpx — corrected flags)
#      · Status code, title, tech detect, server, CDN, favicon
#      · JARM/TLS fingerprints, CNAME chains, redirect location
#      · Per-host response headers captured for WAF detection
#
#    Phase 5  ENRICHMENT
#      · WAF fingerprinting from response headers + body
#      · Cloud provider fingerprinting from CNAME + ASN + tech
#      · CMS / framework fingerprinting
#
#    Phase 6  PERSISTENCE
#      · subdomains.json    — every discovered host (raw + filtered)
#      · dns_resolved.json  — hosts that actually resolve
#      · httpx.json         — alive hosts with rich metadata
#      · hosts_plain.txt    — newline-delimited for other tools
#      · summary.json       — aggregated stats + fingerprints
# =============================================================================

import json
import time
import uuid
import ipaddress
import threading
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, save_json, load_json, run_cmd, which,
    normalize_target, C, send_request,
    detect_waf, detect_provider, detect_dbms,
)


# =============================================================================
#  CONSTANTS
# =============================================================================

DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/namelist.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
]

# Wildcard sentinel — random subdomain to detect *.domain catch-alls
WILDCARD_PROBE_PREFIX = "wildcard-probe-{hex}"


# =============================================================================
#  PHASE 1 — MULTI-SOURCE ENUMERATION
# =============================================================================
def enum_subfinder(domain):
    """subfinder — passive + active, best-in-class coverage."""
    if not which("subfinder"):
        return set()
    log("running subfinder…", "scan", "SUBFINDER")
    r = run_cmd(["subfinder", "-d", domain, "-silent", "-all"], timeout=600)
    if not r or r.returncode != 0:
        return set()
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}


def enum_amass(domain, timeout=900):
    """amass passive mode — slow but high quality."""
    if not which("amass"):
        return set()
    log("running amass (passive)…", "scan", "AMASS")
    r = run_cmd(["amass", "enum", "-passive", "-d", domain,
                 "-timeout", "10", "-silent"], timeout=timeout)
    if not r or r.returncode != 0:
        return set()
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}


def enum_assetfinder(domain):
    """assetfinder — cert + public sources."""
    if not which("assetfinder"):
        return set()
    log("running assetfinder…", "scan", "ASSETFINDER")
    r = run_cmd(["assetfinder", "--subs-only", domain], timeout=300)
    if not r or r.returncode != 0:
        return set()
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}


def enum_crtsh(domain):
    """crt.sh — certificate transparency logs (free)."""
    log("querying crt.sh…", "scan", "CRTSH")
    out = set()
    for attempt in range(2):
        try:
            r = send_request(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=45,
            )
            if r and r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower()
                        if name and "*" not in name and name.endswith(domain):
                            out.add(name)
                return out
        except Exception as e:
            log(f"crt.sh attempt {attempt+1} error: {e}", "warn")
        time.sleep(3)
    return out


def enum_certspotter(domain):
    """certspotter CT API — good coverage, no key needed for basic tier."""
    log("querying certspotter…", "scan", "CERTSPOTTER")
    out = set()
    try:
        r = send_request(
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=20,
        )
        if r and r.status_code == 200:
            for entry in r.json():
                for name in entry.get("dns_names", []):
                    name = name.strip().lower()
                    if name and "*" not in name and name.endswith(domain):
                        out.add(name)
    except Exception as e:
        log(f"certspotter error: {e}", "warn")
    return out


def enum_chaos(domain):
    """chaos — ProjectDiscovery's public subdomain dataset. Needs CHAOS_KEY."""
    if not which("chaos"):
        return set()
    import os
    if not os.environ.get("CHAOS_KEY"):
        return set()
    log("running chaos…", "scan", "CHAOS")
    r = run_cmd(["chaos", "-d", domain, "-silent"], timeout=180)
    if not r or r.returncode != 0:
        return set()
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}


def enum_github_subdomains(domain):
    """github-subdomains — code search for mentions. Needs GITHUB_TOKEN."""
    if not which("github-subdomains"):
        return set()
    import os
    if not os.environ.get("GITHUB_TOKEN"):
        return set()
    log("running github-subdomains…", "scan", "GITHUB-SUBDOMAINS")
    r = run_cmd(["github-subdomains", "-d", domain, "-t",
                 os.environ["GITHUB_TOKEN"]], timeout=300)
    if not r or r.returncode != 0:
        return set()
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}


def enum_wayback(domain):
    """waybackurls + gau — historical URLs to extract hosts from."""
    urls = set()
    if which("gau"):
        log("running gau…", "scan", "GAU")
        r = run_cmd(["gau", "--subs", domain], timeout=300)
        if r and r.stdout:
            urls.update(l.strip() for l in r.stdout.splitlines() if l.strip())
    if which("waybackurls"):
        log("running waybackurls…", "scan", "WAYBACK")
        r = run_cmd(["waybackurls", domain], timeout=300)
        if r and r.stdout:
            urls.update(l.strip() for l in r.stdout.splitlines() if l.strip())

    hosts = set()
    for u in urls:
        try:
            host = urlparse(u if "://" in u else f"http://{u}").netloc.lower()
            host = host.split(":")[0]
            if host.endswith(domain):
                hosts.add(host)
        except Exception:
            continue
    return hosts


def enum_alterx(domain, existing_subs):
    """alterx — generate permutations from existing subdomain patterns."""
    if not which("alterx"):
        return set()
    if not existing_subs:
        return set()
    log("running alterx (permutations)…", "scan", "ALTERX")
    try:
        sub_list = "\n".join(sorted(existing_subs))
        r = run_cmd(["alterx", "-silent"], timeout=180)
        # alterx reads from stdin
        if r and r.stdout:
            return {l.strip().lower() for l in r.stdout.splitlines()
                    if l.strip() and l.strip().endswith(domain)}
    except Exception:
        pass
    return set()


def enum_gotator(domain):
    """gotator — permutation generator (predecessor to alterx)."""
    if not which("gotator"):
        return set()
    log("running gotator (permutations)…", "scan", "GOTATOR")
    # gotator needs input + wordlist; simplified invocation
    return set()


def enum_dnsx_bruteforce(domain, wordlist=None):
    """dnsx with a wordlist — active brute-force."""
    if not which("dnsx") or not which("shuffledns"):
        return set()

    wordlist = wordlist or next(
        (w for w in DEFAULT_WORDLIST_CANDIDATES if Path(w).exists()),
        None,
    )
    if not wordlist:
        log("no subdomain wordlist found — skipping brute-force", "warn")
        return set()

    log(f"running shuffledns bruteforce ({Path(wordlist).name})…",
        "scan", "BRUTEFORCE")

    # shuffledns requires a resolvers file; use dnsx default or common public
    resolvers_file = Path("/tmp/huginn_resolvers.txt")
    if not resolvers_file.exists():
        resolvers_file.write_text(
            "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n"
        )

    r = run_cmd([
        "shuffledns", "-d", domain, "-w", wordlist,
        "-r", str(resolvers_file), "-mode", "bruteforce",
        "-silent",
    ], timeout=1800)

    if not r or r.returncode != 0:
        return set()
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}


# =============================================================================
#  PHASE 2 — WILDCARD DETECTION
# =============================================================================
def detect_wildcard(domain):
    """
    Send a probe to a random subdomain. If it resolves, a wildcard exists.
    Returns the wildcard IP(s) as a set (empty = no wildcard).
    """
    import socket

    probe = WILDCARD_PROBE_PREFIX.format(hex=uuid.uuid4().hex[:12])
    fqdn = f"{probe}.{domain}"
    ips = set()
    try:
        for res in socket.getaddrinfo(fqdn, None):
            ips.add(res[4][0])
    except Exception:
        pass
    if ips:
        log(f"wildcard DNS detected for *.{domain} → {sorted(ips)}",
            "warn", "WILDCARD")
    return ips


def filter_wildcard(subs, wildcard_ips):
    """Remove hosts whose only resolution matches the wildcard IPs."""
    if not wildcard_ips:
        return subs
    import socket
    kept = []
    dropped = 0
    for h in subs:
        try:
            resolved = {res[4][0]
                        for res in socket.getaddrinfo(h, None)}
        except Exception:
            kept.append(h)
            continue
        if resolved and resolved.issubset(wildcard_ips):
            dropped += 1
            continue
        kept.append(h)
    if dropped:
        log(f"filtered {dropped} wildcard-resolved hosts", "ok", "WILDCARD")
    return kept


# =============================================================================
#  PHASE 3 — DNS RESOLUTION (dnsx)
# =============================================================================
def resolve_with_dnsx(hosts, out_dir):
    """dnsx — resolve hosts, capture CNAME chains."""
    if not which("dnsx"):
        log("dnsx not found — skipping pre-resolution filter", "warn")
        return None

    log(f"resolving {len(hosts)} hosts via dnsx…", "scan", "DNSX")
    list_file = out_dir / "_resolve_input.txt"
    list_file.write_text("\n".join(hosts))

    results = []
    r = run_cmd([
        "dnsx", "-l", str(list_file), "-json", "-silent",
        "-a", "-cname", "-resp", "-threads", "100",
    ], timeout=900)

    if r and r.stdout:
        for line in r.stdout.splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass

    log(f"dnsx resolved {len(results)} hosts", "ok")
    return results


# =============================================================================
#  PHASE 4 — HTTP PROBING (httpx, corrected flags)
# =============================================================================
def probe_httpx(hosts, out_dir):
    """
    httpx with rich metadata flags.
    NOTE: `-hash` takes a VALUE (md5|mmh3|simhash), not a flag.
    """
    if not which("httpx"):
        log("httpx not found — using python fallback probe", "warn")
        return _python_probe(hosts)

    log(f"httpx probing {len(hosts)} hosts…", "scan", "HTTPX")
    list_file = out_dir / "_httpx_input.txt"
    list_file.write_text("\n".join(hosts))

    cmd = [
        "httpx",
        "-l", str(list_file),
        "-json",
        "-silent",
        "-no-color",
        # Response metadata
        "-sc",                     # status code
        "-title",                  # HTML title
        "-server",                 # server header
        "-location",               # redirect location
        "-csp-probe",              # CSP header probe
        # Technology + infrastructure
        "-td",                     # tech detect
        "-cdn",                    # CDN detection
        "-ip",                     # resolved IP
        "-cname",                  # CNAME chain
        "-favicon",                # favicon hash
        "-jarm",                   # JARM TLS fingerprint
        "-hash", "md5",            # body md5 (VALUE required)
        # Redirects
        "-follow-redirects",
        "-follow-host-redirects",
        "-max-redirects", "10",
        # Concurrency
        "-threads", "50",
        "-timeout", "10",
        "-retries", "2",
        "-rate-limit", "150",
        "-random-agent",
    ]

    # Optional ASN lookup — requires PD Cloud API key
    # Add `-asn` only if the environment advertises a key.
    import os
    if os.environ.get("PDCP_API_KEY"):
        cmd.append("-asn")
    else:
        log("PDCP_API_KEY not set — skipping ASN enrichment", "info")

    r = run_cmd(cmd, timeout=2400)

    results = []
    if r and r.stdout:
        for line in r.stdout.splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass

    if not results:
        log("httpx returned no results — falling back to python probe", "warn")
        return _python_probe(hosts)

    return results


def _python_probe(hosts):
    """Pure-Python fallback when httpx is unavailable."""
    log(f"python probing {len(hosts)} hosts…", "scan", "PYPROBE")
    results = []
    lock = threading.Lock()

    def probe(host):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            r = send_request(url, timeout=8, allow_redirects=True)
            if r is None:
                continue
            headers = dict(r.headers)
            body = r.text or ""
            with lock:
                results.append({
                    "input": host,
                    "url": r.url,
                    "host": host,
                    "scheme": scheme,
                    "status_code": r.status_code,
                    "content_type": headers.get("Content-Type", ""),
                    "content_length": len(r.content or b""),
                    "webserver": headers.get("Server", ""),
                    "title": _extract_title(body),
                    "tech": [],
                    "headers": headers,
                })
            return

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(probe, hosts))
    return results


def _extract_title(body):
    if not body:
        return ""
    import re
    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
    return m.group(1).strip() if m else ""


# =============================================================================
#  PHASE 5 — ENRICHMENT
# =============================================================================
def enrich_host(entry):
    """
    Add WAF, cloud provider, DBMS hints, and canonical URL.
    Works on httpx JSON output OR fallback-probe output.
    """
    headers = entry.get("headers") or {}
    tech    = entry.get("tech") or []
    cnames  = entry.get("cname") or []
    server  = entry.get("webserver") or ""
    url     = entry.get("url") or entry.get("input") or ""

    # Combine headers + tech + server + cname into a single haystack
    haystack_parts = [
        " ".join(f"{k}: {v}" for k, v in headers.items()) if headers else "",
        server,
        " ".join(tech),
        " ".join(cnames) if isinstance(cnames, list) else str(cnames),
    ]
    haystack = " ".join(p for p in haystack_parts if p)

    entry["waf"]        = detect_waf(haystack)
    entry["cloud"]      = detect_provider(haystack)
    entry["dbms_hint"]  = detect_dbms(haystack)
    entry["server"]     = server
    return entry


def enrich_all(results):
    enriched = [enrich_host(dict(e)) for e in results]
    return enriched


# =============================================================================
#  PHASE 6 — PERSISTENCE + SUMMARY
# =============================================================================
def save_outputs(recon_dir, domain, all_subs, filtered_subs,
                 wildcard_ips, dns_results, alive):
    """Persist every artifact and write a summary."""

    # ---- subdomains.json -----------------------------------------------
    save_json(recon_dir / "subdomains.json", {
        "domain": domain,
        "total_discovered": len(all_subs),
        "after_wildcard_filter": len(filtered_subs),
        "wildcard_ips": sorted(wildcard_ips) if wildcard_ips else [],
        "subdomains": filtered_subs,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    # ---- dns_resolved.json ---------------------------------------------
    if dns_results is not None:
        save_json(recon_dir / "dns_resolved.json", {
            "domain": domain,
            "count": len(dns_results),
            "results": dns_results,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    # ---- httpx.json ----------------------------------------------------
    save_json(recon_dir / "httpx.json", {
        "domain": domain,
        "alive": len(alive),
        "results": alive,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    # ---- hosts_plain.txt -----------------------------------------------
    plain = recon_dir / "hosts_plain.txt"
    with open(plain, "w") as f:
        for h in filtered_subs:
            f.write(h + "\n")

    # ---- alive_plain.txt -----------------------------------------------
    alive_plain = recon_dir / "alive_plain.txt"
    with open(alive_plain, "w") as f:
        for e in alive:
            u = e.get("url") or e.get("input")
            if u:
                f.write(u + "\n")

    # ---- summary.json --------------------------------------------------
    waf_dist      = {}
    cloud_dist    = {}
    dbms_dist     = {}
    status_dist   = {}
    tech_dist     = {}
    for e in alive:
        if e.get("waf"):   waf_dist[e["waf"]]     = waf_dist.get(e["waf"], 0) + 1
        if e.get("cloud"): cloud_dist[e["cloud"]] = cloud_dist.get(e["cloud"], 0) + 1
        if e.get("dbms_hint"): dbms_dist[e["dbms_hint"]] = dbms_dist.get(e["dbms_hint"], 0) + 1
        sc = e.get("status_code")
        if sc: status_dist[str(sc)] = status_dist.get(str(sc), 0) + 1
        for t in (e.get("tech") or []):
            tech_dist[t] = tech_dist.get(t, 0) + 1

    save_json(recon_dir / "summary.json", {
        "domain": domain,
        "subdomains_discovered": len(all_subs),
        "subdomains_after_filter": len(filtered_subs),
        "wildcard_detected": bool(wildcard_ips),
        "wildcard_ips": sorted(wildcard_ips) if wildcard_ips else [],
        "dns_resolved": len(dns_results) if dns_results else len(filtered_subs),
        "alive_http": len(alive),
        "waf_distribution": waf_dist,
        "cloud_distribution": cloud_dist,
        "dbms_distribution": dbms_dist,
        "status_distribution": status_dist,
        "tech_distribution": dict(sorted(tech_dist.items(),
                                          key=lambda x: -x[1])[:30]),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


# =============================================================================
#  ORCHESTRATOR
# =============================================================================
def run(program_dir, domain):
    section("PHASE 1 :: SUBDOMAIN RECON")
    recon_dir = Path(program_dir) / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)

    # ---- Phase 1a — parallel enumeration sources ------------------------
    log("launching parallel enumeration sources", "scan", "ENUM")
    sources = {
        "subfinder":         lambda: enum_subfinder(domain),
        "assetfinder":       lambda: enum_assetfinder(domain),
        "crtsh":             lambda: enum_crtsh(domain),
        "certspotter":       lambda: enum_certspotter(domain),
        "chaos":             lambda: enum_chaos(domain),
        "github-subdomains": lambda: enum_github_subdomains(domain),
        "wayback":           lambda: enum_wayback(domain),
    }

    all_subs = {domain}
    source_counts = {}

    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {pool.submit(fn): name for name, fn in sources.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                result = fut.result() or set()
                source_counts[name] = len(result)
                all_subs.update(result)
                log(f"{name:20} → {len(result)} hosts", "info")
            except Exception as e:
                log(f"{name} failed: {e}", "warn")
                source_counts[name] = 0

    # amass is slow — run it after parallel batch
    amass_result = enum_amass(domain)
    source_counts["amass"] = len(amass_result)
    all_subs.update(amass_result)

    # ---- Phase 1b — permutation expansion -------------------------------
    alt = enum_alterx(domain, all_subs)
    if alt:
        source_counts["alterx"] = len(alt)
        all_subs.update(alt)

    # ---- Phase 1c — active brute-force (optional) -----------------------
    brute = enum_dnsx_bruteforce(domain)
    if brute:
        source_counts["bruteforce"] = len(brute)
        all_subs.update(brute)

    # ---- Normalize + deduplicate ---------------------------------------
    all_subs = {h.strip().lower().rstrip(".")
                for h in all_subs
                if h and h.endswith(domain) and "*" not in h}
    log(f"discovered {len(all_subs)} unique hosts "
        f"({', '.join(f'{k}={v}' for k, v in source_counts.items() if v)})",
        "ok")

    # ---- Phase 2 — wildcard detection -----------------------------------
    section("PHASE 2 :: WILDCARD DETECTION")
    wildcard_ips = detect_wildcard(domain)
    filtered_subs = sorted(filter_wildcard(list(all_subs), wildcard_ips))
    log(f"after wildcard filter: {len(filtered_subs)} hosts", "ok")

    # ---- Phase 3 — DNS resolution ---------------------------------------
    section("PHASE 3 :: DNS RESOLUTION")
    dns_results = resolve_with_dnsx(filtered_subs, recon_dir)
    if dns_results is not None:
        resolved_hosts = sorted({
            r.get("host") for r in dns_results if r.get("host")
        })
        if resolved_hosts:
            filtered_subs = resolved_hosts
        log(f"resolved: {len(filtered_subs)} hosts", "ok")

    # ---- Phase 4 — HTTP probing -----------------------------------------
    section("PHASE 4 :: HTTP PROBING")
    alive = probe_httpx(filtered_subs, recon_dir)
    log(f"alive: {len(alive)} hosts", "ok")

    # ---- Phase 5 — enrichment -------------------------------------------
    section("PHASE 5 :: ENRICHMENT")
    alive = enrich_all(alive)

    # Report WAF / cloud distribution inline
    wafs   = {e["waf"]   for e in alive if e.get("waf")}
    clouds = {e["cloud"] for e in alive if e.get("cloud")}
    if wafs:   log(f"WAFs detected   : {sorted(wafs)}", "ok")
    if clouds: log(f"Cloud providers : {sorted(clouds)}", "ok")

    # ---- Phase 6 — persistence ------------------------------------------
    section("PHASE 6 :: PERSISTENCE")
    save_outputs(recon_dir, domain, all_subs, filtered_subs,
                 wildcard_ips, dns_results, alive)
    log(f"recon artifacts written to {recon_dir}", "ok", "SAVE")

    return recon_dir / "httpx.json"


# =============================================================================
#  ENTRY
# =============================================================================
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("usage: subdomains.py <program_dir> <domain>")
        sys.exit(1)
    run(sys.argv[1], normalize_target(sys.argv[2])[0])
