#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN — Odin's Raven
#  Main orchestrator for automated recon + vulnerability discovery.
# -----------------------------------------------------------------------------
#  Usage:
#    python HUGINN.py                                    # fully interactive
#    python HUGINN.py --target example.com --yes         # non-interactive
#    python HUGINN.py --resume output/prog_20260910      # resume a run
#    python HUGINN.py --scan sqli,xss --browser          # pick scanners
#    python HUGINN.py --target example.com --yes --no-oob
# =============================================================================

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from huginn_utils import (
    banner, section, log, normalize_target,
    save_json, load_json, load_huginn_config, C,
)

import subdomains, crawl, sqli, xss, ssrf, open_redirect


# =============================================================================
#  CONSTANTS
# =============================================================================
VERSION = "2.0.0"

CONFIG_SEARCH_PATHS = [
    Path("./huginn.yaml"),
    Path("./huginn.yml"),
    Path.home() / ".config" / "huginn" / "config.yaml",
    Path.home() / ".huginn.yaml",
]

SCANNERS = {
    "sqli":          sqli.run,
    "xss":           xss.run,
    "ssrf":          ssrf.run,
    "open_redirect": open_redirect.run,
}

DEFAULTS = {
    # Attacker infrastructure
    "attacker_domain":  "beardedviking.org",
    "collab_host":      "oast.beardedviking.org",
    "oob_check_url":    "https://oast.beardedviking.org/check.php",
    "canary_host":      "redirect.beardedviking.org",
    "canary_string":    "HUGINN-CANARY-LANDED",
    "canary_check_url": "https://redirect.beardedviking.org/check.php",
    "alert_payload":    "alert(document.domain)",
    "use_subdomain_oob": False,
    "oob_log_file":     None,
    # Scanner tuning
    "max_workers":      8,
    "delay":            0.15,
    "timeout":          12,
    "use_browser":      False,
    "provider_filter":  None,
    # Scope
    "scope_exclusions": [
        "oast.beardedviking.org",
        "redirect.beardedviking.org",
    ],
}

# ---- Hint signatures -------------------------------------------------------
WAF_SIGNATURES = {
    "cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf_clearance"],
    "akamai":      ["akamai", "akamai-grn", "ak-bmsc"],
    "sucuri":      ["sucuri", "x-sucuri-id"],
    "imperva":     ["imperva", "incapsula", "x-iinfo", "visid_incap"],
    "awswaf":      ["aws waf", "awselb", "x-amzn-requestid"],
    "azurewaf":    ["azure front door", "x-azure-ref"],
    "f5":          ["f5", "big-ip", "bigip", "ts="],
    "modsecurity": ["modsecurity", "mod_security"],
    "fastly":      ["fastly", "x-served-by", "x-fastly"],
    "stackpath":   ["stackpath"],
}

CLOUD_SIGNATURES = {
    "aws":          ["amazon", "aws", "cloudfront", "elb", "route53",
                     "s3.amazonaws", "elasticbeanstalk", "amazonaws.com"],
    "gcp":          ["google cloud", "gcp", "googleusercontent",
                     "appspot", "google frontend", "googleapis"],
    "azure":        ["azure", "microsoft-iis", "front door",
                     "azurewebsites", "cloudapp.azure",
                     "azurefd.net", "trafficmanager.net"],
    "digitalocean": ["digitalocean", "do-"],
    "alibaba":      ["alibaba", "aliyun", "alicdn"],
    "oracle":       ["oracle cloud", "oci", "oraclecloud"],
    "cloudflare":   ["cloudflare"],
    "fastly":       ["fastly"],
    "heroku":       ["heroku", "herokussl"],
    "netlify":      ["netlify"],
    "vercel":       ["vercel"],
}

DBMS_SIGNATURES = {
    "mysql":      ["mysql", "mariadb", "phpmyadmin"],
    "postgresql": ["postgresql", "postgres", "pgsql", "supabase"],
    "mssql":      ["mssql", "sql server", "asp.net", "iis"],
    "oracle":     ["oracle database", "oracle db", "oracle http server"],
    "sqlite":     ["sqlite"],
    "mongodb":    ["mongodb", "mongoose", "atlas"],
}


# =============================================================================
#  CONFIG LOADING
# =============================================================================
def load_config_file(explicit_path=None):
    """Load the first matching huginn.yaml; return {} if none exists."""
    paths = list(CONFIG_SEARCH_PATHS)
    if explicit_path:
        paths.insert(0, Path(explicit_path))
    return load_huginn_config(paths=paths)


def build_config(cli_args):
    """Merge defaults < config file < CLI args."""
    cfg = dict(DEFAULTS)
    cfg.update(load_config_file(explicit_path=cli_args.config))

    # CLI overrides — explicit only
    cli_map = {
        "attacker":       "attacker_domain",
        "collab":         "collab_host",
        "canary":         "canary_host",
        "oob_url":        "oob_check_url",
        "canary_check":   "canary_check_url",
        "alert":          "alert_payload",
        "oob_log":        "oob_log_file",
        "provider":       "provider_filter",
        "workers":        "max_workers",
        "delay":          "delay",
    }
    for cli_key, cfg_key in cli_map.items():
        val = getattr(cli_args, cli_key, None)
        if val is not None:
            cfg[cfg_key] = val

    # Handle --no-oob flag
    if getattr(cli_args, "no_oob", False):
        cfg["oob_check_url"]   = None
        cfg["oob_log_file"]    = None
        cfg["canary_check_url"] = None

    return cfg


# =============================================================================
#  SCOPE ENFORCEMENT
# =============================================================================
def host_in_scope(host, exclusions):
    """True if host is NOT in the exclusion list."""
    host = (host or "").lower()
    for ex in exclusions or []:
        ex = ex.lower().strip()
        if host == ex or host.endswith("." + ex):
            return False
    return True


def filter_httpx_by_scope(httpx_file, exclusions):
    """
    Walk httpx.json and drop out-of-scope entries.
    Rewrites the file in place with the filtered result set.
    Returns (kept_count, dropped_count).
    """
    try:
        data = load_json(httpx_file)
    except Exception as e:
        log(f"cannot filter httpx.json: {e}", "warn")
        return 0, 0

    results = data.get("results", []) or []
    kept, dropped = [], 0
    for r in results:
        host = (r.get("input") or r.get("host") or "").lower()
        if host_in_scope(host, exclusions):
            kept.append(r)
        else:
            dropped += 1

    if dropped:
        log(f"scope filter: dropped {dropped} out-of-scope hosts", "ok", "SCOPE")
        data["results"] = kept
        data["alive"] = len(kept)
        data["scope_filtered_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                   time.gmtime())
        save_json(httpx_file, data)

    return len(kept), dropped


# =============================================================================
#  HINT DERIVATION
# =============================================================================
def _fingerprint_match(haystack, signatures):
    hits = set()
    for key, needles in signatures.items():
        for needle in needles:
            if needle in haystack:
                hits.add(key)
                break
    return hits


def derive_hints(httpx_file):
    """
    Analyse httpx.json to infer WAF, cloud provider, and DBMS.
    Uses every field the new httpx emits: tech, webserver, cname, headers.
    """
    try:
        data = load_json(httpx_file)
    except Exception:
        return {"waf": None, "provider": None, "dbms": None, "tech": []}

    all_tech, all_server, all_cname, all_headers = [], [], [], []

    for entry in data.get("results", []):
        tech = entry.get("tech") or []
        if isinstance(tech, list):
            all_tech.extend([str(t).lower() for t in tech])
        server = (entry.get("webserver") or "").lower()
        if server:
            all_server.append(server)

        cname = entry.get("cname") or []
        if isinstance(cname, list):
            all_cname.extend([str(c).lower() for c in cname])
        elif isinstance(cname, str):
            all_cname.append(cname.lower())

        headers = entry.get("headers") or {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                all_headers.append(f"{k.lower()}: {str(v).lower()}")

    blob = " ".join(all_tech + all_server + all_cname + all_headers)

    wafs   = _fingerprint_match(blob, WAF_SIGNATURES)
    clouds = _fingerprint_match(blob, CLOUD_SIGNATURES)
    dbms   = _fingerprint_match(blob, DBMS_SIGNATURES)

    return {
        "waf":      next(iter(wafs)) if wafs else None,
        "provider": next(iter(clouds)) if clouds else None,
        "dbms":     next(iter(dbms)) if dbms else None,
        "tech":     sorted(set(all_tech)),
        "waf_all":  sorted(wafs),
        "cloud_all": sorted(clouds),
        "dbms_all": sorted(dbms),
    }


# =============================================================================
#  INTERACTIVE PROMPTS
# =============================================================================
def prompt(msg, default=None):
    suffix = f" {C.D}[{default}]{C.R}" if default else ""
    s = input(f"{C.CY}▸{C.R} {C.B}{msg}{C.R}{suffix}: ").strip()
    return s or (default or "")


def authorization_gate(domain, program, skip=False):
    if skip:
        log("authorization gate skipped (--yes)", "warn")
        return True
    print()
    log(f"Target  : {C.WH}{domain}{C.R}")
    log(f"Program : {C.WH}{program}{C.R}")
    print()
    log("By continuing you confirm you are authorized to test this target", "warn")
    log("under the terms of the bug bounty program / rules of engagement.", "warn")
    a = prompt("Type  AUTHORIZED  to continue").strip().upper()
    return a == "AUTHORIZED"


# =============================================================================
#  WORKSPACE
# =============================================================================
def create_workspace(program, resume_dir=None):
    if resume_dir:
        p = Path(resume_dir)
        if not p.exists():
            log(f"resume dir does not exist: {p}", "err")
            sys.exit(1)
        return p

    stamp = time.strftime("%Y%m%d_%H%M%S")
    p = Path("output") / f"{program}_{stamp}"
    (p / "recon").mkdir(parents=True, exist_ok=True)
    (p / "sites").mkdir(parents=True, exist_ok=True)
    (p / "findings").mkdir(parents=True, exist_ok=True)
    return p


def write_mission_file(program_dir, domain, program, scope, config):
    mission = {
        "version": VERSION,
        "target": domain,
        "program": program,
        "scope_notes": scope,
        "scope_exclusions": config.get("scope_exclusions", []),
        "started_at": datetime.utcnow().isoformat() + "Z",
        "config": {
            k: v for k, v in config.items()
            if k not in ("oob_log_file",) and not callable(v)
        },
        "oob_enabled": bool(config.get("oob_check_url")
                             or config.get("oob_log_file")),
    }
    save_json(program_dir / "mission.json", mission)


# =============================================================================
#  RECON
# =============================================================================
def run_recon(program_dir, domain, resume=False, skip_recon=False):
    httpx_file = program_dir / "recon" / "httpx.json"
    subs_file  = program_dir / "recon" / "subdomains.json"

    if skip_recon and httpx_file.exists():
        log("recon skipped (--skip-recon)", "ok")
        return httpx_file

    if resume and httpx_file.exists() and subs_file.exists():
        log("recon already complete — skipping (resume mode)", "ok")
        return httpx_file

    section("PHASE 1 :: RECONNAISSANCE")
    httpx_file = subdomains.run(program_dir, domain)
    crawl.run(program_dir, httpx_file)
    return httpx_file


def print_situational_awareness(program_dir, httpx_file, hints, exclusions):
    section("PHASE 2 :: SITUATIONAL AWARENESS")

    try:
        subs = load_json(program_dir / "recon" / "subdomains.json")
        log(f"subdomains   : {subs.get('total_discovered', subs.get('count', 0))}",
            "info")
    except Exception:
        pass

    try:
        hx = load_json(httpx_file)
        log(f"alive hosts  : {hx.get('alive', 0)}", "info")
        statuses = {}
        for r in hx.get("results", []):
            sc = r.get("status_code", 0)
            statuses[sc] = statuses.get(sc, 0) + 1
        if statuses:
            top = sorted(statuses.items(), key=lambda x: -x[1])[:5]
            log(f"status dist  : {', '.join(f'{k}×{v}' for k,v in top)}",
                "info")
    except Exception:
        pass

    try:
        idx = load_json(program_dir / "sites" / "_index.json")
        log(f"crawled pages: {idx.get('total_pages', 0)}", "info")
        if idx.get("total_deduped"):
            log(f"deduped      : {idx['total_deduped']} duplicate-content pages",
                "info")
    except Exception:
        pass

    try:
        ep = load_json(program_dir / "sites" / "_endpoints.json")
        log(f"JS endpoints : {ep.get('count', 0)}", "info")
    except Exception:
        pass

    try:
        fm = load_json(program_dir / "sites" / "_forms.json")
        log(f"forms        : {fm.get('count', 0)}", "info")
    except Exception:
        pass

    if hints.get("tech"):
        log(f"tech stack   : {', '.join(hints['tech'][:10])}", "info")
    if hints.get("waf"):
        log(f"WAF detected : {C.YE}{hints['waf']}{C.R}", "ok")
    if hints.get("provider"):
        log(f"cloud        : {C.YE}{hints['provider']}{C.R}", "ok")
    if hints.get("dbms"):
        log(f"DB hints     : {C.YE}{hints['dbms']}{C.R}", "ok")
    if exclusions:
        log(f"scope excl.  : {', '.join(exclusions)}", "info")


# =============================================================================
#  SCANNER DISPATCH — matches the current scanner signatures
# =============================================================================
def dispatch_scanner(name, program_dir, domain, config, hints, use_browser):
    """Call the right scanner with the right kwargs."""
    fn = SCANNERS[name]

    if name == "sqli":
        return fn(program_dir,
                  waf_hint=hints.get("waf"),
                  dbms_hint=hints.get("dbms"))

    if name == "xss":
        return fn(program_dir,
                  attacker_domain=config["attacker_domain"],
                  collab_host=config["collab_host"],
                  alert_payload=config["alert_payload"],
                  target_domain=domain,
                  use_browser=use_browser,
                  oob_log_file=config.get("oob_log_file"),
                  oob_base_url=config.get("oob_check_url"))

    if name == "ssrf":
        return fn(program_dir,
                  attacker_domain=config["attacker_domain"],
                  collab_host=config["collab_host"],
                  canary_host=config["canary_host"],
                  oob_check_url=config.get("oob_check_url"),
                  target_domain=domain,
                  provider_filter=(config.get("provider_filter")
                                   or hints.get("provider")),
                  oob_log_file=config.get("oob_log_file"))

    if name == "open_redirect":
        return fn(program_dir,
                  attacker_domain=config["attacker_domain"],
                  canary_host=config["canary_host"],
                  canary_string=config["canary_string"],
                  collab_host=config["collab_host"],
                  canary_check_url=config.get("canary_check_url"),
                  target_domain=domain)

    return fn(program_dir)


def run_scanners(program_dir, domain, config, hints, to_run, use_browser):
    section("PHASE 3 :: STRIKE PHASE")
    print(f"{C.D}Scanners queued: {', '.join(to_run)}{C.R}\n")

    results = {}
    t_start = time.time()
    for name in to_run:
        t0 = time.time()
        log(f"launching {name}…", "scan", name.upper())
        try:
            findings = dispatch_scanner(name, program_dir, domain,
                                        config, hints, use_browser)
            results[name] = findings or []
        except Exception as e:
            log(f"{name} crashed: {e}", "err", name.upper())
            import traceback
            log(traceback.format_exc(), "debug", name.upper())
            results[name] = []
        elapsed = time.time() - t0
        log(f"{name} finished in {elapsed:.1f}s — {len(results[name])} findings",
            "ok", name.upper())

    total = time.time() - t_start
    log(f"all scanners finished in {total:.1f}s", "ok")
    return results


# =============================================================================
#  MISSION REPORT
# =============================================================================
def print_mission_report(program_dir, results):
    section("MISSION REPORT")

    agg = {"confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
           "total": 0}
    per_scanner = {}
    confirmed_curls = []

    for name, findings in results.items():
        per_scanner[name] = {"total": len(findings)}
        for f in findings:
            sev = f.get("severity", "low")
            agg[sev] = agg.get(sev, 0) + 1
            agg["total"] += 1
            per_scanner[name][sev] = per_scanner[name].get(sev, 0) + 1
            if f.get("confirmed") and f.get("curl_command"):
                confirmed_curls.append({
                    "scanner": name,
                    "url":     f.get("url"),
                    "param":   f.get("parameter"),
                    "curl":    f.get("curl_command"),
                    "evidence": (f.get("detection_reason") or "")[:120],
                })

    if agg["total"] == 0:
        log("no findings across any scanner — clean target or noisy recon",
            "info")
    else:
        print(f"\n{C.B}{C.WH}  Scanner              Confirmed  Critical  High  Med  Low  Total{C.R}")
        print(f"{C.D}  {'─' * 74}{C.R}")
        for name, counts in per_scanner.items():
            line = (
                f"  {name:<20} "
                f"{counts.get('confirmed', 0):>9} "
                f"{counts.get('critical', 0):>9} "
                f"{counts.get('high', 0):>5} "
                f"{counts.get('medium', 0):>4} "
                f"{counts.get('low', 0):>4} "
                f"{counts.get('total', 0):>6}"
            )
            print(line)
        print(f"{C.D}  {'─' * 74}{C.R}")
        line = (
            f"  {'TOTAL':<20} "
            f"{agg.get('confirmed', 0):>9} "
            f"{agg.get('critical', 0):>9} "
            f"{agg.get('high', 0):>5} "
            f"{agg.get('medium', 0):>4} "
            f"{agg.get('low', 0):>4} "
            f"{agg['total']:>6}"
        )
        print(f"{C.B}{line}{C.R}\n")

    # Persist aggregate
    save_json(program_dir / "findings" / "_aggregate.json", {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "totals": agg,
        "per_scanner": per_scanner,
        "confirmed_count": len(confirmed_curls),
    })

    # Confirmed-only quick-triage file
    if confirmed_curls:
        save_json(program_dir / "findings" / "_confirmed_index.json", {
            "count": len(confirmed_curls),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "findings": confirmed_curls,
        })
        log(f"{len(confirmed_curls)} CONFIRMED findings → "
            f"findings/_confirmed_index.json", "ok", "TRIAGE")


# =============================================================================
#  ARG PARSING
# =============================================================================
def parse_args():
    ap = argparse.ArgumentParser(
        prog="HUGINN",
        description="Odin's Raven — automated recon + vulnerability discovery",
    )
    ap.add_argument("--version", action="version", version=f"HUGINN {VERSION}")
    ap.add_argument("--target",  help="target domain or URL")
    ap.add_argument("--program", help="program / engagement name")
    ap.add_argument("--scope",   help="scope notes (free text)", default="")
    ap.add_argument("--scan",    help="comma-separated scanners: "
                                      "sqli,xss,ssrf,open_redirect",
                    default=None)
    ap.add_argument("--resume",  help="resume an existing workspace directory")
    ap.add_argument("--config",  help="path to huginn.yaml", default=None)

    # ---- Config overrides ------------------------------------------------
    ap.add_argument("--attacker", help="attacker domain", default=None)
    ap.add_argument("--collab",   help="collaborator host", default=None)
    ap.add_argument("--canary",   help="canary host for open redirect",
                    default=None)
    ap.add_argument("--alert",    help="alert payload template (XSS)",
                    default=None)
    ap.add_argument("--oob-log",  help="path to a local collaborator/Interactsh "
                                        "log file (disables remote poller)",
                    default=None)
    ap.add_argument("--oob-url",  help="URL of the remote OOB check.php",
                    default=None)
    ap.add_argument("--canary-check", help="URL of the canary check.php",
                    default=None)
    ap.add_argument("--provider", help="cloud provider filter for SSRF",
                    choices=["aws", "gcp", "azure", "digitalocean",
                             "alibaba", "oracle", "kubernetes",
                             "tencent", "huawei"],
                    default=None)
    ap.add_argument("--workers",  type=int, default=None,
                    help="max thread workers")
    ap.add_argument("--delay",    type=float, default=None,
                    help="delay between requests")

    # ---- Behavior flags --------------------------------------------------
    ap.add_argument("--browser",  action="store_true",
                    help="enable Playwright browser verification for XSS")
    ap.add_argument("--yes", action="store_true",
                    help="skip interactive prompts (non-interactive mode)")
    ap.add_argument("--no-oob", action="store_true",
                    help="disable all out-of-band confirmation (fastest scan)")
    ap.add_argument("--skip-recon", action="store_true",
                    help="reuse existing recon/httpx.json (fastest iteration)")
    ap.add_argument("--list-scanners", action="store_true",
                    help="list available scanners and exit")

    return ap.parse_args()


# =============================================================================
#  MAIN
# =============================================================================
def main():
    args = parse_args()

    banner()

    if args.list_scanners:
        section("AVAILABLE SCANNERS")
        for name in SCANNERS:
            print(f"  {C.CY}·{C.R} {C.B}{name}{C.R}")
        return

    config = build_config(args)

    # ---- Resolve target -------------------------------------------------
    if args.resume:
        program_dir = Path(args.resume)
        try:
            mission = load_json(program_dir / "mission.json")
            domain  = mission["target"]
            program = mission["program"]
            scope   = mission.get("scope_notes", "")
            log(f"resuming run against {domain}", "ok")
        except Exception as e:
            log(f"cannot resume: {e}", "err")
            sys.exit(1)
    else:
        section("MISSION BRIEF")
        raw_target = args.target or prompt("Target (domain or URL)")
        try:
            domain, _ = normalize_target(raw_target)
        except ValueError:
            log("invalid target", "err")
            sys.exit(1)

        program = args.program or prompt("Program / engagement name",
                                         default=domain.split(".")[0])
        scope   = args.scope or prompt("Scope notes (optional)", default="")

        if not authorization_gate(domain, program, skip=args.yes):
            log("authorization not confirmed — aborting", "err")
            sys.exit(1)

        program_dir = create_workspace(program)
        write_mission_file(program_dir, domain, program, scope, config)

    log(f"workspace: {program_dir}", "ok")
    if scope:
        log(f"scope    : {scope}", "info")
    log(f"attacker : {config['attacker_domain']}", "info")

    # ---- OOB status -----------------------------------------------------
    oob_enabled = bool(config.get("oob_check_url")
                        or config.get("oob_log_file"))
    if oob_enabled:
        if config.get("oob_log_file"):
            log(f"OOB mode : local log ({config['oob_log_file']})", "info")
        else:
            log(f"OOB mode : remote check ({config.get('oob_check_url')}",
                "info")
    else:
        log("OOB mode : disabled (blind detection off)", "warn")

    use_browser = args.browser or config.get("use_browser", False)
    if use_browser:
        log("browser verification: ENABLED", "ok")

    # ---- Scope exclusions -----------------------------------------------
    exclusions = config.get("scope_exclusions") or []

    # ---- Recon ----------------------------------------------------------
    httpx_file = run_recon(program_dir, domain,
                           resume=bool(args.resume),
                           skip_recon=args.skip_recon)

    # ---- Scope filter httpx.json ----------------------------------------
    if exclusions:
        kept, dropped = filter_httpx_by_scope(httpx_file, exclusions)
        if dropped:
            log(f"scope filtered → {kept} hosts kept", "ok", "SCOPE")

    # ---- Hints ----------------------------------------------------------
    hints = derive_hints(httpx_file)
    print_situational_awareness(program_dir, httpx_file, hints, exclusions)

    # ---- Scanner selection ----------------------------------------------
    if args.scan:
        to_run = [s.strip() for s in args.scan.split(",") if s.strip() in SCANNERS]
    elif args.resume or args.yes:
        to_run = list(SCANNERS)
    else:
        section("STRIKE PHASE :: SELECTION")
        print(f"{C.D}Available: {', '.join(SCANNERS)}{C.R}")
        choice = prompt("Run which? (all / comma-separated / skip)",
                        default="all").lower()
        if choice in ("skip", "n", "no"):
            log("recon only — done", "ok")
            return
        to_run = list(SCANNERS) if choice in ("all", "") else \
                 [s.strip() for s in choice.split(",") if s.strip() in SCANNERS]

    if not to_run:
        log("no scanners selected", "warn")
        return

    # ---- Run scanners ---------------------------------------------------
    results = run_scanners(program_dir, domain, config, hints,
                           to_run, use_browser)

    # ---- Report ---------------------------------------------------------
    print_mission_report(program_dir, results)

    log(f"results → {program_dir}", "ok")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted by user", "warn")
        sys.exit(130)
