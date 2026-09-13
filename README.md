<!-- ======================================================================= -->
<!--  HUGINN — Odin's Raven                                                   -->
<!--  Automated Recon & Vulnerability Discovery Suite                         -->
<!-- ======================================================================= -->

<div align="center">
╔══════════════════════════════════════════════════════════════╗
║ ║
║ ██╗ ██╗██╗ ██╗ ██████╗ ██╗███╗ ██╗███╗ ██╗ ║
║ ██║ ██║██║ ██║██╔════╝ ██║████╗ ██║████╗ ██║ ║
║ ███████║██║ ██║██║ ███╗██║██╔██╗ ██║██╔██╗ ██║ ║
║ ██╔══██║██║ ██║██║ ██║██║██║╚██╗██║██║╚██╗██║ ║
║ ██║ ██║╚██████╔╝╚██████╔╝██║██║ ╚████║██║ ╚████║ ║
║ ╚═╝ ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝ ╚═══╝╚═╝ ╚═══╝ ║
║ ║
║ O D I N ' S R A V E N ║
║ Automated Recon & Vulnerability Suite ║
║ ║
╚══════════════════════════════════════════════════════════════╝
</div>


**A modular, out-of-band-verified bug bounty automation framework.**
*Recon → Crawl → Strike → Confirm → Report.*

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen?style=flat-square)](#)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange?style=flat-square)](#contributing)
[![Made with rage](https://img.shields.io/badge/made%20with-rage-red?style=flat-square)](#)

</div>

---

## What Is This?

HUGINN is a Python orchestration framework that automates the boring 80% of bug bounty hunting — subdomain enumeration, crawling, and the four vulnerability classes that show up in almost every program:

| Scanner | Class | Verification |
|---------|-------|--------------|
| **`sqli.py`** | SQL Injection | Error signature matching, DBMS-specific detection, 5-tier severity ladder |
| **`xss.py`** | Cross-Site Scripting | Reflection context detection, DOM-aware payload routing, Playwright browser confirmation |
| **`ssrf.py`** | Server-Side Request Forgery | Cloud metadata detection, credential leak detection, OOB token verification |
| **`open_redirect.py`** | Open Redirect | Chain-follow confirmation, canary landing verification, OAuth/SSO escalation |

Every finding is **verified** — not just "the payload was reflected" but "the payload actually fired and here's the cURL to prove it."

### Why Another Scanner?

Most automated scanners are either:
- **Loud and dumb** — spray 10,000 payloads, drown you in false positives
- **Quiet and useless** — miss 90% of real bugs because they don't understand context

HUGINN sits in the middle:

- **Context-aware routing** — sends `attribute_single` payloads only to parameters that land inside single-quoted attributes
- **Out-of-band verification** — every blind payload carries a unique token; a hit on your OOB receiver upgrades the finding to `CONFIRMED`
- **Payload fidelity** — the YAML payload libraries cover 1990s legacy quirks through 2026 parser-differential research
- **Report-ready output** — every finding ships with a cURL command, response snippet, and remediation guidance

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Attacker Infrastructure](#attacker-infrastructure)
- [Output Structure](#output-structure)
- [Payload Libraries](#payload-libraries)
- [Scanner Details](#scanner-details)
- [Roadmap](#roadmap)
- [Legal & Ethics](#legal--ethics)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

---

## Features

### 🔍 Reconnaissance

- **Nine enumeration sources** running in parallel — subfinder, amass, assetfinder, crt.sh, certspotter, chaos, github-subdomains, gau/waybackurls, alterx
- **Wildcard DNS detection** — filters `*.domain` catch-alls before wasting time on them
- **`robots.txt` + `sitemap.xml` seeding** — free access to admin/API paths most crawlers miss
- **Content-hash dedup** — 500 WordPress posts sharing a template collapse to one entry
- **Per-host parallelism** — 6+ hosts crawling simultaneously
- **JS endpoint extraction** — finds `/api/v1/*`, `/graphql`, and `fetch()` URLs that katana alone misses

### 🎯 Attack Surface Coverage

- **Injection transports**: query params, POST form bodies, JSON bodies, cookies, HTTP headers, path segments, HPP
- **Reflection context detection**: HTML body, attribute (single/double/unquoted), JS string (single/double/template), CSS, comments, title, textarea, noscript
- **Chain verification**: follows open redirect chains, reads canary landing pages
- **OOB polling**: integrates with self-hosted canary infrastructure for blind discovery

### 🎨 Output

- **One JSON per finding** — full request/response context, payload metadata, cURL command
- **Confirmed-only index** — `findings/_confirmed_index.json` for instant triage
- **Per-host summaries** — status distributions, WAF/cloud/DBMS fingerprints
- **Global artifacts** — every endpoint, form, and parameter name discovered

### 🛠️ Operational

- **Resume mode** — skip recon on re-runs, iterate on scanners without re-enumerating
- **Scope enforcement** — exclusion lists prevent scanning your own infrastructure
- **Full CLI** — drive from cron, CI, or interactively
- **Graceful degradation** — one scanner crashing doesn't kill the run
- **Comprehensive logging** — every action timestamped, every decision logged

---

## Architecture
```
┌────────────────────────────────────────────────────────────────────────┐
│ HUGINN.py │
│ (orchestrator, config, hints) │
└───────┬────────────────────────────────────────────────────────────────┘
│
├─── Phase 1 ─── RECON ────────────────────────────────────────┐
│ │
│ subdomains.py │
│ ├── subfinder, amass, assetfinder, crt.sh, certspotter │
│ ├── chaos, github-subdomains, gau, waybackurls, alterx │
│ ├── wildcard DNS detection │
│ ├── dnsx pre-resolution │
│ └── httpx probing (status, tech, JARM, favicon, CDN) │
│ │
│ crawl.py │
│ ├── katana + hakrawler + robots.txt + sitemap.xml │
│ ├── per-host parallel fetch │
│ ├── content-hash dedup │
│ ├── form/endpoint extraction │
│ └── stores one JSON per unique page │
│ │
├─── Phase 2 ─── HINTS ────────────────────────────────────────┤
│ │
│ derive_hints(httpx.json) │
│ ├── WAF fingerprint (Cloudflare, Akamai, Sucuri, ...) │
│ ├── Cloud provider (AWS, GCP, Azure, DigitalOcean, ...) │
│ └── DBMS hints (MySQL, PostgreSQL, MSSQL, Oracle, ...) │
│ │
├─── Phase 3 ─── STRIKE ───────────────────────────────────────┤
│ │
│ sqli.py xss.py ssrf.py open_redirect │
│ │ │ │ │ │
│ └─ error sig └─ context └─ metadata └─ chain │
│ └─ DBMS filter └─ DOM routing └─ cred leak └─ canary │
│ └─ WAF filter └─ browser └─ OOB token └─ OOB │
│ │
├─── Phase 4 ─── OOB DRAIN ───────────────────────────────────┤
│ │
│ Remote poller watches: │
│ https://oast.beardedviking.org/check.php?list=1 │
│ │
│ Every token that appears → upgrades corresponding finding │
│ │
└─── Phase 5 ─── REPORT ──────────────────────────────────────┘

┌──────────────────────────────┐
│ findings/<scanner>/ │
│ <host>/<finding>.json │
│ findings/_aggregate.json │
│ findings/_confirmed.json │
└──────────────────────────────┘
```

---

## Installation

### Prerequisites

- **Python 3.9+**
- **Go 1.20+** (for ProjectDiscovery tooling)
- **Linux or macOS** (Windows works under WSL2)
- **Root/sudo** for system packages

### Automated Setup

The `setup.sh` script detects your OS, fingerprints your hardware, writes `pc_specs.json`, and installs every tool missing from your system:

```bash
git clone https://github.com/<your-username>/huginn.git
cd huginn
chmod +x setup.sh
./setup.sh
```
`setup.sh` is idempotent — safe to re-run. It installs:  
| Tool | Purpose | Source |
| `subfinder` | Passive | subdomain | enumeration | go install |
| `amass` | Active | subdomain | enumeration | go install |
| `httpx` | HTTP probing + fingerprinting | go install |
| `dnsx` | DNS resolution | go install |
| `katana` | Web crawler | go install |
| `hakrawler` | Secondary crawler | go install |
| `nuclei` | Template-based scanning | go install |
| `interactsh-client` | OOB callback listener | go install |
| `waybackurls` | Historical URL collection | go install |
| `gau` | URL gathering | go install |
| `shuffledns` | DNS bruteforce | go install |
| `alterx` | Subdomain permutation | go install |
| `assetfinder` | Certificate transparency | go install |
| `chaos | ProjectDiscovery dataset client | go instal |

## Manual Setup
```
pip install -r requirements.txt
```
`requirements.txt`
```
requests>=2.28
pyyaml>=6.0
beautifulsoup4>=4.11
playwright>=1.40  # optional: browser verification
```
For browser verification (XSS confirmed via actual dialog):
```
playwright install chromium
```
### Verify Installation
```
python HUGINN.py --list-scanners
```
You should see:
```
╭────────────────────────────────────────────────────────────╮
│ AVAILABLE SCANNERS                                         │
╰────────────────────────────────────────────────────────────╯

  · sqli
  · xss
  · ssrf
  · open_redirect
```

# Quick Start

## Interactive Mode
```
python HUGINN.py
```
You'll be prompted for:
* Target domain
* Program name
* Scope notes
* Authorization confirmation (must type AUTHORIZED)

Then HUGINN runs the full pipeline and prompts you to select scanners.

## Non-Interactive Mode
```
python HUGINN.py --target example.com --yes
```
Zero prompts. Full pipeline against `example.com`. Perfect for cron or CI.

### Target a Single Vulnerability Class
```
# Just XSS with browser verification
python HUGINN.py --target example.com --scan xss --browser --yes

# SSRF against an AWS-hosted target
python HUGINN.py --target example.com --scan ssrf --provider aws --yes

# Everything except open redirect
python HUGINN.py --target example.com --scan sqli,xss,ssrf --yes
```
### Iterate on Scanners (Skip Recon)
Once recon is done, reuse it:
```
python HUGINN.py --target example.com --skip-recon --scan xss --yes
```
No subfinder. No crawling. Straight to XSS testing against cached pages.

### Resume a Previous Run
```
python HUGINN.py --resume output/example_20260910_140522
```
Loads the mission file, skips recon, jumps to scanners.

### Fast Scan (No OOB)
When you don't care about blind confirmation:
```
python HUGINN.py --target example.com --yes --no-oob
```
Disables all out-of-band polling. Findings cap at "high" severity instead of "confirmed" — but the scan finishes in a fraction of the time.

## Configuration
HUGINN reads `huginn.yaml` from the project root (or `~/.config/huginn/config.yaml`). Every CLI flag overrides the config file. Every config file key overrides the built-in defaults.
```
# =============================================================================
#  huginn.yaml
# =============================================================================

# ---- Attacker Infrastructure ------------------------------------------------
attacker_domain: beardedviking.org
collab_host:     oast.beardedviking.org
canary_host:     redirect.beardedviking.org
canary_string:   HUGINN-CANARY-LANDED

# ---- OOB Confirmation Endpoints ---------------------------------------------
oob_check_url:    https://oast.beardedviking.org/check.php
canary_check_url: https://redirect.beardedviking.org/check.php

# ---- XSS Payload ------------------------------------------------------------
alert_payload:   alert(document.domain)

# ---- Scanner Tuning ---------------------------------------------------------
max_workers:  8
delay:        0.15
timeout:      12
use_browser:  false
provider_filter: null   # aws | gcp | azure | digitalocean | alibaba | ...

# ---- Scope Exclusions -------------------------------------------------------
# Hosts that will NEVER be scanned — even if discovered during recon.
# Add your own infrastructure to prevent self-scanning.
scope_exclusions:
  - oast.beardedviking.org
  - redirect.beardedviking.org
  # - beardedviking.org          # uncomment to protect your root
  # - staging.example.com        # out-of-scope for the current program
```

### Config Precedence
```
Built-in defaults  <  huginn.yaml  <  CLI arguments
```

## Environment Variables
Variable	Purpose
`PDCP_API_KEY`	ProjectDiscovery Cloud API key (enables `-asn` in httpx)
`CHAOS_KEY`	Chaos dataset key (enables chaos enumeration)
`GITHUB_TOKEN`	GitHub token (enables github-subdomains enumeration)

# Usage

## Full CLI Reference
```
usage: HUGINN [-h] [--version] [--target TARGET] [--program PROGRAM]
              [--scope SCOPE] [--scan SCAN] [--resume RESUME]
              [--config CONFIG] [--attacker ATTACKER] [--collab COLLAB]
              [--canary CANARY] [--alert ALERT] [--oob-log OOB_LOG]
              [--oob-url OOB_URL] [--canary-check CANARY_CHECK]
              [--provider PROVIDER] [--workers WORKERS] [--delay DELAY]
              [--browser] [--yes] [--no-oob] [--skip-recon]
              [--list-scanners]

Core Options:
  --target          Target domain or URL
  --program         Program / engagement name
  --scope           Free-text scope notes
  --scan            Comma-separated scanners to run
  --resume          Resume an existing workspace directory
  --config          Path to huginn.yaml

Attacker Infrastructure:
  --attacker        Attacker domain (default: beardedviking.org)
  --collab          OOB collaborator host
  --canary          Canary host for open redirect confirmation
  --oob-url         Remote OOB check.php URL
  --canary-check    Remote canary check.php URL
  --oob-log         Local log file (disables remote poller)

Scanner Tuning:
  --provider        Cloud provider filter for SSRF
  --workers         Max thread workers
  --delay           Delay between requests (seconds)
  --alert           Alert payload template for XSS

Behavior Flags:
  --browser         Enable Playwright browser verification
  --yes             Non-interactive mode
  --no-oob          Disable all out-of-band confirmation
  --skip-recon      Reuse existing recon/httpx.json
  --list-scanners   List scanners and exit
```

### Example Workflows
**Bug bounty day one:**
```
python HUGINN.py --target target.com --program "Acme Rewards" --yes
```
**Verify an XSS with a real browser:**
```
python HUGINN.py --target target.com --scan xss --browser --skip-recon --yes
```
**Cloud-specific SSRF sweep:**
```
python HUGINN.py --target target.com --scan ssrf --provider aws --yes
```
**Iterate on SQLi payloads:**
```
python HUGINN.py --target target.com --scan sqli --skip-recon --yes
# edit payloads/sqli.yaml
python HUGINN.py --target target.com --scan sqli --skip-recon --yes
```
**Weekly re-scan with diff:**
```
# Cron: Sunday 2am
0 2 * * 0 cd ~/huginn && python HUGINN.py --target target.com \
    --program weekly --yes >> ~/huginn_cron.log 2>&1
```

# Attacker Infrastructure
HUGINN relies on **two self-hosted endpoints** for out-of-band confirmation. These live on your own domain and receive callbacks from payloads that fire on the target.

## `oast.your-domain.tld` — OOB Receiver
Receives HTTP/DNS callbacks from SSRF and blind XSS payloads. Every payload carries a unique `huginn-<hex>` token in the URL path so the scanner can correlate the callback to the exact injection point.

Endpoints:
* `GET /` — receiver, returns JSON with `{"ok": true, "token": "<hex>"}`
* `GET /check.php?list=1` — returns all observed tokens
* `GET /check.php?token=<hex>` — returns full context for a single token
* `GET /check.php?health` — health check

## `redirect.your-domain.tld` — Open Redirect Canary
Receives redirect-chain confirmation hits. Returns `200 OK` with the string `HUGINN-CANARY-LANDED` in the body. When the scanner sees this string after following a redirect chain, the finding is upgraded to `CONFIRMED`.

Endpoints:
* `GET /` — canary page
* `GET /check.php?list=1` — observed tokens
* `GET /check.php?health` — health check

### Verification
```
# OOB receiver
curl -s https://oast.your-domain.tld/check.php?health | jq
# → {"ok": true, "ts": "...", "canary": "HUGINN-CANARY-LANDED"}

# Fire a synthetic token
curl -s "https://oast.your-domain.tld/huginn-deadbeefcafebabe/test"
# → {"ok": true, "token": "deadbeefcafebabe"}

# Confirm it registered
curl -s "https://oast.your-domain.tld/check.php?list=1" | jq
# → {"count": 1, "tokens": {"deadbeefcafebabe": "2026-09-11T..."}}

# Redirect canary
curl -s https://redirect.your-domain.tld/ | grep -o 'HUGINN-CANARY-LANDED'
# → HUGINN-CANARY-LANDED
```
If both work, OOB confirmation is live and every scanner gets maximum value from the payload libraries.
**Deployment instructions** for the PHP infrastructure live in `docs/attacker-infra.md`.

### Output Structure
After a successful run:
```
output/target_20260910_140522/
├── mission.json                       # target, scope, config
│
├── recon/
│   ├── subdomains.json                # every discovered host + wildcard IPs
│   ├── dns_resolved.json              # dnsx output with CNAME chains
│   ├── httpx.json                     # alive hosts with tech/WAF/cloud hints
│   ├── hosts_plain.txt                # newline-delimited hosts
│   ├── alive_plain.txt                # newline-delimited live URLs
│   └── summary.json                   # aggregated stats + fingerprints
│
├── sites/
│   ├── _index.json                    # host → [url, ...]
│   ├── _endpoints.json                # every JS endpoint discovered
│   ├── _forms.json                    # every form discovered
│   ├── _parameters.json               # every unique param name
│   └── <safe_host>/
│       ├── _host_summary.json
│       ├── _forms.json
│       ├── _endpoints.json
│       └── <page_slug>.json           # one per unique page
│
└── findings/
    ├── _aggregate.json                # totals across all scanners
    ├── _confirmed_index.json          # ← CONFIRMED FINDINGS + cURLs
    ├── sqli/
    │   └── <host>/<finding>.json
    ├── xss/
    │   └── <host>/<finding>.json
    ├── ssrf/
    │   └── <host>/<finding>.json
    └── open_redirect/
        └── <host>/<finding>.json
```
## Finding Format
Every finding is a self-contained JSON with everything you need to write the report:
```
{
  "type": "xss",
  "subtype": "reflected_event_handler",
  "severity": "confirmed",
  "confirmed": true,
  "verification_method": "browser_dialog",

  "url": "https://target.com/search?q=test",
  "method": "GET",
  "parameter": "q",
  "injection_point": {
    "location": "query",
    "name": "q",
    "original_value": "test"
  },

  "payload_id": "event-001",
  "payload_name": "IMG onerror",
  "payload": "<img src=x onerror=alert(document.domain)>",
  "payload_category": "event_handlers",

  "reflection": {
    "context": "html_body",
    "encoding": "raw",
    "snippet": "...<div class=\"results\">You searched for: <img src=x onerror=alert(document.domain)></div>..."
  },

  "detection_reason": "Payload survived unmodified in html_body context",
  "evidence": "...<div class=\"results\">You searched for: <img src=x onerror=alert(document.domain)></div>...",
  "response_status": 200,
  "response_length": 4238,
  "response_snippet": "...",

  "browser_verified": {
    "executed": true,
    "dialogs": [{"type": "alert", "message": "target.com"}],
    "url": "https://target.com/search?q=%3Cimg%20src%3Dx..."
  },

  "curl_command": "curl -sk --max-time 15 -i 'https://target.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E'",

  "timestamp": "2026-09-10T19:24:15Z",
  "remediation": "Encode all user-controlled data on output according to..."
}
```
## Confirmed-Only Index
For instant triage, `findings/_confirmed_index.json` contains every confirmed finding with its cURL command — the file you paste into HackerOne:
```
{
  "count": 3,
  "findings": [
    {
      "scanner": "xss",
      "url": "https://target.com/search",
      "param": "q",
      "curl": "curl -sk --max-time 15 -i 'https://target.com/search?q=...'",
      "evidence": "Payload survived unmodified in html_body context"
    }
  ]
}
```

# Payload Libraries
HUGINN ships with four YAML payload libraries. Every payload is an enriched object — not a bare string — so scanners can route by context, filter by WAF, and report metadata accurately.
FilePayloadsCoverage

| File | Payloads | Coverage |
| --- | --- | --- |
| `payloads/sqli.yaml` | ~150 | MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB, Redis, CouchDB; error-based, UNION, blind boolean, blind time, stacked; WAF-specific (Cloudflare, AWS, Azure, Imperva); 1990s → 2026 |
| `payloads/xss.yaml` | ~210 | Basic, event handlers (35+), SVG, MathML, polyglots, filter bypass, encoding, context breaks, WAF bypass, CSP bypass, mXSS, DOM-based, CSTI, prototype pollution, file upload, header injection, namespace confusion, modern (WASM, service worker, import maps, Trusted Types), legacy, blind |
| `payloads/ssrf.yaml` | ~120 | Loopback, IP encoding (decimal/octal/hex/NAT64/6to4/Teredo), RFC1918, cloud metadata (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Alibaba, Oracle, Kubernetes, Tencent, Huawei), protocol abuse (gopher/dict/file/ldap/smb/tftp), whitelist bypass, WAF bypass, DNS rebinding, blind OOB, internal services (Redis, Memcached, FastCGI, Docker, ES), legacy |
| `payloads/open_redirect.yaml` | ~192 | Basic, protocol-relative, backslash (2026 CVEs), whitelist bypass, userinfo, encoding, scheme abuse (javascript:/data:/file:/blob:), fragment, CRLF, HPP, OAuth/SSO (25 params), header-based, cookie-based, path traversal, cloud metadata, Unicode/NFKC, whitespace, modern (2025/2026 parser differentials), legacy, client-side |

## Adding Your Own Payloads
Every payload follows the same enriched-object schema:
```
- id: "my-unique-id"
  name: "Human-readable name"
  category: "category_name"
  context: "html_body"        # xss: where the payload lands
  payload: "<img src=x onerror={{ALERT}}>"
  description: "What this payload does and why it matters."
  tags: ["tag1", "tag2"]
  browsers: ["chrome", "firefox"]
  interaction: false          # requires user interaction?
  severity_hint: "high"       # baseline severity
  references: ["https://..."]
```
Placeholders available for substitution:
| Placeholder | XSS | SSRF | Open Redirect | SQli |
| --- | --- | --- | --- | --- |
| `{{ATTACKER}}` | ✓ | ✓ | ✓ |\
 |
| `{{TARGET}}` | ✓ | ✓ | ✓ |\
 |
| `{{ALERT}}` | ✓ |\
 |\
 |\
 |
| `{{OOB}}` | ✓ | ✓ | ✓ |\
 |
| `{{OOB_HOST}}` | ✓ | ✓ |\
 |\
 |
| `{{CANARY}}` |\
 |\
 | ✓ |\
 |
| `{{CANARY_URL}}` |\
 |\
 | ✓ |\
 |
| `{{RANDOM}}` | ✓ | ✓ | ✓ |\
 |
| `{{COLLAB}}` |\
 | ✓ |\
 |

# Scanner Details

## `sqli.py`
**Injection transports:** query, POST body, JSON body, cookies, headers, path, HPP
**Detection:**

-   Error signature bank (60+ regexes across 11 DBMS)

-   Time-based blind detection (`SLEEP`, `pg_sleep`, `WAITFOR DELAY`, `dbms_lock.sleep`)

-   Response status/length escalation

**Payload filtering:**

-   `waf_hint` --- only runs Cloudflare-specific payloads if Cloudflare detected

-   `dbms_hint` --- only runs MySQL-specific payloads if MySQL detected

**Output subtype examples:**  `error_based`, `blind_time`, `blind_boolean`, `stacked_queries`

### `xss.py`

**Injection transports:** query, POST body, JSON body, cookies, headers, path

**Reflection context detection** --- the killer feature:

1.  Sends a unique marker into the parameter

2.  Locates it in the response

3.  Classifies context: `html_body`, `attribute_double`, `attribute_single`, `attribute_unquoted`, `js_string_single`, `js_string_double`, `js_string_template`, `css`, `html_comment`, `title`, `textarea`

4.  Dispatches **only payloads whose `context` field matches** (plus polyglots)

**Verification:**

-   `payload_survival` --- the exact payload appears unmodified in the response

-   `dangerous_markup` --- `<script>`, `onerror=`, `javascript:` present

-   `oob_callback` --- token appeared in OOB receiver log

-   `browser_dialog` --- Playwright opened the URL and `alert()`/`confirm()`/`prompt()` fired

**Output subtypes:**  `reflected_basic`, `reflected_event_handler`, `reflected_svg`, `mutation_xss`, `dom_based`, `blind_xss`, `polyglot`, `csp_bypass`, `waf_bypass`, etc.

### `ssrf.py`

**Injection transports:** query, POST body, JSON body, cookies, headers, path, HPP

**Detection tiers:**

| Tier | Trigger |
| --- | --- |
| **confirmed** | OOB token appears in receiver log |
| **critical** | Credential-shaped string in body (`AccessKeyId`, `BEGIN PRIVATE KEY`) |
| **critical** | Cloud metadata marker in body (`ami-id`, `metadata-flavor`, `opc/v1`) |
| **critical** | `/proc/self/environ` returns secrets |
| **high** | Payload-specific `detection:` string matched |
| **high** | Local file read (`/etc/passwd`, `win.ini`) |
| **medium** | Timing anomaly ≥ 3.5s |
| **medium** | Response length delta ≥ 500 bytes on internal-IP payloads |
| **low** | Generic internal-service marker |

**Payload features honoured:**  `method` (PUT for IMDSv2 token mint), `headers` (`Metadata-Flavor: Google`), `detection`, `provider`, `protocol`, `service`

### `open_redirect.py`

**Injection transports:** query, POST body, JSON body, cookies, headers, path, HPP

**Verification:**

1.  Location header points to attacker/canary → follow the chain

2.  Chain landing page returns `HUGINN-CANARY-LANDED` → **CONFIRMED**

3.  Async token appears in canary check log → **CONFIRMED**

4.  `<meta refresh>` or JS redirect in body → medium severity

5.  Raw reflection → low severity

**Severity escalation:**

-   OAuth `redirect_uri` / `RelayState` findings are auto-escalated to **critical** (chain potential with code theft)

-   Cloud metadata reachability → **critical** (SSRF via redirect)

-   Scheme abuse (`javascript:`, `data:`) → **high** (chains to XSS)

* * * * *

Roadmap
-------

-   □

    **IDOR module** --- authenticated cross-account comparison (highest ROI for modern programs)

-   □

    **JWT module** --- algorithm confusion, none-alg, kid injection, key confusion

-   □

    **GraphQL module** --- introspection abuse, batching attacks, mutation fuzzing

-   □

    **Report generator** --- Markdown/HTML submission-ready output with severity tables

-   □

    **`ssrf_ports.py`** --- internal port scanner leveraging confirmed SSRF primitives

-   □

    **Docker image** --- one-command deployment

-   □

    **CI integration** --- GitHub Actions workflow for scheduled scans

-   □

    **Slack/Discord notifier** --- real-time alerts on high-severity findings

-   □

    **Web dashboard** --- optional local UI for browsing findings

* * * * *

Legal & Ethics
--------------

**HUGINN is a tool for authorized security testing only.**

By using this software you agree that:

1.  **You have explicit written authorization** to test every target you scan.

2.  **You will respect scope** --- every program defines what's in-scope and what isn't. The `scope_exclusions` list exists for a reason; use it.

3.  **You will not use HUGINN for unauthorized access** to any system. Doing so is a violation of the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws worldwide.

4.  **You are solely responsible** for your actions. The maintainers of HUGINN assume no liability for misuse.

Bug bounty platforms like HackerOne, Bugcrowd, and Intigriti make this easy --- the rules of engagement are public, and automated scanning is permitted when it respects rate limits and stays in scope. **Use HUGINN there.** Not against your neighbor's router, not against your ex's Instagram, not against that one company that was rude to you once.

The tool includes an authorization gate that asks you to type `AUTHORIZED` before scanning. It's not a legal shield --- it's a moment to pause and think.

* * * * *

Contributing
------------

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

# Development Setup
```
git clone https://github.com/BeardedVikingTX/HUGINN
cd huginn
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
./setup.sh --specs-only  # just collect system info, don't install tools
```

## Code Style
-   Python 3.9+ syntax

-   Type hints where they add clarity

-   No new external dependencies without discussion

-   Every new payload added to a YAML library must include: `id`, `name`, `category`, `payload`, `description`, `tags`, `references`

-   Log messages use the shared `log()` helper --- no bare `print()`

## Testing
```
# Syntax check every module
python -m py_compile *.py

# Verify payload libraries parse
python -c "
from huginn_utils import load_payloads
for name in ('sqli', 'xss', 'ssrf', 'open_redirect'):
    data = load_payloads(name)
    count = len(data.get('payloads', []))
    print(f'{name}: {count} payloads')
"
```
### Adding a New Scanner

1.  Create `newscanner.py` with a `run(program_dir, ...)` signature

2.  Follow the existing pattern --- load payloads, extract injection points, verify, persist findings

3.  Register it in `HUGINN.py`'s `SCANNERS` dict

4.  Add its dispatch case in `dispatch_scanner()`

5.  Update this README

* * * * *

Credits
-------

Built on the shoulders of giants:

-   **[ProjectDiscovery](https://projectdiscovery.io/)** --- subfinder, httpx, katana, dnsx, nuclei, interactsh

-   **[OWASP Amass](https://github.com/owasp-amass/amass)** --- deep subdomain enumeration

-   **[TomNomNom](https://github.com/tomnomnom)** --- assetfinder, waybackurls, gf

-   **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** --- the canonical payload reference

-   **[HackTricks](https://hacktricks.wiki/)** --- the canonical methodology reference

-   **[PortSwigger Research](https://portswigger.net/research)** --- 2025/2026 parser-differential research

-   **[SecLists](https://github.com/danielmiessler/SecLists)** --- wordlists

-   **[Interactsh](https://github.com/projectdiscovery/interactsh)** --- OOB callback framework

Individual payload attributions are preserved in each YAML's `references:` field.

* * * * *

License
-------

MIT License --- see [LICENSE](LICENSE) for details.

<div align="center">

**HUGINN** --- Odin's Raven flies the realms to bring back what others miss.

*Speak, and the ravens shall listen.*

</div> ```
