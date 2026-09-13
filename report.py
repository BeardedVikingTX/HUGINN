#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: report.py
#  The Report Forge — turn findings into submissions
# -----------------------------------------------------------------------------
#  Every finding HUGINN produces is a JSON file. This module reads them and
#  renders submission-ready reports in Markdown (HackerOne/Bugcrowd/Intigriti),
#  HTML (local review), or JSON (automation).
#
#  Modes:
#    · --all          Render every finding in the workspace
#    · --finding <f>  Render one specific finding JSON
#    · --dashboard    Render the mission-level summary
#    · --index        Render a top-level README of the whole run
#
#  Usage:
#    python report.py output/example_20260910_140522
#    python report.py output/example_20260910_140522 --all --format md
#    python report.py output/example_20260910_140522 --dashboard
# =============================================================================

import argparse
import html
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, quote

from huginn_utils import (
    banner, section, log, load_json, save_json, safe_filename, C,
)


# =============================================================================
#  REPORTER IDENTITY
# =============================================================================
# Customize this section once. Every report will carry these details.
REPORTER = {
    "handle":        "beardedvikingtx",
    "display_name":  "BeardedVikingTX",
    "real_name":     "Bearded Viking",
    "site":          "https://beardedviking.org",
    "hackerone":     "https://hackerone.com/beardedvikingtx",
    "bugcrowd":      None,   # fill in if you use Bugcrowd
    "intigriti":     None,   # fill in if you use Intigriti
    "email":         "security@beardedviking.org",
    "pgp":           None,   # fingerprint, if you publish one
    "tagline":       "Odin's Raven — automated security testing",
}


# =============================================================================
#  SEVERITY → CVSS MAPPING
# =============================================================================
# Conservative baseline scores. Real CVSS depends on the target's specifics —
# adjust upward if the finding has extra impact (auth bypass, PII exposure).
CVSS_MAP = {
    "confirmed": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "label": "Critical"},
    "critical":  {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "label": "Critical"},
    "high":      {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "label": "High"},
    "medium":    {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "label": "Medium"},
    "low":       {"score": 3.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "label": "Low"},
    "info":      {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N", "label": "Informational"},
}


# =============================================================================
#  VULNERABILITY CLASS TEMPLATES
# =============================================================================
# Each entry supplies: title prefix, summary prose, impact prose, remediation
# bullets, and reference links. Keyed by report type.
VULN_TEMPLATES = {

    # -------------------------------------------------------------------------
    "sqli": {
        "title_prefix":    "SQL Injection",
        "cwe":             "CWE-89",
        "owasp":           "A03:2021 – Injection",
        "summary": (
            "A SQL injection vulnerability exists in the `{param}` parameter of "
            "`{url}`. User-supplied input is concatenated into a SQL query "
            "without parameterisation, allowing an attacker to alter the "
            "intended query structure and execute arbitrary SQL statements "
            "against the backend database."
        ),
        "impact": (
            "An unauthenticated attacker can leverage this vulnerability to:\n\n"
            "- **Extract sensitive data** from the database, including user "
            "  credentials, PII, session tokens, and business records\n"
            "- **Bypass authentication** by manipulating query logic (e.g., "
            "  `' OR 1=1--`)\n"
            "- **Escalate privileges** through UNION-based or stacked queries\n"
            "- **Potentially achieve remote code execution** in configurations "
            "  where the database user has file-write privileges or `xp_cmdshell` "
            "  is enabled (MSSQL)\n"
            "- **Deny service** by dropping tables or running resource-intensive "
            "  queries\n\n"
            "Given the {dbms} backend confirmed by error signatures, this "
            "represents a **{severity_label}** severity issue requiring "
            "immediate remediation."
        ),
        "remediation": [
            "**Use parameterised queries / prepared statements** for all "
            "database access. Never concatenate user input into SQL strings.",
            "**Apply least-privilege to the database user** — the application "
            "should not connect as `root`, `sa`, or `dbo`.",
            "**Validate and whitelist input** — numeric IDs should be cast to "
            "integers server-side; string parameters should be constrained to "
            "expected patterns.",
            "**Deploy a WAF as defence-in-depth** — but never as the primary "
            "control.",
            "**Enable detailed SQL error logging** but **suppress error "
            "messages** from being returned to the client in production.",
        ],
        "references": [
            ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
            ("OWASP Query Parameterization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"),
            ("PortSwigger SQLi Labs", "https://portswigger.net/web-security/sql-injection"),
        ],
    },

    # -------------------------------------------------------------------------
    "xss": {
        "title_prefix":    "Cross-Site Scripting (XSS)",
        "cwe":             "CWE-79",
        "owasp":           "A03:2021 – Injection",
        "summary": (
            "A {reflection_context} cross-site scripting vulnerability exists in "
            "the `{param}` parameter of `{url}`. User-supplied input is reflected "
            "into the response without context-appropriate output encoding, "
            "allowing an attacker to inject arbitrary JavaScript into the "
            "victim's browser session."
        ),
        "impact": (
            "An attacker can craft a link that, when visited by a victim, "
            "executes arbitrary JavaScript in the context of the target "
            "application's origin. This enables:\n\n"
            "- **Session hijacking** — theft of session cookies and auth tokens\n"
            "- **Credential phishing** — injecting fake login forms into the "
            "  trusted page\n"
            "- **CSRF bypass** — reading CSRF tokens and submitting requests on "
            "  behalf of the victim\n"
            "- **Keylogging and form grabbing** — capturing user input in real "
            "  time\n"
            "- **Malware delivery** — redirecting victims to exploit kits or "
            "  malicious downloads\n"
            "- **Defacement** — altering the page content seen by the victim\n\n"
            "This is a **{severity_label}** severity issue and {confirmed_note}"
        ),
        "remediation": [
            "**Context-aware output encoding** is the primary defence. Encode "
            "user-controlled data according to where it lands: HTML entity "
            "encoding for HTML body, attribute encoding for attributes, "
            "JavaScript string encoding for JS strings, URL encoding for URLs.",
            "**Adopt a context-aware templating engine** (Twig, Jinja2 with "
            "autoescape, Handlebars with HTML escaping) that escapes by default.",
            "**Deploy a strict Content Security Policy** — no `unsafe-inline`, "
            "no `unsafe-eval`, and use nonces or hashes for any inline scripts.",
            "**Sanitise rich text** with a maintained library (DOMPurify, "
            "bleach) if the application must accept HTML from users.",
            "**Set `HttpOnly` and `Secure` flags on session cookies** to "
            "mitigate cookie theft in case XSS still occurs.",
        ],
        "references": [
            ("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
            ("PortSwigger XSS", "https://portswigger.net/web-security/cross-site-scripting"),
            ("CSP Reference", "https://content-security-policy.com/"),
        ],
    },

    # -------------------------------------------------------------------------
    "ssrf": {
        "title_prefix":    "Server-Side Request Forgery (SSRF)",
        "cwe":             "CWE-918",
        "owasp":           "A10:2021 – Server-Side Request Forgery",
        "summary": (
            "A server-side request forgery vulnerability exists in the `{param}` "
            "parameter of `{url}`. The application fetches a URL supplied by the "
            "user without validating the destination against an allow-list, "
            "allowing an attacker to make the server issue HTTP requests to "
            "arbitrary internal or external destinations."
        ),
        "impact": (
            "The application server can be coerced into making requests from "
            "within the target's trusted network. This enables:\n\n"
            "- **Cloud metadata theft** — retrieval of AWS/GCP/Azure credentials "
            "  from the instance metadata service (169.254.169.254), often "
            "  leading to **full cloud account compromise**\n"
            "- **Internal service enumeration** — mapping the internal network "
            "  via response timing and body analysis\n"
            "- **Authentication bypass** — accessing internal admin panels that "
            "  trust requests from the application server\n"
            "- **Data exfiltration** — reading local files via `file://` or "
            "  internal APIs via `gopher://`\n"
            "- **RCE pivot** — interacting with internal services (Redis, "
            "  Docker, FastCGI) that are only reachable from loopback\n\n"
            "This is a **{severity_label}** severity issue. {confirmed_note}"
        ),
        "remediation": [
            "**Enforce a strict allow-list** of permitted destinations. Prefer "
            "allowing hostnames over IPs, and resolve them server-side before "
            "the outbound request.",
            "**Block RFC1918 addresses, loopback, link-local, and IPv6 "
            "transition addresses** (`::ffff:`, `64:ff9b::`, `2002::`) in the "
            "URL parser, not in a regex.",
            "**Require IMDSv2 on AWS** — this alone mitigates the most common "
            "SSRF escalation. Disable unused metadata services on other clouds.",
            "**Do not trust `X-Forwarded-Host`, `Referer`, or `Host` headers** "
            "when constructing outbound URLs.",
            "**Route all outbound fetches through a dedicated egress proxy** "
            "that enforces the allow-list and logs destinations.",
            "**Forbid non-http(s) schemes** — no `gopher://`, `file://`, "
            "`dict://`, `ldap://`, `smb://`.",
        ],
        "references": [
            ("OWASP SSRF", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
            ("PortSwigger SSRF", "https://portswigger.net/web-security/ssrf"),
            ("AWS IMDSv2 Documentation", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"),
            ("HackTricks SSRF", "https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/"),
        ],
    },

    # -------------------------------------------------------------------------
    "open_redirect": {
        "title_prefix":    "Open Redirect",
        "cwe":             "CWE-601",
        "owasp":           "Unvalidated Redirects and Forwards",
        "summary": (
            "An open redirect vulnerability exists in the `{param}` parameter of "
            "`{url}`. The application redirects users to a destination taken "
            "from user input without validating it against an allow-list, "
            "allowing an attacker to redirect victims to an arbitrary external "
            "site under the trusted domain's URL."
        ),
        "impact": (
            "An attacker can craft a link on the trusted domain that redirects "
            "the victim to an attacker-controlled site. This enables:\n\n"
            "- **Phishing at scale** — `https://trusted.com/redirect?url=evil.com` "
            "  displays the trusted domain in the URL bar before the redirect\n"
            "- **OAuth/SSO token theft** — if the vulnerable parameter is "
            "  `redirect_uri`, `RelayState`, or `returnTo`, an attacker can "
            "  intercept authorization codes and gain full account access\n"
            "- **Bypass of URL allow-lists** — many apps trust URLs from their "
            "  own domain even after redirect\n"
            "- **Referer leakage** — sensitive data in `Referer` headers sent "
            "  to the attacker's site\n"
            "- **Trust chain abuse** — the redirect can bootstrap further "
            "  attacks against users who trust the target domain\n\n"
            "This is a **{severity_label}** severity issue. {confirmed_note}"
        ),
        "remediation": [
            "**Never accept a full URL as a redirect destination.** Map an "
            "opaque ID (e.g., `?page=42`) to an internal destination, or "
            "constrain the value to a small allow-list of known paths.",
            "**Reject protocol-relative URLs** (`//evil.com`), backslash-prefixed "
            "URLs (`/\\evil.com`), and non-`http(s)` schemes.",
            "**Validate after decoding** — a URL that looks like "
            "`https%3A%2F%2Fevil.com` is still an attack.",
            "**Use a library** for redirect validation instead of rolling your "
            "own regex — the parser-differential bugs documented in 2025/2026 "
            "are easy to reintroduce.",
            "**Apply an allow-list to `redirect_uri` in every OAuth/OIDC client** "
            "and validate that the value is an **exact match** against a "
            "registered URI, not a prefix or suffix match.",
        ],
        "references": [
            ("OWASP Unvalidated Redirects", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
            ("PortSwigger Open Redirects", "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"),
            ("RFC 9700 — OAuth 2.0 Security Best Practices", "https://datatracker.ietf.org/doc/rfc9700/"),
        ],
    },
}


# =============================================================================
#  FINDING LOADER
# =============================================================================
def load_mission(program_dir):
    """Load mission.json if it exists."""
    p = Path(program_dir) / "mission.json"
    if not p.exists():
        return {}
    try:
        return load_json(p)
    except Exception:
        return {}


def load_findings(program_dir):
    """
    Walk findings/<scanner>/<host>/*.json and return every finding
    as a dict with `_scanner` and `_file` attached.
    """
    findings_root = Path(program_dir) / "findings"
    if not findings_root.exists():
        return []

    findings = []
    for jf in findings_root.rglob("*.json"):
        name = jf.name
        if name.startswith("_"):
            continue
        try:
            rec = load_json(jf)
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        # Attach context
        rel = jf.relative_to(findings_root)
        parts = rel.parts
        rec["_scanner"]  = parts[0] if len(parts) >= 1 else "unknown"
        rec["_file"]     = str(jf)
        rec["_host"]     = parts[1] if len(parts) >= 2 else (
            urlparse(rec.get("url", "")).netloc or "unknown")
        findings.append(rec)
    return findings


def dedup_findings(findings):
    """
    Collapse findings that share the same URL + parameter + subtype.
    Keep the highest-severity instance.
    """
    order = {"confirmed": 5, "critical": 4, "high": 3,
             "medium": 2, "low": 1, "info": 0}
    seen = {}
    for f in findings:
        key = (
            f.get("url", ""),
            f.get("parameter", ""),
            f.get("subtype", ""),
        )
        cur = seen.get(key)
        if cur is None:
            seen[key] = f
            continue
        if order.get(f.get("severity", "low"), 0) > \
           order.get(cur.get("severity", "low"), 0):
            seen[key] = f
    return list(seen.values())


# =============================================================================
#  SEVERITY HELPERS
# =============================================================================
def severity_info(finding):
    sev = (finding.get("severity") or "low").lower()
    return CVSS_MAP.get(sev, CVSS_MAP["low"])


def severity_emoji(sev):
    return {
        "confirmed": "🟢",
        "critical":  "🔴",
        "high":      "🟠",
        "medium":    "🟡",
        "low":       "⚪",
        "info":      "ℹ️",
    }.get(sev, "⚪")


# =============================================================================
#  CONTEXT BUILDERS
# =============================================================================
def reflection_context_label(ctx):
    """Human-readable description of a reflection context."""
    return {
        "html_body":                 "reflected (HTML body)",
        "attribute_double":          "reflected (double-quoted attribute)",
        "attribute_single":          "reflected (single-quoted attribute)",
        "attribute_unquoted":        "reflected (unquoted attribute)",
        "js_string_single":          "DOM-based (single-quoted JS string)",
        "js_string_double":          "DOM-based (double-quoted JS string)",
        "js_string_template":        "DOM-based (JS template literal)",
        "html_comment":              "stored (HTML comment)",
        "css":                       "stored (CSS context)",
        "title":                     "stored (HTML title)",
        "textarea":                  "stored (textarea)",
        "js_code":                   "DOM-based (JS code block)",
    }.get(ctx or "", "reflected")


def cvss_block(sev_info):
    return (
        f"**CVSS v3.1 Score:** `{sev_info['score']}` "
        f"({sev_info['label']})\n"
        f"**CVSS Vector:** `{sev_info['vector']}`"
    )


def reporter_signature_md():
    """Markdown signature block for the bottom of every report."""
    lines = [
        "---",
        "",
        f"**Reported by:** [{REPORTER['display_name']}]"
        f"({REPORTER['hackerone']})",
        f"**Website:** {REPORTER['site']}",
        f"**Email:** {REPORTER['email']}",
    ]
    if REPORTER.get("pgp"):
        lines.append(f"**PGP:** `{REPORTER['pgp']}`")
    lines.append("")
    lines.append(
        "*This vulnerability was discovered as part of authorised security "
        "testing. Details are provided in good faith under coordinated "
        "disclosure. Please contact me with any questions or to request "
        "additional evidence.*"
    )
    return "\n".join(lines)


def reporter_signature_html():
    return f"""
<hr>
<div style="color:#6e7681;font-size:0.9em;line-height:1.6">
  <p>
    <strong>Reported by:</strong>
    <a href="{html.escape(REPORTER['hackerone'])}">{html.escape(REPORTER['display_name'])}</a><br>
    <strong>Website:</strong>
    <a href="{html.escape(REPORTER['site'])}">{html.escape(REPORTER['site'])}</a><br>
    <strong>Email:</strong>
    {html.escape(REPORTER['email'])}
    {('<br><strong>PGP:</strong> <code>' + html.escape(REPORTER['pgp']) + '</code>') if REPORTER.get('pgp') else ''}
  </p>
  <p>
    <em>This vulnerability was discovered as part of authorised security
    testing. Details are provided in good faith under coordinated disclosure.</em>
  </p>
</div>
"""


# =============================================================================
#  REPORT — single finding → Markdown / HTML / JSON
# =============================================================================
class Report:

    def __init__(self, finding, mission=None):
        self.f    = finding
        self.m    = mission or {}
        self.sev  = severity_info(finding)
        self.type = (finding.get("type") or "unknown").lower()
        self.tpl  = VULN_TEMPLATES.get(self.type, {})

    # ------------------------------------------------------------------ #
    #  Field accessors
    # ------------------------------------------------------------------ #
    @property
    def url(self):
        return self.f.get("url", "")

    @property
    def param(self):
        return self.f.get("parameter", "unknown")

    @property
    def host(self):
        return urlparse(self.url).netloc or self.f.get("_host", "")

    @property
    def program(self):
        return self.m.get("program", self.host)

    @property
    def confirmed(self):
        return bool(self.f.get("confirmed"))

    @property
    def subtype(self):
        return self.f.get("subtype", self.type)

    # ------------------------------------------------------------------ #
    #  Title
    # ------------------------------------------------------------------ #
    def title(self):
        """Impact-first title, e.g. 'SQL Injection in `q` on /search'."""
        prefix = self.tpl.get("title_prefix", self.type.upper())
        path = urlparse(self.url).path or "/"
        return f"{prefix} in `{self.param}` at `{path}`"

    # ------------------------------------------------------------------ #
    #  Subtitle / summary line
    # ------------------------------------------------------------------ #
    def subtitle(self):
        conf = "confirmed" if self.confirmed else "unconfirmed"
        return (
            f"{self.sev['label']} · {self.sev['score']} CVSS · "
            f"{conf} · {self.subtype}"
        )

    # ------------------------------------------------------------------ #
    #  Summary prose
    # ------------------------------------------------------------------ #
    def summary(self):
        tpl = self.tpl.get("summary", "")
        if not tpl:
            return (
                f"A vulnerability of type `{self.type}` was identified at "
                f"`{self.url}` in the `{self.param}` parameter."
            )
        ctx = ""
        refl = self.f.get("reflection") or {}
        if refl.get("context"):
            ctx = reflection_context_label(refl["context"])

        dbms = (self.f.get("payload_provider")
                or self.f.get("matched_dbms")
                or "the target's database")

        return tpl.format(
            url=self.url,
            param=self.param,
            dbms=dbms,
            reflection_context=ctx or "reflected",
            severity_label=self.sev["label"],
            confirmed_note=(
                "The finding was **confirmed** via out-of-band callback."
                if self.confirmed else
                "The finding is **high-confidence** but not OOB-confirmed."
            ),
        )

    # ------------------------------------------------------------------ #
    #  Impact
    # ------------------------------------------------------------------ #
    def impact(self):
        tpl = self.tpl.get("impact", "")
        if not tpl:
            return (
                f"This vulnerability allows an attacker to affect the target "
                f"application in a way not intended by its designers. See the "
                f"remediation section for the recommended fix."
            )
        return tpl.format(
            severity_label=self.sev["label"],
            confirmed_note=(
                "Confirmed via out-of-band callback."
                if self.confirmed else
                "Not yet OOB-confirmed but reproducible."
            ),
        )

    # ------------------------------------------------------------------ #
    #  Steps to reproduce
    # ------------------------------------------------------------------ #
    def repro_steps(self):
        steps = []
        steps.append(
            f"Navigate to the affected endpoint and observe the "
            f"vulnerable parameter:"
        )
        steps.append(f"```\n{self.url}\n```")
        steps.append(
            f"Inject the payload into the `{self.param}` parameter:"
        )
        steps.append(f"```\n{self.f.get('payload', '(payload not recorded)')}\n```")

        if self.f.get("curl_command"):
            steps.append(
                "The full request can be reproduced with the following cURL "
                "command:"
            )
            steps.append(f"```bash\n{self.f['curl_command']}\n```")

        if self.f.get("response_status"):
            steps.append(
                f"Observe the response (HTTP `{self.f['response_status']}`):"
            )

        if self.f.get("evidence"):
            ev = self.f["evidence"]
            # If it looks like HTML, present as such
            lang = "html" if "<" in ev and ">" in ev else "text"
            steps.append(f"```{lang}\n{ev[:600]}\n```")

        if self.confirmed and self.f.get("browser_verified"):
            bv = self.f["browser_verified"]
            dialogs = bv.get("dialogs") or []
            if dialogs:
                steps.append(
                    "**Browser confirmation** — opening the URL in a headless "
                    "Chromium instance triggered the following dialog(s):"
                )
                for d in dialogs:
                    steps.append(f"- `{d.get('type')}` — `{d.get('message')}`")

        if self.confirmed and self.f.get("oob_url"):
            steps.append(
                "**Out-of-band confirmation** — the callback was received at:"
            )
            steps.append(f"```\n{self.f['oob_url']}\n```")

        return steps

    # ------------------------------------------------------------------ #
    #  Remediation
    # ------------------------------------------------------------------ #
    def remediation(self):
        tpl = self.tpl.get("remediation", [])
        if tpl:
            return tpl
        return [
            "Follow OWASP guidance for the affected vulnerability class.",
            "Test the fix with the same payload after remediation.",
            "Consider adding this case to your pre-release security checklist.",
        ]

    # ------------------------------------------------------------------ #
    #  References
    # ------------------------------------------------------------------ #
    def references(self):
        refs = list(self.tpl.get("references", []))
        payload_refs = self.f.get("payload_references") or []
        for r in payload_refs:
            if isinstance(r, str):
                refs.append((r, r))
        return refs

    # ------------------------------------------------------------------ #
    #  Metadata table
    # ------------------------------------------------------------------ #
    def metadata_rows(self):
        rows = [
            ("Target",       self.host),
            ("Endpoint",     self.url),
            ("Parameter",    self.param),
            ("Vulnerability", self.tpl.get("title_prefix", self.type)),
            ("Subtype",      self.subtype),
            ("Severity",     f"{self.sev['label']} ({self.sev['score']})"),
            ("Confidence",   "Confirmed" if self.confirmed else "High"),
            ("CWE",          self.tpl.get("cwe", "—")),
            ("OWASP",        self.tpl.get("owasp", "—")),
            ("Discovered",   self.f.get("timestamp", "—")),
        ]
        if self.f.get("payload_id"):
            rows.append(("Payload ID", self.f["payload_id"]))
        if self.f.get("payload_name"):
            rows.append(("Payload Name", self.f["payload_name"]))
        if self.f.get("verification_method"):
            rows.append(("Verification", self.f["verification_method"]))
        return rows

    # ------------------------------------------------------------------ #
    #  MARKDOWN rendering
    # ------------------------------------------------------------------ #
    def to_markdown(self):
        lines = []

        # --- Title ---------------------------------------------------
        lines.append(f"# {self.title()}")
        lines.append("")
        lines.append(f"*{self.subtitle()}*")
        lines.append("")

        # --- Metadata table -----------------------------------------
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        for k, v in self.metadata_rows():
            lines.append(f"| **{k}** | {v} |")
        lines.append("")

        # --- CVSS ---------------------------------------------------
        lines.append("## Severity")
        lines.append("")
        lines.append(cvss_block(self.sev))
        lines.append("")

        # --- Summary -------------------------------------------------
        lines.append("## Summary")
        lines.append("")
        lines.append(self.summary())
        lines.append("")

        # --- Steps to Reproduce -------------------------------------
        lines.append("## Steps to Reproduce")
        lines.append("")
        for i, step in enumerate(self.repro_steps(), 1):
            lines.append(f"**Step {i}.** {step}")
            lines.append("")

        # --- Impact --------------------------------------------------
        lines.append("## Impact")
        lines.append("")
        lines.append(self.impact())
        lines.append("")

        # --- Remediation --------------------------------------------
        lines.append("## Recommended Remediation")
        lines.append("")
        for bullet in self.remediation():
            lines.append(f"- {bullet}")
        lines.append("")

        # --- References ---------------------------------------------
        refs = self.references()
        if refs:
            lines.append("## References")
            lines.append("")
            for name, url in refs:
                lines.append(f"- [{name}]({url})")
            lines.append("")

        # --- Reporter signature -------------------------------------
        lines.append(reporter_signature_md())

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  HTML rendering
    # ------------------------------------------------------------------ #
    def to_html(self):
        md = self.to_markdown()
        # Minimal markdown → HTML (headings, bold, code, lists, tables)
        body = _md_to_html(md)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(self.title())}</title>
<style>
  :root {{
    --bg: #0a0e14; --fg: #c9d1d9; --muted: #6e7681;
    --accent: #39ff88; --link: #58a6ff; --border: #161b22;
    --code-bg: #0d1117; --red: #ff5c5c; --orange: #ffa657;
    --yellow: #ffd866; --green: #39ff88;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 2.5rem 1rem; background: var(--bg); color: var(--fg);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    line-height: 1.65;
  }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ color: var(--accent); font-size: 1.65rem; border-bottom: 2px solid var(--accent); padding-bottom: .5rem; letter-spacing: .02em; }}
  h2 {{ color: var(--accent); font-size: 1.15rem; margin-top: 2.2rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; letter-spacing: .04em; }}
  h3 {{ color: var(--fg); font-size: 1rem; margin-top: 1.4rem; }}
  em {{ color: var(--muted); }}
  a {{ color: var(--link); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{
    background: var(--code-bg); color: var(--accent); padding: 2px 6px;
    border-radius: 4px; font-size: .92em;
  }}
  pre {{
    background: var(--code-bg); padding: 1rem; border-radius: 6px;
    overflow-x: auto; border: 1px solid var(--border);
    white-space: pre-wrap; word-break: break-all;
  }}
  pre code {{ background: none; padding: 0; color: var(--fg); }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ padding: .55rem .75rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
  th {{ background: var(--code-bg); color: var(--accent); }}
  ul, ol {{ padding-left: 1.5rem; }}
  li {{ margin: .35rem 0; }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: .8em; font-weight: 600; letter-spacing: .05em;
  }}
</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>
"""

    # ------------------------------------------------------------------ #
    #  JSON export
    # ------------------------------------------------------------------ #
    def to_json(self):
        return {
            "title":       self.title(),
            "subtitle":    self.subtitle(),
            "program":     self.program,
            "target":      self.host,
            "url":         self.url,
            "parameter":   self.param,
            "type":        self.type,
            "subtype":     self.subtype,
            "severity":    self.f.get("severity"),
            "cvss_score":  self.sev["score"],
            "cvss_vector": self.sev["vector"],
            "cwe":         self.tpl.get("cwe"),
            "owasp":       self.tpl.get("owasp"),
            "confirmed":   self.confirmed,
            "metadata":    {k: v for k, v in self.metadata_rows()},
            "summary_md":  self.summary(),
            "steps_md":    self.repro_steps(),
            "impact_md":   self.impact(),
            "remediation": self.remediation(),
            "references":  [{"name": n, "url": u} for n, u in self.references()],
            "raw_finding": self.f,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "generated_by": {
                "tool":     "HUGINN report.py",
                "version":  "2.0.0",
                "reporter": REPORTER,
            },
        }


# =============================================================================
#  MINI MARKDOWN RENDERER (for HTML output)
# =============================================================================
def _md_to_html(md):
    """Render a subset of markdown to HTML — enough for our report format."""
    lines = md.split("\n")
    out = []
    in_code = False
    in_table = False
    code_lang = ""

    def close_table():
        nonlocal in_table
        if in_table:
            out.append("</tbody></table>")
            in_table = False

    for line in lines:
        # Code fences
        if line.startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
                code_lang = ""
            else:
                code_lang = line[3:].strip()
                out.append(f"<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(html.escape(line))
            continue

        # Blank line
        if not line.strip():
            close_table()
            out.append("")
            continue

        # Headings
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            text = _inline_md(m.group(2))
            out.append(f"<h{level}>{text}</h{level}>")
            continue

        # Horizontal rule
        if re.match(r"^---+$", line):
            close_table()
            out.append("<hr>")
            continue

        # Table
        if "|" in line and line.strip().startswith("|"):
            if not in_table:
                out.append("<table><tbody>")
                in_table = True
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(c.startswith("-") or c == "" for c in cells):
                continue  # separator row
            tag = "th" if all(not c.startswith("**") for c in cells) and len(out) and "<table>" in out[-1][:7] else "td"
            # Simple heuristic: first table row is header
            if out[-1] == "<table><tbody>":
                row = "".join(f"<th>{_inline_md(c)}</th>" for c in cells)
            else:
                row = "".join(f"<td>{_inline_md(c)}</td>" for c in cells)
            out.append(f"<tr>{row}</tr>")
            continue

        # Bulleted list
        m = re.match(r"^-\s+(.*)$", line)
        if m:
            close_table()
            out.append(f"<ul><li>{_inline_md(m.group(1))}</li></ul>")
            continue

        # Paragraph
        close_table()
        out.append(f"<p>{_inline_md(line)}</p>")

    return "\n".join(out)


def _inline_md(text):
    """Convert inline markdown: **bold**, *ital*, `code`, [link](url)."""
    text = html.escape(text)
    # links [text](url)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{html.escape(m.group(2))}">{m.group(1)}</a>',
        text,
    )
    # inline code
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # bold
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    # italics
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    return text


# =============================================================================
#  DASHBOARD + INDEX
# =============================================================================
def render_dashboard(program_dir, findings, mission):
    """Top-level summary of the whole run."""
    order = {"confirmed": 5, "critical": 4, "high": 3,
             "medium": 2, "low": 1, "info": 0}

    # Group by severity
    grouped = {}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        grouped.setdefault(sev, []).append(f)

    # Group by type
    by_type = {}
    for f in findings:
        t = f.get("type") or "unknown"
        by_type.setdefault(t, []).append(f)

    target = mission.get("target", "unknown")
    program = mission.get("program", target)

    lines = [
        f"# HUGINN Report — {program}",
        "",
        f"*Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
        f"**Target:** `{target}`  ",
        f"**Findings:** {len(findings)}  ",
        f"**Confirmed:** {sum(1 for f in findings if f.get('confirmed'))}",
        "",
        "---",
        "",
        "## Findings by Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("confirmed", "critical", "high", "medium", "low", "info"):
        n = len(grouped.get(sev, []))
        if n:
            lines.append(f"| **{sev.title()}** | {n} |")
    lines.append("")

    lines.append("## Findings by Class")
    lines.append("")
    lines.append("| Class | Count | Confirmed |")
    lines.append("|-------|-------|-----------|")
    for t, items in sorted(by_type.items(),
                            key=lambda x: -len(x[1])):
        conf = sum(1 for f in items if f.get("confirmed"))
        lines.append(f"| {t} | {len(items)} | {conf} |")
    lines.append("")

    # Top confirmed findings
    confirmed = [f for f in findings if f.get("confirmed")]
    if confirmed:
        lines.append("## Confirmed Findings")
        lines.append("")
        for f in sorted(confirmed,
                        key=lambda x: -order.get(x.get("severity", "low"), 0)):
            r = Report(f, mission)
            lines.append(f"- **{r.title()}** — {r.url}")
            if f.get("curl_command"):
                lines.append(f"  ```bash\n  {f['curl_command']}\n  ```")
        lines.append("")

    lines.append(reporter_signature_md())
    return "\n".join(lines)


def render_index(program_dir, findings, mission):
    """Short top-level README for the workspace directory."""
    target  = mission.get("target", "unknown")
    program = mission.get("program", target)
    started = mission.get("started_at", "unknown")

    confirmed = [f for f in findings if f.get("confirmed")]
    high = [f for f in findings if f.get("severity") in ("critical", "high")]

    lines = [
        f"# HUGINN Workspace — {program}",
        "",
        f"- **Target:** `{target}`",
        f"- **Started:** {started}",
        f"- **Total findings:** {len(findings)}",
        f"- **Confirmed findings:** {len(confirmed)}",
        f"- **Critical/High findings:** {len(high)}",
        "",
        "## Files in this workspace",
        "",
        "- `mission.json` — scope, config, and metadata for this run",
        "- `recon/` — subdomains, DNS, HTTP fingerprints",
        "- `sites/` — crawled pages, forms, endpoints",
        "- `findings/` — one JSON per finding, grouped by scanner",
        "- `reports/` — Markdown / HTML reports generated by `report.py`",
        "",
        "## Quick triage",
        "",
        "```bash",
        f"python report.py {program_dir} --all",
        f"python report.py {program_dir} --dashboard",
        "```",
        "",
        reporter_signature_md(),
    ]
    return "\n".join(lines)


# =============================================================================
#  WRITER
# =============================================================================
def write_report(report, output_dir, fmt="md"):
    """Write a single report to disk and return the path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_title = safe_filename(report.title().replace(" ", "_")[:120])

    if fmt == "md":
        path = output_dir / f"{safe_title}.md"
        path.write_text(report.to_markdown(), encoding="utf-8")
    elif fmt == "html":
        path = output_dir / f"{safe_title}.html"
        path.write_text(report.to_html(), encoding="utf-8")
    elif fmt == "json":
        path = output_dir / f"{safe_title}.json"
        save_json(path, report.to_json())
    else:
        raise ValueError(f"unknown format: {fmt}")

    return path


def write_multiformat(report, output_dir, formats):
    """Write the same report in every requested format."""
    paths = {}
    for fmt in formats:
        paths[fmt] = write_report(report, output_dir, fmt)
    return paths


# =============================================================================
#  MAIN
# =============================================================================
def generate(program_dir, formats=("md",), mode="all",
             single_finding=None, dedup=True):
    program_dir = Path(program_dir)
    if not program_dir.exists():
        log(f"workspace not found: {program_dir}", "err")
        sys.exit(1)

    mission  = load_mission(program_dir)
    findings = load_findings(program_dir)

    if dedup:
        before = len(findings)
        findings = dedup_findings(findings)
        if before != len(findings):
            log(f"dedup: {before} → {len(findings)} findings", "ok")

    reports_dir = program_dir / "reports"
    reports_dir.mkdir(exist_ok=True)

    # ---- Single finding mode ------------------------------------------
    if mode == "single" and single_finding:
        target = Path(single_finding)
        if not target.exists():
            log(f"finding file not found: {target}", "err")
            sys.exit(1)
        finding = load_json(target)
        finding["_scanner"] = target.parent.parent.name
        report = Report(finding, mission)
        paths = write_multiformat(report, reports_dir, formats)
        log(f"wrote: {', '.join(str(p) for p in paths.values())}", "ok")
        return

    # ---- Dashboard mode ------------------------------------------------
    if mode == "dashboard":
        md = render_dashboard(program_dir, findings, mission)
        path = reports_dir / "_dashboard.md"
        path.write_text(md, encoding="utf-8")
        log(f"dashboard → {path}", "ok", "SAVE")
        # Also emit HTML
        html_doc = _wrap_html(md, "HUGINN Dashboard")
        (reports_dir / "_dashboard.html").write_text(html_doc, encoding="utf-8")
        return

    # ---- Index mode ----------------------------------------------------
    if mode == "index":
        md = render_index(program_dir, findings, mission)
        path = program_dir / "README.md"
        path.write_text(md, encoding="utf-8")
        log(f"index → {path}", "ok", "SAVE")
        return

    # ---- All findings mode ---------------------------------------------
    log(f"rendering {len(findings)} findings to {reports_dir}", "scan")

    # Sort by severity so the biggest findings render first
    order = {"confirmed": 5, "critical": 4, "high": 3,
             "medium": 2, "low": 1, "info": 0}
    findings = sorted(findings,
                      key=lambda f: -order.get(f.get("severity", "low"), 0))

    count = 0
    for finding in findings:
        try:
            report = Report(finding, mission)
            write_multiformat(report, reports_dir, formats)
            count += 1
            sev = finding.get("severity", "low")
            log(f"{severity_emoji(sev)} {report.title()[:80]}",
                "ok", "REPORT")
        except Exception as e:
            log(f"failed to render {finding.get('_file', '?')}: {e}", "warn")

    log(f"wrote {count} reports to {reports_dir}", "ok", "DONE")

    # Also emit the dashboard for convenience
    md = render_dashboard(program_dir, findings, mission)
    (reports_dir / "_dashboard.md").write_text(md, encoding="utf-8")
    log(f"dashboard → {reports_dir / '_dashboard.md'}", "ok", "SAVE")


def _wrap_html(md_body, title):
    """Wrap markdown-rendered HTML in a full page."""
    body = _md_to_html(md_body)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root{{--bg:#0a0e14;--fg:#c9d1d9;--muted:#6e7681;--accent:#39ff88;
        --link:#58a6ff;--border:#161b22;--code-bg:#0d1117}}
  body{{margin:0;padding:2.5rem 1rem;background:var(--bg);color:var(--fg);
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
       line-height:1.65}}
  .container{{max-width:960px;margin:0 auto}}
  h1{{color:var(--accent);border-bottom:2px solid var(--accent);padding-bottom:.5rem}}
  h2{{color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:.3rem;margin-top:2.2rem}}
  a{{color:var(--link);text-decoration:none}}a:hover{{text-decoration:underline}}
  code{{background:var(--code-bg);color:var(--accent);padding:2px 6px;border-radius:4px}}
  pre{{background:var(--code-bg);padding:1rem;border-radius:6px;overflow-x:auto;
      border:1px solid var(--border);white-space:pre-wrap;word-break:break-all}}
  pre code{{background:none;color:var(--fg);padding:0}}
  table{{border-collapse:collapse;width:100%;margin:1rem 0}}
  th,td{{padding:.55rem .75rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}}
  th{{background:var(--code-bg);color:var(--accent)}}
  hr{{border:none;border-top:1px solid var(--border);margin:2rem 0}}
</style></head><body><div class="container">
{body}
</div></body></html>
"""


# =============================================================================
#  CLI
# =============================================================================
def parse_args():
    ap = argparse.ArgumentParser(
        prog="report.py",
        description="HUGINN Report Forge — findings → submission-ready reports",
    )
    ap.add_argument("program_dir", help="workspace directory (output/<prog>_<ts>)")
    ap.add_argument("--all", action="store_true",
                    help="render every finding (default)")
    ap.add_argument("--finding", default=None,
                    help="render a single finding JSON file")
    ap.add_argument("--dashboard", action="store_true",
                    help="render the dashboard summary only")
    ap.add_argument("--index", action="store_true",
                    help="render a top-level README.md for the workspace")
    ap.add_argument("--format", default="md",
                    choices=["md", "html", "json", "all"],
                    help="output format (default: md)")
    ap.add_argument("--no-dedup", action="store_true",
                    help="do not collapse duplicate findings")
    return ap.parse_args()


def main():
    args = parse_args()
    banner()
    section("REPORT FORGE")

    formats = ("md", "html", "json") if args.format == "all" else (args.format,)

    if args.finding:
        mode = "single"
    elif args.dashboard:
        mode = "dashboard"
    elif args.index:
        mode = "index"
    else:
        mode = "all"

    generate(
        program_dir=args.program_dir,
        formats=formats,
        mode=mode,
        single_finding=args.finding,
        dedup=not args.no_dedup,
    )

    print()
    log(f"done — see {Path(args.program_dir) / 'reports'}", "ok")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
        sys.exit(130)
