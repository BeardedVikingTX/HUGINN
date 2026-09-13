<!-- ======================================================================= -->
<!--  HUGINN — Security Policy                                                -->
<!--  Odin's Raven does not fall to lesser ravens.                            -->
<!-- ======================================================================= -->

**HUGINN — SECURITY POLICY**

*The raven sees all. The raven reports honestly.*

</div>

---

## HUGINN's Pledge to Researchers

> *"Cattle die, kinsmen die, the self must also die. I know one thing
> which never dies: the reputation of the honored researcher."*
> — Hávamál, stanza 77 (adapted)

We believe security research done in good faith is **a public good**, not a
threat. If you find a vulnerability in HUGINN and report it responsibly, we
will:

- **Never** threaten legal action against you for good-faith research
- **Never** demand you remain silent while we sit on a fix for months
- **Always** credit you publicly (unless you ask us not to)
- **Always** tell you honestly what we plan to do and when

This policy is our side of the bargain. Read it, verify it, hold us to it.

---

## Table of Contents

- [Scope — What We Want to Hear About](#scope--what-we-want-to-hear-about)
- [Out of Scope — What We Don't](#out-of-scope--what-we-dont)
- [How to Report](#how-to-report)
- [What to Include](#what-to-include)
- [Our Response Timeline](#our-response-timeline)
- [Disclosure Policy](#disclosure-policy)
- [Recognition — The Raven's Hall of Fame](#recognition--the-ravens-hall-of-fame)
- [Severity Guidance](#severity-guidance)
- [Supported Versions](#supported-versions)
- [Legal Safe Harbor](#legal-safe-harbor)
- [Contact](#contact)

---

## Scope — What We Want to Hear About

The following are **in scope**. If you find a vulnerability in any of these,
we genuinely want to know.

### Python Codebase

- **Remote code execution** in any scanner, orchestrator, or utility module
- **Command injection** via payloads, YAML config, or CLI arguments
- **Path traversal** in the output directory logic (`findings/`, `sites/`,
  `recon/`, `logs/`)
- **Arbitrary file write** triggered by a scanner's response to a target
- **Credential leakage** in logs, findings, or terminal output
- **SSRF** introduced by HUGINN itself (not vulnerabilities it finds)
- **Bypass of the authorization gate** in `HUGINN.py`
- **Sandbox escape** if running in a containerized deployment

### Payload Libraries (`payloads/*.yaml`)

- **Template injection** — a payload that executes during scanner's own
  substitution step rather than on the target
- **Serialization issues** — YAML that triggers unsafe loading behavior
- **Scanner-side crashes** — a well-formed YAML entry that reliably takes
  down a scanner mid-run

### Attacker Infrastructure (PHP)

- **Remote code execution** in `oast/`, `redirect/`, or any deployed PHP
- **Log injection** allowing arbitrary content into `oob.log` or
  `redirect.log` beyond what a legitimate callback would write
- **Token forgery** — generating a valid `huginn-<hex>` token without
  triggering the receiver
- **Cache poisoning** — response manipulation that could trick a scanner
  into a false `confirmed` finding

### Build & Setup

- **Supply chain** — malicious dependency injection in `setup.sh`,
  `requirements.txt`, or any build step
- **Privilege escalation** during `setup.sh` execution
- **`pc_specs.json` leakage** — collection of sensitive system data beyond
  what's documented

### Documentation

- **Paywall bypass** in any future hosted docs
- **Cross-site scripting** in the log viewer (`view.php`) beyond what a
  legitimate log entry would trigger

---

## Out of Scope — What We Don't

The following are **not** vulnerabilities in HUGINN. Please don't report them.

### Findings Produced by HUGINN

If you use HUGINN to find a bug in `target.com`, that's a bug in
`target.com`. Report it to the target's security team or bug bounty
program — not to us. We can't fix someone else's SQLi.

### Third-Party Tools

Vulnerabilities in `subfinder`, `httpx`, `katana`, `nuclei`, `amass`, or
any other tool HUGINN orchestrates should go to that project's maintainers:

- ProjectDiscovery tools → https://github.com/projectdiscovery
- OWASP Amass → https://github.com/owasp-amass/amass

### Our Own Infrastructure

**Do not scan `beardedviking.org`, `oast.beardedviking.org`,
`redirect.beardedviking.org`, or any subdomain thereof.** These are not a
bug bounty target. If you scan them, you are not conducting security
research — you are attacking infrastructure that exists solely to help
other researchers. We will treat it accordingly.

### Theoretical & Low-Impact

- Missing security headers on documentation pages
- Version disclosure in headers
- Rate limiting on the OOB receiver (it's meant to receive callbacks)
- "Clickjacking on a page that does nothing"
- Reports generated from automated scanners with no manual validation
- Findings that require the user to already have root access to the
  machine running HUGINN

### Social Engineering

- Phishing HUGINN maintainers
- Pretexting against contributors
- Impersonating HUGINN in communications with third parties

---

## How to Report

### Preferred: GitHub Private Vulnerability Reporting

Go to https://github.com/beardedviking/huginn/security/advisories/new

This creates a private advisory only visible to maintainers. It's the
fastest path and gives us a full audit trail.

### Secondary: Email

**security@beardedviking.org**

Encrypt sensitive details with our PGP key:

- **Fingerprint:** `0000 0000 0000 0000 0000  0000 0000 0000 0000 0000`
- **Download:** https://beardedviking.org/.well-known/pgp-key.asc
- **Keyserver:** `hkps://keys.openpgp.org`

*(PGP key will be published alongside the first stable release. Until
then, email in plaintext is acceptable — we'll establish encrypted
channels after first contact.)*

### Do Not

- Open a public GitHub issue
- Post to Twitter/X, Reddit, or any public forum before we've had a
  chance to respond
- Contact HUGINN users directly
- Discuss the finding with third parties before coordinated disclosure

---

## What to Include

A good report is worth a hundred vague ones. Please include:

1. **Summary** — one paragraph describing the vulnerability
2. **Impact** — what an attacker can do, and to whom
3. **Reproduction steps** — the exact commands, inputs, or files
4. **Affected versions** — from `python HUGINN.py --version` and the
   git commit hash if you're running from source
5. **Environment** — OS, Python version, relevant tool versions
6. **Proof of concept** — a minimal, self-contained PoC. Do **not**
   publish it publicly until after disclosure
7. **Suggested remediation** — optional, but appreciated
8. **Your contact info** — how to reach you, and whether you want credit
   under a pseudonym

If you can't fill every field, send what you have. A partial report
beats no report.

---

## Our Response Timeline

We commit to the following maximum times:

| Stage | Timeframe |
|-------|-----------|
| **Acknowledge receipt** | 72 hours |
| **Initial triage** (validate and assess) | 7 days |
| **Fix for critical findings** | 30 days |
| **Fix for high-severity findings** | 60 days |
| **Fix for medium-severity findings** | 90 days |
| **Public advisory** | Coordinated with you |

If we miss a deadline, we will tell you **why** and give you a revised
timeline. Silence is unacceptable and you are entitled to publish if we
go dark.

### What "Critical" Means Here

For a security tool, "critical" means:

- Remote code execution in any module
- Any bug that could cause HUGINN to attack a target the user did not
  authorize
- Any bug that leaks the user's attacker infrastructure credentials
- Any bug that allows a target to trick HUGINN into a false-confirmed
  finding

If you're unsure whether your finding qualifies, report it and let us
assess.

---

## Disclosure Policy

We practice **coordinated disclosure**:

1. You report privately
2. We acknowledge within 72 hours
3. We work with you to understand and fix the issue
4. We agree on a disclosure date — typically **when the fix is
   released**, but never more than **90 days after initial report**
5. We publish a security advisory crediting you (unless you decline)
6. You're free to publish your own write-up after the advisory goes live

We will **not** pressure you to delay disclosure. If we can't ship a fix
in 90 days, you can publish. We accept the reputational consequences.

If a vulnerability is already being actively exploited, tell us. We'll
ship an emergency fix and disclose immediately.

---

## Recognition — The Raven's Hall of Fame

Every researcher who reports a valid security issue is credited here,
unless they decline.

| Researcher | Finding | Date | Advisory |
|------------|---------|------|----------|
| *(your name here)* | *(your finding)* | *(date)* | *(link)* |

Recognition is our thank-you. We don't currently have a bug bounty
program — HUGINN is a free and open-source project — but we will:

- Credit you in the security advisory
- Credit you in the release notes
- Add you to this Hall of Fame
- Send you a personal thank-you
- Advocate for you publicly if you wish

If HUGINN ever generates revenue, a percentage will go into a
discretionary reward fund for past and future reporters.

---

## Severity Guidance

We use CVSS v3.1 as a reference, but our own judgment governs.

| Severity | Examples | Our Response |
|----------|----------|--------------|
| **Critical** | RCE, credential leak, unauthorized-target attack, false-confirmed findings | Emergency fix; advisory within 7 days of fix |
| **High** | Path traversal, auth bypass, log injection enabling downstream issues | Fix within 60 days; advisory on release |
| **Medium** | DoS on the tool itself, information disclosure of non-sensitive data | Fix within 90 days |
| **Low** | Hardening suggestions, defense-in-depth improvements | Fixed on the next regular release |

If we disagree with your severity assessment, we'll discuss it openly
and respectfully. You may always publish under your own rating.

---

## Supported Versions

| Version | Status | Security Support |
|---------|--------|------------------|
| `2.x` (current) | Active | ✅ Full support |
| `1.x` | Deprecated | ❌ No — upgrade to 2.x |
| `< 1.0` | Pre-release | ❌ No |

**Only the latest minor version of the current major release receives
security patches.** If you report an issue in an older version, we'll
ask you to reproduce against the current release.

---

## Legal Safe Harbor

**This is important. Please read carefully.**

Bearded Viking Security Forge and the HUGINN maintainers commit to the
following:

> If you conduct security research in **good faith** and in **compliance
> with this policy**, we will:
>
> 1. **Not** pursue or support any legal action against you
> 2. **Not** report you to law enforcement or your employer
> 3. **Not** file a DMCA takedown against your write-up or PoC
> 4. **Not** require you to sign an NDA as a condition of disclosing
> 5. Consider your research "authorized" for the purposes of the
>    Computer Fraud and Abuse Act (18 U.S.C. § 1030), the Computer
>    Misuse Act 1990, and equivalent legislation in your jurisdiction,
>    to the extent permitted by law
>
> "Good faith" means you:
>
> - Reported the vulnerability privately to us before public disclosure
> - Did not exploit it beyond what was necessary to demonstrate impact
> - Did not access, modify, or exfiltrate data belonging to third parties
> - Did not use the vulnerability for personal or financial gain
> - Respected the privacy of HUGINN users and their infrastructure

If legal action is taken against you by a third party based on your
good-faith research under this policy, we will publicly support you and
provide what documentation we reasonably can.

This safe harbor applies **only to vulnerabilities in HUGINN's own
codebase and infrastructure**. It does **not** authorize you to scan
`beardedviking.org` or any target you don't otherwise have permission
to test.

We follow the [disclose.io](https://disclose.io/) standard for safe
harbor language.

---

## Contact

| Purpose | Channel |
|---------|---------|
| Security vulnerability | security@beardedviking.org |
| General project questions | contact@beardedviking.org |
| Legal / licensing | legal@beardedviking.org |
| GitHub Security Advisory | https://github.com/beardedviking/huginn/security/advisories/new |

**PGP Fingerprint:**
`0000 0000 0000 0000 0000  0000 0000 0000 0000 0000`

**Response commitment:** 72 hours, always.

---

<div align="center">

*The raven flies silent until it has something worth saying.*
*Report responsibly. Disclose responsibly. Fly true.*

**— The HUGINN Maintainers**

</div>

Contact: mailto:security@beardedviking.org
Contact: https://github.com/beardedviking/huginn/security/advisories/new
Expires: 2027-09-11T00:00:00.000Z
Encryption: https://beardedviking.org/.well-known/pgp-key.asc
Acknowledgments: https://github.com/beardedviking/huginn/blob/main/SECURITY.md#recognition--the-ravens-hall-of-fame
Preferred-Languages: en
Canonical: https://beardedviking.org/.well-known/security.txt
Policy: https://github.com/beardedviking/huginn/blob/main/SECURITY.md

