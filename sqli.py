#!/usr/bin/env python3
# =============================================================================
#  HUGINN :: sqli.py
#  SQL Injection Scanner — payload-injection + response forensics engine
# -----------------------------------------------------------------------------
#  Strategy:
#    1. Load the enriched payloads/sqli.yaml (150+ objects, filtered by WAF/DBMS)
#    2. Extract EVERY plausible injection point per page:
#         · URL query params
#         · POST form fields (HTML <form>)
#         · JSON body fields (recursive)
#         · Cookies
#         · High-signal headers (Referer, User-Agent, X-Forwarded-For, ...)
#    3. Baseline the un-injected response for each injection point
#    4. Inject each payload; classify by:
#         · DBMS error signatures (regex bank)
#         · Response status changes (200 -> 500)
#         · Response length deltas
#         · Time delays (for SLEEP/pg_sleep/WAITFOR payloads)
#    5. Persist every hit as a fully-described JSON finding
# =============================================================================

import re
import time
import json
import hashlib
from pathlib import Path
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, load_json, save_json, load_payloads, send_request,
    safe_filename, C,
)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# =============================================================================
#  ERROR SIGNATURE BANK
#  Every DBMS message that suggests raw SQL reached the engine unescaped.
# =============================================================================
ERROR_SIGNATURES = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Zend_Db_Adapter_Mysqli_Exception",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"You have an error in your SQL syntax",
        r"MySqlException",
        r"MySQLSyntaxErrorException",
        r"mysqli_",
        r"MariaDB server version",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR: parser: parse error at or near",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"unterminated quoted string at or near",
    ],
    "mssql": [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"macromedia\.jdbc\.sqlserver",
        r"com\.jnetdirect\.jsql",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"System\.Data\.SqlClient\.SqlException",
        r"mssql_query\(\)",
    ],
    "oracle": [
        r"\bORA-[0-9]{4,5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"ORA-00933",
        r"ORA-01756",
        r"ORA-00911",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError:",
        r"sqlite3\.ProgrammingError:",
        r"SQLite3::SQLException",
        r"org\.sqlite\.JDBC",
    ],
    "sybase": [
        r"Sybase message",
        r"Sybase.*Server message",
        r"SybSQLException",
        r"com\.sybase\.jdbc",
    ],
    "db2": [
        r"DB2 SQL error",
        r"CLI Driver.*DB2",
        r"com\.ibm\.db2",
    ],
    "informix": [
        r"Informix ODBC Driver",
        r"com\.informix\.jdbc",
        r"ODBC Informix driver",
    ],
    "ingres": [
        r"Ingres SQLSTATE",
        r"Ingres\W.*Driver",
    ],
    "access": [
        r"JET Database Engine",
        r"Access Database Engine",
        r"Microsoft Access Driver",
        r"Syntax error.*in query expression",
    ],
    "generic": [
        r"SQL command not properly ended",
        r"syntax error at or near",
        r"Unclosed quotation mark",
        r"Unterminated string literal",
        r"invalid query",
        r"Dynamic SQL Error",
        r"Syntax error in string in query expression",
    ],
}

# Flatten for fast "any hit" scanning
ALL_SIGNATURES = [(dbms, re.compile(sig, re.I))
                  for dbms, sigs in ERROR_SIGNATURES.items()
                  for sig in sigs]

# Additional hints that a 500 is SQL-caused even without a DBMS string
GENERIC_500_HINTS = re.compile(
    r"(sql|query|database|odbc|jdbc|driver|syntax|column|table)", re.I
)

# Payload substrings that imply time-based testing
TIME_PAYLOADS = re.compile(
    r"(sleep|pg_sleep|waitfor\s+delay|benchmark|dbms_lock\.sleep)", re.I
)


# =============================================================================
#  INJECTION POINT MODEL
# =============================================================================
class InjectionPoint:
    """One fuzzable location on one page."""
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "extra_headers", "form_data", "json_body",
                 "content_type", "baseline")

    def __init__(self, url, method, location, name, value,
                 json_path=None, extra_headers=None,
                 form_data=None, json_body=None, content_type=None):
        self.url = url
        self.method = method
        self.location = location       # query | body_form | body_json | cookie | header
        self.name = name
        self.value = value
        self.json_path = json_path     # for body_json
        self.extra_headers = extra_headers or {}
        self.form_data = form_data or {}
        self.json_body = json_body
        self.content_type = content_type
        self.baseline = None

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        return f"<IP {self.location}:{self.name} @ {self.method} {self.url}>"


# =============================================================================
#  INJECTION POINT EXTRACTION
# =============================================================================
def _extract_query_params(page):
    url = page["url"]
    parsed = urlparse(url)
    if not parsed.query:
        return []
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return [InjectionPoint(url, "GET", "query", k, v[0])
            for k, v in qs.items()]


def _extract_from_html(page):
    """Parse HTML for forms (POST bodies) and cookies."""
    if BeautifulSoup is None:
        return [], []
    url = page["url"]
    html = page.get("content") or ""
    if not html:
        return [], []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return [], []

    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or url
        action_url = urljoin(url, action)
        method = (form.get("method") or "GET").upper()
        # gather named fields
        data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            if inp.has_attr("type") and inp["type"].lower() in ("submit", "button", "file"):
                continue
            value = inp.get("value") or ""
            data[name] = value
        if not data:
            continue
        for name, value in data.items():
            forms.append(InjectionPoint(
                action_url, method, "body_form", name, value,
                form_data=dict(data),
                content_type="application/x-www-form-urlencoded",
            ))

    # cookies set on the page (rare, but occasionally reflected)
    cookies = []
    for c in soup.find_all("input", {"type": "hidden"}):
        # hidden inputs are already covered as form fields
        pass
    return forms, cookies


def _extract_from_headers(page):
    """High-signal headers worth fuzzing (server-side trusted values)."""
    target_headers = [
        "Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Client-IP", "Forwarded", "Origin",
    ]
    return [InjectionPoint(page["url"], "GET", "header", h, "")
            for h in target_headers]


def _extract_from_cookies(page):
    """Pull cookies from the stored response headers."""
    headers = page.get("headers") or {}
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not set_cookie:
        return []
    cookies = []
    # very simple Set-Cookie parsing — good enough for fuzzing
    for chunk in set_cookie.split(","):
        m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
        if m:
            cookies.append(InjectionPoint(
                page["url"], "GET", "cookie", m.group(1).strip(), m.group(2).strip()
            ))
    return cookies


def _extract_from_json_body(page):
    """If the stored page is JSON, walk it and register every scalar leaf."""
    ct = (page.get("content_type") or "").lower()
    if "json" not in ct and not (page.get("content") or "").lstrip().startswith(("{", "[")):
        return []
    try:
        body = json.loads(page["content"])
    except Exception:
        return []

    points = []

    def walk(obj, path="$"):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")
        else:
            points.append(InjectionPoint(
                page["url"], "POST", "body_json",
                path, str(obj), json_path=path,
                json_body=json.loads(page["content"]),
                content_type="application/json",
            ))

    walk(body)
    return points


def extract_injection_points(pages):
    """Turn every crawled page into a flat list of InjectionPoints."""
    points = []
    seen = set()
    for page in pages:
        candidates = []
        candidates.extend(_extract_query_params(page))
        forms, _ = _extract_from_html(page)
        candidates.extend(forms)
        candidates.extend(_extract_from_headers(page))
        candidates.extend(_extract_from_cookies(page))
        candidates.extend(_extract_from_json_body(page))

        for ip in candidates:
            k = ip.key()
            if k in seen:
                continue
            seen.add(k)
            points.append(ip)
    return points


# =============================================================================
#  REQUEST BUILDER
#  Given an InjectionPoint + a payload, construct the outgoing request.
# =============================================================================
def build_request(ip, payload, timeout=12):
    """Send the injected request for the given point."""
    headers = dict(ip.extra_headers)
    url = ip.url
    data = None

    if ip.location == "query":
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))

    elif ip.location == "body_form":
        body = dict(ip.form_data)
        body[ip.name] = payload
        data = body
        headers["Content-Type"] = ip.content_type or "application/x-www-form-urlencoded"

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))  # deep copy
        # navigate json_path
        _set_json_path(body, ip.json_path, payload)
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"

    elif ip.location == "cookie":
        existing = headers.get("Cookie", "")
        pair = f"{ip.name}={payload}"
        headers["Cookie"] = f"{existing}; {pair}".strip("; ") if existing else pair

    elif ip.location == "header":
        headers[ip.name] = payload

    return send_request(
        url, method=ip.method, headers=headers,
        timeout=timeout, allow_redirects=False, data=data,
    )


def _set_json_path(obj, path, value):
    """Navigate a JSON pointer-ish path and set the leaf."""
    # supports "$.a.b[0].c"
    tokens = re.findall(r"\.([^\.\[\]]+)|\[(\d+)\]", path)
    cur = obj
    for i, (name, idx) in enumerate(tokens):
        key = name if name else int(idx)
        if i == len(tokens) - 1:
            cur[key] = value
            return
        cur = cur[key]


# =============================================================================
#  DETECTION LOGIC
# =============================================================================
def _match_error_signature(body):
    """Return (dbms, matched_snippet) or (None, None)."""
    if not body:
        return None, None
    for dbms, regex in ALL_SIGNATURES:
        m = regex.search(body)
        if m:
            start = max(0, m.start() - 80)
            end = min(len(body), m.end() + 200)
            return dbms, body[start:end]
    return None, None


def _classify_hit(baseline, resp, payload):
    """
    Decide if this response constitutes a SQLi finding.
    Returns dict with {confidence, reason, dbms, evidence} or None.
    """
    if resp is None:
        return None

    body = resp.text or ""
    dbms, evidence = _match_error_signature(body)

    # --- 1. DBMS error signature (highest confidence) -----------------------
    if dbms and evidence:
        return {
            "confidence": "high",
            "reason": f"DBMS error signature matched ({dbms})",
            "dbms": dbms,
            "evidence": evidence,
            "status": resp.status_code,
            "length": len(body),
        }

    # --- 2. Status escalation (200 -> 500) ----------------------------------
    if baseline and baseline.status_code < 500 and resp.status_code >= 500:
        if GENERIC_500_HINTS.search(body):
            return {
                "confidence": "medium",
                "reason": "Status escalation 2xx/3xx -> 5xx with SQL-ish body content",
                "dbms": None,
                "evidence": body[:400],
                "status": resp.status_code,
                "length": len(body),
            }

    # --- 3. Time-based detection (only if payload implies it) ---------------
    if baseline and TIME_PAYLOADS.search(payload):
        # measure elapsed on the actual send (see caller) — handled there
        pass

    return None


def _dedup_signature(finding):
    """Same URL+param+dbms+matched-signature shouldn't be reported twice."""
    h = hashlib.md5(
        f"{finding['url']}|{finding['parameter']}|{finding.get('matched_dbms')}"
        f"|{finding.get('matched_signature','')[:40]}".encode()
    ).hexdigest()
    return h


# =============================================================================
#  SCANNER
# =============================================================================
class SQLiScanner:

    def __init__(self, program_dir, sites_root=None,
                 max_workers=8, delay=0.15, timeout=12,
                 waf_hint=None, dbms_hint=None):
        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "sqli"
        self.findings_root.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self.delay = delay
        self.timeout = timeout
        self.waf_hint = waf_hint
        self.dbms_hint = dbms_hint
        self.seen_signatures = set()
        self._payload_cache = None

    # ------------------------------------------------------------------ #
    #  Payload loading & filtering
    # ------------------------------------------------------------------ #
    def load_and_filter_payloads(self):
        data = load_payloads("sqli")
        raw = data.get("payloads", [])
        filtered = []

        for entry in raw:
            if isinstance(entry, str):
                filtered.append({
                    "id": "raw", "name": "raw", "category": "unknown",
                    "dbms": "generic", "waf": None,
                    "payload": entry, "tags": [], "description": "",
                })
                continue

            # WAF filter — drop payloads targeting a DIFFERENT WAF
            entry_waf = entry.get("waf")
            if self.waf_hint and entry_waf:
                if self.waf_hint.lower() not in entry_waf.lower():
                    continue

            # DBMS filter — drop payloads for a different DBMS
            entry_dbms = (entry.get("dbms") or "all").lower()
            if self.dbms_hint and entry_dbms not in ("all", "generic"):
                if self.dbms_hint.lower() not in entry_dbms:
                    continue

            filtered.append(entry)

        self._payload_cache = filtered
        return filtered

    # ------------------------------------------------------------------ #
    #  Baseline
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        try:
            ip.baseline = build_request(ip, ip.value, timeout=self.timeout)
        except Exception:
            ip.baseline = None
        return ip.baseline

    # ------------------------------------------------------------------ #
    #  Test one payload against one injection point
    # ------------------------------------------------------------------ #
    def test_payload(self, ip, payload_obj):
        payload = payload_obj["payload"]
        is_time_payload = bool(TIME_PAYLOADS.search(payload))

        start = time.time()
        try:
            resp = build_request(ip, payload, timeout=self.timeout)
        except Exception:
            return None
        elapsed = time.time() - start
        if resp is None:
            return None

        hit = _classify_hit(ip.baseline, resp, payload)

        # time-based detection — appended if the payload is time-based
        if not hit and is_time_payload and elapsed >= 4.0:
            hit = {
                "confidence": "medium",
                "reason": f"Time-based delay detected ({elapsed:.2f}s)",
                "dbms": self.dbms_hint,
                "evidence": f"Elapsed {elapsed:.2f}s for time-based payload",
                "status": resp.status_code,
                "length": len(resp.text or ""),
            }

        if not hit:
            return None

        # -- build the finding record -------------------------------------
        finding = {
            "type": "sqli",
            "subtype": "error_based" if "signature" in hit["reason"].lower()
                       else ("time_based" if "time" in hit["reason"].lower()
                             else "anomaly"),
            "confidence": hit["confidence"],
            "url": ip.url,
            "method": ip.method,
            "injection_point": {
                "location": ip.location,
                "name": ip.name,
                "original_value_preview": ip.value[:60],
                "json_path": ip.json_path,
            },
            "parameter": ip.name,
            "payload_id": payload_obj.get("id"),
            "payload_name": payload_obj.get("name"),
            "payload": payload,
            "payload_category": payload_obj.get("category"),
            "payload_tags": payload_obj.get("tags", []),
            "payload_description": payload_obj.get("description", ""),
            "matched_dbms": hit.get("dbms"),
            "matched_signature": hit["reason"],
            "evidence_snippet": hit["evidence"],
            "response_status": resp.status_code,
            "response_length": hit["length"],
            "baseline_status": ip.baseline.status_code if ip.baseline else None,
            "baseline_length": len(ip.baseline.text) if ip.baseline else None,
            "elapsed_seconds": round(elapsed, 3),
            "test_url": ip.url,
            "test_headers": dict(ip.extra_headers),
            "test_body": ip.form_data if ip.location == "body_form" else (
                ip.json_body if ip.location == "body_json" else None),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Use parameterized queries / prepared statements. Never "
                "concatenate user input into SQL. Apply least-privilege DB "
                "accounts. Validate and whitelist input server-side."
            ),
        }

        sig = _dedup_signature(finding)
        if sig in self.seen_signatures:
            return None
        self.seen_signatures.add(sig)

        # -- persist ------------------------------------------------------
        host = urlparse(ip.url).netloc
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_") + "__" + ip.name
        )
        out_path = self.findings_root / safe_filename(host) / f"{slug}.json"
        save_json(out_path, finding)

        log(
            f"[{finding['confidence'].upper()}] {ip.location}:{ip.name} "
            f"@ {ip.url}  ({finding['payload_name']})",
            "hit", "SQLI"
        )
        return finding

    # ------------------------------------------------------------------ #
    #  Test one injection point across all payloads
    # ------------------------------------------------------------------ #
    def test_point(self, ip, payloads):
        self.capture_baseline(ip)
        findings = []
        for p in payloads:
            f = self.test_payload(ip, p)
            if f:
                findings.append(f)
                break  # one solid hit per injection point is enough
            time.sleep(self.delay)
        return findings

    # ------------------------------------------------------------------ #
    #  Main entry
    # ------------------------------------------------------------------ #
    def run(self):
        section("SQLi SCANNER :: INITIALISING")

        payloads = self.load_and_filter_payloads()
        log(f"loaded {len(payloads)} payloads "
            f"(waf={self.waf_hint or 'none'}, dbms={self.dbms_hint or 'none'})",
            "info")

        pages = []
        for jf in self.sites_root.rglob("*.json"):
            if jf.name.startswith("_"):
                continue
            try:
                rec = load_json(jf)
                if rec.get("url"):
                    pages.append(rec)
            except Exception:
                continue

        log(f"loaded {len(pages)} crawled pages", "info")

        points = extract_injection_points(pages)
        log(f"extracted {len(points)} injection points", "ok")

        if not points:
            log("nothing to test", "warn")
            return []

        section("SQLi SCANNER :: STRIKE PHASE")
        all_findings = []
        done = 0
        total = len(points)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.test_point, ip, payloads): ip
                       for ip in points}
            for fut in as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    hits = fut.result()
                    all_findings.extend(hits)
                except Exception as e:
                    log(f"error testing {ip}: {e}", "warn")
                if done % 10 == 0 or done == total:
                    log(f"progress {done}/{total}  hits={len(all_findings)}",
                        "info")

        # summary
        section("SQLi SCANNER :: COMPLETE")
        if all_findings:
            by_conf = {}
            for f in all_findings:
                by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
            for c in ("high", "medium", "low"):
                if c in by_conf:
                    log(f"{c}: {by_conf[c]}", "ok")
            log(f"total findings: {len(all_findings)}", "ok", "DONE")
        else:
            log("no SQLi findings", "info", "DONE")

        save_json(self.findings_root / "_summary.json", {
            "total": len(all_findings),
            "by_confidence": {c: sum(1 for f in all_findings if f["confidence"] == c)
                              for c in ("high", "medium", "low")},
            "waf_hint": self.waf_hint,
            "dbms_hint": self.dbms_hint,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [f["test_url"] + " :: " + f["parameter"]
                         for f in all_findings],
        })

        return all_findings


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None, waf_hint=None, dbms_hint=None):
    scanner = SQLiScanner(
        program_dir=program_dir,
        sites_root=sites_root,
        waf_hint=waf_hint,
        dbms_hint=dbms_hint,
    )
    return scanner.run()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: sqli.py <program_dir> [waf_hint] [dbms_hint]")
        sys.exit(1)
    waf = sys.argv[2] if len(sys.argv) > 2 else None
    dbms = sys.argv[3] if len(sys.argv) > 3 else None
    run(sys.argv[1], waf_hint=waf, dbms_hint=dbms)
