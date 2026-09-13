#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  HUGINN :: path_traversal.py
#  Path / Directory Traversal Scanner — 2026 Edition
# -----------------------------------------------------------------------------
#  Injects traversal payloads into every path segment of every crawled URL
#  and inspects the response for content markers, status changes, and error
#  signatures that indicate the traversal succeeded.
#
#  Verification signals (in order of confidence):
#    confirmed : Sensitive file content matched a detection marker
#    high      : Status changed from 404/403 to 200 with a large body
#    medium    : Error message mentioning a path or directory structure
#    low       : Timing anomaly consistent with path resolution
# =============================================================================

import re
import json
import time
import shlex
import hashlib
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from huginn_utils import (
    log, section, load_json, save_json, load_payloads, send_request,
    safe_filename, C,
)


# =============================================================================
#  DETECTION MARKERS
# =============================================================================
# Content markers that prove a specific file was actually read.
FILE_MARKERS = {
    "linux_passwd": [
        re.compile(r"root:[x*]?:0:0:", re.I),
        re.compile(r"daemon:[x*]?:1:1:", re.I),
    ],
    "linux_shadow": [
        re.compile(r"root:\$[0-9a-z]+\$", re.I),
    ],
    "linux_proc_environ": [
        re.compile(r"[A-Z_]{3,}=[^\x00]+", re.M),
    ],
    "windows_ini": [
        re.compile(r"\[extensions\]", re.I),
        re.compile(r"\[fonts\]", re.I),
        re.compile(r"\[mci extensions\]", re.I),
    ],
    "windows_hosts": [
        re.compile(r"localhost\s+localhost", re.I),
        re.compile(r"# Copyright.*Microsoft", re.I),
    ],
    "php_source": [
        re.compile(r"<\?php\s", re.I),
    ],
    "aws_creds": [
        re.compile(r"aws_access_key_id", re.I),
        re.compile(r"aws_secret_access_key", re.I),
    ],
    "k8s_token": [
        re.compile(r"^eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.", re.M),
    ],
    "docker_sock": [
        re.compile(r"HTTP/1\.1\s+\d+", re.I),  # Docker HTTP socket
    ],
    "ssh_key": [
        re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    ],
}

# Error signatures that suggest path traversal reached a filesystem layer
ERROR_SIGNATURES = [
    re.compile(r"no such file or directory", re.I),
    re.compile(r"failed to open stream", re.I),
    re.compile(r"cannot find the path specified", re.I),
    re.compile(r"invalid path", re.I),
    re.compile(r"java\.io\.FileNotFoundException", re.I),
    re.compile(r"System\.IO\.DirectoryNotFoundException", re.I),
    re.compile(r"fopen\([^)]*\): (Failed|No such)", re.I),
    re.compile(r"/var/www", re.I),
    re.compile(r"/usr/local/", re.I),
    re.compile(r"C:\\\\inetpub", re.I),
]


# =============================================================================
#  HELPERS
# =============================================================================
def _get_host(url):
    return urlparse(url).netloc.lower()


def _response_snippet(body, needle, window=180):
    if not body or not needle:
        return ""
    idx = body.lower().find(needle.lower())
    if idx == -1:
        return body[:window * 2]
    return body[max(0, idx - window): idx + len(needle) + window]


def _detect_file_marker(body):
    """Return (category, marker_match) or (None, None)."""
    if not body:
        return None, None
    for category, patterns in FILE_MARKERS.items():
        for rx in patterns:
            m = rx.search(body)
            if m:
                return category, m.group(0)[:120]
    return None, None


def _detect_error(body):
    if not body:
        return None
    for rx in ERROR_SIGNATURES:
        m = rx.search(body)
        if m:
            return m.group(0)[:200]
    return None


# =============================================================================
#  INJECTION POINT
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "segment_index", "segment_value", "baseline")

    def __init__(self, url, segment_index, segment_value):
        self.url = url
        self.segment_index = segment_index
        self.segment_value = segment_value
        self.baseline = None

    def key(self):
        return (self.url, self.segment_index)

    def __repr__(self):
        return f"<PT seg[{self.segment_index}]={self.segment_value!r} @ {self.url}>"


def extract_injection_points(pages):
    points = []
    seen = set()
    for page in pages:
        url = page.get("url", "")
        if not url:
            continue
        parsed = urlparse(url)
        segs = [s for s in parsed.path.split("/") if s]
        for idx, seg in enumerate(segs):
            # Skip obviously-static segments
            if seg in ("api", "v1", "v2", "v3", "rest", "graphql",
                       "static", "assets", "public"):
                continue
            k = (url, idx)
            if k in seen:
                continue
            seen.add(k)
            points.append(InjectionPoint(url, idx, seg))
    return points


# =============================================================================
#  REQUEST BUILDER
# =============================================================================
def _build_url_with_segment(ip, payload):
    """Replace one path segment with the payload, preserving the rest."""
    parsed = urlparse(ip.url)
    segs = [s for s in parsed.path.split("/") if s]
    if ip.segment_index >= len(segs):
        return None
    segs[ip.segment_index] = payload
    new_path = "/" + "/".join(segs)
    return urlunparse(parsed._replace(path=new_path))


def build_request(ip, payload, timeout=15):
    url = _build_url_with_segment(ip, payload)
    if not url:
        return None, None
    resp = send_request(url, timeout=timeout, allow_redirects=False)
    return url, resp


def build_curl(ip, payload, timeout=15):
    url = _build_url_with_segment(ip, payload)
    if not url:
        return ""
    return f"curl -sk --max-time {timeout} -i {shlex.quote(url)}"


# =============================================================================
#  SCANNER
# =============================================================================
class PathTraversalScanner:

    def __init__(self, program_dir, sites_root=None,
                 max_workers=6, delay=0.15, timeout=15):
        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "path_traversal"
        self.findings_root.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.delay = delay
        self.timeout = timeout
        self.seen_signatures = set()
        self._payloads = None

    def load_payloads(self):
        data = load_payloads("path_traversal")
        raw = data.get("payloads", [])
        out = []
        for entry in raw:
            if isinstance(entry, str):
                out.append({"id": "raw", "name": "raw",
                            "category": "unknown", "payload": entry,
                            "tags": [], "description": ""})
                continue
            out.append(entry)
        self._payloads = out
        return out

    # ------------------------------------------------------------------ #
    #  Baseline
    # ------------------------------------------------------------------ #
    def capture_baseline(self, ip):
        _, resp = build_request(ip, ip.segment_value, timeout=self.timeout)
        ip.baseline = resp

    # ------------------------------------------------------------------ #
    #  Classification
    # ------------------------------------------------------------------ #
    def _classify(self, ip, payload_obj, resp):
        if resp is None:
            return None
        body = resp.text or ""

        # 1. File-content marker matched — very high confidence
        category, marker = _detect_file_marker(body)
        if category:
            return {
                "severity": "critical" if category in (
                    "aws_creds", "k8s_token", "ssh_key", "docker_sock",
                    "linux_shadow", "linux_proc_environ"
                ) else "high",
                "reason": f"File content matched '{category}' marker",
                "evidence": marker,
                "verification_method": "content_marker",
                "file_category": category,
            }

        # 2. Status escalation from 404/403 to 200 with meaningful body
        base_status = ip.baseline.status_code if ip.baseline else None
        if base_status in (403, 404) and resp.status_code == 200 \
                and len(body) > 100:
            return {
                "severity": "high",
                "reason": f"Status changed {base_status} -> 200 with {len(body)} bytes",
                "evidence": body[:200],
                "verification_method": "status_change",
            }

        # 3. Error signature leak
        err = _detect_error(body)
        if err and base_status == 200 and resp.status_code != 200:
            return {
                "severity": "medium",
                "reason": f"Filesystem error signature: {err}",
                "evidence": err,
                "verification_method": "error_signature",
            }

        return None

    # ------------------------------------------------------------------ #
    #  Test one point
    # ------------------------------------------------------------------ #
    def test_point(self, ip):
        self.capture_baseline(ip)
        findings = []
        for p in self._payloads:
            payload = p["payload"]
            url, resp = build_request(ip, payload, timeout=self.timeout)
            if resp is None:
                time.sleep(self.delay)
                continue
            hit = self._classify(ip, p, resp)
            if hit:
                f = self._build_finding(ip, p, hit, resp, url)
                if f:
                    findings.append(f)
            time.sleep(self.delay)
        return findings

    # ------------------------------------------------------------------ #
    #  Finding
    # ------------------------------------------------------------------ #
    def _build_finding(self, ip, payload_obj, hit, resp, url):
        finding = {
            "type": "path_traversal",
            "subtype": hit["verification_method"],
            "severity": hit["severity"],
            "confirmed": hit["verification_method"] == "content_marker",

            "url": ip.url,
            "test_url": url,
            "segment_index": ip.segment_index,
            "segment_value": ip.segment_value,

            "payload_id": payload_obj.get("id"),
            "payload_name": payload_obj.get("name"),
            "payload": payload_obj["payload"],
            "payload_category": payload_obj.get("category"),
            "payload_tags": payload_obj.get("tags", []),
            "payload_description": payload_obj.get("description", ""),

            "detection_reason": hit["reason"],
            "evidence": hit.get("evidence", ""),
            "file_category": hit.get("file_category"),

            "response_status": resp.status_code,
            "response_length": len(resp.text or ""),
            "response_snippet": (resp.text or "")[:800],
            "baseline_status": ip.baseline.status_code if ip.baseline else None,

            "curl_command": build_curl(ip, payload_obj["payload"]),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "remediation": (
                "Never pass user-controlled data to filesystem APIs. If the "
                "application must accept a path from the user, resolve it to "
                "a canonical absolute path and verify it starts with an "
                "expected base directory. Reject any input containing '..', "
                "absolute paths, or non-whitelisted characters. Use a map of "
                "logical IDs to real filenames rather than accepting paths "
                "directly."
            ),
        }

        sig = hashlib.md5(
            f"{ip.url}|{ip.segment_index}|{payload_obj.get('id')}|{hit['severity']}".encode()
        ).hexdigest()
        if sig in self.seen_signatures:
            return None
        self.seen_signatures.add(sig)

        host = _get_host(ip.url)
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_") or "_root"
        )
        fname = (f"{slug}__seg{ip.segment_index}__"
                 f"{payload_obj.get('id','x')}_path_traversal.json")
        out_path = self.findings_root / safe_filename(host) / fname
        save_json(out_path, finding)

        sev_color = {
            "critical": "\033[38;5;196m",
            "high":     "\033[38;5;208m",
            "medium":   "\033[38;5;226m",
            "low":      "\033[38;5;240m",
        }.get(hit["severity"], "\033[0m")

        log(f"[{sev_color}{hit['severity'].upper():8}\033[0m] "
            f"seg[{ip.segment_index}]={ip.segment_value!r} @ {ip.url} "
            f"→ {payload_obj.get('name')} ({hit['verification_method']})",
            "hit", "PT")
        return finding

    # ------------------------------------------------------------------ #
    #  Run
    # ------------------------------------------------------------------ #
    def run(self):
        section("PATH TRAVERSAL SCANNER :: INITIALISING")

        self.load_payloads()
        log(f"loaded {len(self._payloads)} payloads", "info")

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
        log(f"extracted {len(points)} path segment injection points", "ok")

        if not points:
            log("nothing to test", "warn")
            return []

        section("PATH TRAVERSAL SCANNER :: STRIKE PHASE")
        all_findings = []
        done, total = 0, len(points)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.test_point, ip): ip for ip in points}
            for fut in as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    all_findings.extend(fut.result())
                except Exception as e:
                    log(f"error testing {ip}: {e}", "warn")
                if done % 20 == 0 or done == total:
                    log(f"progress {done}/{total}  hits={len(all_findings)}",
                        "info")

        # Summary
        section("PATH TRAVERSAL SCANNER :: COMPLETE")
        if all_findings:
            by_sev = {}
            for f in all_findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            for s in ("critical", "high", "medium", "low"):
                if s in by_sev:
                    log(f"{s}: {by_sev[s]}", "ok")
            log(f"total findings: {len(all_findings)}", "ok", "DONE")
        else:
            log("no path traversal findings", "info", "DONE")

        save_json(self.findings_root / "_summary.json", {
            "total": len(all_findings),
            "by_severity": {s: sum(1 for f in all_findings if f["severity"] == s)
                            for s in ("critical", "high", "medium", "low")},
            "by_category": {},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [
                {"url": f["url"], "segment_index": f["segment_index"],
                 "severity": f["severity"], "subtype": f["subtype"],
                 "payload_name": f["payload_name"]}
                for f in all_findings
            ],
        })
        return all_findings


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, sites_root=None):
    return PathTraversalScanner(program_dir, sites_root).run()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: path_traversal.py <program_dir>")
        sys.exit(1)
    run(sys.argv[1])
