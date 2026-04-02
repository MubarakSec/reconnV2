from __future__ import annotations

import hashlib
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import urljoin, urlparse

import requests

BACKUP_SUFFIXES = [
    ".bak",
    ".old",
    ".backup",
    ".zip",
    ".tar.gz",
    ".tgz",
    ".rar",
]

MIN_BACKUP_BYTES = 200

JS_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "aws_secret",
        re.compile(r"(?i)aws(.{0,4})?secret(.{0,4})?=\s*['\"]([A-Za-z0-9/+]{40})['\"]"),
    ),
    ("google_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[aboprs]-[A-Za-z0-9-]{10,48}")),
    (
        "generic_token",
        re.compile(
            r"(?i)(?:api|access|secret|token|key)[\w.-]{0,10}['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
    ),
]

USER_AGENT = "recon-cli-active/0.1"


@dataclass
class ActiveResult:
    payloads: List[Dict[str, object]]
    artifact_data: object
    artifact_name: str


def create_session(
    timeout: float = 6.0,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    verify_tls: bool = True,
) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update(cookies)
    return session


def _top_urls(
    url_entries: Sequence[Dict[str, object]], limit: int = 50, min_score: int = 10
) -> List[Dict[str, object]]:
    candidates = [
        entry
        for entry in url_entries
        if int(entry.get("score", 0) or 0) >= min_score and not entry.get("noise")  # type: ignore[call-overload]
    ]
    candidates.sort(key=lambda entry: int(entry.get("score", 0) or 0), reverse=True)  # type: ignore[return-value, call-overload]
    return candidates[:limit]


def run_backup_hunt(
    url_entries: Sequence[Dict[str, object]], session: requests.Session
) -> ActiveResult:
    candidates = _top_urls(url_entries, limit=40)
    hits: List[Dict[str, object]] = []
    findings: List[Dict[str, object]] = []
    
    # Cache for baseline hashes to avoid redundant requests
    baseline_hashes: Dict[str, str] = {}
    
    for entry in candidates:
        url = entry.get("url")
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path.endswith("/"):
            continue
            
        # Get baseline for soft-404 detection
        # 1. Random non-existent URL baseline for this host
        host_origin = f"{parsed.scheme}://{parsed.netloc}"
        if host_origin not in baseline_hashes:
            random_url = urljoin(host_origin, f"/nonexistent_{random.randint(1000, 9999)}")
            try:
                r_base = session.get(random_url, timeout=5, allow_redirects=True)
                baseline_hashes[host_origin] = hashlib.md5(r_base.text[:8192].encode()).hexdigest()
            except:
                baseline_hashes[host_origin] = "error"

        # 2. Original URL baseline
        if url not in baseline_hashes:
            try:
                r_orig = session.get(url, timeout=5, allow_redirects=True)
                baseline_hashes[url] = hashlib.md5(r_orig.text[:8192].encode()).hexdigest()
            except:
                baseline_hashes[url] = "error"

        for suffix in BACKUP_SUFFIXES:
            variant_path = f"{path}{suffix}"
            variant_url = urljoin(host_origin, variant_path)
            try:
                resp = session.get(
                    variant_url, timeout=6, allow_redirects=True, stream=True
                )
            except requests.RequestException:
                continue
            
            status = resp.status_code
            if status != 200:
                resp.close()
                continue

            headers = resp.headers
            encoding = resp.encoding or "utf-8"
            content_length = headers.get("Content-Length")
            declared_size = None
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = None
            
            preview = bytearray()
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        break
                    preview.extend(chunk)
                    if len(preview) >= 8192: # Read enough for a good hash
                        break
            finally:
                resp.close()

            length_value = declared_size if declared_size is not None else len(preview)
            
            # Soft-404 & Content Validation
            from recon_cli.utils import validation
            if not validation.is_sensible_file(
                preview, 
                variant_url, 
                content_type=headers.get("Content-Type", ""),
                original_html_hash=baseline_hashes.get(url) or baseline_hashes.get(host_origin)
            ):
                continue

            hits.append(
                {
                    "base_url": url,
                    "variant_url": variant_url,
                    "status": status,
                    "length": length_value,
                }
            )
            
            snippet = preview.decode(encoding, errors="replace")[:200] if preview else None
            
            findings.append(
                {
                    "type": "url",
                    "source": "active-backup",
                    "url": variant_url,
                    "status_code": status,
                    "length": length_value,
                    "tags": ["active", "backup", "high-risk"],
                    "score": max(85, int(entry.get("score", 0) or 0) + 20),  # type: ignore[call-overload]
                    "artifact": None,
                    "note": f"Discovered backup variant of {url}",
                    "preview": snippet,
                }
            )
    return ActiveResult(findings, hits, "backup_hits.json")


def run_cors_checks(hosts: Iterable[str], session: requests.Session) -> ActiveResult:
    results: List[Dict[str, object]] = []
    findings: List[Dict[str, object]] = []
    test_origin = f"https://{random.randint(1000, 9999)}.evil.origin"
    for host in hosts:
        target_url = f"https://{host}"
        try:
            resp = session.get(target_url, headers={"Origin": test_origin}, timeout=6)
        except requests.RequestException:
            continue
        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        allow_credentials = (
            resp.headers.get("Access-Control-Allow-Credentials", "false").lower()
            == "true"
        )
        misconfig = False
        if allow_origin == "*" and allow_credentials:
            misconfig = True
        elif allow_origin and allow_origin.lower() == test_origin.lower():
            misconfig = True

        if misconfig:
            findings.append(
                {
                    "type": "finding",
                    "source": "active-cors",
                    "hostname": host,
                    "description": "Potential CORS misconfiguration",
                    "details": {
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_credentials,
                        "status_code": resp.status_code,
                        "url": target_url,
                    },
                    "tags": ["active", "cors", "high-risk"],
                    "score": 80,
                    "priority": "high",
                }
            )
            results.append(
                {
                    "host": host,
                    "allow_origin": allow_origin,
                    "allow_credentials": allow_credentials,
                    "status": resp.status_code,
                }
            )
    return ActiveResult(findings, results, "cors_findings.json")


def run_response_diff(hosts: Sequence[str], session: requests.Session) -> ActiveResult:
    limit = min(len(hosts), 15)
    fingerprints: Dict[str, Dict[str, object]] = {}
    groups: Dict[str, List[str]] = defaultdict(list)
    for host in hosts[:limit]:
        url = f"https://{host}"
        try:
            resp = session.get(url, timeout=6)
        except requests.RequestException:
            continue
        body = resp.text[:4000]
        fp = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()
        fingerprints[host] = {
            "hash": fp,
            "status": resp.status_code,
            "length": len(body),
        }
        groups[fp].append(host)

    findings: List[Dict[str, object]] = []
    artifact = []
    for fp, group in groups.items():
        if len(group) < 2:
            continue
        reference = group[0]
        artifact.append({"hash": fp, "hosts": group})
        for host in group[1:]:
            findings.append(
                {
                    "type": "finding",
                    "source": "active-diff",
                    "hostname": host,
                    "description": "Similar response across subdomains",
                    "details": {
                        "reference": reference,
                        "matched": host,
                    },
                    "tags": ["active", "misconfiguration", "surface:duplicate"],
                    "score": 45,
                    "priority": "medium",
                }
            )
    return ActiveResult(findings, artifact, "http_diff.json")


def run_js_secret_harvest(
    url_entries: Sequence[Dict[str, object]], session: requests.Session
) -> ActiveResult:
    js_candidates = [
        entry
        for entry in url_entries
        if isinstance(entry.get("url"), str)
        and entry.get("url").lower().endswith(".js")  # type: ignore[attr-defined]
        and entry.get("status_code") in {200, 302}
    ]
    js_candidates = js_candidates[:40]
    findings: List[Dict[str, object]] = []
    artifact: List[Dict[str, object]] = []
    for entry in js_candidates:
        url = entry["url"]
        try:
            resp = session.get(url, timeout=6)  # type: ignore[arg-type]
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        text = resp.text[:200000]
        matches = []
        for name, pattern in JS_SECRET_PATTERNS:
            for match in pattern.findall(text):
                match_value = match if isinstance(match, str) else match[-1]
                match_str = str(match_value)
                match_hash = hashlib.sha256(
                    match_str.encode("utf-8", "ignore")
                ).hexdigest()[:16]
                matches.append(
                    {"type": name, "hash": match_hash, "length": len(match_str)}
                )
        if matches:
            findings.append(
                {
                    "type": "finding",
                    "source": "active-js-secrets",
                    "hostname": urlparse(url).hostname,  # type: ignore[call-overload]
                    "description": "Potential secret leaked in JavaScript",
                    "details": {"url": url, "hits": matches},
                    "tags": ["active", "secret", "high-risk"],
                    "score": max(95, int(entry.get("score", 0) or 0) + 30),  # type: ignore[call-overload]
                    "priority": "critical",
                }
            )
            artifact.append({"url": url, "matches": matches})
    return ActiveResult(findings, artifact, "js_secrets.json")


MODULE_REGISTRY = {
    "backup": run_backup_hunt,
    "cors": run_cors_checks,
    "diff": run_response_diff,
    "js-secrets": run_js_secret_harvest,
}


def available_modules() -> List[str]:
    return sorted(MODULE_REGISTRY.keys())


def execute_module(
    name: str,
    *,
    url_entries: Sequence[Dict[str, object]],
    hosts: Sequence[str],
    session: requests.Session,
) -> ActiveResult:
    handler = MODULE_REGISTRY.get(name)
    if handler is None:
        raise ValueError(f"Unknown active module: {name}")
    if handler in {run_backup_hunt, run_js_secret_harvest}:
        return handler(url_entries, session)  # type: ignore[operator]
    if handler in {run_cors_checks, run_response_diff}:
        return handler(hosts, session)  # type: ignore[operator]
    raise ValueError(f"Unhandled active module: {name}")
