from __future__ import annotations

from typing import Dict, Iterable, List


FINDING_TYPES = {
    "finding",
    "vulnerability",
    "vuln",
    "idor_suspect",
    "auth_matrix_issue",
    "nuclei",
    "secret",
    "credential",
}

HOST_TYPES = {
    "host",
    "hostname",
    "asset",
    "asset_enrichment",
}

SECRET_TYPES = {
    "secret",
    "credential",
}


def resolve_severity(entry: Dict[str, object]) -> str:
    severity = str(entry.get("severity") or "").lower()
    if severity:
        return severity
    priority = str(entry.get("priority") or "").lower()
    if priority in {"critical", "high", "medium", "low", "info"}:
        return priority
    score = entry.get("score")
    try:
        score_value = float(score)
    except (TypeError, ValueError):
        score_value = None
    if score_value is not None:
        if score_value >= 90:
            return "critical"
        if score_value >= 75:
            return "high"
        if score_value >= 50:
            return "medium"
        if score_value >= 20:
            return "low"
    return "info"


def resolve_finding_type(entry: Dict[str, object]) -> str:
    finding_type = entry.get("finding_type")
    if isinstance(finding_type, str) and finding_type:
        return finding_type
    raw_type = entry.get("type", "unknown")
    if raw_type != "finding":
        return str(raw_type)
    tags = set(entry.get("tags", []) or [])
    source = str(entry.get("source", "") or "").lower()
    if "sqli" in tags or source == "sqlmap":
        return "sql_injection"
    if "xss" in tags or source == "dalfox":
        return "xss"
    if "takeover" in tags or source == "takeover-check":
        return "subdomain_takeover"
    if "secret" in tags or source == "secrets-static":
        return "exposed_secret"
    return str(raw_type)


def is_secret(entry: Dict[str, object]) -> bool:
    finding_type = entry.get("finding_type")
    if isinstance(finding_type, str) and finding_type:
        if finding_type == "exposed_secret":
            return True
    entry_type = entry.get("type")
    if isinstance(entry_type, str) and entry_type in SECRET_TYPES:
        return True
    source = str(entry.get("source") or "").lower()
    if source == "secrets-static":
        return True
    tags = entry.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and (tag == "secret" or tag.startswith("secret")):
                return True
    return False


def is_finding(entry: Dict[str, object]) -> bool:
    if entry.get("finding_type"):
        return True
    entry_type = entry.get("type")
    if isinstance(entry_type, str) and entry_type in FINDING_TYPES:
        return True
    return False


def is_host(entry: Dict[str, object]) -> bool:
    entry_type = entry.get("type")
    if isinstance(entry_type, str) and entry_type in HOST_TYPES:
        return True
    return False


def categorize_results(
    items: Iterable[Dict[str, object]],
    include_secret_in_findings: bool = True,
) -> Dict[str, List[Dict[str, object]]]:
    results: Dict[str, List[Dict[str, object]]] = {
        "hosts": [],
        "urls": [],
        "findings": [],
        "secrets": [],
        "other": [],
    }
    for entry in items:
        if not isinstance(entry, dict):
            continue
        if is_secret(entry):
            results["secrets"].append(entry)
            if include_secret_in_findings:
                results["findings"].append(entry)
            continue
        if is_finding(entry):
            results["findings"].append(entry)
            continue
        entry_type = entry.get("type")
        if entry_type == "url":
            results["urls"].append(entry)
            continue
        if is_host(entry):
            results["hosts"].append(entry)
            continue
        results["other"].append(entry)
    return results
