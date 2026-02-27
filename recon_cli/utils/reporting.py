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

FINDING_STAGE_BY_SOURCE = {
    "dalfox": "vuln_scan",
    "sqlmap": "vuln_scan",
    "waf-probe": "waf_probe",
    "security-headers": "security_headers",
    "tls-hygiene": "tls_hygiene",
    "takeover-check": "takeover_check",
    "upload-probe": "upload_probe",
    "secrets-static": "secrets_detection",
    "extended-validation": "extended_validation",
    "graphql-exploit": "graphql_exploit",
    "auth-matrix": "auth_matrix",
    "idor-stage": "idor_probe",
    "cloud-discovery": "cloud_asset_discovery",
    "cms-scan": "cms_scan",
    "nmap": "nmap_scan",
    "nmap-udp": "nmap_scan",
    "verify-findings": "verify_findings",
}

FINDING_STAGE_BY_TYPE = {
    "xss": "vuln_scan",
    "sql_injection": "vuln_scan",
    "waf_detected": "waf_probe",
    "waf_bypass_possible": "waf_probe",
    "security_headers": "security_headers",
    "tls_hygiene": "tls_hygiene",
    "subdomain_takeover": "takeover_check",
    "upload_directory_listing": "upload_probe",
    "exposed_secret": "secrets_detection",
    "open_redirect": "extended_validation",
    "lfi": "extended_validation",
    "ssrf": "extended_validation",
    "xxe": "extended_validation",
    "graphql_authz": "graphql_exploit",
    "auth_matrix_issue": "auth_matrix",
    "cloud_asset_public": "cloud_asset_discovery",
    "cms": "cms_scan",
}

IMPACT_HINTS = {
    "sql_injection": "can expose or modify backend data",
    "xss": "may enable account takeover through browser-side script execution",
    "subdomain_takeover": "can enable hostile content hosting on a trusted domain",
    "exposed_secret": "can lead to credential abuse and further compromise",
    "open_redirect": "can support phishing and token theft chains",
    "lfi": "can expose sensitive files and runtime secrets",
    "ssrf": "can reach internal services not exposed publicly",
    "xxe": "can expose local files or internal network resources",
    "graphql_authz": "can expose unauthorized cross-tenant data",
    "upload_directory_listing": "can leak uploaded sensitive files",
    "auth_matrix_issue": "indicates broken authorization boundaries",
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


def resolve_confidence_label(entry: Dict[str, object]) -> str:
    label = entry.get("confidence_label")
    if isinstance(label, str) and label:
        return label.lower()

    if entry.get("verified") is True:
        return "verified"

    tags = entry.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if not isinstance(tag, str):
                continue
            lower = tag.lower()
            if lower == "confirmed" or lower == "verified:live" or lower.endswith(":confirmed"):
                return "verified"

    source = str(entry.get("source") or "").lower()
    if source in {"extended-validation", "exploit-validation"}:
        return "verified"

    confidence = entry.get("confidence")
    if confidence is not None:
        try:
            value = float(confidence)
        except (TypeError, ValueError):
            value = None
        if value is not None:
            if value >= 0.85:
                return "high"
            if value >= 0.6:
                return "medium"
            return "low"

    severity = resolve_severity(entry)
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def is_verified_finding(entry: Dict[str, object]) -> bool:
    return resolve_confidence_label(entry) == "verified"


def has_proof(entry: Dict[str, object]) -> bool:
    if is_verified_finding(entry):
        return True
    for key in ("evidence", "proof", "repro_cmd", "request", "response"):
        if entry.get(key):
            return True
    return False


def rank_findings(
    items: Iterable[Dict[str, object]],
    *,
    limit: int | None = None,
) -> List[Dict[str, object]]:
    priority_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    confidence_order = {"low": 0, "medium": 1, "high": 2, "verified": 3}

    def _priority_rank(value: object) -> int:
        if not isinstance(value, str):
            return -1
        return priority_order.get(value.lower(), -1)

    def _confidence_rank(value: object) -> int:
        if not isinstance(value, str):
            return -1
        return confidence_order.get(value.lower(), -1)

    def _key(entry: Dict[str, object]) -> tuple[int, int, int, int, int]:
        score = int(entry.get("score", 0) or 0)
        severity = resolve_severity(entry)
        priority = str(entry.get("priority") or severity)
        confidence = resolve_confidence_label(entry)
        verified = 1 if confidence == "verified" else 0
        proof = 1 if has_proof(entry) else 0
        return (
            verified,
            proof,
            _confidence_rank(confidence),
            score,
            _priority_rank(priority),
        )

    ranked = sorted([entry for entry in items if isinstance(entry, dict)], key=_key, reverse=True)
    if limit is not None:
        return ranked[:limit]
    return ranked


def filter_findings(
    items: Iterable[Dict[str, object]],
    *,
    verified_only: bool = False,
    proof_required: bool = False,
) -> List[Dict[str, object]]:
    filtered: List[Dict[str, object]] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        if verified_only and not is_verified_finding(entry):
            continue
        if proof_required and not has_proof(entry):
            continue
        filtered.append(entry)
    return filtered


def infer_replay_stage(entry: Dict[str, object]) -> str | None:
    source = str(entry.get("source") or "").lower()
    if source in FINDING_STAGE_BY_SOURCE:
        return FINDING_STAGE_BY_SOURCE[source]
    finding_type = str(entry.get("finding_type") or "").lower()
    if finding_type in FINDING_STAGE_BY_TYPE:
        return FINDING_STAGE_BY_TYPE[finding_type]
    return None


def build_finding_rerun_command(job_id: str, entry: Dict[str, object]) -> str:
    stage = infer_replay_stage(entry)
    if stage:
        return f"recon-cli rerun {job_id} --stages {stage} --keep-results"
    return f"recon-cli rerun {job_id} --restart"


def build_submission_summary(entry: Dict[str, object]) -> str:
    severity = resolve_severity(entry).upper()
    finding_type = resolve_finding_type(entry)
    finding_label = finding_type.replace("_", " ")
    target = entry.get("url") or entry.get("hostname") or entry.get("host") or "target"
    confidence = resolve_confidence_label(entry)
    impact = IMPACT_HINTS.get(finding_type, "can expose additional attack surface and business risk")
    title = str(entry.get("title") or entry.get("name") or "").strip()
    title_fragment = f"{title}: " if title else ""
    return (
        f"{title_fragment}{severity} {finding_label} on {target}; "
        f"confidence={confidence}; impact={impact}."
    )


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
