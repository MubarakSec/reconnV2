from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Dict, Iterable, List
from urllib.parse import parse_qsl, urlparse


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
    "secret-validator": "secret_exposure_validator",
    "cloud-discovery": "cloud_asset_discovery",
    "cms-scan": "cms_scan",
    "nmap": "nmap_scan",
    "nmap-udp": "nmap_scan",
    "verify-findings": "verify_findings",
    "idor-validator": "idor_validator",
    "ssrf-validator": "ssrf_validator",
    "open-redirect-validator": "open_redirect_validator",
    "auth-bypass-validator": "auth_bypass_validator",
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
    "idor": "idor_validator",
    "graphql_authz": "graphql_exploit",
    "auth_matrix_issue": "auth_matrix",
    "auth_bypass": "auth_bypass_validator",
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
    "idor": "can expose unauthorized records across tenants or users",
    "graphql_authz": "can expose unauthorized cross-tenant data",
    "upload_directory_listing": "can leak uploaded sensitive files",
    "auth_matrix_issue": "indicates broken authorization boundaries",
    "auth_bypass": "indicates restricted functionality can be accessed without proper authorization",
}

POC_EXPECTED_BY_TYPE = {
    "sql_injection": "The command reports injectable parameter(s) with DB fingerprint evidence.",
    "xss": "The payload is reflected/executed in browser context or scanner confirms execution.",
    "subdomain_takeover": "Service fingerprint and DNS state indicate claimable takeover condition.",
    "open_redirect": "Response redirects to attacker-controlled destination.",
    "lfi": "Response includes local file content patterns (e.g. /etc/passwd).",
    "ssrf": "Out-of-band interaction or internal fetch evidence confirms server-side request.",
    "xxe": "XML parser expansion leads to file/interaction evidence.",
    "idor": "Changing object identifiers returns data/actions belonging to a different user.",
    "graphql_authz": "Unauthorized GraphQL query returns data across privilege boundary.",
    "exposed_secret": "Secret pattern is present in response/body and hash/metadata confirms match.",
    "upload_directory_listing": "Uploaded/accessible directory listing is exposed with sensitive content paths.",
    "auth_matrix_issue": "Cross-role access matrix shows forbidden action permitted.",
    "auth_bypass": "Forced-browse or privilege-boundary test reaches restricted content unexpectedly.",
}


def _extract_host(entry: Dict[str, object]) -> str:
    host = str(entry.get("hostname") or entry.get("host") or "").strip()
    if host:
        return host
    url = str(entry.get("url") or "").strip()
    if not url:
        return ""
    try:
        return str(urlparse(url).hostname or "").strip()
    except ValueError:
        return ""


def _is_private_host(host: str) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in {"localhost"} or host.endswith(".local")
    return ip.is_private or ip.is_loopback or ip.is_link_local


def confidence_to_score(label: str) -> float:
    mapping = {
        "low": 0.25,
        "medium": 0.55,
        "high": 0.8,
        "verified": 1.0,
    }
    return mapping.get(str(label).lower(), 0.25)


def build_finding_fingerprint(entry: Dict[str, object]) -> str:
    finding_type = resolve_finding_type(entry)
    template = str(entry.get("template_id") or entry.get("template") or entry.get("templateID") or "")
    host = _extract_host(entry).lower()
    url_value = str(entry.get("url") or entry.get("matched_at") or "")
    path = ""
    params: List[str] = []
    if url_value:
        try:
            parsed = urlparse(url_value)
            path = parsed.path or ""
            params = sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        except ValueError:
            path = ""
            params = []
    param_hint = ""
    for key in ("parameter", "param", "name"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            param_hint = value
            break
    if not param_hint:
        details = entry.get("details")
        if isinstance(details, dict):
            for key in ("parameter", "param", "name"):
                value = details.get(key)
                if isinstance(value, str) and value:
                    param_hint = value
                    break
    raw = "|".join(
        [
            finding_type,
            template,
            host,
            path,
            ",".join(sorted(params)),
            param_hint,
        ]
    )
    return f"fp_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _recency_score(entry: Dict[str, object]) -> int:
    raw_value = entry.get("timestamp") or entry.get("detected_at") or entry.get("created_at")
    if not isinstance(raw_value, str) or not raw_value.strip():
        return 0
    value = raw_value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        observed = datetime.fromisoformat(value)
    except ValueError:
        return 0
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - observed.astimezone(timezone.utc)).days
    if age_days <= 7:
        return 8
    if age_days <= 30:
        return 4
    return 0


def compute_risk_score(entry: Dict[str, object]) -> int:
    severity = resolve_severity(entry)
    severity_base = {
        "critical": 65,
        "high": 50,
        "medium": 35,
        "low": 20,
        "info": 10,
    }.get(severity, 10)

    host = _extract_host(entry)
    exposure_score = 5 if _is_private_host(host) else 15

    confidence = resolve_confidence_label(entry)
    exploitability_score = {
        "verified": 20,
        "high": 14,
        "medium": 8,
        "low": 3,
    }.get(confidence, 3)
    if has_proof(entry):
        exploitability_score += 6

    tokens = {
        str(tag).lower()
        for tag in (entry.get("tags") or [])
        if isinstance(tag, str)
    }
    context_blob = " ".join(
        [
            str(entry.get("title") or ""),
            str(entry.get("name") or ""),
            str(entry.get("url") or ""),
            str(entry.get("description") or ""),
            " ".join(sorted(tokens)),
        ]
    ).lower()
    business_terms = {"auth", "admin", "api", "payment", "account", "billing"}
    business_hits = sum(1 for term in business_terms if term in context_blob)
    business_score = min(15, business_hits * 4)
    recency = _recency_score(entry)

    total = severity_base + exposure_score + exploitability_score + business_score + recency
    return int(max(0, min(100, total)))


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

    def _key(entry: Dict[str, object]) -> tuple[int, int, int, int, int, int]:
        risk_score = compute_risk_score(entry)
        score = int(entry.get("score", 0) or 0)
        severity = resolve_severity(entry)
        priority = str(entry.get("priority") or severity)
        confidence = resolve_confidence_label(entry)
        verified = 1 if confidence == "verified" else 0
        proof = 1 if has_proof(entry) else 0
        return (
            risk_score,
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


def _proof_text(entry: Dict[str, object]) -> str:
    for key in ("proof", "evidence", "request", "response"):
        value = entry.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        return str(value)
    if is_verified_finding(entry):
        return "verified"
    return ""


def build_triage_entry(entry: Dict[str, object], *, job_id: str) -> Dict[str, object]:
    finding_type = resolve_finding_type(entry)
    severity = resolve_severity(entry)
    source = str(entry.get("source") or "")
    target = str(entry.get("url") or entry.get("hostname") or entry.get("host") or "")
    title = str(entry.get("title") or entry.get("name") or entry.get("description") or finding_type)
    confidence = resolve_confidence_label(entry)
    proof = _proof_text(entry)
    repro_cmd = str(entry.get("repro_cmd") or "").strip() or build_finding_rerun_command(job_id, entry)
    hostname = str(entry.get("hostname") or entry.get("host") or "")
    endpoint = str(entry.get("url") or "")
    auth_requirement = _infer_auth_requirement(entry)
    environment = _infer_environment(hostname, endpoint)
    impact_hypothesis = IMPACT_HINTS.get(finding_type, "can expose additional attack surface and business risk")
    raw_id = "|".join(
        [
            str(job_id),
            finding_type,
            source,
            target,
            title,
        ]
    )
    finding_id = f"fnd_{hashlib.sha1(raw_id.encode('utf-8')).hexdigest()[:12]}"
    tags = entry.get("tags")
    if not isinstance(tags, list):
        tags = []
    return {
        "finding_id": finding_id,
        "job_id": job_id,
        "severity": severity,
        "confidence": confidence,
        "finding_type": finding_type,
        "title": title,
        "target": target,
        "source": source,
        "risk_score": compute_risk_score(entry),
        "proof": proof,
        "repro_cmd": repro_cmd,
        "poc_steps": [
            {
                "command": repro_cmd,
                "expected_success": POC_EXPECTED_BY_TYPE.get(
                    finding_type,
                    "The command reproduces the behavior and yields evidence aligned with the finding.",
                ),
            }
        ],
        "asset_context": {
            "host": hostname,
            "endpoint": endpoint,
            "auth_requirement": auth_requirement,
            "environment": environment,
        },
        "impact_hypothesis": impact_hypothesis,
        "submission_summary": build_submission_summary(entry),
        "tags": [str(tag) for tag in tags if isinstance(tag, str)],
    }


def _infer_auth_requirement(entry: Dict[str, object]) -> str:
    tags = {
        str(tag).strip().lower()
        for tag in (entry.get("tags") or [])
        if isinstance(tag, str)
    }
    if any(token in tags for token in {"auth", "authenticated", "admin", "privileged"}):
        return "likely_required"
    url = str(entry.get("url") or "").lower()
    if any(token in url for token in ("/admin", "/account", "/settings", "/profile", "/api/private")):
        return "likely_required"
    if any(token in tags for token in {"public", "unauthenticated"}):
        return "public"
    return "unknown"


def _infer_environment(hostname: str, endpoint: str) -> str:
    value = f"{hostname} {endpoint}".lower()
    if any(token in value for token in ("staging", "stage.", "dev.", "test.", "qa.")):
        return "non_prod"
    if value:
        return "prod_or_unknown"
    return "unknown"


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
