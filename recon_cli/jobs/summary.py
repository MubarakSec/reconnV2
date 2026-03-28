from __future__ import annotations

import os
from datetime import datetime

from collections import Counter
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from recon_cli.jobs.manager import JobManager

from recon_cli.utils.jsonl import iter_jsonl


SUMMARY_TOP = int(os.environ.get("RECON_SUMMARY_TOP", 50))
STAGE_HEALTH_SIGNALS = {
    "api_recon": ("api_spec_auth_required", "api_spec_auth_challenge"),
    "graphql_recon": ("graphql_detected", "graphql_introspection_enabled"),
    "graphql_exploit": ("graphql_sensitive_schema", "graphql_query_enabled"),
    "api_schema_probe": (
        "api_schema_endpoint",
        "api_auth_required",
        "api_auth_weak",
        "api_auth_challenge",
        "api_public_endpoint",
    ),
    "oauth_discovery": (
        "oidc_config",
        "oauth_config",
        "oauth_authorize_endpoint",
        "oauth_token_endpoint",
    ),
    "ws_grpc_discovery": ("ws_detected", "ws_candidate", "grpc_detected"),
    "upload_probe": ("upload_surface", "upload_dir_exposed"),
    "vhost_discovery": ("vhost_found",),
    "subdomain_permute": ("subdomain_permuted",),
    "cloud_asset_discovery": ("cloud_asset_public", "cloud_asset_exists"),
    "ct_asn_pivot": ("ct_discovery", "asn_prefix"),
    "html_form_mining": ("form_discovered",),
    "cms_scan": ("cms_drupal", "cms_joomla", "cms_magento", "cms_module_discovered"),
    "exploit_validation": ("poc_validated", "poc_failed"),
    "extended_validation": (
        "ssrf_confirmed",
        "xxe_confirmed",
        "open_redirect_confirmed",
        "lfi_confirmed",
    ),
}


def _is_confirmed(entry: dict) -> bool:
    tags = entry.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if tag == "confirmed" or str(tag).endswith(":confirmed"):
                return True
    source = entry.get("source")
    if isinstance(source, str) and source in {
        "extended-validation",
        "exploit-validation",
        "ssrf-validator",
        "open-redirect-validator",
        "idor-validator",
        "input-validator",
    }:
        return True
    return False


def _priority_rank(value: object) -> int:
    order = {"noise": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if not isinstance(value, str):
        return -1
    return order.get(value.lower(), -1)


def _ranking_key(entry: dict) -> tuple[int, int, int, int]:
    tags_raw = entry.get("tags", [])
    tags = (
        {str(tag).lower() for tag in tags_raw} if isinstance(tags_raw, list) else set()
    )
    confirmed = 1 if _is_confirmed(entry) else 0
    non_repetitive = 0 if "auth:repetitive" in tags else 1
    score = int(entry.get("score", 0) or 0)
    return (confirmed, non_repetitive, score, _priority_rank(entry.get("priority")))


def generate_summary_data(record, prev_record=None) -> Dict[str, Any]:
    from recon_cli.utils.reporting import is_finding, resolve_confidence_label, build_finding_fingerprint

    results_path = record.paths.results_jsonl
    trimmed_path = record.paths.trimmed_results_jsonl
    summary_path = results_path
    if trimmed_path.exists() and trimmed_path.stat().st_size > 0:
        summary_path = trimmed_path

    # Previous results fingerprinting for diff
    prev_fingerprints = set()
    if prev_record:
        prev_results_path = prev_record.paths.results_jsonl
        if prev_results_path.exists():
            for entry in iter_jsonl(prev_results_path):
                etype = entry.get("type")
                if is_finding(entry):
                    prev_fingerprints.add(build_finding_fingerprint(entry))
                elif etype == "url":
                    prev_fingerprints.add(f"url_{entry.get('url')}")
                elif etype in {"host", "hostname", "asset"}:
                    host = entry.get("hostname") or entry.get("host")
                    if host: prev_fingerprints.add(f"host_{host}")

    counts: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    priority_counter: Counter[str] = Counter()
    signal_counter: Counter[str] = Counter()
    noise_count = 0
    findings_total = 0
    verified_count = 0
    new_findings_count = 0
    new_urls_count = 0
    top_candidates: List[dict] = []
    top_urls: List[dict] = []
    top_findings: List[dict] = []

    for entry in iter_jsonl(results_path):
        etype = entry.get("type", "unknown")
        counts[etype] += 1
        
        is_fnd = is_finding(entry)
        is_new = False
        if is_fnd:
            findings_total += 1
            if resolve_confidence_label(entry) == "verified":
                verified_count += 1
            if prev_record:
                fp = build_finding_fingerprint(entry)
                if fp not in prev_fingerprints:
                    is_new = True
                    new_findings_count += 1
        
        if etype == "signal":
            signal_type = entry.get("signal_type")
            if signal_type:
                signal_counter[str(signal_type)] += 1
        elif etype == "url":
            score = int(entry.get("score", 0))
            status = entry.get("status_code")
            if status:
                status_counter[str(status)] += 1
            
            if prev_record:
                if f"url_{entry.get('url')}" not in prev_fingerprints:
                    is_new = True
                    new_urls_count += 1

            tags = set(entry.get("tags", []))
            if "noise" in tags or score < 75:
                noise_count += 1
                continue
            priority = entry.get("priority") or "unknown"
            priority_counter[priority] += 1
        elif etype == "asset_enrichment":
            tags = entry.get("tags", [])
            if tags:
                priority_counter["enriched_hosts"] += 1
        elif etype in {"finding", "idor_suspect", "idor_candidate"}:
            priority = entry.get("priority") or "unknown"
            priority_counter[priority] += 1
        
        if is_new:
            entry["is_new_result"] = True

    for entry in iter_jsonl(summary_path):
        etype = entry.get("type", "unknown")
        score = int(entry.get("score", 0))

        # Carry over the is_new_result flag if it was set in the first pass
        is_new = entry.get("is_new_result", False)
        if not is_new and prev_record:
            if is_finding(entry):
                is_new = build_finding_fingerprint(entry) not in prev_fingerprints
            elif etype == "url":
                is_new = f"url_{entry.get('url')}" not in prev_fingerprints

        if etype == "url":
            if score < 75:
                continue
            tags = set(entry.get("tags", []))
            if "noise" in tags:
                continue
            priority = entry.get("priority") or "unknown"
            payload = entry | {"score": score, "priority": priority, "is_new_result": is_new}
            top_candidates.append(payload)
            top_urls.append(payload)
        elif etype in {"finding", "idor_suspect", "idor_candidate"}:
            priority = entry.get("priority") or "unknown"
            payload = entry | {"score": score, "priority": priority, "is_new_result": is_new}
            top_candidates.append(payload)
            top_findings.append(payload)

    top_candidates.sort(key=_ranking_key, reverse=True)
    top_urls.sort(key=_ranking_key, reverse=True)
    top_findings.sort(key=_ranking_key, reverse=True)

    verified_ratio = (verified_count / findings_total) if findings_total else 0.0

    return {
        "counts": dict(counts),
        "status_counter": dict(status_counter),
        "priority_counter": dict(priority_counter),
        "signal_counter": dict(signal_counter),
        "noise_count": noise_count,
        "findings_total": findings_total,
        "verified_count": verified_count,
        "verified_ratio": verified_ratio,
        "new_findings_count": new_findings_count,
        "new_urls_count": new_urls_count,
        "top_candidates": top_candidates,
        "top_urls": top_urls,
        "top_findings": top_findings,
    }


def generate_summary(context) -> None:
    record = context.record
    prev_job_id = getattr(record.spec, "incremental_from", None)
    prev_record = None
    if prev_job_id:
        prev_record = context.manager.load_job(prev_job_id)

    data = generate_summary_data(record, prev_record=prev_record)

    metadata = record.metadata
    spec = record.spec
    job_id = spec.job_id

    def _extract_context(entry: dict) -> str:
        host = entry.get("hostname") or entry.get("host")
        if not host:
            url_value = entry.get("url")
            if isinstance(url_value, str):
                try:
                    host = urlparse(url_value).hostname
                except ValueError:
                    host = None
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        port = entry.get("port") or details.get("port")
        ip = entry.get("ip") or details.get("ip")
        if host and port:
            return f"{host}:{port}"
        if host:
            return str(host)
        if ip and port:
            return f"{ip}:{port}"
        if ip:
            return str(ip)
        return ""

    def _format_finding_label(entry: dict) -> str:
        label = (
            entry.get("description")
            or entry.get("title")
            or entry.get("name")
            or entry.get("url")
            or entry.get("hostname")
            or "(unknown)"
        )
        context_value = _extract_context(entry)
        new_tag = " [NEW]" if entry.get("is_new_result") else ""
        if context_value:
            return f"{label} [{context_value}]{new_tag}"
        return f"{label}{new_tag}"

    def _format_url_label(entry: dict) -> str:
        label = entry.get("url") or "(unknown)"
        status = entry.get("status_code") or entry.get("status")
        new_tag = " [NEW]" if entry.get("is_new_result") else ""
        if status:
            return f"{label} (status:{status}){new_tag}"
        return f"{label}{new_tag}"

    def _parse_iso(value: object) -> Optional[datetime]:
        if not isinstance(value, str) or not value:
            return None
        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    lines = []
    lines.append(
        "================================================================================"
    )
    lines.append(f"  RECON SUMMARY: {spec.target}")
    lines.append(
        "================================================================================"
    )
    lines.append(f"Job ID       : {metadata.job_id}")
    lines.append(f"Profile      : {spec.profile}")
    if prev_job_id:
        lines.append(f"Incremental  : {prev_job_id}")
    lines.append(f"Duration     : {metadata.started_at} -> {metadata.finished_at}")

    if prev_job_id:
        lines.append("")
        lines.append("== DIFF SUMMARY (NEW since last scan) ==")
        lines.append(f"New Hosts    : {data.get('counts', {}).get('asset_enrichment', 0)}")
        lines.append(f"New URLs     : {data.get('new_urls_count', 0)}")
        lines.append(f"New Findings : {data.get('new_findings_count', 0)}")

    started_dt = _parse_iso(metadata.started_at)
    finished_dt = _parse_iso(metadata.finished_at)
    if started_dt and finished_dt:
        wall_clock = (finished_dt - started_dt).total_seconds()
        if wall_clock >= 0:
            lines.append(f"Wall Clock   : {wall_clock:.1f}s")

    # Resilience: Report broken stages
    broken_stages = metadata.stats.get("broken_stages", {})
    if broken_stages:
        lines.append("")
        lines.append(f"== ⚠️  BROKEN STAGES ({len(broken_stages)}) ==")
        for stage, error in broken_stages.items():
            lines.append(f"[!] {stage:25}: {error}")

    top_findings = data["top_findings"]
    confirmed_findings = [entry for entry in top_findings if _is_confirmed(entry)]
    if confirmed_findings:
        from recon_cli.utils.reporting import POC_EXPECTED_BY_TYPE, resolve_finding_type
        lines.append("")
        lines.append(f"== 🛡️ CONFIRMED FINDINGS ({len(confirmed_findings)}) ==")
        for entry in confirmed_findings[:SUMMARY_TOP]:
            label = _format_finding_label(entry)
            score = entry.get("score", 0)
            priority = (entry.get("priority") or "high").upper()
            f_type = resolve_finding_type(entry)
            
            lines.append(f"[*] [{score:3}] ({priority:8}) {label}")
            if entry.get("url"):
                lines.append(f"    URL     : {entry.get('url')}")
            
            # Add Action Proof hint
            poc_hint = POC_EXPECTED_BY_TYPE.get(f_type)
            if poc_hint:
                lines.append(f"    PROOF   : {poc_hint}")
            
            # Show direct evidence if available
            proof = entry.get("proof") or entry.get("evidence")
            if proof:
                if isinstance(proof, (dict, list)):
                    proof_str = json.dumps(proof)
                else:
                    proof_str = str(proof)
                # Truncate long proof
                if len(proof_str) > 120:
                    proof_str = proof_str[:117] + "..."
                lines.append(f"    EVIDENCE: {proof_str}")
            lines.append("")

    high_priority_candidates = [
        entry
        for entry in top_findings
        if not _is_confirmed(entry) and int(entry.get("score", 0)) >= 70
    ]
    if high_priority_candidates:
        lines.append("")
        lines.append(
            f"== HIGH PRIORITY CANDIDATES ({len(high_priority_candidates)}) =="
        )
        for entry in high_priority_candidates[:SUMMARY_TOP]:
            label = _format_finding_label(entry)
            score = entry.get("score", 0)
            priority = (entry.get("priority") or "med").upper()
            lines.append(f"[?] [{score:3}] ({priority:8}) {label}")

    lines.append("")
    lines.append("== STATS ==")
    counts = data["counts"]
    for key in sorted(counts):
        if counts[key] > 0:
            lines.append(f"{key:18}: {counts[key]}")

    if data["verified_count"]:
        lines.append(
            f"Verified Ratio    : {data['verified_ratio']:.2%} ({data['verified_count']}/{data['findings_total']})"
        )

    status_counter = data["status_counter"]
    if status_counter:
        lines.append("")
        lines.append("== HTTP Status Codes ==")
        for code, count in sorted(status_counter.items()):
            lines.append(f"{code}: {count}")
        
        # ELITE: Session Expiry Warning
        if "401" in status_counter:
            lines.append("")
            lines.append("⚠️  WARNING: 401 Unauthorized responses detected!")
            lines.append("    Session may have expired mid-scan. ReconnV2 attempted auto-reauth")
            lines.append("    if configured, but some results may be incomplete.")

    # Quality metrics
    total_urls = counts.get("url", 0)
    noise_count = data["noise_count"]
    findings_total = data["findings_total"]
    verified_count = data["verified_count"]
    verified_ratio = data["verified_ratio"]
    noise_ratio = (noise_count / total_urls) if total_urls else 0.0

    lines.append("")
    lines.append("== Quality ==")
    lines.append(
        f"Noise ratio     : {noise_ratio:.2%} (noise {noise_count} / urls {total_urls})"
    )
    lines.append(
        f"Verified ratio  : {verified_ratio:.2%} (verified {verified_count} / findings {findings_total})"
    )

    top_urls = data["top_urls"]
    if top_urls:
        lines.append("")
        lines.append(
            f"== RELEVANT URLS (score >= 75, top {min(len(top_urls), SUMMARY_TOP)}) =="
        )
        for entry in top_urls[:SUMMARY_TOP]:
            label = _format_url_label(entry)
            score = entry.get("score", 0)
            priority = (entry.get("priority") or "med").upper()
            tags = ",".join(entry.get("tags", []))
            lines.append(f"[-] [{score:3}] ({priority:8}) {label} {tags}")

    next_actions: list[str] = []
    if confirmed_findings:
        next_actions.append("Manually verify and report the confirmed vulnerabilities.")
    if high_priority_candidates:
        next_actions.append(
            "Perform deeper manual analysis on high-priority candidates."
        )
    if data["counts"].get("api_spec", 0) > 0:
        next_actions.append(
            "Examine discovered API specifications for sensitive endpoints."
        )
    if data["counts"].get("finding", 0) > 0:
        next_actions.append(
            f"Review detailed findings with: recon report {job_id}"
        )

    if next_actions:
        lines.append("")
        lines.append("== NEXT ACTIONS ==")
        for i, action in enumerate(next_actions, 1):
            lines.append(f"{i}. {action}")

    content = "\n".join(lines) + "\n"
    record.paths.results_txt.write_text(content, encoding="utf-8")

    # Update metadata stats
    counts = data["counts"]
    total_urls = counts.get("url", 0)
    noise_count = data["noise_count"]
    findings_total = data["findings_total"]
    verified_count = data["verified_count"]

    dupe_seen = 0
    dupe_count = 0
    if (
        hasattr(context, "results")
        and getattr(context.results, "stats", None) is not None
    ):
        dupe_seen = int(context.results.stats.get("records_seen", 0))
        dupe_count = int(context.results.stats.get("records_duplicate", 0))

    noise_ratio = (noise_count / total_urls) if total_urls else 0.0
    verified_ratio = data["verified_ratio"]
    duplicate_ratio = (dupe_count / dupe_seen) if dupe_seen else 0.0

    metadata.stats.update({f"type_{key}": value for key, value in counts.items()})
    metadata.stats["noise_suppressed"] = noise_count
    metadata.stats["quality"] = {
        "noise_ratio": noise_ratio,
        "verified_ratio": verified_ratio,
        "duplicate_ratio": duplicate_ratio,
        "noise": noise_count,
        "urls": total_urls,
        "verified_findings": verified_count,
        "findings": findings_total,
        "duplicates": dupe_count,
        "records_seen": dupe_seen,
    }
    context.manager.update_metadata(record)


class JobSummary:
    def __init__(self, manager: Optional[JobManager] = None) -> None:
        from recon_cli.jobs.manager import JobManager

        self.manager = manager or JobManager()

    def get_summary(self, job_id: str) -> Optional[Dict[str, Any]]:
        record = self.manager.load_job(job_id)
        if not record:
            return None
        counts: Counter[str] = Counter()
        for entry in iter_jsonl(record.paths.results_jsonl):
            etype = entry.get("type", "unknown")
            counts[etype] += 1
        return {
            "job_id": job_id,
            "target": record.spec.target,
            "profile": record.spec.profile,
            "status": record.metadata.status,
            "counts": dict(counts),
        }
