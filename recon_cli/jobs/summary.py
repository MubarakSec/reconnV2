from __future__ import annotations

import os
from datetime import datetime

from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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


def generate_summary(context) -> None:
    from recon_cli.utils.reporting import is_finding, resolve_confidence_label

    record = context.record
    metadata = record.metadata
    spec = record.spec
    results_path = record.paths.results_jsonl
    trimmed_path = record.paths.trimmed_results_jsonl
    summary_path = results_path
    if trimmed_path.exists() and trimmed_path.stat().st_size > 0:
        summary_path = trimmed_path

    counts = Counter()
    status_counter = Counter()
    priority_counter = Counter()
    signal_counter = Counter()
    noise_count = 0
    findings_total = 0
    verified_count = 0
    verified_ratio = 0.0
    top_candidates: List[dict] = []
    top_urls: List[dict] = []
    top_findings: List[dict] = []

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
        if context_value:
            return f"{label} [{context_value}]"
        return label

    def _format_url_label(entry: dict) -> str:
        label = entry.get("url") or "(unknown)"
        status = entry.get("status_code") or entry.get("status")
        if status:
            return f"{label} (status:{status})"
        return label

    def _parse_iso(value: object) -> Optional[datetime]:
        if not isinstance(value, str) or not value:
            return None
        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            return datetime.fromisoformat(value)
        except ValueError:
            return None

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
            {str(tag).lower() for tag in tags_raw}
            if isinstance(tags_raw, list)
            else set()
        )
        confirmed = 1 if _is_confirmed(entry) else 0
        non_repetitive = 0 if "auth:repetitive" in tags else 1
        score = int(entry.get("score", 0) or 0)
        return (confirmed, non_repetitive, score, _priority_rank(entry.get("priority")))

    for entry in iter_jsonl(results_path):
        etype = entry.get("type", "unknown")
        counts[etype] += 1
        if is_finding(entry):
            findings_total += 1
            if resolve_confidence_label(entry) == "verified":
                verified_count += 1
        if etype == "signal":
            signal_type = entry.get("signal_type")
            if signal_type:
                signal_counter[str(signal_type)] += 1
        elif etype == "url":
            score = int(entry.get("score", 0))
            status = entry.get("status_code")
            if status:
                status_counter[str(status)] += 1
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

    for entry in iter_jsonl(summary_path):
        etype = entry.get("type", "unknown")
        score = int(entry.get("score", 0))
        if etype == "url":
            if score < 75:
                continue
            tags = set(entry.get("tags", []))
            if "noise" in tags:
                continue
            priority = entry.get("priority") or "unknown"
            payload = entry | {"score": score, "priority": priority}
            top_candidates.append(payload)
            top_urls.append(payload)
        elif etype in {"finding", "idor_suspect", "idor_candidate"}:
            priority = entry.get("priority") or "unknown"
            payload = entry | {"score": score, "priority": priority}
            top_candidates.append(payload)
            top_findings.append(payload)

    top_candidates.sort(key=_ranking_key, reverse=True)
    top_urls.sort(key=_ranking_key, reverse=True)
    top_findings.sort(key=_ranking_key, reverse=True)

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
    lines.append(f"Duration     : {metadata.started_at} -> {metadata.finished_at}")

    started_dt = _parse_iso(metadata.started_at)
    finished_dt = _parse_iso(metadata.finished_at)
    if started_dt and finished_dt:
        wall_clock = (finished_dt - started_dt).total_seconds()
        if wall_clock >= 0:
            lines.append(f"Wall Clock   : {wall_clock:.1f}s")

    confirmed_findings = [entry for entry in top_findings if _is_confirmed(entry)]
    if confirmed_findings:
        lines.append("")
        lines.append(f"== CONFIRMED FINDINGS ({len(confirmed_findings)}) ==")
        for entry in confirmed_findings[:SUMMARY_TOP]:
            label = _format_finding_label(entry)
            score = entry.get("score", 0)
            priority = (entry.get("priority") or "high").upper()
            tags = ",".join(entry.get("tags", []))
            lines.append(f"[*] [{score:3}] ({priority:8}) {label}")
            if entry.get("url"):
                lines.append(f"    URL: {entry.get('url')}")

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
    for key in sorted(counts):
        if counts[key] > 0:
            lines.append(f"{key:18}: {counts[key]}")

    if verified_count:
        verified_ratio = (verified_count / findings_total) if findings_total else 0.0
        lines.append(
            f"Verified Ratio    : {verified_ratio:.2%} ({verified_count}/{findings_total})"
        )
    if status_counter:
        lines.append("")
        lines.append("== HTTP Status Codes ==")
        for code, count in sorted(status_counter.items()):
            lines.append(f"{code}: {count}")
    if priority_counter:
        lines.append("")
        lines.append("== Priority Counts ==")
        for priority, count in priority_counter.most_common():
            lines.append(f"{priority}: {count}")
    total_urls = counts.get("url", 0)
    noise_ratio = (noise_count / total_urls) if total_urls else 0.0
    verified_ratio = (verified_count / findings_total) if findings_total else 0.0
    dupe_seen = 0
    dupe_count = 0
    if (
        hasattr(context, "results")
        and getattr(context.results, "stats", None) is not None
    ):
        dupe_seen = int(context.results.stats.get("records_seen", 0))
        dupe_count = int(context.results.stats.get("records_duplicate", 0))
    duplicate_ratio = (dupe_count / dupe_seen) if dupe_seen else 0.0
    lines.append("")
    lines.append("== Quality ==")
    lines.append(
        f"Noise ratio     : {noise_ratio:.2%} (noise {noise_count} / urls {total_urls})"
    )
    lines.append(
        f"Verified ratio  : {verified_ratio:.2%} (verified {verified_count} / findings {findings_total})"
    )
    if dupe_seen:
        lines.append(
            f"Duplicate ratio : {duplicate_ratio:.2%} (duplicates {dupe_count} / seen {dupe_seen})"
        )
    else:
        lines.append("Duplicate ratio : n/a (no in-memory stats)")
    missing_tools = (
        metadata.stats.get("missing_tools") if hasattr(metadata, "stats") else None
    )
    if missing_tools:
        lines.append("")
        lines.append("== Missing Tools ==")
        lines.append(", ".join(sorted(missing_tools)))
    stage_progress = (
        metadata.stats.get("stage_progress") if hasattr(metadata, "stats") else None
    )
    if stage_progress:
        durations: List[tuple[str, float, str]] = []
        total_duration = 0.0
        for entry in stage_progress:
            if not isinstance(entry, dict):
                continue
            start = _parse_iso(entry.get("started_at"))
            end = _parse_iso(entry.get("finished_at"))
            if not start or not end:
                continue
            duration = (end - start).total_seconds()
            total_duration += duration
            durations.append(
                (
                    str(entry.get("stage", "unknown")),
                    duration,
                    str(entry.get("status", "unknown")),
                )
            )
        if durations:
            lines.append("")
            lines.append("== Stage Timings ==")
            lines.append(f"Total: {total_duration:.1f}s (stage progress window)")
            for stage, duration, status in sorted(
                durations, key=lambda item: item[1], reverse=True
            )[:10]:
                lines.append(f"{stage:20} {duration:6.1f}s ({status})")
    if STAGE_HEALTH_SIGNALS:
        lines.append("")
        lines.append("== Stage Health ==")
        for stage, signal_types in STAGE_HEALTH_SIGNALS.items():
            total_signals = sum(signal_counter.get(sig, 0) for sig in signal_types)
            status = "signals" if total_signals else "no-signals"
            lines.append(f"{stage:20} {status} ({total_signals})")
    if noise_count:
        metadata.stats["noise_suppressed"] = noise_count
    correlation_stats = (
        getattr(metadata, "stats", {}).get("correlation")
        if hasattr(metadata, "stats")
        else None
    )
    if correlation_stats:
        lines.append("")
        lines.append("== Correlation Summary ==")
        lines.append(f"Graph nodes: {correlation_stats.get('graph_nodes', 0)}")
        lines.append(f"Graph edges: {correlation_stats.get('graph_edges', 0)}")
        if correlation_stats.get("ip_clusters"):
            lines.append(f"IP clusters: {correlation_stats['ip_clusters']}")
        if correlation_stats.get("asn_clusters"):
            lines.append(f"ASN clusters: {correlation_stats['asn_clusters']}")
        if correlation_stats.get("provider_clusters"):
            lines.append(f"Provider clusters: {correlation_stats['provider_clusters']}")
        if correlation_stats.get("api_hosts"):
            lines.append(f"Hosts exposing APIs: {correlation_stats['api_hosts']}")
        top_tags = (
            correlation_stats.get("top_tags")
            if isinstance(correlation_stats, dict)
            else None
        )
        if top_tags:
            summary_tags = ", ".join(f"{tag}:{count}" for tag, count in top_tags[:5])
            lines.append(f"Top tags: {summary_tags}")
    secrets_stats = (
        getattr(metadata, "stats", {}).get("secrets")
        if hasattr(metadata, "stats")
        else None
    )
    if secrets_stats and secrets_stats.get("findings"):
        lines.append("")
        lines.append("== Secrets Summary ==")
        lines.append(
            f"Matches: {secrets_stats.get('findings', 0)} across {secrets_stats.get('urls', 0)} URLs"
        )
        patterns = secrets_stats.get("patterns", {})
        if patterns:
            top_patterns = ", ".join(
                f"{name}:{count}"
                for name, count in sorted(
                    patterns.items(), key=lambda item: item[1], reverse=True
                )[:5]
            )
            lines.append(f"Top patterns: {top_patterns}")
        guidance = secrets_stats.get("guidance")
        if guidance:
            lines.append(f"Guidance: {guidance}")
    scanner_stats = (
        getattr(metadata, "stats", {}).get("scanners")
        if hasattr(metadata, "stats")
        else None
    )
    if scanner_stats:
        lines.append("")
        lines.append("== Scanner Summary ==")
        for name, data in scanner_stats.items():
            if isinstance(data, dict):
                lines.append(
                    f"{name}: targets={data.get('targets', 0)}, findings={data.get('findings', 0)}"
                )
            else:
                lines.append(f"{name}: {data}")
    nmap_stats = (
        getattr(metadata, "stats", {}).get("nmap")
        if hasattr(metadata, "stats")
        else None
    )
    if nmap_stats:
        lines.append("")
        lines.append("== Nmap Summary ==")
        lines.append(f"Hosts scanned: {nmap_stats.get('hosts', 0)}")
        lines.append(f"Services: {nmap_stats.get('services', 0)}")
        if nmap_stats.get("udp_services"):
            lines.append(f"UDP services: {nmap_stats.get('udp_services', 0)}")
        lines.append(f"Findings: {nmap_stats.get('findings', 0)}")
    auth_stats = (
        getattr(metadata, "stats", {}).get("auth_discovery")
        if hasattr(metadata, "stats")
        else None
    )
    if auth_stats:
        lines.append("")
        lines.append("== Auth Discovery ==")
        lines.append(f"Forms discovered: {auth_stats.get('forms', 0)}")
    auth_session = (
        getattr(metadata, "stats", {}).get("auth")
        if hasattr(metadata, "stats")
        else None
    )
    if auth_session:
        lines.append("")
        lines.append("== Auth Session ==")
        lines.append(f"Enabled: {auth_session.get('enabled', False)}")
        lines.append(f"Profile: {auth_session.get('profile', 'default')}")
        if auth_session.get("login_success") or auth_session.get("login_failed"):
            lines.append(f"Login success: {auth_session.get('login_success', 0)}")
            lines.append(f"Login failed: {auth_session.get('login_failed', 0)}")
    surface_stats = (
        getattr(metadata, "stats", {}).get("auth_surface")
        if hasattr(metadata, "stats")
        else None
    )
    if surface_stats:
        lines.append("")
        lines.append("== Auth Surfaces ==")
        lines.append(f"Login: {surface_stats.get('login', 0)}")
        lines.append(f"Password reset: {surface_stats.get('password_reset', 0)}")
        lines.append(f"Register: {surface_stats.get('register', 0)}")
    js_stats = (
        getattr(metadata, "stats", {}).get("js_intel")
        if hasattr(metadata, "stats")
        else None
    )
    if js_stats:
        lines.append("")
        lines.append("== JS Intelligence ==")
        lines.append(f"JS files: {js_stats.get('files', 0)}")
        lines.append(f"Endpoints: {js_stats.get('endpoints', 0)}")
    api_stats = (
        getattr(metadata, "stats", {}).get("api_recon")
        if hasattr(metadata, "stats")
        else None
    )
    if api_stats:
        lines.append("")
        lines.append("== API Recon ==")
        lines.append(f"Specs: {api_stats.get('specs', 0)}")
        lines.append(f"URLs added: {api_stats.get('urls_added', 0)}")
    param_stats = (
        getattr(metadata, "stats", {}).get("param_mining")
        if hasattr(metadata, "stats")
        else None
    )
    if param_stats:
        lines.append("")
        lines.append("== Parameter Mining ==")
        lines.append(f"Parameters: {param_stats.get('params', 0)}")
        lines.append(f"URLs analyzed: {param_stats.get('urls', 0)}")
    waf_stats = (
        getattr(metadata, "stats", {}).get("waf_probe")
        if hasattr(metadata, "stats")
        else None
    )
    if waf_stats:
        lines.append("")
        lines.append("== WAF Probe ==")
        lines.append(f"Findings: {waf_stats.get('findings', 0)}")
    takeover_stats = (
        getattr(metadata, "stats", {}).get("takeover")
        if hasattr(metadata, "stats")
        else None
    )
    if takeover_stats:
        lines.append("")
        lines.append("== Takeover Checks ==")
        lines.append(f"Hosts checked: {takeover_stats.get('checked', 0)}")
        lines.append(f"Findings: {takeover_stats.get('findings', 0)}")
    vuln_stats = (
        getattr(metadata, "stats", {}).get("vuln_scan")
        if hasattr(metadata, "stats")
        else None
    )
    if vuln_stats:
        lines.append("")
        lines.append("== Vuln Scanners ==")
        lines.append(f"Findings: {vuln_stats.get('findings', 0)}")
    verify_stats = (
        getattr(metadata, "stats", {}).get("verification")
        if hasattr(metadata, "stats")
        else None
    )
    if verify_stats:
        lines.append("")
        lines.append("== Verification ==")
        lines.append(
            f"Attempted: {verify_stats.get('attempted', 0)} | "
            f"Verified: {verify_stats.get('verified', 0)} | "
            f"Failed: {verify_stats.get('failed', 0)} | "
            f"Skipped: {verify_stats.get('skipped', 0)}"
        )
        status_codes = verify_stats.get("status_codes")
        if isinstance(status_codes, dict) and status_codes:
            status_summary = ", ".join(
                f"{code}:{count}" for code, count in sorted(status_codes.items())
            )
            lines.append(f"Status codes: {status_summary}")
        if verify_stats.get("artifact"):
            lines.append(f"Artifact: {verify_stats.get('artifact')}")
    idor_stats = (
        getattr(metadata, "stats", {}).get("idor")
        if hasattr(metadata, "stats")
        else None
    )
    if idor_stats and idor_stats.get("suspects"):
        lines.append("")
        lines.append("== IDOR Suspects ==")
        lines.append(f"Suspects: {idor_stats.get('suspects', 0)}")
    shots_stats = (
        getattr(metadata, "stats", {}).get("screenshots")
        if hasattr(metadata, "stats")
        else None
    )
    if shots_stats:
        lines.append("")
        lines.append("== Screenshots ==")
        lines.append(f"Count: {shots_stats.get('count', 0)}")
        if shots_stats.get("manifest"):
            lines.append(f"Manifest: {shots_stats.get('manifest')}")
    learning_stats = (
        getattr(metadata, "stats", {}).get("learning")
        if hasattr(metadata, "stats")
        else None
    )
    if learning_stats and learning_stats.get("predictions"):
        lines.append("")
        lines.append("== Learning Predictions ==")
        lines.append(f"Model trained: {learning_stats.get('trained', False)}")
        for host, prob in learning_stats.get("top_hosts", []):
            lines.append(f"{host}: {prob:.2f}")
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
    secrets_stats = (
        getattr(metadata, "stats", {}).get("secrets")
        if hasattr(metadata, "stats")
        else None
    )
    if secrets_stats and secrets_stats.get("findings"):
        next_actions.append(
            "Rotate/revoke exposed credentials and add to secrets manager."
        )
    auth_stats = (
        getattr(metadata, "stats", {}).get("auth_matrix")
        if hasattr(metadata, "stats")
        else None
    )
    if auth_stats and auth_stats.get("issues"):
        next_actions.append(
            "Review auth-matrix issues; ensure least-privilege tokens differ in content."
        )
    if getattr(metadata, "stats", {}).get("idor", {}).get("suspects"):
        next_actions.append("Validate IDOR suspects and add authorization checks.")
    if missing_tools:
        next_actions.append("Install missing external tools for fuller coverage.")
    if not next_actions and (
        priority_counter.get("high", 0) > 0 or priority_counter.get("critical", 0) > 0
    ):
        next_actions.append(
            "Investigate high/critical items first; rerun with full profile if needed."
        )
    if next_actions:
        lines.append("")
        lines.append("== Next Actions ==")
        for item in next_actions:
            lines.append(f"- {item}")
    record.paths.results_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Write expanded findings list (score >= 60) to results_bigger.txt
    def _is_finding(entry: dict) -> bool:
        if entry.get("finding_type"):
            return True
        etype = entry.get("type")
        return isinstance(etype, str) and etype in {
            "finding",
            "idor_suspect",
            "idor_candidate",
            "vulnerability",
            "vuln",
        }

    bigger_path = record.paths.root / "results_bigger.txt"
    big_lines: List[str] = []
    big_findings: List[dict] = []
    for entry in iter_jsonl(results_path):
        if not isinstance(entry, dict):
            continue
        if not _is_finding(entry):
            continue
        score = int(entry.get("score", 0))
        if score < 60:
            continue
        priority = entry.get("priority") or "unknown"
        payload = entry | {"score": score, "priority": priority}
        big_findings.append(payload)

    big_findings.sort(key=_ranking_key, reverse=True)
    big_lines.append(f"Findings >= 60: {len(big_findings)}")
    for entry in big_findings:
        confirmed = _is_confirmed(entry)
        label = _format_finding_label(entry)
        score = entry.get("score", 0)
        priority = entry.get("priority", "unknown")
        tags = ",".join(entry.get("tags", []))
        url_value = (
            entry.get("url") or entry.get("details", {}).get("url")
            if isinstance(entry.get("details"), dict)
            else ""
        )
        status_label = "CONFIRMED" if confirmed else "CANDIDATE"
        if url_value:
            big_lines.append(
                f"[{score:4}] ({priority}) {status_label} {label} | {url_value} {tags}"
            )
        else:
            big_lines.append(f"[{score:4}] ({priority}) {status_label} {label} {tags}")
    bigger_path.write_text("\n".join(big_lines) + "\n", encoding="utf-8")

    confirmed_path = record.paths.root / "results_confirmed.txt"
    confirmed_lines: List[str] = []
    confirmed_entries: List[dict] = []
    for entry in iter_jsonl(results_path):
        if not isinstance(entry, dict):
            continue
        if not _is_finding(entry):
            continue
        if not _is_confirmed(entry):
            continue
        score = int(entry.get("score", 0))
        priority = entry.get("priority") or "unknown"
        payload = entry | {"score": score, "priority": priority}
        confirmed_entries.append(payload)
    confirmed_entries.sort(key=_ranking_key, reverse=True)
    confirmed_lines.append(f"Confirmed findings: {len(confirmed_entries)}")
    for entry in confirmed_entries:
        label = _format_finding_label(entry)
        score = entry.get("score", 0)
        priority = entry.get("priority", "unknown")
        tags = ",".join(entry.get("tags", []))
        url_value = (
            entry.get("url") or entry.get("details", {}).get("url")
            if isinstance(entry.get("details"), dict)
            else ""
        )
        if url_value:
            confirmed_lines.append(
                f"[{score:4}] ({priority}) {label} | {url_value} {tags}"
            )
        else:
            confirmed_lines.append(f"[{score:4}] ({priority}) {label} {tags}")
    confirmed_path.write_text("\n".join(confirmed_lines) + "\n", encoding="utf-8")

    metadata.stats.update({f"type_{key}": value for key, value in counts.items()})
    metadata.stats.update(
        {f"status_{code}": value for code, value in status_counter.items()}
    )
    metadata.stats["noise_suppressed"] = noise_count
    metadata.stats["confirmed_findings"] = len(confirmed_entries)
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
    for priority, count in priority_counter.items():
        metadata.stats[f"priority_{priority}"] = count
    context.manager.update_metadata(record)


class JobSummary:
    def __init__(self, manager: Optional[JobManager] = None) -> None:
        self.manager = manager or JobManager()

    def get_summary(self, job_id: str) -> Optional[Dict[str, Any]]:
        record = self.manager.load_job(job_id)
        if not record:
            return None
        counts = Counter()
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
