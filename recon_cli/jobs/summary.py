from __future__ import annotations

import os
from datetime import datetime

from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from recon_cli.jobs.manager import JobManager

from recon_cli.utils.jsonl import iter_jsonl


SUMMARY_TOP = int(os.environ.get("RECON_SUMMARY_TOP", 50))


def generate_summary(context) -> None:
    record = context.record
    metadata = record.metadata
    spec = record.spec
    results_path = record.paths.results_jsonl
    trimmed_path = record.paths.trimmed_results_jsonl
    summary_source = "full"
    summary_path = results_path
    if trimmed_path.exists() and trimmed_path.stat().st_size > 0:
        summary_source = "trimmed"
        summary_path = trimmed_path

    counts = Counter()
    status_counter = Counter()
    priority_counter = Counter()
    noise_count = 0
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

    for entry in iter_jsonl(results_path):
        etype = entry.get("type", "unknown")
        counts[etype] += 1
        if etype == "url":
            score = int(entry.get("score", 0))
            status = entry.get("status_code")
            if status:
                status_counter[str(status)] += 1
            tags = set(entry.get("tags", []))
            if "noise" in tags:
                noise_count += 1
                continue
            priority = entry.get("priority") or "unknown"
            priority_counter[priority] += 1
        elif etype == "asset_enrichment":
            tags = entry.get("tags", [])
            if tags:
                priority_counter["enriched_hosts"] += 1
        elif etype in {"finding", "idor_suspect"}:
            priority = entry.get("priority") or "unknown"
            priority_counter[priority] += 1

    for entry in iter_jsonl(summary_path):
        etype = entry.get("type", "unknown")
        if etype == "url":
            score = int(entry.get("score", 0))
            tags = set(entry.get("tags", []))
            if "noise" in tags:
                continue
            priority = entry.get("priority") or "unknown"
            payload = entry | {"score": score, "priority": priority}
            top_candidates.append(payload)
            top_urls.append(payload)
        elif etype in {"finding", "idor_suspect"}:
            score = int(entry.get("score", 0))
            priority = entry.get("priority") or "unknown"
            payload = entry | {"score": score, "priority": priority}
            top_candidates.append(payload)
            top_findings.append(payload)

    top_candidates.sort(key=lambda item: item.get("score", 0), reverse=True)
    top_urls.sort(key=lambda item: item.get("score", 0), reverse=True)
    top_findings.sort(key=lambda item: item.get("score", 0), reverse=True)

    lines = []
    lines.append(f"Job ID       : {metadata.job_id}")
    lines.append(f"Target       : {spec.target}")
    lines.append(f"Profile      : {spec.profile}")
    lines.append(f"Queued       : {metadata.queued_at}")
    lines.append(f"Started      : {metadata.started_at}")
    lines.append(f"Finished     : {metadata.finished_at}")
    lines.append(f"Summary Src  : {summary_source}")
    lines.append("")
    lines.append("== Totals ==")
    for key in sorted(counts):
        lines.append(f"{key:18}: {counts[key]}")
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
    missing_tools = metadata.stats.get("missing_tools") if hasattr(metadata, "stats") else None
    if missing_tools:
        lines.append("")
        lines.append("== Missing Tools ==")
        lines.append(", ".join(sorted(missing_tools)))
    stage_progress = metadata.stats.get("stage_progress") if hasattr(metadata, "stats") else None
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
            durations.append((str(entry.get("stage", "unknown")), duration, str(entry.get("status", "unknown"))))
        if durations:
            lines.append("")
            lines.append("== Stage Timings ==")
            lines.append(f"Total: {total_duration:.1f}s")
            for stage, duration, status in sorted(durations, key=lambda item: item[1], reverse=True)[:10]:
                lines.append(f"{stage:20} {duration:6.1f}s ({status})")
    if noise_count:
        metadata.stats["noise_suppressed"] = noise_count
    correlation_stats = getattr(metadata, 'stats', {}).get('correlation') if hasattr(metadata, 'stats') else None
    if correlation_stats:
        lines.append('')
        lines.append('== Correlation Summary ==')
        lines.append(f"Graph nodes: {correlation_stats.get('graph_nodes', 0)}")
        lines.append(f"Graph edges: {correlation_stats.get('graph_edges', 0)}")
        if correlation_stats.get('ip_clusters'):
            lines.append(f"IP clusters: {correlation_stats['ip_clusters']}")
        if correlation_stats.get('asn_clusters'):
            lines.append(f"ASN clusters: {correlation_stats['asn_clusters']}")
        if correlation_stats.get('provider_clusters'):
            lines.append(f"Provider clusters: {correlation_stats['provider_clusters']}")
        if correlation_stats.get('api_hosts'):
            lines.append(f"Hosts exposing APIs: {correlation_stats['api_hosts']}")
        top_tags = correlation_stats.get('top_tags') if isinstance(correlation_stats, dict) else None
        if top_tags:
            summary_tags = ', '.join(f"{tag}:{count}" for tag, count in top_tags[:5])
            lines.append(f"Top tags: {summary_tags}")
    secrets_stats = getattr(metadata, 'stats', {}).get('secrets') if hasattr(metadata, 'stats') else None
    if secrets_stats and secrets_stats.get('findings'):
        lines.append('')
        lines.append('== Secrets Summary ==')
        lines.append(f"Matches: {secrets_stats.get('findings', 0)} across {secrets_stats.get('urls', 0)} URLs")
        patterns = secrets_stats.get('patterns', {})
        if patterns:
            top_patterns = ', '.join(f"{name}:{count}" for name, count in sorted(patterns.items(), key=lambda item: item[1], reverse=True)[:5])
            lines.append(f"Top patterns: {top_patterns}")
        guidance = secrets_stats.get('guidance')
        if guidance:
            lines.append(f"Guidance: {guidance}")
    scanner_stats = getattr(metadata, 'stats', {}).get('scanners') if hasattr(metadata, 'stats') else None
    if scanner_stats:
        lines.append('')
        lines.append('== Scanner Summary ==')
        for name, data in scanner_stats.items():
            if isinstance(data, dict):
                lines.append(f"{name}: targets={data.get('targets', 0)}, findings={data.get('findings', 0)}")
            else:
                lines.append(f"{name}: {data}")
    nmap_stats = getattr(metadata, 'stats', {}).get('nmap') if hasattr(metadata, 'stats') else None
    if nmap_stats:
        lines.append('')
        lines.append('== Nmap Summary ==')
        lines.append(f"Hosts scanned: {nmap_stats.get('hosts', 0)}")
        lines.append(f"Services: {nmap_stats.get('services', 0)}")
        if nmap_stats.get('udp_services'):
            lines.append(f"UDP services: {nmap_stats.get('udp_services', 0)}")
        lines.append(f"Findings: {nmap_stats.get('findings', 0)}")
    auth_stats = getattr(metadata, 'stats', {}).get('auth_discovery') if hasattr(metadata, 'stats') else None
    if auth_stats:
        lines.append('')
        lines.append('== Auth Discovery ==')
        lines.append(f"Forms discovered: {auth_stats.get('forms', 0)}")
    auth_session = getattr(metadata, 'stats', {}).get('auth') if hasattr(metadata, 'stats') else None
    if auth_session:
        lines.append('')
        lines.append('== Auth Session ==')
        lines.append(f"Enabled: {auth_session.get('enabled', False)}")
        lines.append(f"Profile: {auth_session.get('profile', 'default')}")
        if auth_session.get('login_success') or auth_session.get('login_failed'):
            lines.append(f"Login success: {auth_session.get('login_success', 0)}")
            lines.append(f"Login failed: {auth_session.get('login_failed', 0)}")
    surface_stats = getattr(metadata, 'stats', {}).get('auth_surface') if hasattr(metadata, 'stats') else None
    if surface_stats:
        lines.append('')
        lines.append('== Auth Surfaces ==')
        lines.append(f"Login: {surface_stats.get('login', 0)}")
        lines.append(f"Password reset: {surface_stats.get('password_reset', 0)}")
        lines.append(f"Register: {surface_stats.get('register', 0)}")
    js_stats = getattr(metadata, 'stats', {}).get('js_intel') if hasattr(metadata, 'stats') else None
    if js_stats:
        lines.append('')
        lines.append('== JS Intelligence ==')
        lines.append(f"JS files: {js_stats.get('files', 0)}")
        lines.append(f"Endpoints: {js_stats.get('endpoints', 0)}")
    api_stats = getattr(metadata, 'stats', {}).get('api_recon') if hasattr(metadata, 'stats') else None
    if api_stats:
        lines.append('')
        lines.append('== API Recon ==')
        lines.append(f"Specs: {api_stats.get('specs', 0)}")
        lines.append(f"URLs added: {api_stats.get('urls_added', 0)}")
    param_stats = getattr(metadata, 'stats', {}).get('param_mining') if hasattr(metadata, 'stats') else None
    if param_stats:
        lines.append('')
        lines.append('== Parameter Mining ==')
        lines.append(f"Parameters: {param_stats.get('params', 0)}")
        lines.append(f"URLs analyzed: {param_stats.get('urls', 0)}")
    waf_stats = getattr(metadata, 'stats', {}).get('waf_probe') if hasattr(metadata, 'stats') else None
    if waf_stats:
        lines.append('')
        lines.append('== WAF Probe ==')
        lines.append(f"Findings: {waf_stats.get('findings', 0)}")
    takeover_stats = getattr(metadata, 'stats', {}).get('takeover') if hasattr(metadata, 'stats') else None
    if takeover_stats:
        lines.append('')
        lines.append('== Takeover Checks ==')
        lines.append(f"Hosts checked: {takeover_stats.get('checked', 0)}")
        lines.append(f"Findings: {takeover_stats.get('findings', 0)}")
    vuln_stats = getattr(metadata, 'stats', {}).get('vuln_scan') if hasattr(metadata, 'stats') else None
    if vuln_stats:
        lines.append('')
        lines.append('== Vuln Scanners ==')
        lines.append(f"Findings: {vuln_stats.get('findings', 0)}")
    verify_stats = getattr(metadata, 'stats', {}).get('verification') if hasattr(metadata, 'stats') else None
    if verify_stats:
        lines.append('')
        lines.append('== Verification ==')
        lines.append(
            f"Attempted: {verify_stats.get('attempted', 0)} | "
            f"Verified: {verify_stats.get('verified', 0)} | "
            f"Failed: {verify_stats.get('failed', 0)} | "
            f"Skipped: {verify_stats.get('skipped', 0)}"
        )
        status_codes = verify_stats.get('status_codes')
        if isinstance(status_codes, dict) and status_codes:
            status_summary = ', '.join(f"{code}:{count}" for code, count in sorted(status_codes.items()))
            lines.append(f"Status codes: {status_summary}")
        if verify_stats.get('artifact'):
            lines.append(f"Artifact: {verify_stats.get('artifact')}")
    idor_stats = getattr(metadata, 'stats', {}).get('idor') if hasattr(metadata, 'stats') else None
    if idor_stats and idor_stats.get('suspects'):
        lines.append('')
        lines.append('== IDOR Suspects ==')
        lines.append(f"Suspects: {idor_stats.get('suspects', 0)}")
    shots_stats = getattr(metadata, 'stats', {}).get('screenshots') if hasattr(metadata, 'stats') else None
    if shots_stats:
        lines.append('')
        lines.append('== Screenshots ==')
        lines.append(f"Count: {shots_stats.get('count', 0)}")
        if shots_stats.get('manifest'):
            lines.append(f"Manifest: {shots_stats.get('manifest')}")
    learning_stats = getattr(metadata, 'stats', {}).get('learning') if hasattr(metadata, 'stats') else None
    if learning_stats and learning_stats.get('predictions'):
        lines.append('')
        lines.append('== Learning Predictions ==')
        lines.append(f"Model trained: {learning_stats.get('trained', False)}")
        for host, prob in learning_stats.get('top_hosts', []):
            lines.append(f"{host}: {prob:.2f}")
    if top_findings:
        lines.append("")
        lines.append(f"== Top Findings (top {min(len(top_findings), SUMMARY_TOP)}) ==")
        for entry in top_findings[:SUMMARY_TOP]:
            label = _format_finding_label(entry)
            score = entry.get("score", 0)
            priority = entry.get("priority", "unknown")
            tags = ",".join(entry.get("tags", []))
            lines.append(f"[{score:4}] ({priority}) {label} {tags}")
    if top_urls:
        lines.append("")
        lines.append(f"== Top URLs (top {min(len(top_urls), SUMMARY_TOP)}) ==")
        for entry in top_urls[:SUMMARY_TOP]:
            label = _format_url_label(entry)
            score = entry.get("score", 0)
            priority = entry.get("priority", "unknown")
            tags = ",".join(entry.get("tags", []))
            lines.append(f"[{score:4}] ({priority}) {label} {tags}")
    next_actions: list[str] = []
    secrets_stats = getattr(metadata, 'stats', {}).get('secrets') if hasattr(metadata, 'stats') else None
    if secrets_stats and secrets_stats.get('findings'):
        next_actions.append("Rotate/revoke exposed credentials and add to secrets manager.")
    auth_stats = getattr(metadata, 'stats', {}).get('auth_matrix') if hasattr(metadata, 'stats') else None
    if auth_stats and auth_stats.get("issues"):
        next_actions.append("Review auth-matrix issues; ensure least-privilege tokens differ in content.")
    if getattr(metadata, 'stats', {}).get('idor', {}).get('suspects'):
        next_actions.append("Validate IDOR suspects and add authorization checks.")
    if missing_tools:
        next_actions.append("Install missing external tools for fuller coverage.")
    if not next_actions and (priority_counter.get("high", 0) > 0 or priority_counter.get("critical", 0) > 0):
        next_actions.append("Investigate high/critical items first; rerun with full profile if needed.")
    if next_actions:
        lines.append("")
        lines.append("== Next Actions ==")
        for item in next_actions:
            lines.append(f"- {item}")
    record.paths.results_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    metadata.stats.update({f"type_{key}": value for key, value in counts.items()})
    metadata.stats.update({f"status_{code}": value for code, value in status_counter.items()})
    metadata.stats["noise_suppressed"] = noise_count
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
