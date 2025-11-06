from __future__ import annotations

import os

from collections import Counter
from typing import List

from recon_cli.utils.jsonl import read_jsonl


SUMMARY_TOP = int(os.environ.get("RECON_SUMMARY_TOP", 50))


def generate_summary(context) -> None:
    record = context.record
    metadata = record.metadata
    spec = record.spec
    items = read_jsonl(record.paths.results_jsonl)
    counts = Counter()
    status_counter = Counter()
    priority_counter = Counter()
    noise_count = 0
    top_candidates: List[dict] = []

    for entry in items:
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
            top_candidates.append(entry | {"score": score, "priority": priority})
        elif etype == "asset_enrichment":
            tags = entry.get("tags", [])
            if tags:
                priority_counter["enriched_hosts"] += 1
        elif etype == "finding":
            score = int(entry.get("score", 0))
            priority = entry.get("priority") or "unknown"
            priority_counter[priority] += 1
            top_candidates.append(entry | {"score": score, "priority": priority})

    top_candidates.sort(key=lambda item: item.get("score", 0), reverse=True)
    top_urls = top_candidates[:SUMMARY_TOP]

    lines = []
    lines.append(f"Job ID       : {metadata.job_id}")
    lines.append(f"Target       : {spec.target}")
    lines.append(f"Profile      : {spec.profile}")
    lines.append(f"Queued       : {metadata.queued_at}")
    lines.append(f"Started      : {metadata.started_at}")
    lines.append(f"Finished     : {metadata.finished_at}")
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
    learning_stats = getattr(metadata, 'stats', {}).get('learning') if hasattr(metadata, 'stats') else None
    if learning_stats and learning_stats.get('predictions'):
        lines.append('')
        lines.append('== Learning Predictions ==')
        lines.append(f"Model trained: {learning_stats.get('trained', False)}")
        for host, prob in learning_stats.get('top_hosts', []):
            lines.append(f"{host}: {prob:.2f}")
    if top_urls:
        lines.append("")
        lines.append(f"== Top Findings (top {len(top_urls)}) ==")
        for entry in top_urls:
            label = entry.get("url") or entry.get("description") or entry.get("hostname") or "(unknown)"
            score = entry.get("score", 0)
            priority = entry.get("priority", "unknown")
            tags = ",".join(entry.get("tags", []))
            lines.append(f"[{score:4}] ({priority}) {label} {tags}")
    record.paths.results_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    metadata.stats.update({f"type_{key}": value for key, value in counts.items()})
    metadata.stats.update({f"status_{code}": value for code, value in status_counter.items()})
    metadata.stats["noise_suppressed"] = noise_count
    for priority, count in priority_counter.items():
        metadata.stats[f"priority_{priority}"] = count
    context.manager.update_metadata(record)
