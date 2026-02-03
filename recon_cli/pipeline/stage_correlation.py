from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlparse

from recon_cli.correlation.graph import Graph
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.feature_defs import FEATURE_KEYS, compute_asn_score
from recon_cli.pipeline.progress import ProgressLogger
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import iter_jsonl


def root_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


class CorrelationStage(Stage):
    name = "correlation"

    def execute(self, context: PipelineContext) -> None:
        results_path = context.record.paths.results_jsonl
        trimmed_path = context.record.paths.trimmed_results_jsonl
        logger = context.logger
        source_path = trimmed_path if trimmed_path.exists() else results_path
        if trimmed_path.exists():
            logger.info("Correlation using trimmed results (%s)", trimmed_path.name)
        records = iter_jsonl(source_path)
        if records is None:
            logger.info("No results recorded; skipping correlation stage")
            return

        graph = Graph()
        ip_hosts: Dict[str, set] = defaultdict(set)
        asn_hosts: Dict[str, set] = defaultdict(set)
        provider_hosts: Dict[str, set] = defaultdict(set)
        api_endpoints: Dict[str, set] = defaultdict(set)
        tech_counter = Counter()
        features_by_host: Dict[str, Dict[str, float]] = defaultdict(lambda: {key: 0.0 for key in FEATURE_KEYS})
        tag_histogram: Dict[str, Counter] = defaultdict(Counter)

        processed = 0
        runtime = context.runtime_config
        max_records = max(0, getattr(runtime, "correlation_max_records", 0))
        svg_node_limit = max(0, getattr(runtime, "correlation_svg_node_limit", 0))
        truncated = False
        urls_seen = 0
        api_path_total = 0
        seen_any = False
        progress = ProgressLogger(context.logger, interval=2.0)

        registered_hosts: Dict[str, Tuple[str, str]] = {}

        def ensure_host(host: str) -> Tuple[str, str]:
            if host in registered_hosts:
                return registered_hosts[host]
            root = root_domain(host)
            graph.add_node("domain", root)
            graph.add_node("subdomain", host)
            graph.add_edge("subdomain", host, "belongs_to", "domain", root)
            registered_hosts[host] = (root, host)
            return registered_hosts[host]

        for entry in records:
            if max_records and processed >= max_records:
                truncated = True
                logger.info(
                    "Correlation truncated after %s records (limit=%s)",
                    processed,
                    max_records,
                )
                break
            seen_any = True
            processed += 1
            progress.maybe(
                f"Correlation processed {processed} records (hosts={len(features_by_host)}, urls={urls_seen}, apis={api_path_total})"
            )

            etype = entry.get("type")
            if etype == "hostname":
                host = entry.get("hostname")
                if not host:
                    continue
                root, subdomain = ensure_host(host)
                graph.add_node("domain", root, sources=[entry.get("source")])
                graph.add_node("subdomain", subdomain, tags=entry.get("tags"))
                _ = features_by_host[subdomain]
            elif etype == "asset":
                host = entry.get("hostname")
                ip = entry.get("ip")
                if not host or not ip:
                    continue
                root, subdomain = ensure_host(host)
                features = features_by_host[subdomain]
                graph.add_node(
                    "ip",
                    ip,
                    record_type=entry.get("record_type"),
                    org=entry.get("org"),
                    country=entry.get("country"),
                )
                graph.add_edge("subdomain", subdomain, "resolves_to", "ip", ip, source=entry.get("source"))
                ip_hosts[ip].add(subdomain)
                features["asn_score"] = max(features.get("asn_score", 0.0), compute_asn_score(entry.get("asn")))
                asn = entry.get("asn")
                if asn:
                    graph.add_node("asn", asn, org=entry.get("org"))
                    graph.add_edge("ip", ip, "belongs_to", "asn", asn)
                    asn_hosts[asn].add(subdomain)
            elif etype == "asset_enrichment":
                host = entry.get("hostname")
                ip = entry.get("ip")
                provider = entry.get("provider")
                subdomain = None
                if host:
                    root, subdomain = ensure_host(host)
                if ip:
                    graph.add_node("ip", ip)
                if subdomain and ip:
                    graph.add_edge("subdomain", subdomain, "resolves_to", "ip", ip)
                if provider and subdomain:
                    graph.add_node("provider", provider)
                    graph.add_edge("subdomain", subdomain, "served_by", "provider", provider)
                    provider_hosts[provider].add(subdomain)
            elif etype == "url":
                url = entry.get("url")
                if not url:
                    continue
                urls_seen += 1
                host = entry.get("hostname") or urlparse(url).hostname
                tags = list(entry.get("tags", []))
                graph.add_node(
                    "url",
                    url,
                    status=entry.get("status_code"),
                    tags=tags,
                    priority=entry.get("priority"),
                )
                subdomain = None
                if host:
                    root, subdomain = ensure_host(host)
                    graph.add_edge("subdomain", subdomain, "serves", "url", url, status=entry.get("status_code"))
                    features = features_by_host[subdomain]
                    features["url_count"] = features.get("url_count", 0.0) + 1.0
                parsed = urlparse(url)
                if parsed.path.endswith(".js"):
                    graph.add_edge("url", url, "category", "resource", "javascript")
                if "/api" in (parsed.path or ""):
                    endpoint_host = subdomain or parsed.netloc or ""
                    if endpoint_host:
                        if endpoint_host != subdomain:
                            _, endpoint_host = ensure_host(endpoint_host)
                        path_value = parsed.path or "/"
                        paths = api_endpoints[endpoint_host]
                        if path_value not in paths:
                            paths.add(path_value)
                            api_path_total += 1
                        graph.add_edge("subdomain", endpoint_host, "exposes_api", "endpoint", path_value)
                        features_by_host[endpoint_host]["has_api"] = 1.0
                    if "service:api" not in tags:
                        tags.append("service:api")
                    graph.add_node("url", url, tags=tags)
                if tags:
                    if subdomain:
                        tag_histogram[subdomain].update(tags)
                        if any(tag in {"surface:login", "service:sso", "surface:admin"} for tag in tags):
                            features_by_host[subdomain]["has_login"] = 1.0
                    for tag in tags:
                        graph.add_node("tag", tag)
                        graph.add_edge("url", url, "tag", "tag", tag)
                        if subdomain:
                            graph.add_edge("subdomain", subdomain, "has_tag", "tag", tag)
                if parsed.query:
                    params = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
                    if params:
                        graph.add_edge("url", url, "has_params", "param_group", ",".join(sorted(params)))
                server = entry.get("server")
                if server:
                    tech_label = server.lower()
                    graph.add_node("tech", tech_label)
                    graph.add_edge("url", url, "served_by", "tech", tech_label)
                    if subdomain:
                        graph.add_edge("subdomain", subdomain, "uses", "tech", tech_label)
                    tech_counter[f"server:{tech_label}"] += 1
                for tag in entry.get("tags", []):
                    if tag.startswith("service:") or tag.startswith("env:"):
                        tech_counter[tag] += 1
                        graph.add_node("tag", tag)
                        graph.add_edge("url", url, "tag", "tag", tag)
                        if subdomain:
                            graph.add_edge("subdomain", subdomain, "has_tag", "tag", tag)
            elif etype == "finding":
                description = entry.get("description") or entry.get("url") or entry.get("hostname") or "finding"
                finding_id = f"{entry.get('source','finding')}::{hash(description)}"
                graph.add_node(
                    "finding",
                    finding_id,
                    description=description,
                    priority=entry.get("priority"),
                    score=entry.get("score"),
                )
                host = entry.get("hostname")
                if host:
                    root, subdomain = ensure_host(host)
                    graph.add_edge("finding", finding_id, "impacts", "subdomain", subdomain)
                    features = features_by_host[subdomain]
                    features["finding_count"] = features.get("finding_count", 0.0) + 1.0
                    source = str(entry.get("source", ""))
                    if source.startswith("active-js-secrets") or source.startswith("secrets"):
                        hits = entry.get("details", {}).get("hits")
                        increment = float(len(hits)) if isinstance(hits, list) and hits else 1.0
                        features["js_secrets_count"] = features.get("js_secrets_count", 0.0) + increment
                url = entry.get("details", {}).get("url") or entry.get("url")
                if url:
                    graph.add_node("url", url)
                    graph.add_edge("finding", finding_id, "references", "url", url)

        if not seen_any:
            logger.info("No results recorded; skipping correlation stage")
            return

        logger.info(
            "Correlation building artifacts from %s records (hosts=%s, urls=%s, apis=%s)",
            processed,
            len(features_by_host),
            urls_seen,
            api_path_total,
        )

        artifacts_dir = context.record.paths.ensure_subdir("correlation")
        graph_path = artifacts_dir / "graph.json"
        try:
            graph.save(graph_path)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to save correlation graph JSON: %s", exc)
            graph_path = None
        svg_path = artifacts_dir / "graph.svg"
        node_count = graph.node_count()
        svg_generated = False
        if svg_node_limit and node_count > svg_node_limit:
            logger.info(
                "Skipping SVG generation; node count %s exceeds limit %s",
                node_count,
                svg_node_limit,
            )
        else:
            try:
                svg_generated = graph.save_svg(svg_path)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to render correlation SVG: %s", exc)
                svg_generated = False

        clusters = {
            "ip": [
                {"value": ip, "hosts": sorted(hosts)}
                for ip, hosts in ip_hosts.items()
                if len(hosts) > 1
            ],
            "asn": [
                {"value": asn, "hosts": sorted(hosts)}
                for asn, hosts in asn_hosts.items()
                if len(hosts) > 1
            ],
            "provider": [
                {"value": provider, "hosts": sorted(hosts)}
                for provider, hosts in provider_hosts.items()
                if len(hosts) > 1
            ],
        }
        (artifacts_dir / "clusters.json").write_text(json.dumps(clusters, indent=2, sort_keys=True), encoding="utf-8")

        if tech_counter:
            (artifacts_dir / "tech_summary.json").write_text(
                json.dumps(dict(tech_counter.most_common()), indent=2, sort_keys=True),
                encoding="utf-8",
            )

        api_report = {host: sorted(paths) for host, paths in api_endpoints.items() if paths}
        if api_report:
            (artifacts_dir / "api_endpoints.json").write_text(
                json.dumps(api_report, indent=2, sort_keys=True), encoding="utf-8"
            )
        api_clusters = [
            {"subdomain": host, "paths": sorted(paths), "count": len(paths)}
            for host, paths in api_endpoints.items()
            if len(paths) > 1
        ]
        api_clusters.sort(key=lambda item: item["count"], reverse=True)

        provider_common = [
            {"provider": provider, "hosts": sorted(hosts), "count": len(hosts)}
            for provider, hosts in provider_hosts.items()
        ]
        provider_common.sort(key=lambda item: item["count"], reverse=True)

        top_nodes = graph.top_connected(limit=10)

        correlation_summary = {
            "graph_nodes": node_count,
            "graph_edges": graph.edge_count(),
            "ip_clusters": len(clusters["ip"]),
            "asn_clusters": len(clusters["asn"]),
            "provider_clusters": len(clusters["provider"]),
            "api_hosts": len(api_report),
            "top_nodes": top_nodes,
            "top_api_clusters": api_clusters[:10],
            "common_providers": provider_common[:10],
            "truncated": truncated,
            "max_records": max_records,
            "processed": processed,
        }
        if svg_generated:
            correlation_summary["graph_svg"] = str(svg_path)
        (artifacts_dir / "correlation_report.json").write_text(
            json.dumps(
                {
                    "summary": correlation_summary,
                    "top_ip_clusters": clusters["ip"][:5],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        for host, counter in tag_histogram.items():
            total = sum(counter.values())
            if total:
                entropy = 0.0
                for count in counter.values():
                    p = count / total
                    entropy -= p * math.log2(p)
                features_by_host[host]["tag_entropy"] = entropy

        features_payload = {
            host: {key: float(value) for key, value in features.items()} for host, features in features_by_host.items()
        }
        (artifacts_dir / "features.json").write_text(json.dumps(features_payload, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("correlation", {})
        stats.update(correlation_summary)
        if tech_counter:
            stats["top_tags"] = tech_counter.most_common(10)
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Correlation graph built (nodes=%s, edges=%s)",
            graph.node_count(),
            graph.edge_count(),
        )
