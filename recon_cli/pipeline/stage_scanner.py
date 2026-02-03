from __future__ import annotations

from typing import Dict, List, Set
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.tools.executor import CommandExecutor
from recon_cli.utils.jsonl import read_jsonl

try:
    from recon_cli.scanners import integrations as scanner_integrations
except ImportError:  # pragma: no cover - optional dependency
    scanner_integrations = None  # type: ignore


class ScannerStage(Stage):
    name = "scanner"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(context.record.spec.scanners) or bool(getattr(context.runtime_config, "auto_scanners", True))

    def execute(self, context: PipelineContext) -> None:
        if scanner_integrations is None:
            context.logger.warning("Scanner integrations unavailable; skipping scanner stage")
            return
        scanners = [s.lower() for s in context.record.spec.scanners]
        if not scanners and getattr(context.runtime_config, "auto_scanners", True):
            scanners = ["nuclei", "wpscan"]
        if not scanners:
            return
        available = []
        for scanner in scanners:
            if scanner not in scanner_integrations.available_scanners():
                context.logger.warning("Unknown scanner requested: %s", scanner)
                continue
            if not CommandExecutor.available(scanner):
                context.logger.info("Scanner %s not available in PATH; skipping", scanner)
                continue
            available.append(scanner)
        if not available:
            context.logger.info("No scanners to execute after availability checks")
            return

        items = read_jsonl(context.record.paths.results_jsonl)
        url_entries = [entry for entry in items if entry.get("type") == "url"]
        if not url_entries:
            context.logger.info("No URL entries available for scanner stage")
            return

        host_info: Dict[str, Dict[str, object]] = {}
        for entry in url_entries:
            host = entry.get("hostname") or (entry.get("url") and urlparse(entry["url"]).hostname)
            if not host:
                continue
            data = host_info.setdefault(
                host,
                {"urls": [], "tags": set(), "servers": set(), "api": False, "technologies": set()},
            )
            url = entry.get("url")
            if url:
                data["urls"].append(url)
                path = urlparse(url).path.lower()
                if "/api" in path:
                    data["api"] = True
            for tag in entry.get("tags", []):
                data["tags"].add(tag)
                if tag == "service:api":
                    data["api"] = True
            server = entry.get("server")
            if server:
                data["servers"].add(server.lower())
            technologies = entry.get("technologies") or []
            if isinstance(technologies, list):
                data["technologies"].update({str(item).lower() for item in technologies if item})
            elif technologies:
                data["technologies"].add(str(technologies).lower())

        runtime = context.runtime_config
        scanner_dir = context.record.paths.ensure_subdir("scanners")
        summary: Dict[str, Dict[str, object]] = {}

        if "nuclei" in available:
            api_hosts = [host for host, info in host_info.items() if info.get("api")]
            if not api_hosts:
                api_hosts = list(host_info.keys())
            api_hosts = api_hosts[: runtime.max_scanner_hosts]
            findings: List[scanner_integrations.ScannerFinding] = []
            nuclei_tags: List[str] = []
            if getattr(runtime, "nuclei_tags", None):
                nuclei_tags = [tag.strip() for tag in str(runtime.nuclei_tags).split(",") if tag.strip()]
            targets: List[str] = []
            for host in api_hosts:
                urls = host_info[host]["urls"]
                base_url = urls[0] if urls else f"https://{host}"
                targets.append(base_url)
            batch_size = max(1, int(getattr(runtime, "nuclei_batch_size", 1)))
            pending_batches = [targets[i : i + batch_size] for i in range(0, len(targets), batch_size)]
            timed_out_batches = 0
            batches_run = 0
            retried_singles: Set[str] = set()
            while pending_batches:
                batch = pending_batches.pop(0)
                if not batch:
                    continue
                computed_timeout = int(getattr(runtime, "nuclei_batch_timeout_base", 300)) + int(
                    getattr(runtime, "nuclei_batch_timeout_per_target", 45)
                ) * len(batch)
                max_timeout = int(getattr(runtime, "nuclei_batch_timeout_max", runtime.scanner_timeout))
                if max_timeout < runtime.scanner_timeout:
                    max_timeout = runtime.scanner_timeout
                batch_timeout = min(max_timeout, max(computed_timeout, runtime.scanner_timeout))
                result = scanner_integrations.run_nuclei_batch(
                    context.executor,
                    context.logger,
                    batch,
                    scanner_dir,
                    batch_timeout,
                    tags=nuclei_tags or None,
                    request_timeout=int(getattr(runtime, "nuclei_timeout", 10)),
                    retries=int(getattr(runtime, "nuclei_retries", 1)),
                )
                batches_run += 1
                for finding in result.findings:
                    context.results.append(finding.payload)
                findings.extend(result.findings)
                if result.stats.get("timed_out"):
                    timed_out_batches += 1
                    if len(batch) > 1:
                        mid = len(batch) // 2
                        pending_batches.insert(0, batch[mid:])
                        pending_batches.insert(0, batch[:mid])
                    else:
                        single_target = batch[0]
                        if single_target not in retried_singles:
                            retried_singles.add(single_target)
                            single_timeout = int(getattr(runtime, "nuclei_single_timeout", batch_timeout))
                            retry_result = scanner_integrations.run_nuclei_batch(
                                context.executor,
                                context.logger,
                                batch,
                                scanner_dir,
                                max(single_timeout, batch_timeout),
                                tags=nuclei_tags or None,
                                request_timeout=int(getattr(runtime, "nuclei_timeout", 10)),
                                retries=int(getattr(runtime, "nuclei_retries", 1)),
                            )
                            batches_run += 1
                            for finding in retry_result.findings:
                                context.results.append(finding.payload)
                            findings.extend(retry_result.findings)
            summary["nuclei"] = {
                "targets": len(api_hosts),
                "findings": len(findings),
                "batches": batches_run,
                "timeouts": timed_out_batches,
            }

        if "wpscan" in available:

            def is_wordpress(info: Dict[str, object]) -> bool:
                tags = {t.lower() for t in info.get("tags", set())}
                if any("wordpress" in tag for tag in tags):
                    return True
                techs = info.get("technologies", set())
                if any("wordpress" in tech for tech in techs):
                    return True
                servers = info.get("servers", set())
                if any("wordpress" in server for server in servers):
                    return True
                urls = info.get("urls", [])
                for url in urls:
                    path = urlparse(url).path.lower()
                    if any(token in path for token in ("/wp-", "/wp-admin", "/wp-content", "/wp-json", "/xmlrpc.php")):
                        return True
                return False

            wp_hosts = [host for host, info in host_info.items() if is_wordpress(info)]
            wp_hosts = wp_hosts[: runtime.max_scanner_hosts]
            findings = []
            for host in wp_hosts:
                urls = host_info[host]["urls"]
                base_url = urls[0] if urls else f"https://{host}"
                result = scanner_integrations.run_wpscan(
                    context.executor,
                    context.logger,
                    host,
                    base_url,
                    scanner_dir,
                    runtime.scanner_timeout,
                )
                for finding in result.findings:
                    context.results.append(finding.payload)
                findings.extend(result.findings)
            summary["wpscan"] = {
                "targets": len(wp_hosts),
                "findings": len(findings),
            }

        if summary:
            stats = context.record.metadata.stats.setdefault("scanners", {})
            for name, data in summary.items():
                stats[name] = data
            context.manager.update_metadata(context.record)
            context.logger.info(
                "Scanner summary: %s",
                ", ".join(f"{name}:{data['findings']}" for name, data in summary.items()),
            )
