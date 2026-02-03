from __future__ import annotations

import socket
from typing import List, Tuple

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError


class ResolveStage(Stage):
    name = "dns_resolve"

    def execute(self, context: PipelineContext) -> None:

        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts to resolve")
            return

        hosts: List[str] = []
        with hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if host:
                    hosts.append(host)

        total_hosts = len(hosts)
        if total_hosts == 0:
            context.logger.info("No hosts to resolve")
            return

        output_path = context.record.paths.artifact("massdns.out")
        tracker = context.results
        executor = context.executor
        resolutions: List[tuple[str, str]] = []

        if executor.available("massdns") and context.runtime_config.resolvers_file:
            context.logger.info("Resolving %s hosts with massdns", total_hosts)
            cmd = [
                "massdns",
                "-r",
                str(context.runtime_config.resolvers_file),
                "-t",
                "A",
                "-o",
                "S",
                "-w",
                str(output_path),
                str(hosts_path),
            ]
            try:
                executor.run(cmd, check=False, timeout=context.runtime_config.tool_timeout)
            except CommandError:
                context.logger.warning("massdns execution failed; falling back to system resolver")
        else:
            if not executor.available("massdns"):
                context.logger.info("massdns not available; using system resolver for %s hosts", total_hosts)
                note_missing_tool(context, "massdns")
            else:
                context.logger.info("Resolvers file missing; system resolver fallback for %s hosts", total_hosts)

        if not output_path.exists() or output_path.stat().st_size == 0:
            resolutions = self._fallback_resolve(context, hosts)
            if resolutions:
                with output_path.open("w", encoding="utf-8") as handle:
                    for hostname, ip in resolutions:
                        handle.write(f"{hostname} A {ip}\n")
        else:
            with output_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        hostname = parts[0].rstrip(".")
                        ip = parts[-1]
                        resolutions.append((hostname, ip))

        for hostname, ip in resolutions:
            payload = {
                "type": "asset",
                "source": "massdns",
                "hostname": hostname,
                "ip": ip,
                "record_type": "A",
            }
            tracker.append(payload)
        context.record.metadata.stats["resolved_hosts"] = len({host for host, _ in resolutions})
        context.manager.update_metadata(context.record)

    def _fallback_resolve(self, context: PipelineContext, hosts: List[str]) -> List[Tuple[str, str]]:
        limit = context.runtime_config.fallback_dns_limit
        results: List[Tuple[str, str]] = []
        for idx, target in enumerate(hosts):
            if limit and idx >= limit:
                context.logger.warning(
                    "Fallback DNS limit reached (%s hosts); skipping remaining %s entries",
                    limit,
                    max(0, len(hosts) - limit),
                )
                break
            try:
                infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                continue
            ips = {info[4][0] for info in infos}
            if ips:
                for ip in ips:
                    results.append((target, ip))
            if (idx + 1) % 50 == 0:
                context.logger.debug(
                    "Fallback DNS progress: processed %s hosts (%s resolved)",
                    idx + 1,
                    len(results),
                )
        return results
