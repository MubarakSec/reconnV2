from __future__ import annotations

import json
from typing import List
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError
from recon_cli.utils import validation


class PassiveEnumerationStage(Stage):
    """
    Passive subdomain discovery.
    """

    name = "passive_enumeration"

    def is_enabled(self, context: PipelineContext) -> bool:
        return context.record.spec.profile in {"passive", "full"}

    def execute(self, context: PipelineContext) -> None:
        logger = context.logger
        executor = context.executor
        targets = context.targets
        artifacts = context.record.paths
        allow_ip = context.record.spec.allow_ip
        tool_timeout = context.runtime_config.tool_timeout

        logger.info("Starting passive enumeration for %d targets", len(targets))
        logger.debug("Tool timeout: %ds, Allow IP: %s", tool_timeout, allow_ip)

        subfinder_out = artifacts.artifact("subfinder.txt")
        amass_out = artifacts.artifact("amass.json")
        wayback_out = artifacts.artifact("waybackurls.txt")
        passive_hosts_out = artifacts.artifact("passive_hosts.txt")
        targets_file = artifacts.artifact("targets.txt")

        subfinder_hosts: set[str] = set()
        amass_hosts: set[str] = set()
        wayback_urls: List[str] = []
        seed_hosts: set[str] = set()
        for target in targets:
            if allow_ip and validation.is_ip(target):
                seed_hosts.add(target)
                continue
            try:
                seed_hosts.add(validation.normalize_hostname(target))
            except ValueError:
                logger.debug("Skipping invalid target: %s", target)
                continue

        if executor.available("subfinder"):
            logger.info("Running subfinder...")
            try:
                completed = executor.run(
                    ["subfinder", "-dL", str(targets_file), "-silent"],
                    capture_output=True,
                    check=False,
                    timeout=tool_timeout,
                )
                output = (completed.stdout or "") if hasattr(completed, "stdout") else ""
                if output:
                    lines = [line.strip() for line in output.splitlines() if line.strip()]
                    subfinder_hosts.update(lines)
                    subfinder_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    logger.info("subfinder found %d subdomains", len(lines))
                else:
                    logger.debug("subfinder returned no output")
            except CommandError as exc:
                logger.warning("subfinder execution failed: %s", exc)
        else:
            logger.warning("subfinder not available; skipping")
            note_missing_tool(context, "subfinder")

        if executor.available("amass"):
            logger.info("Running amass passive enum...")
            try:
                executor.run(
                    [
                        "amass",
                        "enum",
                        "-passive",
                        "-df",
                        str(targets_file),
                        "-o",
                        str(amass_out),
                    ],
                    check=False,
                    timeout=tool_timeout,
                )
                if amass_out.exists():
                    with amass_out.open("r", encoding="utf-8") as handle:
                        for line in handle:
                            try:
                                payload = json.loads(line)
                            except json.JSONDecodeError:
                                payload = None
                            if isinstance(payload, dict):
                                name = payload.get("name")
                                if name:
                                    amass_hosts.add(name.strip())
                                    continue
                            host = line.strip()
                            if host:
                                amass_hosts.add(host)
            except CommandError:
                context.logger.warning("amass execution failed; continuing")
        else:
            context.logger.warning("amass not available; skipping")
            note_missing_tool(context, "amass")

        wayback_cmd = None
        if executor.available("waybackurls"):
            wayback_cmd = "waybackurls"
        elif executor.available("gau"):
            wayback_cmd = "gau"
        if wayback_cmd:
            aggregated: List[str] = []
            for target in targets:
                try:
                    completed = executor.run([wayback_cmd, target], capture_output=True, check=False, timeout=tool_timeout)
                except CommandError:
                    context.logger.warning("%s failed for %s", wayback_cmd, target)
                    continue
                output = (completed.stdout or "") if hasattr(completed, "stdout") else ""
                if output:
                    aggregated.extend(line.strip() for line in output.splitlines() if line.strip())
            if aggregated:
                wayback_out.write_text("\n".join(aggregated) + "\n", encoding="utf-8")
                wayback_urls.extend(aggregated)
        else:
            context.logger.warning("waybackurls/gau not available; skipping URL discovery")
            note_missing_tool(context, "waybackurls/gau")

        tracker = context.results
        for hostname in sorted(subfinder_hosts):
            try:
                normalized = validation.normalize_hostname(hostname)
            except ValueError:
                continue
            payload = {
                "type": "hostname",
                "source": "subfinder",
                "hostname": normalized,
            }
            tracker.append(payload)
        for hostname in sorted(amass_hosts):
            try:
                normalized = validation.normalize_hostname(hostname)
            except ValueError:
                continue
            payload = {
                "type": "hostname",
                "source": "amass",
                "hostname": normalized,
            }
            tracker.append(payload)
        for url in wayback_urls:
            parsed = urlparse(url)
            host = parsed.hostname
            hostname = None
            if host:
                try:
                    hostname = validation.normalize_hostname(host)
                except ValueError:
                    hostname = None
            if not context.url_allowed(url):
                continue
            payload = {
                "type": "url",
                "source": wayback_cmd or "waybackurls",
                "url": url,
                "hostname": hostname,
            }
            tracker.append(payload)

        for hostname in sorted(seed_hosts):
            tracker.append(
                {
                    "type": "hostname",
                    "source": "input",
                    "hostname": hostname,
                }
            )

        passive_hosts_set: set[str] = set()
        for host in (subfinder_hosts | amass_hosts | seed_hosts):
            if not host:
                continue
            if allow_ip and validation.is_ip(host):
                passive_hosts_set.add(host)
                continue
            try:
                passive_hosts_set.add(validation.normalize_hostname(host))
            except ValueError:
                continue
        passive_hosts = sorted(passive_hosts_set)
        if passive_hosts:
            passive_hosts_out.write_text("\n".join(passive_hosts) + "\n", encoding="utf-8")
        context.record.metadata.stats["passive_hostnames"] = len(passive_hosts)
        context.manager.update_metadata(context.record)
