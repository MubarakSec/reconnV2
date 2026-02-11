from __future__ import annotations

import json
import time
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
        tracker = context.results

        logger.info("Starting passive enumeration for %d targets", len(targets))
        logger.debug("Tool timeout: %ds, Allow IP: %s", tool_timeout, allow_ip)

        subfinder_out = artifacts.artifact("subfinder.txt")
        amass_out = artifacts.artifact("amass.json")
        wayback_out = artifacts.artifact("waybackurls.txt")
        wayback_tmp = artifacts.artifact("wayback_tmp.txt")
        passive_hosts_out = artifacts.artifact("passive_hosts.txt")
        targets_file = artifacts.artifact("targets.txt")

        subfinder_hosts: set[str] = set()
        amass_hosts: set[str] = set()
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
            wayback_targets: list[str] = []
            seen_targets: set[str] = set()
            for target in targets:
                if allow_ip and validation.is_ip(target):
                    continue
                if target in seen_targets:
                    continue
                seen_targets.add(target)
                wayback_targets.append(target)

            max_wayback_urls = max(0, int(getattr(context.runtime_config, "wayback_max_urls", 0) or 0))
            max_wayback_per_target = max(
                0, int(getattr(context.runtime_config, "wayback_max_per_target", 0) or 0)
            )
            fair_share = bool(getattr(context.runtime_config, "wayback_fair_share", True))
            wayback_total = 0
            wrote_any = False
            wayback_targets_processed = 0
            wayback_targets_skipped = 0
            global_cap_hit = False

            if wayback_targets:
                with wayback_out.open("w", encoding="utf-8") as out_handle:
                    for idx, target in enumerate(wayback_targets, 1):
                        if max_wayback_urls and wayback_total >= max_wayback_urls:
                            wayback_targets_skipped = len(wayback_targets) - idx + 1
                            global_cap_hit = True
                            logger.warning(
                                "%s URL limit reached (%s); skipping remaining targets",
                                wayback_cmd,
                                max_wayback_urls,
                            )
                            break
                        wayback_targets_processed += 1
                        target_budget = max_wayback_per_target
                        if fair_share and max_wayback_urls:
                            remaining_targets = len(wayback_targets) - idx + 1
                            remaining_budget = max(0, max_wayback_urls - wayback_total)
                            if remaining_targets > 0 and remaining_budget > 0:
                                fair_budget = max(1, (remaining_budget + remaining_targets - 1) // remaining_targets)
                                if target_budget <= 0:
                                    target_budget = fair_budget
                                else:
                                    target_budget = min(target_budget, fair_budget)
                        if target_budget > 0:
                            logger.info(
                                "Running %s (%s/%s): %s [budget=%d URLs]",
                                wayback_cmd,
                                idx,
                                len(wayback_targets),
                                target,
                                target_budget,
                            )
                        else:
                            logger.info("Running %s (%s/%s): %s", wayback_cmd, idx, len(wayback_targets), target)
                        start = time.monotonic()
                        wayback_tmp.unlink(missing_ok=True)
                        try:
                            executor.run_to_file(
                                [wayback_cmd, target],
                                wayback_tmp,
                                timeout=tool_timeout,
                                redact=False,
                            )
                        except CommandError:
                            context.logger.warning("%s failed for %s", wayback_cmd, target)
                            continue
                        elapsed = time.monotonic() - start

                        if not wayback_tmp.exists():
                            logger.debug("%s returned no output for %s", wayback_cmd, target)
                            logger.info("%s finished for %s in %.1fs", wayback_cmd, target, elapsed)
                            continue

                        url_added = 0
                        budget_reached = False
                        with wayback_tmp.open("r", encoding="utf-8", errors="ignore") as handle:
                            for line in handle:
                                url = line.strip()
                                if not url:
                                    continue
                                parsed = urlparse(url)
                                if not parsed.scheme or not parsed.netloc:
                                    continue
                                out_handle.write(url + "\n")
                                wrote_any = True
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
                                wayback_total += 1
                                url_added += 1
                                out_handle.write(url + "\n")
                                wrote_any = True
                                if target_budget and url_added >= target_budget:
                                    logger.warning(
                                        "%s per-target URL budget reached for %s (%s); moving to next target",
                                        wayback_cmd,
                                        target,
                                        target_budget,
                                    )
                                    budget_reached = True
                                    break
                                if max_wayback_urls and wayback_total >= max_wayback_urls:
                                    logger.warning(
                                        "%s URL limit reached (%s); stopping ingestion",
                                        wayback_cmd,
                                        max_wayback_urls,
                                    )
                                    global_cap_hit = True
                                    break
                        wayback_tmp.unlink(missing_ok=True)
                        logger.info(
                            "%s finished for %s in %.1fs (%d URLs%s)",
                            wayback_cmd,
                            target,
                            elapsed,
                            url_added,
                            ", budget reached" if budget_reached else "",
                        )
                        if max_wayback_urls and wayback_total >= max_wayback_urls:
                            wayback_targets_skipped = len(wayback_targets) - idx
                            break

                stats = context.record.metadata.stats.setdefault("wayback", {})
                stats.update(
                    {
                        "tool": wayback_cmd,
                        "targets_total": len(wayback_targets),
                        "targets_processed": wayback_targets_processed,
                        "targets_skipped": wayback_targets_skipped,
                        "urls_ingested": wayback_total,
                        "max_urls": max_wayback_urls,
                        "max_per_target": max_wayback_per_target,
                        "fair_share": fair_share,
                        "global_cap_hit": bool(global_cap_hit or (max_wayback_urls and wayback_total >= max_wayback_urls)),
                    }
                )
                context.manager.update_metadata(context.record)
                logger.info(
                    "%s summary: processed=%d skipped=%d ingested=%d",
                    wayback_cmd,
                    wayback_targets_processed,
                    wayback_targets_skipped,
                    wayback_total,
                )

            if not wrote_any and wayback_out.exists():
                wayback_out.unlink(missing_ok=True)
        else:
            context.logger.warning("waybackurls/gau not available; skipping URL discovery")
            note_missing_tool(context, "waybackurls/gau")

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
