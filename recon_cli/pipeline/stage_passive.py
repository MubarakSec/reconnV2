from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError
from recon_cli.utils import validation


class PassiveEnumerationStage(Stage):
    """
    Passive subdomain discovery.
    """

    name = "passive_enumeration"
    provides = ["hostname"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return context.record.spec.profile in {"passive", "full"}

    def execute(self, context: PipelineContext) -> None:
        logger = context.logger
        targets = context.targets
        artifacts = context.record.paths
        allow_ip = context.record.spec.allow_ip
        tool_timeout = context.runtime_config.tool_timeout
        tracker = context.results

        logger.info("Starting passive enumeration for %d targets", len(targets))
        logger.debug("Tool timeout: %ds, Allow IP: %s", tool_timeout, allow_ip)

        amass_out = artifacts.artifact("amass.json")
        wayback_out = artifacts.artifact("waybackurls.txt")
        passive_hosts_out = artifacts.artifact("passive_hosts.txt")
        targets_file = artifacts.artifact("targets.txt")

        # 1. Normalize and seed hosts (input hosts)
        seed_hosts: set[str] = set()
        hostname_targets: list[str] = []
        for target in targets:
            if allow_ip and validation.is_ip(target):
                seed_hosts.add(target)
                continue
            try:
                norm = validation.normalize_hostname(target)
                seed_hosts.add(norm)
                hostname_targets.append(norm)
            except ValueError:
                logger.debug("Skipping invalid target: %s", target)
                continue

        subfinder_hosts: set[str] = set()
        amass_hosts: set[str] = set()

        if hostname_targets:
            # 2. Subfinder
            subfinder_hosts = self._run_subfinder(context, targets_file, tool_timeout)

            # 3. Amass
            amass_hosts = self._run_amass(
                context, targets_file, tool_timeout, amass_out
            )
        else:
            logger.info("Skipping passive subdomain discovery (targets are all IPs)")

        # 4. Wayback URL discovery (includes fallback)
        self._run_wayback(context, list(targets), tool_timeout, wayback_out)

        # 5. Result Collation & Tracking
        for hostname in sorted(subfinder_hosts):
            try:
                normalized = validation.normalize_hostname(hostname)
                tracker.append(
                    {"type": "hostname", "source": "subfinder", "hostname": normalized}
                )
            except ValueError:
                continue
        for hostname in sorted(amass_hosts):
            try:
                normalized = validation.normalize_hostname(hostname)
                tracker.append(
                    {"type": "hostname", "source": "amass", "hostname": normalized}
                )
            except ValueError:
                continue
        for hostname in sorted(seed_hosts):
            tracker.append(
                {"type": "hostname", "source": "input", "hostname": hostname}
            )

        # 6. Final Host Consolidation and Artifact Generation
        passive_hosts_set: set[str] = set()
        for host in subfinder_hosts | amass_hosts | seed_hosts:
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
            passive_hosts_out.write_text(
                "\n".join(passive_hosts) + "\n", encoding="utf-8"
            )

        context.record.metadata.stats["passive_hostnames"] = len(passive_hosts)
        context.manager.update_metadata(context.record)

    def _run_subfinder(
        self, context: PipelineContext, targets_file: Any, tool_timeout: int
    ) -> set[str]:
        logger = context.logger
        executor = context.executor
        subfinder_hosts: set[str] = set()
        subfinder_out = context.record.paths.artifact("subfinder.txt")

        if executor.available("subfinder"):
            logger.info("Running subfinder...")
            try:
                completed = executor.run(
                    ["subfinder", "-dL", str(targets_file), "-silent"],
                    capture_output=True,
                    check=False,
                    timeout=tool_timeout,
                )
                output = (
                    (completed.stdout or "") if hasattr(completed, "stdout") else ""
                )
                if output:
                    lines = [
                        line.strip() for line in output.splitlines() if line.strip()
                    ]
                    subfinder_hosts.update(lines)
                    subfinder_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    logger.info("subfinder found %d subdomains", len(lines))
                else:
                    logger.debug("subfinder returned no output")
            except CommandError as exc:
                logger.warning("subfinder execution failed: %s", exc)
            except Exception as exc:
                logger.error("Unexpected error in subfinder: %s", exc)
        else:
            logger.warning("subfinder not available; skipping")
            note_missing_tool(context, "subfinder")
        return subfinder_hosts

    def _run_amass(
        self,
        context: PipelineContext,
        targets_file: Any,
        tool_timeout: int,
        amass_out: Any,
    ) -> set[str]:
        logger = context.logger
        executor = context.executor
        amass_hosts: set[str] = set()

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
                                if isinstance(payload, dict):
                                    name = payload.get("name")
                                    if name:
                                        amass_hosts.add(name.strip())
                                        continue
                            except json.JSONDecodeError:
                                logger.debug(
                                    "Invalid JSON in amass output: %s",
                                    line.strip()[:100],
                                )

                            host = line.strip()
                            if host:
                                amass_hosts.add(host)
            except CommandError:
                logger.warning("amass execution failed; continuing")
            except Exception as exc:
                logger.error("Unexpected error in amass: %s", exc)
        else:
            logger.warning("amass not available; skipping")
            note_missing_tool(context, "amass")
        return amass_hosts

    def _run_wayback(
        self,
        context: PipelineContext,
        targets: list[str],
        tool_timeout: int,
        wayback_out: Any,
    ) -> None:
        logger = context.logger
        executor = context.executor
        artifacts = context.record.paths
        wayback_tmp = artifacts.artifact("wayback_tmp.txt")
        allow_ip = context.record.spec.allow_ip
        tracker = context.results

        wayback_cmd = None
        if executor.available("waybackurls"):
            wayback_cmd = "waybackurls"
        elif executor.available("gau"):
            wayback_cmd = "gau"

        wayback_targets: list[str] = []
        seen_targets: set[str] = set()
        for target in targets:
            if allow_ip and validation.is_ip(target):
                continue
            if target in seen_targets:
                continue
            seen_targets.add(target)
            wayback_targets.append(target)

        if not wayback_targets:
            return

        max_wayback_urls = max(
            0, int(getattr(context.runtime_config, "wayback_max_urls", 0) or 0)
        )
        max_wayback_per_target = max(
            0, int(getattr(context.runtime_config, "wayback_max_per_target", 0) or 0)
        )
        fair_share = bool(getattr(context.runtime_config, "wayback_fair_share", True))

        wayback_total = 0
        wrote_any = False
        wayback_targets_processed = 0
        wayback_targets_skipped = 0
        global_cap_hit = False

        with wayback_out.open("w", encoding="utf-8") as out_handle:
            for idx, target in enumerate(wayback_targets, 1):
                if max_wayback_urls and wayback_total >= max_wayback_urls:
                    wayback_targets_skipped = len(wayback_targets) - idx + 1
                    global_cap_hit = True
                    logger.warning(
                        "Wayback URL limit reached (%s); skipping remaining targets",
                        max_wayback_urls,
                    )
                    break

                wayback_targets_processed += 1
                target_budget = max_wayback_per_target
                if fair_share and max_wayback_urls:
                    remaining_targets = len(wayback_targets) - idx + 1
                    remaining_budget = max(0, max_wayback_urls - wayback_total)
                    if remaining_targets > 0 and remaining_budget > 0:
                        fair_budget = max(
                            1,
                            (remaining_budget + remaining_targets - 1)
                            // remaining_targets,
                        )
                        if target_budget <= 0:
                            target_budget = fair_budget
                        else:
                            target_budget = min(target_budget, fair_budget)

                if wayback_cmd:
                    logger.info(
                        "Running %s (%s/%s): %s%s",
                        wayback_cmd,
                        idx,
                        len(wayback_targets),
                        target,
                        f" [budget={target_budget} URLs]" if target_budget > 0 else "",
                    )
                    start = time.monotonic()
                    wayback_tmp.unlink(missing_ok=True)
                    try:
                        executor.run_to_file(
                            [wayback_cmd, target],
                            wayback_tmp,
                            timeout=tool_timeout,
                            redact=False,
                        )
                        elapsed = time.monotonic() - start
                    except CommandError:
                        logger.warning("%s failed for %s", wayback_cmd, target)
                        continue
                    except Exception as exc:
                        logger.error(
                            "Unexpected error in %s for %s: %s",
                            wayback_cmd,
                            target,
                            exc,
                        )
                        continue

                    if not wayback_tmp.exists():
                        logger.debug(
                            "%s returned no output for %s", wayback_cmd, target
                        )
                        continue

                    url_added = 0
                    budget_reached = False
                    with wayback_tmp.open(
                        "r", encoding="utf-8", errors="ignore"
                    ) as handle:
                        for line in handle:
                            url = line.strip()
                            if not url:
                                continue
                            parsed = urlparse(url)
                            if not parsed.scheme or not parsed.netloc:
                                continue
                            host = parsed.hostname
                            hostname = None
                            if host:
                                try:
                                    hostname = validation.normalize_hostname(host)
                                except ValueError:
                                    logger.debug(
                                        "Failed to normalize hostname: %s", host
                                    )

                            if not context.url_allowed(url):
                                continue

                            payload = {
                                "type": "url",
                                "source": wayback_cmd,
                                "url": url,
                                "hostname": hostname,
                            }
                            tracker.append(payload)
                            url_added += 1
                            out_handle.write(url + "\n")
                            wrote_any = True

                            if target_budget and url_added >= target_budget:
                                budget_reached = True
                                break
                            if (
                                max_wayback_urls
                                and (wayback_total + url_added) >= max_wayback_urls
                            ):
                                global_cap_hit = True
                                break

                    wayback_total += url_added
                    logger.info(
                        "%s finished for %s in %.1fs (%d URLs%s)",
                        wayback_cmd,
                        target,
                        elapsed,
                        url_added,
                        ", budget reached" if budget_reached else "",
                    )
                    wayback_tmp.unlink(missing_ok=True)

                else:
                    # FALLBACK API
                    logger.info(
                        "Using Wayback API fallback (%s/%s): %s%s",
                        idx,
                        len(wayback_targets),
                        target,
                        f" [budget={target_budget} URLs]" if target_budget > 0 else "",
                    )
                    start = time.monotonic()
                    limit = target_budget if target_budget > 0 else 10000
                    urls = self._run_wayback_api_fallback(context, target, limit)
                    elapsed = time.monotonic() - start

                    url_added = 0
                    budget_reached = False
                    for url in urls:
                        if not url:
                            continue
                        parsed = urlparse(url)
                        if not parsed.scheme or not parsed.netloc:
                            continue
                        host = parsed.hostname
                        hostname = None
                        if host:
                            try:
                                hostname = validation.normalize_hostname(host)
                            except ValueError:
                                logger.debug("Failed to normalize hostname: %s", host)

                        if not context.url_allowed(url):
                            continue

                        payload = {
                            "type": "url",
                            "source": "wayback_api",
                            "url": url,
                            "hostname": hostname,
                        }
                        tracker.append(payload)
                        url_added += 1
                        out_handle.write(url + "\n")
                        wrote_any = True

                        if target_budget and url_added >= target_budget:
                            budget_reached = True
                            break
                        if (
                            max_wayback_urls
                            and (wayback_total + url_added) >= max_wayback_urls
                        ):
                            global_cap_hit = True
                            break

                    wayback_total += url_added
                    logger.info(
                        "Wayback API finished for %s in %.1fs (%d URLs%s)",
                        target,
                        elapsed,
                        url_added,
                        ", budget reached" if budget_reached else "",
                    )

                if max_wayback_urls and wayback_total >= max_wayback_urls:
                    wayback_targets_skipped = len(wayback_targets) - idx
                    break

        # Stats update
        stats = context.record.metadata.stats.setdefault("wayback", {})
        stats.update(
            {
                "tool": wayback_cmd or "wayback_api",
                "targets_total": len(wayback_targets),
                "targets_processed": wayback_targets_processed,
                "targets_skipped": wayback_targets_skipped,
                "urls_ingested": wayback_total,
                "max_urls": max_wayback_urls,
                "max_per_target": max_wayback_per_target,
                "fair_share": fair_share,
                "global_cap_hit": bool(
                    global_cap_hit
                    or (max_wayback_urls and wayback_total >= max_wayback_urls)
                ),
            }
        )
        context.manager.update_metadata(context.record)

        if not wrote_any and wayback_out.exists():
            wayback_out.unlink(missing_ok=True)

        if not wayback_cmd:
            logger.info("waybackurls/gau not available; used API fallback")
        else:
            logger.info(
                "%s summary: processed=%d skipped=%d ingested=%d",
                wayback_cmd,
                wayback_targets_processed,
                wayback_targets_skipped,
                wayback_total,
            )

    def _run_wayback_api_fallback(
        self, context: PipelineContext, domain: str, limit: int
    ) -> list[str]:
        """
        Fallback for Wayback Machine using the CDX API directly.
        """
        logger = context.logger
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit={limit}"
        try:
            logger.debug("Querying Wayback CDX API for %s (limit=%d)", domain, limit)
            resp = httpx.get(url, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            if not data or len(data) < 2:
                return []
            # CDX API returns a list of lists, first row is header ["original"]
            return [row[0] for row in data[1:]]
        except Exception as exc:
            logger.warning("Wayback CDX API fallback failed for %s: %s", domain, exc)
            return []
