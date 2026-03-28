from __future__ import annotations

from typing import List, Set
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils import validation


class SubdomainPermuteStage(Stage):
    name = "subdomain_permute"

    COMMON_SUFFIXES = [
        "dev",
        "staging",
        "stage",
        "test",
        "qa",
        "preprod",
        "prod",
        "int",
        "internal",
        "beta",
        "old",
        "new",
        "backup",
        "bk",
        "api",
        "admin",
        "portal",
    ]

    COMMON_PREFIXES = [
        "dev",
        "staging",
        "test",
        "qa",
        "prod",
        "preprod",
        "int",
        "internal",
        "beta",
        "old",
        "new",
        "api",
        "admin",
        "portal",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_subdomain_permute", False))

    def execute(self, context: PipelineContext) -> None:
        seeds = self._collect_seed_hosts(context)
        if not seeds:
            context.logger.info("No subdomains for permutation")
            return

        runtime = context.runtime_config
        max_new = int(getattr(runtime, "permute_max", 500))
        prefix_count = int(getattr(runtime, "permute_prefixes", 8))
        suffix_count = int(getattr(runtime, "permute_suffixes", 8))

        prefixes = self.COMMON_PREFIXES[: max(1, prefix_count)]
        suffixes = self.COMMON_SUFFIXES[: max(1, suffix_count)]

        generated: Set[str] = set()
        for host in seeds:
            parts = host.split(".")
            if len(parts) < 3:
                continue
            label = parts[0]
            root = ".".join(parts[1:])
            for prefix in prefixes:
                candidate = f"{prefix}.{label}.{root}"
                generated.add(candidate)
                if len(generated) >= max_new:
                    break
            if len(generated) >= max_new:
                break
            for suffix in suffixes:
                candidate = f"{label}-{suffix}.{root}"
                generated.add(candidate)
                if len(generated) >= max_new:
                    break
            if len(generated) >= max_new:
                break
        if not generated:
            return

        added = 0
        for candidate in sorted(generated):
            try:
                normalized = validation.normalize_hostname(candidate)
            except ValueError:
                context.logger.debug("Failed to normalize candidate: %s", candidate)
                continue
            signal_id = context.emit_signal(
                "subdomain_permuted",
                "host",
                normalized,
                confidence=0.3,
                source="subdomain-permute",
                tags=["permute"],
            )
            payload = {
                "type": "hostname",
                "source": "permute",
                "hostname": normalized,
                "score": 15,
                "tags": ["permute"],
                "evidence_id": signal_id or None,
            }
            if context.results.append(payload):
                added += 1

        stats = context.record.metadata.stats.setdefault("permute", {})
        stats["seeds"] = len(seeds)
        stats["generated"] = len(generated)
        stats["added"] = added
        context.manager.update_metadata(context.record)

    def _collect_seed_hosts(self, context: PipelineContext) -> List[str]:
        seeds: Set[str] = set()
        for entry in context.iter_results():
            etype = entry.get("type")
            if etype == "hostname":
                host = entry.get("hostname")
            elif etype == "url":
                host = entry.get("hostname") or (
                    entry.get("url") and urlparse(entry.get("url")).hostname
                )
            else:
                host = None
            if isinstance(host, str) and host:
                seeds.add(host)
        return sorted(seeds)
