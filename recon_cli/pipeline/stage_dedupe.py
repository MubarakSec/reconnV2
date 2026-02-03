from __future__ import annotations

from typing import List

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import validation


class DedupeStage(Stage):
    name = "dedupe_canonicalize"

    def execute(self, context: PipelineContext) -> None:
        passive_hosts_path = context.record.paths.artifact("passive_hosts.txt")
        if not passive_hosts_path.exists():
            context.logger.info("No passive hosts found; skipping dedupe")
            return
        dedupe_path = context.record.paths.artifact("dedupe_hosts.txt")
        seen = set()
        normalized: List[str] = []
        with passive_hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if not host:
                    continue
                if context.record.spec.allow_ip and validation.is_ip(host):
                    canonical = host
                else:
                    try:
                        canonical = validation.normalize_hostname(host)
                    except ValueError:
                        continue
                if canonical in seen:
                    continue
                seen.add(canonical)
                normalized.append(canonical)
        dedupe_path.write_text("\n".join(normalized) + "\n", encoding="utf-8")
        context.record.metadata.stats["dedupe_hosts"] = len(normalized)
        context.manager.update_metadata(context.record)
        prev_job_id = getattr(context.record.spec, "incremental_from", None)
        if prev_job_id:
            prev = context.manager.load_job(prev_job_id)
            if prev:
                prev_dedupe = prev.paths.artifact("dedupe_hosts.txt")
                if prev_dedupe.exists():
                    try:
                        prev_hosts = {line.strip() for line in prev_dedupe.read_text(encoding="utf-8").splitlines() if line.strip()}
                        merged = sorted(set(normalized) | prev_hosts)
                        dedupe_path.write_text("\n".join(merged) + "\n", encoding="utf-8")
                        context.record.metadata.stats["dedupe_hosts"] = len(merged)
                        context.manager.update_metadata(context.record)
                    except Exception:
                        context.logger.warning("Failed to merge previous dedupe hosts for incremental run")
