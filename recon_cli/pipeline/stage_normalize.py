from __future__ import annotations

from pathlib import Path

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, StageError
from recon_cli.utils import validation


class NormalizeStage(Stage):
    name = "normalize_scope"

    def execute(self, context: PipelineContext) -> None:
        spec = context.record.spec
        allow_ip = spec.allow_ip
        if spec.targets_file:
            targets_path = Path(spec.targets_file)
            if not targets_path.is_absolute():
                targets_path = Path.cwd() / targets_path
            if not targets_path.exists():
                candidate = context.record.paths.root / "inputs" / Path(spec.targets_file).name
                if candidate.exists():
                    targets_path = candidate
                    spec.targets_file = str(candidate)
                    context.manager.update_spec(context.record)
                else:
                    raise StageError(f"Targets file not found: {targets_path}")
            targets = validation.load_targets_from_file(str(targets_path), allow_ip=allow_ip)
        else:
            targets = [validation.validate_target(spec.target, allow_ip=allow_ip)]
        limit = max(0, context.runtime_config.max_targets_per_job)
        total_targets = len(targets)
        if limit and total_targets > limit:
            context.logger.warning("Target list capped at %s (received %s)", limit, total_targets)
            targets = targets[:limit]
            context.record.metadata.stats.setdefault("targets_capped", {})["total"] = total_targets
        context.targets = targets
        spec.target = targets[0]
        context.manager.update_spec(context.record)
        targets_artifact = context.record.paths.artifact("targets.txt")
        targets_artifact.write_text("\n".join(targets) + "\n", encoding="utf-8")
        context.record.metadata.stats["targets"] = len(targets)
        context.manager.update_metadata(context.record)
