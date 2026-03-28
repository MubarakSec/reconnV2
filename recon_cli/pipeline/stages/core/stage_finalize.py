from __future__ import annotations

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage


class FinalizeStage(Stage):
    name = "finalize"

    def execute(self, context: PipelineContext) -> None:
        from recon_cli.jobs import summary

        summary.generate_summary(context)
