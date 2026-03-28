from __future__ import annotations

from recon_cli.pipeline.stages.core.stage_scoring import ScoringStage


class RescoreStage(ScoringStage):
    name = "post_scoring"
