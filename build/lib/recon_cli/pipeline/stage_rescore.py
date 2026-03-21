from __future__ import annotations

from recon_cli.pipeline.stage_scoring import ScoringStage


class RescoreStage(ScoringStage):
    name = "post_scoring"
