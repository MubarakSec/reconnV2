from __future__ import annotations

from typing import List, Dict, Any
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.engine.hypothesis import EvidenceLevel


class DecisionEngineStage(Stage):
    """
    Autonomous Decision Engine Stage.
    Centralizes planning, execution, and judging of bug hypotheses.
    This is the core of Phase 4.
    """
    name = "decision_engine"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_decision_engine", True))

    async def run_async(self, context: PipelineContext) -> None:
        context.logger.info("Starting Autonomous Decision Engine...")
        
        # 1. Planning
        hypotheses = context.planner.generate_hypotheses()
        context.logger.info("Planner generated %d hypotheses", len(hypotheses))
        
        if not hypotheses:
            return

        # Limit hypotheses per run for now
        max_hypotheses = int(getattr(context.runtime_config, "engine_max_hypotheses", 20))
        for hyp in hypotheses[:max_hypotheses]:
            context.logger.info("Testing hypothesis: %s on %s", hyp.type.value, hyp.target_url)
            
            # 2. Execution
            observations = await context.executor_engine.execute(hyp)
            
            # 3. Judging
            result = context.judge.evaluate(hyp, observations)
            
            if result.level == EvidenceLevel.CONFIRMED:
                context.logger.warning("🚨 BUG CONFIRMED by Judge: %s on %s", hyp.type.value, hyp.target_url)
                
                # Standardize proof artifacts (Phase 6)
                finding_data = result.finding_data or {}
                
                # Emit finding
                finding = {
                    "type": "finding",
                    "finding_type": hyp.type.value,
                    "source": self.name,
                    "url": hyp.target_url,
                    "description": f"Confirmed {hyp.type.value} via autonomous engine",
                    "details": {
                        "reasoning": result.reasoning,
                        "confidence": result.confidence,
                        # Phase 6 Triage metadata
                        "triage": {
                            "exploit_preconditions": "Requires authenticated role" if hyp.identity_requirements else "None",
                            "evidence_source_chain": ["planner", "executor", "judge"]
                        }
                    },
                    # Phase 6 Core Proof Elements
                    "proof": {
                        "target": finding_data.get("target", hyp.target_url),
                        "role_or_identity_used": finding_data.get("role_or_identity_used"),
                        "exact_request_sequence": finding_data.get("exact_request_sequence"),
                        "exact_differential_observation": finding_data.get("exact_differential_observation"),
                        "replay_command": finding_data.get("replay_command"),
                        "confidence_rationale": finding_data.get("confidence_rationale", result.reasoning[0] if result.reasoning else "")
                    },
                    "severity": "high",
                    "confidence_label": "verified",
                    "tags": ["autonomous", "engine", "confirmed"]
                }
                context.results.append(finding)
                
                # Update stats
                context.update_stats(self.name, confirmed=1)
            elif result.level == EvidenceLevel.REJECTED:
                context.logger.info("Hypothesis REJECTED: %s", hyp.target_url)
            else:
                context.logger.info("Hypothesis INCONCLUSIVE: %s", hyp.target_url)

        context.update_stats(self.name, hypotheses_tested=min(len(hypotheses), max_hypotheses))
        context.manager.update_metadata(context.record)
