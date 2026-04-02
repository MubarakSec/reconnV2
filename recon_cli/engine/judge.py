from __future__ import annotations

import hashlib
from typing import List, Optional, Dict, Any
from recon_cli.engine.hypothesis import Hypothesis, Observation, JudgeResult, EvidenceLevel


class Judge:
    """
    The final arbiter of truth.
    Evaluates observations to confirm or reject bug hypotheses.
    """

    def evaluate(self, hypothesis: Hypothesis, observations: List[Observation]) -> JudgeResult:
        """Analyze observations and decide if the hypothesis is a real bug."""
        if not observations:
            return JudgeResult(
                level=EvidenceLevel.INCONCLUSIVE,
                confidence=0.0,
                reasoning=["No observations collected"]
            )

        # Basic IDOR logic as an example
        if hypothesis.type.value == "idor":
            return self._judge_idor(hypothesis, observations)
        elif hypothesis.type.value == "ssrf":
            return self._judge_ssrf(hypothesis, observations)
        elif hypothesis.type.value == "auth_bypass":
            return self._judge_auth_bypass(hypothesis, observations)
        
        return JudgeResult(
            level=EvidenceLevel.INCONCLUSIVE,
            confidence=0.0,
            reasoning=[f"Hypothesis type {hypothesis.type} not yet supported by Judge"]
        )

    def _judge_ssrf(self, hypothesis: Hypothesis, observations: List[Observation]) -> JudgeResult:
        # SSRF Judge logic (simplified for engine illustration)
        # Check if the body contains OAST or Internal indicators
        INTERNAL_INDICATORS = ("127.0.0.1", "localhost", "169.254.169.254", "latest/meta-data")
        
        for obs in observations:
            if any(ind in obs.body for ind in INTERNAL_INDICATORS):
                return JudgeResult(
                    level=EvidenceLevel.CONFIRMED,
                    confidence=0.8,
                    reasoning=[f"Internal metadata or loopback indicator found in {obs.url}"],
                    finding_data={"target": hypothesis.target_url, "confidence_rationale": "Response contained internal server data indicators"}
                )
                
        return JudgeResult(
            level=EvidenceLevel.REJECTED,
            confidence=0.6,
            reasoning=["No internal indicators found in responses"]
        )

    def _judge_auth_bypass(self, hypothesis: Hypothesis, observations: List[Observation]) -> JudgeResult:
        # Auth Bypass: Compare anonymous vs authenticated responses
        auth_obs = [o for o in observations if o.identity_id is not None]
        anon_obs = [o for o in observations if o.identity_id is None]
        
        if not auth_obs or not anon_obs:
            return JudgeResult(level=EvidenceLevel.INCONCLUSIVE, confidence=0.0, reasoning=["Missing either authenticated or anonymous observation"])
            
        auth_status = auth_obs[0].status
        anon_status = anon_obs[0].status
        auth_hash = self._hash_body(auth_obs[0].body)
        anon_hash = self._hash_body(anon_obs[0].body)
        
        if auth_status in {200, 201, 204} and anon_status == auth_status and anon_hash == auth_hash:
            return JudgeResult(
                level=EvidenceLevel.CONFIRMED,
                confidence=0.9,
                reasoning=["Anonymous user received identical successful response to authenticated user"],
                finding_data={"target": hypothesis.target_url, "confidence_rationale": "Anonymous user saw the same sensitive resource as an authenticated user."}
            )
            
        return JudgeResult(
            level=EvidenceLevel.REJECTED,
            confidence=0.8,
            reasoning=["Anonymous response differed from authenticated response or was correctly blocked"]
        )

    def _judge_idor(self, hypothesis: Hypothesis, observations: List[Observation]) -> JudgeResult:
        # 1. Separate into Baseline (owner) and Test (other roles)
        # For simplicity, assume first observation is baseline if identity matched
        baseline = observations[0]
        test_obs = observations[1:]
        
        confirmed_identities = []
        if baseline.status < 400:
            confirmed_identities.append(baseline.identity_id)
            
        reasons = []
        baseline_hash = self._hash_body(baseline.body)
        
        for obs in test_obs:
            obs_hash = self._hash_body(obs.body)
            if obs.status == baseline.status and obs_hash == baseline_hash:
                confirmed_identities.append(obs.identity_id)
                reasons.append(f"Identity {obs.identity_id} saw identical content to baseline")

        if len(confirmed_identities) > 1:
            return JudgeResult(
                level=EvidenceLevel.CONFIRMED,
                confidence=0.9 if len(confirmed_identities) > 2 else 0.7,
                reasoning=reasons,
                finding_data={
                    "target": hypothesis.target_url,
                    "role_or_identity_used": confirmed_identities[1:], # Exclude baseline
                    "exact_request_sequence": [
                        {"method": baseline.method, "url": baseline.url, "identity": baseline.identity_id},
                        {"method": test_obs[0].method, "url": test_obs[0].url, "identity": test_obs[0].identity_id}
                    ],
                    "exact_differential_observation": {
                        "baseline_status": baseline.status,
                        "test_status": test_obs[0].status,
                        "baseline_length": len(baseline.body),
                        "test_length": len(test_obs[0].body)
                    },
                    "replay_command": f"reconn scan {hypothesis.target_url} --identity {test_obs[0].identity_id}",
                    "confidence_rationale": "Identical successful response received across different identity boundaries."
                }
            )
        
        return JudgeResult(
            level=EvidenceLevel.REJECTED,
            confidence=0.8,
            reasoning=["No other identity could access the resource"]
        )

    @staticmethod
    def _hash_body(body: str) -> str:
        return hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
