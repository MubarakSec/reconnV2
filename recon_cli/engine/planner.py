from __future__ import annotations

from typing import TYPE_CHECKING, List
from recon_cli.engine.hypothesis import Hypothesis, HypothesisType

if TYPE_CHECKING:
    from recon_cli.pipeline.context import PipelineContext


class Planner:
    """
    Centralized planning engine.
    Generates bug hypotheses based on the target graph and available identities.
    """

    def __init__(self, context: PipelineContext):
        self.context = context

    def generate_hypotheses(self) -> List[Hypothesis]:
        """Scan the target graph and prior findings to suggest what to test next."""
        hypotheses = []
        
        # 1. Look for IDOR candidates (endpoints with identifiers)
        hypotheses.extend(self._plan_idor())
        
        # 2. Look for SSRF candidates (endpoints with URL-like parameters)
        hypotheses.extend(self._plan_ssrf())
        
        # 3. Look for Auth Bypass candidates (protected endpoints)
        hypotheses.extend(self._plan_auth_bypass())
        
        # Sort by priority
        hypotheses.sort(key=lambda h: h.priority, reverse=True)
        return hypotheses

    def _plan_idor(self) -> List[Hypothesis]:
        hypotheses = []
        
        # Look for object_ids in the graph
        with self.context.target_graph._lock:
            for node in self.context.target_graph._graph._nodes.values():
                if node.type == "object_id":
                    obj_id = node.id
                    host = node.attrs.get("host")
                    
                    # Find related endpoints for this host
                    # (In a more advanced graph, we'd have explicit edges)
                    # For now, let's find api_endpoints on the same host
                    for other_node in self.context.target_graph._graph._nodes.values():
                        if other_node.type == "api_endpoint" and other_node.attrs.get("host") == host:
                            url = other_node.attrs.get("url")
                            if "{" in url: # Template URL
                                hypotheses.append(Hypothesis(
                                    type=HypothesisType.IDOR,
                                    target_url=url.replace("{id}", obj_id), # Simple replacement logic
                                    priority=0.8,
                                    parameters={"id": obj_id, "original_node": node.id},
                                    identity_requirements=["authenticated"],
                                    metadata={"host": host}
                                ))
        
        return hypotheses

    def _plan_ssrf(self) -> List[Hypothesis]:
        hypotheses = []
        
        with self.context.target_graph._lock:
            for node in self.context.target_graph._graph._nodes.values():
                if node.type == "ssrf_sink":
                    url = node.attrs.get("url")
                    param = node.attrs.get("param")
                    
                    hypotheses.append(Hypothesis(
                        type=HypothesisType.SSRF,
                        target_url=url,
                        priority=0.9,
                        parameters={"param": param},
                        metadata={"host": node.attrs.get("host")}
                    ))
        
        return hypotheses

    def _plan_auth_bypass(self) -> List[Hypothesis]:
        return []
