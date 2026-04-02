from __future__ import annotations

import time
from typing import TYPE_CHECKING, List, Optional
from recon_cli.engine.hypothesis import Hypothesis, Observation
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig

if TYPE_CHECKING:
    from recon_cli.pipeline.context import PipelineContext


class Executor:
    """
    Executes bug hypotheses by performing network requests.
    Handles multi-identity replay automatically.
    """

    def __init__(self, context: PipelineContext):
        self.context = context

    async def execute(self, hypothesis: Hypothesis) -> List[Observation]:
        """Execute a hypothesis and collect observations."""
        observations = []
        
        # 1. Resolve identities to use
        identities_to_test = []
        if hypothesis.identity_requirements:
            for role in hypothesis.identity_requirements:
                identities_to_test.extend(self.context._auth_manager.get_identities_by_role(role))
        else:
            # Default to all if none specified
            identities_to_test = self.context._auth_manager.get_all_identities()
        
        # Always add Anonymous if not already there
        identities_to_test.append(None)

        config = HTTPClientConfig(total_timeout=30.0)
        async with AsyncHTTPClient(config, context=self.context) as client:
            for identity in identities_to_test:
                identity_id = identity.identity_id if identity else None
                
                start_time = time.monotonic()
                try:
                    method = str(hypothesis.parameters.get("method", "GET")).upper()
                    json_body = hypothesis.parameters.get("json")
                    data_body = hypothesis.parameters.get("data")
                    custom_headers = hypothesis.parameters.get("headers")
                    
                    resp = await client._request(
                        method=method,
                        url=hypothesis.target_url,
                        identity_id=identity_id,
                        json=json_body,
                        data=data_body,
                        headers=custom_headers
                    )
                    elapsed = time.monotonic() - start_time
                    
                    observations.append(Observation(
                        url=hypothesis.target_url,
                        method=method,
                        status=resp.status,
                        headers=resp.headers,
                        body=resp.body,
                        identity_id=identity_id,
                        response_time=elapsed
                    ))
                except Exception as exc:
                    self.context.logger.debug("Execution failed for %s: %s", hypothesis.target_url, exc)
        
        return observations
