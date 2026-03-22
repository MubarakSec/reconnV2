from __future__ import annotations

import asyncio
import httpx
import time
from typing import Dict, List, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class RaceConditionStage(Stage):
    """
    Advanced Race Condition Stage (Turbo-Intruder style).
    Targets critical state-changing actions to find business logic flaws.
    """
    name = "race_condition"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_race_condition", True))

    async def run_async(self, context: PipelineContext) -> None:
        candidates = self._select_candidates(context)
        if not candidates:
            return

        context.logger.info("Starting race condition testing on %d high-value endpoints", len(candidates))
        
        async with httpx.AsyncClient(verify=False, timeout=20) as client:
            for url in candidates:
                await self._test_race(context, client, url)

    async def _test_race(self, context: PipelineContext, client: httpx.AsyncClient, url: str) -> None:
        # We send 20 simultaneous requests
        num_requests = 20
        method = "POST" # Usually race conditions impact state-changing POSTs
        
        # Prepare tokens/auth if available
        headers = context.auth_headers({"User-Agent": "recon-cli race-pro"})
        
        context.logger.info("Triggering race condition sync-burst on %s", url)
        
        tasks = [
            client.request(method, url, headers=headers, json={"recon_race": "1"}) 
            for _ in range(num_requests)
        ]
        
        start_time = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Analyze results for anomalies (e.g., more than one 'Success' where only one is expected)
        self._analyze_race_results(context, url, responses, end_time - start_time)

    def _analyze_race_results(self, context: PipelineContext, url: str, responses: List[Any], duration: float) -> None:
        stats = {}
        for resp in responses:
            if isinstance(resp, httpx.Response):
                stats[resp.status_code] = stats.get(resp.status_code, 0) + 1
        
        # If we see multiple 200s or 201s in a very short time, it's worth flagging
        success_codes = {200, 201, 302}
        total_success = sum(count for code, count in stats.items() if code in success_codes)
        
        if total_success > 1:
            context.emit_signal(
                "race_condition_suspect", "url", url,
                confidence=0.4, source=self.name,
                tags=["business-logic", "race-condition"],
                evidence={"stats": stats, "burst_duration": duration}
            )

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        candidates = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                path = urlparse(url).path.lower()
                # Target sensitive looking paths
                if any(h in path for h in ["transfer", "pay", "update", "coupon", "redeem", "vote"]):
                    candidates.append(url)
        return list(dict.fromkeys(candidates))[:5]
