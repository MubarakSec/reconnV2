from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.race_burst import RaceBurstClient, BurstResponse


class RaceConditionStage(Stage):
    """
    Advanced Race Condition Stage (Turbo-Intruder style).
    Targets critical state-changing actions to find business logic flaws.
    Uses Last-Byte Sync technique to bypass network jitter.
    """
    name = "race_condition"
    requires = ["http_probe", "js_intel"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_race_condition", True))

    async def run_async(self, context: PipelineContext) -> None:
        candidates = self._select_candidates(context)
        if not candidates:
            return

        context.logger.info("Starting advanced race condition testing on %d high-value endpoints", len(candidates))
        
        verify_tls = getattr(context.runtime_config, "verify_tls", True)
        client = RaceBurstClient(verify_tls=verify_tls)
        
        for url in candidates:
            await self._test_race(context, client, url)

    async def _test_race(self, context: PipelineContext, client: RaceBurstClient, url: str) -> None:
        # We send 20 simultaneous requests
        num_requests = 20
        method = "POST" 
        
        # Prepare headers
        headers = context.auth_headers({
            "User-Agent": "recon-cli/2.0 race-pro",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        
        # Simple generic payload
        body = b'{"race_test": "1"}'
        
        context.logger.info("Triggering Last-Byte Sync burst on %s", url)
        
        results = await client.sync_burst(
            url, 
            method=method, 
            headers=headers, 
            body=body, 
            count=num_requests
        )
        
        self._analyze_race_results(context, url, results)

    def _analyze_race_results(self, context: PipelineContext, url: str, results: List[Tuple[Optional[BurstResponse], Optional[str]]]) -> None:
        stats = {}
        durations = []
        
        for resp, err in results:
            if resp:
                stats[resp.status] = stats.get(resp.status, 0) + 1
                durations.append(resp.elapsed)
        
        if not durations:
            return

        avg_duration = sum(durations) / len(durations)
        success_codes = {200, 201, 302}
        total_success = sum(count for code, count in stats.items() if code in success_codes)
        
        # Heuristic: If we see multiple successes in a tight window
        if total_success > 1:
            context.emit_signal(
                "race_condition_suspect", "url", url,
                confidence=0.5, source=self.name,
                tags=["business-logic", "race-condition", "last-byte-sync"],
                evidence={
                    "stats": stats, 
                    "avg_burst_elapsed": round(avg_duration, 4),
                    "total_success": total_success,
                    "method": "Last-Byte Sync"
                }
            )

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        candidates = []
        high_value_keywords = ["transfer", "pay", "update", "coupon", "redeem", "vote", "checkout", "withdraw", "gift"]
        
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                path = urlparse(url).path.lower()
                # Target sensitive looking paths
                if any(h in path for h in high_value_keywords):
                    candidates.append(url)
        
        # Also include any API endpoints that look like they might be state-changing
        for r in context.filter_results("api"):
             url = r.get("url")
             if url and any(h in url.lower() for h in high_value_keywords):
                 candidates.append(url)

        return list(dict.fromkeys(candidates))[:5]
