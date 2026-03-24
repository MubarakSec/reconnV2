from __future__ import annotations

import asyncio
import time
import statistics
import uuid
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urlparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig

class TimingAttackStage(Stage):
    name = "timing_attacks"
    optional = True

    LOGIN_HINTS = {"login", "signin", "auth", "reset", "forgot", "signup", "register"}
    USER_PARAMS = {"user", "username", "email", "login", "handle", "account"}

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_timing_attacks", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        items = context.get_results()
        
        endpoints = self._collect_endpoints(context, items)
        if not endpoints:
            return

        timeout = float(getattr(runtime, "timing_timeout", 10.0))
        iterations = int(getattr(runtime, "timing_iterations", 5))
        
        config = HTTPClientConfig(
            max_concurrent=2, # Keep it low to avoid noise
            total_timeout=timeout,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
        )

        async with AsyncHTTPClient(config, context=context) as client:
            for url, method, user_param in endpoints:
                context.logger.info("Testing timing on %s (%s)", url, user_param)
                
                # We need a "valid" looking user and a "non-existent" one
                # If we don't have a valid one, we can still compare two different non-existent ones
                # but better is a known valid. For now, let's use a very long vs very short.
                invalid_user = f"nonexistent_{uuid.uuid4().hex}"
                
                # Measure baseline (invalid)
                invalid_times = await self._measure(client, context, url, method, user_param, invalid_user, iterations)
                if not invalid_times: continue
                
                # Measure another one to see variance
                another_invalid_user = f"another_{uuid.uuid4().hex}"
                another_times = await self._measure(client, context, url, method, user_param, another_invalid_user, iterations)
                if not another_times: continue
                
                # If iterations > 2, we can do some stats
                avg_1 = statistics.mean(invalid_times)
                avg_2 = statistics.mean(another_times)
                std_1 = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
                
                # This is just a basic check. Real timing attacks are harder.
                # If we had a VALID user, the difference would be more obvious.
                diff = abs(avg_1 - avg_2)
                if diff > 0.1: # 100ms difference is quite large for two invalid users
                    finding = {
                        "type": "finding",
                        "finding_type": "timing_leak",
                        "confidence": "low",
                        "url": url,
                        "severity": "medium",
                        "description": f"Potential timing side-channel detected on {url}. Average response time varied by {diff:.4f}s.",
                        "tags": ["business-logic", "timing-attack", "enumeration"],
                        "evidence": {
                            "parameter": user_param,
                            "avg_1": avg_1,
                            "avg_2": avg_2,
                            "diff": diff,
                            "iterations": iterations
                        }
                    }
                    context.results.append(finding)

    async def _measure(self, client: AsyncHTTPClient, context: PipelineContext, url: str, method: str, param: str, value: str, iterations: int) -> List[float]:
        times = []
        headers = context.auth_headers({"User-Agent": "recon-cli timing-attack", "Content-Type": "application/x-www-form-urlencoded"})
        data = {param: value, "password": "Password123!"} # Common dummy password
        
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                if method == "POST":
                    await client.post(url, data=data, headers=headers)
                else:
                    await client.get(url, params=data, headers=headers)
                times.append(time.perf_counter() - start)
            except Exception:
                continue
            await asyncio.sleep(0.5) # Jitter reduction
        return times

    def _collect_endpoints(self, context: PipelineContext, items: List[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
        endpoints = []
        for entry in items:
            if entry.get("type") == "form":
                url = entry["url"]
                method = (entry.get("method") or "post").upper()
                inputs = entry.get("inputs") or []
                input_names = [i.get("name") for i in inputs if isinstance(i, dict) and i.get("name")]
                
                # Find the user parameter
                user_param = next((p for p in input_names if any(h in p.lower() for h in self.USER_PARAMS)), None)
                if user_param and any(h in url.lower() for h in self.LOGIN_HINTS):
                    endpoints.append((url, method, user_param))
            
            elif entry.get("type") == "url":
                # Check for login-like URLs with params
                url = entry["url"]
                if any(h in url.lower() for h in self.LOGIN_HINTS):
                    parsed = urlparse(url)
                    params = [k for k, v in parse_qsl(parsed.query)]
                    user_param = next((p for p in params if any(h in p.lower() for h in self.USER_PARAMS)), None)
                    if user_param:
                        endpoints.append((url, "GET", user_param))
        
        return endpoints[:5]
