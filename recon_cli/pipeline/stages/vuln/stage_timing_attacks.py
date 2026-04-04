from __future__ import annotations

import asyncio
import time
import statistics
import uuid
from pathlib import Path
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils import fs
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig

class TimingAttackStage(Stage):
    name = "timing_attacks"
    optional = True
    ACCOUNTS_FILE = Path("data/accounts.json")

    LOGIN_HINTS = {"login", "signin", "auth", "reset", "forgot", "signup", "register"}
    USER_PARAMS = {"user", "username", "email", "login", "handle", "account"}

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_timing_attacks", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        overrides = context.record.spec.runtime_overrides or {}
        items = context.get_results()
        
        endpoints = self._collect_endpoints(context, items)
        if not endpoints:
            return

        timeout = float(
            overrides.get(
                "timing_timeout",
                getattr(runtime, "timing_timeout", 10.0),
            )
        )
        iterations = max(
            1,
            int(
                overrides.get(
                    "timing_iterations",
                    getattr(runtime, "timing_iterations", 10),
                )
            ),
        )
        
        config = HTTPClientConfig(
            max_concurrent=1, # Strict sequential testing to minimize local noise
            total_timeout=timeout,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
        )

        accounts_data = {}
        if self.ACCOUNTS_FILE.exists():
            try:
                accounts_data = fs.read_json(self.ACCOUNTS_FILE)
            except Exception as e:
                context.logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="timing_attacks", error_type=type(e).__name__).inc()
                except: pass

        async with AsyncHTTPClient(config, context=context) as client:
            for url, method, user_param in endpoints:
                host = urlparse(url).hostname or ""
                context.logger.info("Testing timing on %s (%s)", url, user_param)
                
                # Try to find a valid username for this host
                valid_user = None
                creds = accounts_data.get(host)
                if creds:
                    valid_user = creds.get("email") or creds.get("username")
                
                if not valid_user:
                    context.logger.debug("No valid user found for %s, skipping high-confidence timing test", host)
                    continue

                invalid_user = f"nonexistent_{uuid.uuid4().hex[:12]}@example.com"
                
                # 1. Warm up (discard)
                await self._measure(client, context, url, method, user_param, invalid_user, 2)
                
                # 2. Measure invalid
                invalid_times = await self._measure(client, context, url, method, user_param, invalid_user, iterations)
                if not invalid_times: continue
                
                # 3. Measure valid
                valid_times = await self._measure(client, context, url, method, user_param, valid_user, iterations)
                if not valid_times: continue
                
                avg_invalid = statistics.mean(invalid_times)
                avg_valid = statistics.mean(valid_times)
                
                # Use standard deviation to see if the difference is statistically significant
                std_invalid = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
                std_valid = statistics.stdev(valid_times) if len(valid_times) > 1 else 0
                
                diff = abs(avg_valid - avg_invalid)
                
                # Heuristic: Difference should be greater than 2x the standard deviation of both
                is_significant = diff > (std_invalid * 2) and diff > (std_valid * 2)
                
                if is_significant and diff > 0.05: # At least 50ms difference
                    severity = "medium"
                    confidence = "medium"
                    if diff >= 0.2:
                        severity = "high"
                        confidence = "high"

                    finding = {
                        "type": "finding",
                        "finding_type": "user_enumeration_timing",
                        "confidence": confidence,
                        "url": url,
                        "severity": severity,
                        "description": f"Potential user enumeration via timing detected on {url}. Valid user responded in {avg_valid:.4f}s vs invalid user in {avg_invalid:.4f}s.",
                        "tags": ["business-logic", "timing-attack", "enumeration"],
                        "evidence": {
                            "parameter": user_param,
                            "valid_user": valid_user,
                            "avg_valid": avg_valid,
                            "avg_invalid": avg_invalid,
                            "std_valid": std_valid,
                            "std_invalid": std_invalid,
                            "diff": diff,
                            "iterations": iterations
                        }
                    }
                    context.results.append(finding)
                    context.emit_signal("timing_enumeration", "url", url, confidence=0.7, source=self.name, evidence={"diff": diff})

    async def _measure(self, client: AsyncHTTPClient, context: PipelineContext, url: str, method: str, param: str, value: str, iterations: int) -> List[float]:
        times = []
        headers = context.auth_headers({"User-Agent": "recon-cli timing-attack", "Content-Type": "application/x-www-form-urlencoded"})
        # We use a password that is definitely wrong but consistent
        data = {param: value, "password": f"WrongPass_{uuid.uuid4().hex[:8]}"}
        
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
            await asyncio.sleep(0.3) # Small delay to avoid server-side rate limiting noise
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
