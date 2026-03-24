from __future__ import annotations

import asyncio
import hashlib
import uuid
import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


@dataclass
class Sink:
    url: str
    method: str
    params: List[str]
    source_type: str  # 'form' or 'api'

@dataclass
class Source:
    url: str
    hostname: str

class SecondOrderInjectionStage(Stage):
    name = "second_order_injection"
    optional = True

    # Payloads that are safe but identifiable
    CANARY_PREFIX = "recon_canary_"
    
    # We use these to see if they are rendered without escaping
    XSS_PAYLOAD = "<svg/onload=alert('{{CANARY}}')>"
    SQL_PAYLOAD = "'; -- {{CANARY}}"
    
    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_second_order", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        timeout = float(getattr(runtime, "second_order_timeout", 10.0))
        concurrency = int(getattr(runtime, "second_order_concurrency", 5))
        
        sinks = self._collect_sinks(context)
        sources = self._collect_sources(context)
        
        if not sinks or not sources:
            context.logger.info("Second-order: Not enough sinks (%d) or sources (%d) found", len(sinks), len(sources))
            return

        context.logger.info("Second-order: Testing %d sinks against %d sources", len(sinks), len(sources))

        config = HTTPClientConfig(
            max_concurrent=concurrency,
            total_timeout=timeout,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
        )

        async with AsyncHTTPClient(config, context=context) as client:
            # Group sinks by host to avoid overwhelming a single host
            sinks_by_host: Dict[str, List[Sink]] = {}
            for sink in sinks:
                host = urlparse(sink.url).hostname or ""
                sinks_by_host.setdefault(host, []).append(sink)

            for host, host_sinks in sinks_by_host.items():
                host_sources = [s for s in sources if s.hostname == host]
                if not host_sources:
                    continue
                
                # Limit sinks per host to avoid spam
                for sink in host_sinks[:3]:
                    canary = f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:8]}"
                    
                    # 1. Inject Canary into Sink
                    context.logger.debug("Injecting canary %s into %s %s", canary, sink.method, sink.url)
                    success = await self._inject(client, context, sink, canary)
                    if not success:
                        continue
                    
                    # Give it a small moment for DB persistence
                    await asyncio.sleep(1)
                    
                    # 2. Check all sources for the canary
                    for source in host_sources[:15]:
                        context.logger.debug("Checking source %s for canary %s", source.url, canary)
                        found, body = await self._check_source(client, context, source.url, canary)
                        if found:
                            finding = {
                                "type": "finding",
                                "finding_type": "second_order_injection",
                                "confidence": "high",
                                "url": source.url,
                                "sink_url": sink.url,
                                "canary": canary,
                                "severity": "high",
                                "description": f"Second-order data reflection detected. Data injected into {sink.url} appeared in {source.url}.",
                                "tags": ["business-logic", "injection", "second-order"],
                                "evidence": {
                                    "sink_method": sink.method,
                                    "reflected_body_snippet": body[body.find(canary)-50:body.find(canary)+50] if canary in body else ""
                                }
                            }
                            context.results.append(finding)
                            context.logger.info("SECOND-ORDER INJECTION DETECTED: %s -> %s", sink.url, source.url)

    def _collect_sinks(self, context: PipelineContext) -> List[Sink]:
        sinks = []
        for entry in context.get_results():
            etype = entry.get("type")
            if etype == "form":
                method = (entry.get("method") or "post").upper()
                if method in {"POST", "PUT", "PATCH"}:
                    inputs = entry.get("inputs") or []
                    input_names = [i.get("name") for i in inputs if isinstance(i, dict) and i.get("name")]
                    if input_names:
                        sinks.append(Sink(url=entry["url"], method=method, params=input_names, source_type="form"))
            elif etype == "api_spec":
                # If we parsed an api spec, we might have added URLs with tags
                pass
        
        # Also look for URLs tagged with api:spec that might be sinks
        for entry in context.get_results():
            if entry.get("type") == "url":
                tags = entry.get("tags") or []
                if "api:spec" in tags:
                    # Generic heuristic for sinks in APIs
                    url = entry["url"]
                    if any(x in url.lower() for x in ["/update", "/create", "/set", "/add", "/delete"]):
                        sinks.append(Sink(url=url, method="POST", params=["id"], source_type="api"))
        
        return sinks

    def _collect_sources(self, context: PipelineContext) -> List[Source]:
        sources = []
        seen = set()
        for entry in context.get_results():
            if entry.get("type") == "url":
                url = entry["url"]
                if url in seen: continue
                status = entry.get("status_code")
                if status == 200:
                    parsed = urlparse(url)
                    sources.append(Source(url=url, hostname=parsed.hostname or ""))
                    seen.add(url)
        return sources

    async def _inject(self, client: AsyncHTTPClient, context: PipelineContext, sink: Sink, canary: str) -> bool:
        headers = context.auth_headers({"User-Agent": "recon-cli second-order", "Content-Type": "application/x-www-form-urlencoded"})
        
        # Try both plain canary and XSS/SQL payloads
        payload_val = f"{canary} {self.XSS_PAYLOAD.replace('{{CANARY}}', canary)}"
        
        data = {p: payload_val for p in sink.params}
        
        try:
            if sink.method == "POST":
                resp = await client.post(sink.url, data=data, headers=headers)
            elif sink.method == "PUT":
                resp = await client.put(sink.url, data=data, headers=headers)
            elif sink.method == "PATCH":
                resp = await client.patch(sink.url, data=data, headers=headers)
            else:
                return False
            
            return resp.status < 400
        except Exception as e:
            context.logger.debug("Injection failed for %s: %s", sink.url, e)
            return False

    async def _check_source(self, client: AsyncHTTPClient, context: PipelineContext, url: str, canary: str) -> Tuple[bool, str]:
        headers = context.auth_headers({"User-Agent": "recon-cli second-order"})
        try:
            resp = await client.get(url, headers=headers)
            if resp.status == 200:
                body = resp.body
                if canary in body:
                    return True, body
            return False, ""
        except Exception:
            return False, ""
