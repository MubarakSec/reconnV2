from __future__ import annotations

import json
import uuid
import asyncio
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class OAuthVulnerabilityStage(Stage):
    """
    Advanced OAuth Vulnerability Scanner.
    Tests for redirect_uri hijacking, state parameter omission, and other common OAuth flaws.
    """
    name = "oauth_vuln"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_oauth_vuln", True))

    async def run_async(self, context: PipelineContext) -> None:
        authorize_endpoints = [
            r for r in context.filter_results("url")
            if "surface:authorize" in r.get("tags", [])
        ]
        
        if not authorize_endpoints:
            context.logger.info("No OAuth authorize endpoints found for vulnerability testing")
            return

        runtime = context.runtime_config
        config = HTTPClientConfig(
            max_concurrent=10,
            total_timeout=float(getattr(runtime, "api_recon_timeout", 10)),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=10.0
        )

        async with AsyncHTTPClient(config) as client:
            for endpoint in authorize_endpoints:
                url = endpoint.get("url")
                if not url: continue
                
                # Concurrent tests for this endpoint
                await asyncio.gather(
                    self._test_state_omission(context, client, url),
                    self._test_redirect_hijacking(context, client, url)
                )

    async def _test_state_omission(self, context: PipelineContext, client: AsyncHTTPClient, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if "state" not in params: return

        test_params = {k: v for k, v in params.items() if k != "state"}
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
        
        try:
            resp = await client.get(test_url, follow_redirects=False)
            if resp.status in [200, 302] and "error" not in resp.body.lower():
                context.emit_signal(
                    "oauth_weakness", "url", url, 
                    confidence=0.6, source=self.name,
                    tags=["oauth", "weakness", "no-state"],
                    evidence={"description": "Authorization request accepted without state parameter"}
                )
        except Exception: pass

    async def _test_redirect_hijacking(self, context: PipelineContext, client: AsyncHTTPClient, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if "redirect_uri" not in params: return

        original_redirect = params["redirect_uri"]
        attacker_domain = f"evil-{uuid.uuid4().hex[:6]}.com"
        
        test_redirects = [
            f"https://{attacker_domain}/callback",
            f"{original_redirect}.{attacker_domain}",
            f"{original_redirect}@{attacker_domain}"
        ]

        for payload in test_redirects:
            test_params = dict(params)
            test_params["redirect_uri"] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            
            try:
                resp = await client.get(test_url, follow_redirects=False)
                location = str(resp.headers.get("Location", ""))
                if payload in location:
                    signal_id = context.emit_signal(
                        "oauth_vuln_confirmed", "url", url,
                        confidence=0.9, source=self.name,
                        tags=["oauth", "vulnerability", "redirect-hijack"],
                        evidence={"payload": payload, "location": location}
                    )
                    context.results.append({
                        "type": "finding", "finding_type": "oauth_redirect_hijack", "url": url,
                        "severity": "high", "description": f"OAuth redirect_uri hijacking confirmed with payload: {payload}",
                        "proof": f"Redirected to: {location}", "tags": ["oauth", "confirmed", "critical"],
                        "evidence_id": signal_id or None
                    })
                    break
            except Exception: pass
