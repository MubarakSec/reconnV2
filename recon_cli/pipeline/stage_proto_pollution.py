from __future__ import annotations

import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
from recon_cli.utils.proto_probes import ProtoPollutionPayloads


class ProtoPollutionStage(Stage):
    """
    Dedicated Prototype Pollution Testing Stage.
    Tests both Client-Side (DOM) and Server-Side (Node.js) sinks.
    """
    name = "proto_pollution"
    requires = ["http_probe", "js_intel"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_proto_pollution", True))

    async def run_async(self, context: PipelineContext) -> bool:
        targets = self._select_candidates(context)
        if not targets:
            return True

        context.logger.info("Starting Prototype Pollution testing on %d targets", len(targets))
        
        # 1. Client-Side Probing (Playwright)
        await self._test_client_side(context, targets)
        
        # 2. Server-Side Probing (HTTP API)
        await self._test_server_side(context, targets)

        return True

    async def _test_client_side(self, context: PipelineContext, targets: List[str]):
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            for url in targets:
                for payload in ProtoPollutionPayloads.CLIENT_URL_PAYLOADS:
                    test_url = url + payload
                    page = await browser.new_page()
                    try:
                        await page.goto(test_url, wait_until="networkidle", timeout=15000)
                        res = await page.evaluate(ProtoPollutionPayloads.CLIENT_VERIFY_SCRIPT)
                        if res and res.get("status") == "confirmed":
                            self._report_vuln(context, url, "Client-side Prototype Pollution", payload)
                            break
                    except Exception: pass
                    finally: await page.close()
            await browser.close()

    async def _test_server_side(self, context: PipelineContext, targets: List[str]):
        # Filter for API-like targets
        api_targets = [t for t in targets if "api" in t.lower() or "/v1" in t.lower()]
        if not api_targets: return

        config = HTTPClientConfig(max_concurrent=5, verify_ssl=False)
        async with AsyncHTTPClient(config, context=context) as client:
            for url in api_targets:
                for payload in ProtoPollutionPayloads.SERVER_JSON_PAYLOADS:
                    try:
                        # Send pollution payload
                        resp = await client.post(url, json=payload)
                        # Probe for reflection/pollution
                        if resp and resp.body and "reconn_pp" in resp.body:
                            self._report_vuln(context, url, "Server-side Prototype Pollution (Reflection)", str(payload))
                            break
                    except Exception: pass

    def _report_vuln(self, context: PipelineContext, url: str, vtype: str, evidence: str):
        context.logger.warning("🚨 %s FOUND on %s", vtype.upper(), url)
        context.results.append({
            "type": "finding", "finding_type": "prototype_pollution",
            "url": url, "description": f"{vtype} confirmed via payload: {evidence}",
            "severity": "high", "tags": ["prototype-pollution", "logic-bug", "confirmed"]
        })
        context.emit_signal("pp_confirmed", "url", url, confidence=0.9, source=self.name, evidence={"payload": evidence})

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        candidates = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                path = urlparse(url).path.lower()
                # Focus on root pages and APIs
                if path in ["", "/", "/api", "/v1", "/login", "/register", "/app"] or "api" in url.lower():
                    candidates.append(url)
        return list(dict.fromkeys(candidates))[:15]
