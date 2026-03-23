from __future__ import annotations

import httpx
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class WebCacheVulnStage(Stage):
    """
    Advanced Web Cache Vulnerability Stage.
    Tests for:
    1. Web Cache Deception (leaking sensitive data via static extensions).
    2. Web Cache Poisoning (injecting unkeyed headers to corrupt cache).
    """
    name = "web_cache_vuln"

    # Extensions that common caches (Cloudflare, Akamai) treat as static
    STATIC_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2"]
    
    # Headers often unkeyed but reflected in responses
    POISON_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_cache_vuln", True))

    async def run_async(self, context: PipelineContext) -> None:
        results = context.get_results()
        # Find interesting URLs (prioritize API and Auth)
        targets = [r["url"] for r in results if r.get("type") == "url" and "auth" in str(r.get("tags", []))]
        targets = list(dict.fromkeys(targets))[:15]

        if not targets:
            return

        context.logger.info("Starting web cache vulnerability testing on %d targets", len(targets))
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for url in targets:
                await self._test_cache_deception(context, client, url)
                await self._test_cache_poisoning(context, client, url)

    async def _test_cache_deception(self, context: PipelineContext, client: httpx.AsyncClient, url: str) -> None:
        """
        Tests if requesting a sensitive page with a static extension triggers caching.
        Example: /api/v1/profile -> /api/v1/profile.css
        """
        if "?" in url: return # Skip parameterized URLs for this simple check
        
        headers = context.auth_headers({"User-Agent": "recon-cli cache-pro"})
        
        for ext in self.STATIC_EXTENSIONS[:3]: # Limit to most common
            test_url = f"{url}{ext}"
            try:
                resp = await client.get(test_url, headers=headers)
                # If we get a 200 and the body looks like the original sensitive data, it's a hit
                if resp.status_code == 200 and ("email" in resp.text or "username" in resp.text):
                    # Check for cache headers
                    cache_hit = any(h.lower() in ["cf-cache-status", "x-cache", "age"] for h in resp.headers)
                    
                    self._report_cache_finding(
                        context, test_url, "cache_deception",
                        f"Potential Web Cache Deception detected via {ext}",
                        "high" if cache_hit else "medium",
                        {"extension": ext, "cache_headers": dict(resp.headers)}
                    )
            except Exception: pass

    async def _test_cache_poisoning(self, context: PipelineContext, client: httpx.AsyncClient, url: str) -> None:
        """
        Tests if unkeyed headers are reflected and potentially cached.
        """
        poison_val = f"poison-{int(time.time())}.com"
        
        for header in self.POISON_HEADERS:
            headers = {header: poison_val, "User-Agent": "recon-cli cache-pro"}
            try:
                # 1. Send poisoning request
                resp1 = await client.get(url, headers=headers)
                
                # 2. Check if reflected
                if poison_val in resp1.text:
                    # 3. Check if cached (send request WITHOUT header)
                    time.sleep(1)
                    resp2 = await client.get(url)
                    if poison_val in resp2.text:
                        self._report_cache_finding(
                            context, url, "cache_poisoning",
                            f"Web Cache Poisoning CONFIRMED via {header}",
                            "critical",
                            {"header": header, "value": poison_val}
                        )
                        return # Found one, move to next URL
            except Exception: pass

    def _report_cache_finding(self, context: PipelineContext, url: str, f_type: str, desc: str, severity: str, details: Dict[str, Any]) -> None:
        finding = {
            "type": "finding",
            "finding_type": f_type,
            "source": self.name,
            "url": url,
            "hostname": urlparse(url).hostname,
            "description": desc,
            "severity": severity,
            "score": 95 if severity == "critical" else 80,
            "details": details,
            "tags": ["cache", "confirmed" if severity == "critical" else "suspect"]
        }
        context.results.append(finding)
        context.emit_signal(f"{f_type}_detected", "url", url, confidence=0.8, source=self.name)
