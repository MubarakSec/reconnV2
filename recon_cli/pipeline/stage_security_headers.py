from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class SecurityHeadersStage(Stage):
    name = "security_headers"

    REQUIRED_HEADERS = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_security_headers", False))

    async def run_async(self, context: PipelineContext) -> None:
        items = [r for r in context.filter_results("url")]
        if not items: return

        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "security_headers_max_urls", 40))
        timeout = int(getattr(runtime, "security_headers_timeout", 8))
        verify_tls = bool(getattr(runtime, "verify_tls", True))

        best_by_host: Dict[str, Tuple[int, str, str]] = {}
        for entry in items:
            url = entry.get("url")
            if not isinstance(url, str) or not url or not context.url_allowed(url): continue
            p = urlparse(url)
            host = p.hostname or ""
            if not host: continue
            score = int(entry.get("score", 0))
            if host not in best_by_host or (p.scheme == "https" and best_by_host[host][2] != "https") or score > best_by_host[host][0]:
                best_by_host[host] = (score, url, p.scheme or "")

        candidates = sorted(best_by_host.values(), key=lambda x: x[0], reverse=True)
        if max_urls > 0: candidates = candidates[:max_urls]
        if not candidates: return

        config = HTTPClientConfig(
            max_concurrent=20,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "security_headers_rps", 50.0))
        )

        findings = 0
        async with AsyncHTTPClient(config) as client:
            tasks = [client.get(url, headers={"User-Agent": "recon-cli security-headers"}, follow_redirects=True) for _, url, _ in candidates]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for (score, url, scheme), resp in zip(candidates, responses):
                if isinstance(resp, Exception) or resp.status >= 500: continue
                
                headers = {k.lower(): str(v) for k, v in resp.headers.items()}
                missing, present = [], []

                for h in self.REQUIRED_HEADERS:
                    if h in headers: present.append(h)
                    else: missing.append(h)

                if scheme == "https":
                    if "strict-transport-security" in headers: present.append("strict-transport-security")
                    else: missing.append("strict-transport-security")

                if not missing: continue

                severity = "medium" if ("strict-transport-security" in missing and scheme == "https") else "low"
                payload = {
                    "type": "finding", "finding_type": "security_headers", "source": self.name,
                    "hostname": urlparse(url).hostname, "url": url, "description": "Missing recommended security headers",
                    "details": {"missing": missing, "present": present},
                    "tags": ["security-headers"] + [f"missing:{n}" for n in missing],
                    "score": 55 if severity == "medium" else 35,
                    "priority": severity, "severity": severity,
                }
                if context.results.append(payload): findings += 1

        if findings:
            stats = context.record.metadata.stats.setdefault("security_headers", {})
            stats.update({"checked": len(candidates), "findings": findings})
            context.manager.update_metadata(context.record)
