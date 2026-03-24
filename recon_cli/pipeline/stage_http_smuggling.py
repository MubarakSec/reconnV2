from __future__ import annotations

import asyncio
import uuid
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.raw_http import send_raw_http


class HttpSmugglingStage(Stage):
    """
    HTTP Request Smuggling Detection Stage (CL.TE & TE.CL).
    Uses raw sockets to detect desync vulnerabilities.
    """
    name = "http_smuggling"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_smuggling", True))

    async def run_async(self, context: PipelineContext) -> None:
        targets = self._select_targets(context)
        if not targets:
            return

        context.logger.info("Starting HTTP Smuggling (CL.TE/TE.CL) detection on %d targets", len(targets))
        
        # Limit concurrency
        semaphore = asyncio.Semaphore(5)
        tasks = [self._test_url_with_sem(context, url, semaphore) for url in targets]
        await asyncio.gather(*tasks)

    async def _test_url_with_sem(self, context: PipelineContext, url: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            await self._test_url(context, url)

    async def _test_url(self, context: PipelineContext, url: str) -> None:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host: return
        path = parsed.path or "/"

        normal_payload = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: ReconnV2\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode('utf-8')

        # 1. CL.TE Detection Payload (Timeout based)
        # We send a Content-Length larger than the body. 
        # If the front-end uses CL but the back-end uses TE, the back-end will wait for more data.
        cl_te_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"User-Agent: ReconnV2\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode('utf-8')

        # 2. TE.CL Detection Payload (Timeout based)
        # We send a chunked body but with a Content-Length that doesn't include the final '0' chunk.
        te_cl_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"User-Agent: ReconnV2\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLE\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode('utf-8')

        # Run tests
        for technique, payload in [("CL.TE", cl_te_payload), ("TE.CL", te_cl_payload)]:
            res, err = await send_raw_http(url, payload, timeout=5.0)
            if err == "TIMEOUT":
                # Possible vulnerability confirmed by timeout
                # We double check with a normal request to ensure it's not just a slow server
                n_res, n_err = await send_raw_http(url, normal_payload, timeout=2.0)
                if n_res and n_res.status < 500:
                    # Normal request succeeded quickly, but smuggling payload timed out
                    # High probability of desync
                    self._report_vulnerability(context, url, technique, "Timeout-based desync detected")
            
            # ELITE: TE Mutation (to bypass some WAFs)
            te_mutations = ["Transfer-Encoding: xchunked", "Transfer-Encoding : chunked", "Transfer-Encoding: \tchunked"]
            for mutation in te_mutations:
                mutated_payload = payload.replace(b"Transfer-Encoding: chunked", mutation.encode('utf-8'))
                res, err = await send_raw_http(url, mutated_payload, timeout=5.0)
                if err == "TIMEOUT":
                    # Check if normal request is still OK
                    n_res, n_err = await send_raw_http(url, normal_payload, timeout=2.0)
                    if n_res and n_res.status < 500:
                        self._report_vulnerability(context, url, f"{technique}-mutated", f"Desync detected via TE mutation: {mutation}")
                        break

    def _report_vulnerability(self, context: PipelineContext, url: str, technique: str, reason: str) -> None:
        context.logger.warning("🚨 POTENTIAL HTTP REQUEST SMUGGLING (%s) on %s", technique, url)
        context.emit_signal("http_smuggling_suspected", "url", url, confidence=0.7, source=self.name, evidence={"technique": technique, "reason": reason})
        context.results.append({
            "type": "finding", "finding_type": "http_smuggling",
            "url": url, "description": f"Potential HTTP Request Smuggling ({technique}) detected: {reason}",
            "severity": "high", "tags": ["smuggling", "desync", "vulnerability"]
        })

    def _select_targets(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        targets = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                if url.startswith("http"):
                    # Focus on root or interesting paths
                    parsed = urlparse(url)
                    if parsed.path in ["", "/", "/api"] or "auth" in str(r.get("tags", [])):
                        targets.append(url)
        
        return list(dict.fromkeys(targets))[:20]
