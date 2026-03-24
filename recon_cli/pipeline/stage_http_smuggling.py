from __future__ import annotations

import asyncio
import uuid
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.raw_http import send_raw_http
from recon_cli.utils.h2_smuggling import H2SmugglingDetector


class HttpSmugglingStage(Stage):
    """
    HTTP Request Smuggling Detection Stage (CL.TE, TE.CL and H2 desync).
    Uses raw sockets for H1.1 and H2-aware clients for H2 desync.
    """
    name = "http_smuggling"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_smuggling", True))

    async def run_async(self, context: PipelineContext) -> None:
        targets = self._select_targets(context)
        if not targets:
            return

        context.logger.info("Starting HTTP Smuggling (H1.1 & H2) detection on %d targets", len(targets))
        
        # Limit concurrency
        semaphore = asyncio.Semaphore(5)
        tasks = [self._test_url_with_sem(context, url, semaphore) for url in targets]
        await asyncio.gather(*tasks)

    async def _test_url_with_sem(self, context: PipelineContext, url: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            await self._test_url(context, url)
            await self._test_h2_smuggling(context, url)

    async def _test_url(self, context: PipelineContext, url: str) -> None:
        """Traditional H1.1 Smuggling Tests."""
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
                if await self._verify_normal_h1(url, normal_payload):
                    self._report_vulnerability(context, url, technique, "Timeout-based desync detected")
            
            # TE Mutation
            te_mutations = ["Transfer-Encoding: xchunked", "Transfer-Encoding : chunked", "Transfer-Encoding: \tchunked"]
            for mutation in te_mutations:
                mutated_payload = payload.replace(b"Transfer-Encoding: chunked", mutation.encode('utf-8'))
                res, err = await send_raw_http(url, mutated_payload, timeout=5.0)
                if err == "TIMEOUT":
                    if await self._verify_normal_h1(url, normal_payload):
                        self._report_vulnerability(context, url, f"{technique}-mutated", f"Desync detected via TE mutation: {mutation}")
                        break

    async def _test_h2_smuggling(self, context: PipelineContext, url: str) -> None:
        """HTTP/2 Specific Smuggling Tests."""
        verify_tls = getattr(context.runtime_config, "verify_tls", True)
        detector = H2SmugglingDetector(verify_tls=verify_tls)
        
        if not await detector.check_h2_support(url):
            return

        context.logger.info("Target %s supports H2, running H2 desync tests", url)
        
        # H2.CL test
        is_vuln, reason = await detector.detect_h2_cl(url)
        if is_vuln:
            self._report_vulnerability(context, url, "H2.CL", reason)
            
        # H2.TE test
        is_vuln, reason = await detector.detect_h2_te(url)
        if is_vuln:
            self._report_vulnerability(context, url, "H2.TE", reason)

    async def _verify_normal_h1(self, url: str, normal_payload: bytes) -> bool:
        n_res, n_err = await send_raw_http(url, normal_payload, timeout=2.0)
        return bool(n_res and n_res.status < 500)

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
                    parsed = urlparse(url)
                    if parsed.path in ["", "/", "/api"] or "auth" in str(r.get("tags", [])):
                        targets.append(url)
        
        return list(dict.fromkeys(targets))[:20]
