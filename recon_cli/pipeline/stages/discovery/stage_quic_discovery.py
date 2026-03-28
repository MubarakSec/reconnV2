import asyncio
import httpx
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.quic_probe import QUICDetector


class QuicDiscoveryStage(Stage):
    """
    HTTP/3 (QUIC) Protocol Discovery and WAF Bypass Probing Stage.
    Identifies if a target supports QUIC and attempts to use it for WAF bypass.
    """
    name = "quic_discovery"
    requires = ["http_probe"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_quic_discovery", True))

    async def run_async(self, context: PipelineContext) -> bool:
        targets = self._select_candidates(context)
        if not targets:
            return True

        context.logger.info("Starting HTTP/3 (QUIC) discovery on %d targets", len(targets))
        
        verify_tls = getattr(context.runtime_config, "verify_tls", True)
        detector = QUICDetector(verify_tls=verify_tls)

        for url in targets:
            is_h3, reason = await detector.check_quic(url)
            if is_h3:
                context.logger.info("Found HTTP/3 support on %s: %s", url, reason)
                context.results.append({
                    "type": "url", "source": self.name, "url": url,
                    "hostname": urlparse(url).hostname,
                    "tags": ["protocol:h3", "quic"],
                    "score": 25
                })
                context.emit_signal("h3_detected", "url", url, confidence=0.8, source=self.name, evidence={"reason": reason})

                # ELITE: Active WAF Bypass Probing over H3
                await self._probe_h3_bypass(context, url, verify_tls)

        return True

    async def _probe_h3_bypass(self, context: PipelineContext, url: str, verify_tls: bool) -> None:
        """
        Attempts to re-probe the host over H3 to verify WAF bypass potential.
        If H3 is successful and returns different results than H2/H1, it's a bypass finding.
        """
        try:
            # We use httpx directly for H3 since AsyncHTTPClient is currently aiohttp-based (H1/H2)
            async with httpx.AsyncClient(http3=True, verify=verify_tls, timeout=10.0) as client:
                # Test with a common 'blocked' payload like etc/passwd to see if H3 bypasses WAF
                bypass_payloads = ["/etc/passwd", "/?id='OR+1=1", "/.git/config"]
                for payload in bypass_payloads:
                    test_url = f"{url.rstrip('/')}{payload}"
                    try:
                        resp = await client.get(test_url)
                        # If H3 returns 200/404 for a payload that usually gets a 403 (WAF block), it's a bypass!
                        if resp.status_code in [200, 404]:
                            context.logger.info("🚨 POTENTIAL WAF BYPASS via HTTP/3 on %s for %s", url, payload)
                            context.results.append({
                                "type": "finding",
                                "finding_type": "waf_bypass_quic",
                                "url": test_url,
                                "hostname": urlparse(url).hostname,
                                "description": f"Potential WAF bypass detected via HTTP/3 (QUIC). Payload {payload} was not blocked.",
                                "severity": "high",
                                "confidence": "medium",
                                "tags": ["waf-bypass", "quic", "protocol-smuggling"],
                                "evidence": {
                                    "protocol": "HTTP/3",
                                    "status": resp.status_code,
                                    "payload": payload
                                }
                            })
                            context.emit_signal("waf_bypass_possible", "url", url, confidence=0.7, source=self.name)
                            break # One confirmed bypass is enough
                    except Exception:
                        continue
        except Exception as e:
            context.logger.debug("H3 bypass probe failed for %s: %s", url, e)

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        roots = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                if urlparse(url).path in ["", "/"]:
                    roots.append(url)
        return list(dict.fromkeys(roots))[:30]

