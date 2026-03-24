from __future__ import annotations

import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.quic_probe import QUICDetector


class QuicDiscoveryStage(Stage):
    """
    HTTP/3 (QUIC) Protocol Discovery Stage.
    Identifies if a target supports QUIC, which can often bypass WAFs.
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

        return True

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        roots = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                if urlparse(url).path in ["", "/"]:
                    roots.append(url)
        return list(dict.fromkeys(roots))[:30]
