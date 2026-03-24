from __future__ import annotations

import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
from recon_cli.utils.favicon import fetch_favicon_hash


class FaviconReconStage(Stage):
    """
    Favicon Hashing and Technology Identification Stage.
    Finds favicons, hashes them (MMH3), and identifies tech stacks.
    """
    name = "favicon_recon"
    requires = ["http_probe"]

    # Known Favicon Hashes (Shodan-style)
    TECH_MAP = {
        1163230216: "Spring Boot",
        -1253869855: "Django",
        -1275862201: "Jenkins",
        1158145124: "Roundcube",
        -1105229910: "Kibana",
        -413153351: "Elasticsearch",
        1490280015: "Zabbix",
        -1343739718: "FortiGate",
        -1220473105: "SonarQube",
        -1670852252: "Citrix ADC",
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_favicon_recon", True))

    async def run_async(self, context: PipelineContext) -> bool:
        targets = self._select_targets(context)
        if not targets:
            return True

        context.logger.info("Starting Favicon Recon on %d targets", len(targets))
        
        config = HTTPClientConfig(max_concurrent=10, verify_ssl=False)
        async with AsyncHTTPClient(config, context=context) as client:
            for url in targets:
                favicon_url = urljoin(url, "/favicon.ico")
                fhash = await fetch_favicon_hash(favicon_url, client)
                if fhash is not None:
                    tech = self.TECH_MAP.get(fhash)
                    tags = ["favicon", f"hash:{fhash}"]
                    if tech:
                        tags.append(f"tech:{tech.lower()}")
                        context.logger.info("Found %s on %s via favicon", tech, url)
                        context.results.append({
                            "type": "finding", "finding_type": "tech_identified",
                            "url": url, "description": f"Technology identified via favicon hash: {tech}",
                            "severity": "info", "tags": tags
                        })
                    
                    context.emit_signal("favicon_hash", "url", url, confidence=0.8, source=self.name, evidence={"hash": fhash, "tech": tech})

        return True

    def _select_targets(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        roots = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                parsed = urlparse(url)
                if parsed.path in ["", "/"]:
                    roots.append(url)
        return list(dict.fromkeys(roots))[:50]
