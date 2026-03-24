from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import fs
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
from recon_cli.utils.favicon import fetch_favicon_hash


class FaviconReconStage(Stage):
    """
    Favicon Hashing and Technology Identification Stage.
    Finds favicons, hashes them (MMH3), and identifies tech stacks.
    """
    name = "favicon_recon"
    requires = ["http_probe"]
    FAVICONS_DATA = Path("data/favicons.json")

    # Fallback/Core Map (in case external file is missing)
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

    def _load_tech_map(self, context: PipelineContext) -> Dict[int, str]:
        """Loads extended fingerprints from data/favicons.json"""
        full_map = self.TECH_MAP.copy()
        if self.FAVICONS_DATA.exists():
            try:
                data = fs.read_json(self.FAVICONS_DATA)
                for h, tech in data.items():
                    try:
                        full_map[int(h)] = str(tech)
                    except ValueError: continue
                context.logger.debug("Loaded %d favicon fingerprints from %s", len(data), self.FAVICONS_DATA)
            except Exception as e:
                context.logger.warning("Failed to load favicon fingerprints: %s", e)
        return full_map

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_favicon_recon", True))

    async def run_async(self, context: PipelineContext) -> bool:
        targets = self._select_targets(context)
        if not targets:
            return True

        tech_map = self._load_tech_map(context)
        context.logger.info("Starting Favicon Recon on %d targets (Fingerprints: %d)", len(targets), len(tech_map))
        
        config = HTTPClientConfig(max_concurrent=10, verify_ssl=False)
        async with AsyncHTTPClient(config, context=context) as client:
            for url in targets:
                favicon_url = urljoin(url, "/favicon.ico")
                fhash = await fetch_favicon_hash(favicon_url, client)
                if fhash is not None:
                    tech = tech_map.get(fhash)
                    tags = ["favicon", f"hash:{fhash}"]
                    if tech:
                        tags.append(f"tech:{tech.lower().replace(' ', '_')}")
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
