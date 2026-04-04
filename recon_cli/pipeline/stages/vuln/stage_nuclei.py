from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError


from recon_cli.engine.nuclei_engine import NucleiEngine

class NucleiStage(Stage):
    """
    Nuclei Template Integration Stage.
    Runs nuclei against discovered hosts using critical/high templates.
    """
    name = "nuclei"

    # Map project tech tags to nuclei tags
    TECH_MAPPING = {
        "tech:wordpress": "wordpress",
        "tech:php": "php",
        "tech:java": "java",
        "tech:node": "nodejs",
        "tech:asp": "iis",
        "cms:drupal": "drupal",
        "cms:joomla": "joomla",
        "service:api": "api",
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_nuclei", True))

    def execute(self, context: PipelineContext) -> None:
        engine = NucleiEngine(context)
        if not engine.is_enabled():
            context.logger.info("Nuclei stage is disabled.")
            return

        targets = self._select_targets(context)
        if not targets:
            context.logger.info("No targets found for nuclei scanning")
            return

        # Collect relevant tech tags for all targets
        tech_tags = self._collect_tech_tags(context)
        nuclei_tags = {"cve", "vulnerability", "critical", "high"}
        for t in tech_tags:
            if t in self.TECH_MAPPING:
                nuclei_tags.add(self.TECH_MAPPING[t])
        
        try:
            artifact = engine.run(targets, tags=nuclei_tags)
            self._ingest_results(context, artifact)
        except (RuntimeError, ValueError) as e:
            context.logger.info("Skipping Nuclei scan: %s", e)
        except Exception as e:
            context.logger.error("An unexpected error occurred during Nuclei scan: %s", e)


    def _collect_tech_tags(self, context: PipelineContext) -> set[str]:
        tags = set()
        for r in context.get_results():
            for t in r.get("tags", []):
                if t.startswith(("tech:", "cms:", "service:")):
                    tags.add(t)
        return tags

    def _select_targets(self, context: PipelineContext) -> List[str]:
        results = context.get_results()
        hosts = set()
        for r in results:
            if r.get("type") == "hostname":
                hosts.add(f"https://{r['hostname']}")
            elif r.get("type") == "url":
                parsed = urlparse(r["url"])
                if parsed.hostname:
                    hosts.add(f"{parsed.scheme}://{parsed.hostname}")
        return sorted(list(hosts))

    def _ingest_results(self, context: PipelineContext, artifact: Path) -> None:
        if not artifact.exists(): return
        
        findings_count = 0
        with artifact.open("r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    finding = {
                        "type": "finding",
                        "source": "nuclei",
                        "finding_type": data.get("template-id"),
                        "url": data.get("matched-at") or data.get("url"),
                        "hostname": urlparse(data.get("url")).hostname,
                        "description": data.get("info", {}).get("name"),
                        "severity": data.get("info", {}).get("severity"),
                        "score": 90 if data.get("info", {}).get("severity") == "critical" else 75,
                        "tags": ["nuclei", "confirmed"] + data.get("info", {}).get("tags", []),
                        "proof": data.get("extracted-results") or data.get("matcher-name")
                    }
                    if context.results.append(finding):
                        findings_count += 1
                        context.emit_signal(
                            "nuclei_confirmed", "url", finding["url"],
                            confidence=1.0, source="nuclei",
                            evidence=data
                        )
                except Exception: continue
        
        context.logger.info("Nuclei found %d critical/high vulnerabilities", findings_count)
