from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError


class NucleiStage(Stage):
    """
    Nuclei Template Integration Stage.
    Runs nuclei against discovered hosts using critical/high templates.
    """
    name = "nuclei"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_nuclei", True))

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        if not executor.available("nuclei"):
            context.logger.warning("nuclei not available; skipping nuclei stage")
            note_missing_tool(context, "nuclei")
            return

        targets = self._select_targets(context)
        if not targets:
            context.logger.info("No targets found for nuclei scanning")
            return

        # Prepare targets file
        target_file = context.record.paths.artifact("nuclei_targets.txt")
        target_file.write_text("\n".join(targets))

        artifact = context.record.paths.artifact("nuclei_results.json")
        
        # Run Nuclei
        # -s critical,high: only high impact
        # -jsonl: for easier parsing
        cmd = [
            "nuclei",
            "-list", str(target_file),
            "-severity", "critical,high",
            "-jsonl",
            "-o", str(artifact),
            "-silent"
        ]

        context.logger.info("Running nuclei against %d targets", len(targets))
        try:
            executor.run(cmd, check=False, timeout=1800) # 30 min timeout
            self._ingest_results(context, artifact)
        except CommandError as e:
            context.logger.error("Nuclei execution failed: %s", e)

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
