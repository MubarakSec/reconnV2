from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.tools.executor import CommandError


class VulnScanStage(Stage):
    name = "vuln_scan"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(
            getattr(context.runtime_config, "enable_dalfox", False)
            or getattr(context.runtime_config, "enable_sqlmap", False)
        )

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        candidates = context.get_data("param_urls", []) or []
        if not candidates:
            context.logger.info("No parameterized URLs for vuln scan")
            return
        artifacts_dir = context.record.paths.ensure_subdir("vuln_scans")
        findings = 0
        if getattr(context.runtime_config, "enable_dalfox", False) and executor.available("dalfox"):
            max_urls = int(getattr(context.runtime_config, "dalfox_max_urls", 20))
            timeout = int(getattr(context.runtime_config, "dalfox_timeout", 600))
            for url in candidates[:max_urls]:
                artifact = artifacts_dir / f"dalfox_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
                cmd = ["dalfox", "url", url]
                try:
                    result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
                except CommandError:
                    context.logger.warning("dalfox failed for %s", url)
                    continue
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                artifact.write_text(output, encoding="utf-8")
                if re.search(r"\bVULN\b|\bPOC\b|reflected", output, re.IGNORECASE):
                    payload = {
                        "type": "finding",
                        "source": "dalfox",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "Potential XSS detected by dalfox",
                        "details": {"output_snippet": output[:1000]},
                        "tags": ["xss", "dalfox"],
                        "score": 80,
                        "priority": "high",
                    }
                    if context.results.append(payload):
                        findings += 1
        if getattr(context.runtime_config, "enable_sqlmap", False) and executor.available("sqlmap"):
            max_urls = int(getattr(context.runtime_config, "sqlmap_max_urls", 10))
            timeout = int(getattr(context.runtime_config, "sqlmap_timeout", 900))
            level = int(getattr(context.runtime_config, "sqlmap_level", 1))
            risk = int(getattr(context.runtime_config, "sqlmap_risk", 1))
            for url in candidates[:max_urls]:
                artifact = artifacts_dir / f"sqlmap_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
                cmd = [
                    "sqlmap",
                    "-u",
                    url,
                    "--batch",
                    "--level",
                    str(level),
                    "--risk",
                    str(risk),
                    "--random-agent",
                    "--threads",
                    "2",
                    "--timeout",
                    "10",
                    "--retries",
                    "1",
                ]
                try:
                    result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
                except CommandError:
                    context.logger.warning("sqlmap failed for %s", url)
                    continue
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                artifact.write_text(output, encoding="utf-8")
                if re.search(r"parameter .* is vulnerable|sqlmap identified", output, re.IGNORECASE):
                    payload = {
                        "type": "finding",
                        "source": "sqlmap",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "Potential SQL injection detected by sqlmap",
                        "details": {"output_snippet": output[:1200]},
                        "tags": ["sqli", "sqlmap"],
                        "score": 85,
                        "priority": "high",
                    }
                    if context.results.append(payload):
                        findings += 1
        if findings:
            stats = context.record.metadata.stats.setdefault("vuln_scan", {})
            stats["findings"] = findings
            context.manager.update_metadata(context.record)
