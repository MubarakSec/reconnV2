from __future__ import annotations

import json
from collections import Counter
from typing import List, Dict, Tuple, Any, Iterable
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.secrets.detector import SecretsDetector
from recon_cli.utils import enrich as enrich_utils


class SecretsDetectionStage(Stage):
    name = "secrets_detection"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_secrets", False))

    async def run_async(self, context: PipelineContext) -> None:
        items = [r for r in context.filter_results("url")]
        if not items:
            return
            
        candidates: List[Tuple[int, str, str]] = []  # (score, url, host)
        for entry in items:
            url = entry.get("url")
            if not isinstance(url, str) or not url or not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            ext = parsed.path.split(".")[-1].lower() if "." in parsed.path else ""
            if ext not in {"js", "json", "env", "config", "txt", "properties", "yml", "yaml"}:
                continue
            score = int(entry.get("score", 0))
            host = entry.get("hostname") or parsed.hostname or ""
            candidates.append((score, url, host))
            
        if not candidates:
            context.logger.info("No URL candidates for secrets detection")
            return
            
        candidates.sort(reverse=True, key=lambda item: item[0])
        max_files = context.runtime_config.secrets_max_files
        selected_urls = [url for _, url, _ in candidates[:max_files]]
        
        detector = SecretsDetector(
            timeout=context.runtime_config.secrets_timeout,
            verify_tls=bool(context.runtime_config.verify_tls),
        )
        
        # ELITE: Call async scan_urls
        results = await detector.scan_urls(selected_urls, max_files)
        if not results:
            context.logger.info("Secrets detector found no confirmed matches")
            return

        artifacts_dir = context.record.paths.ensure_subdir("secrets")
        artifact_path = artifacts_dir / "matches.json"
        
        serialised = {
            url: [
                {
                    "pattern": m.pattern, "value_hash": m.value_hash,
                    "length": m.length, "entropy": m.entropy,
                    "start": m.start, "end": m.end, "confidence": m.confidence
                }
                for m in matches
            ]
            for url, matches in results.items()
        }
        artifact_path.write_text(json.dumps(serialised, indent=2, sort_keys=True), encoding="utf-8")

        total_matches = 0
        for url, matches in results.items():
            host = urlparse(url).hostname or ""
            for match in matches:
                total_matches += 1
                score, priority = self._score_priority(match.confidence)
                context.results.append({
                    "type": "finding", "finding_type": "exposed_secret", "source": "secrets-static",
                    "hostname": host, "url": url, "description": f"{match.pattern} ({match.confidence})",
                    "details": {
                        "pattern": match.pattern, "value_hash": match.value_hash,
                        "length": match.length, "entropy": match.entropy,
                        "confidence": match.confidence
                    },
                    "tags": ["secret", "static", match.confidence, "elite-entropy"],
                    "score": score, "priority": priority, "severity": self._severity_from_confidence(match.confidence),
                })

        context.logger.info("Secrets detection found %s high-confidence matches across %s URLs", total_matches, len(results))
        context.manager.update_metadata(context.record)

    @staticmethod
    def _score_priority(confidence: str) -> tuple[int, str]:
        if confidence == "high": return 95, "critical"
        if confidence == "medium": return 80, "high"
        return 55, "medium"

    @staticmethod
    def _severity_from_confidence(confidence: str) -> str:
        if confidence == "high": return "critical"
        if confidence == "medium": return "high"
        return "medium"
