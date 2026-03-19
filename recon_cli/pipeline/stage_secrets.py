from __future__ import annotations

import json
from collections import Counter
from typing import List
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.secrets.detector import SecretsDetector
from recon_cli.utils import enrich as enrich_utils
from recon_cli.utils.jsonl import iter_jsonl, read_jsonl


class SecretsDetectionStage(Stage):
    name = "secrets_detection"

    def is_enabled(self, context: PipelineContext) -> bool:
        if not context.runtime_config.enable_secrets:
            return False
        return context.runtime_config.secrets_max_files > 0

    def execute(self, context: PipelineContext) -> None:
        items = read_jsonl(context.record.paths.results_jsonl)
        if not items:
            return
        candidates: List[tuple[int, str, str]] = []  # (score, url, host)
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url or not isinstance(url, str):
                continue
            if not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            ext = parsed.path.split(".")[-1].lower() if "." in parsed.path else ""
            if ext not in {
                "js",
                "json",
                "env",
                "config",
                "txt",
                "properties",
                "yml",
                "yaml",
            }:
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
        session = context.auth_session(selected_urls[0] if selected_urls else None)
        detector = SecretsDetector(
            timeout=context.runtime_config.secrets_timeout,
            verify_tls=bool(context.runtime_config.verify_tls),
            session=session,
        )
        results = detector.scan_urls(selected_urls, max_files)
        if not results:
            context.logger.info("Secrets detector found no matches")
            return

        artifacts_dir = context.record.paths.ensure_subdir("secrets")
        artifact_path = artifacts_dir / "matches.json"
        serialised = {
            url: [
                {
                    "pattern": match.pattern,
                    "value_hash": match.value_hash,
                    "length": match.length,
                    "entropy": match.entropy,
                    "start": match.start,
                    "end": match.end,
                }
                for match in matches
            ]
            for url, matches in results.items()
        }
        artifact_path.write_text(
            json.dumps(serialised, indent=2, sort_keys=True), encoding="utf-8"
        )

        pattern_counter: Counter[str] = Counter()
        total_matches = 0
        for url, matches in results.items():
            if not context.url_allowed(url):
                continue
            host = urlparse(url).hostname or ""
            for match in matches:
                total_matches += 1
                pattern_counter[match.pattern] += 1
                score, priority = self._score_priority(match.confidence)
                context.results.append(
                    {
                        "type": "finding",
                        "finding_type": "exposed_secret",
                        "source": "secrets-static",
                        "hostname": host,
                        "url": url,
                        "description": f"{match.pattern} ({match.confidence})",
                        "details": {
                            "pattern": match.pattern,
                            "value_hash": match.value_hash,
                            "length": match.length,
                            "entropy": match.entropy,
                            "location": {"start": match.start, "end": match.end},
                        },
                        "tags": ["secret", "static", match.confidence],
                        "score": score,
                        "priority": priority,
                        "severity": self._severity_from_confidence(match.confidence),
                    }
                )

        boosted_urls = {
            url: max(self._score_priority(match.confidence)[0] for match in matches)
            for url, matches in results.items()
            if matches
        }
        if boosted_urls:
            results_path = context.record.paths.results_jsonl
            updated_entries = []
            for entry in iter_jsonl(results_path):
                if entry.get("type") == "url":
                    entry_url = entry.get("url")
                    if entry_url in boosted_urls:
                        tags = set(entry.get("tags", []))
                        tags.update({"secret", "secret-hit"})
                        entry["tags"] = sorted(tags)
                        entry["score"] = max(
                            int(entry.get("score", 0)), boosted_urls[entry_url]
                        )
                        entry["priority"] = enrich_utils.classify_priority(
                            entry["score"]
                        )
                updated_entries.append(entry)
            context.results.replace_all(updated_entries)

        stats = context.record.metadata.stats.setdefault("secrets", {})
        stats.update(
            {
                "findings": total_matches,
                "urls": len(results),
                "patterns": dict(pattern_counter),
                "guidance": "Rotate/revoke affected keys and update secrets management immediately.",
            }
        )
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Secrets detection found %s matches across %s URLs",
            total_matches,
            len(results),
        )

    @staticmethod
    def _score_priority(confidence: str) -> tuple[int, str]:
        if confidence == "high":
            return 95, "critical"
        if confidence == "medium":
            return 80, "high"
        return 55, "medium"

    @staticmethod
    def _severity_from_confidence(confidence: str) -> str:
        if confidence == "high":
            return "critical"
        if confidence == "medium":
            return "high"
        return "medium"
