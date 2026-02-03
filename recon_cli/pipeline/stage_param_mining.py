from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Dict, List
from urllib.parse import parse_qsl, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class ParamMiningStage(Stage):
    name = "param_mining"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_param_mining", False))

    def execute(self, context: PipelineContext) -> None:
        candidates: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if url and "?" in url:
                candidates.append(url)
        js_endpoints = context.get_data("js_endpoints", []) or []
        for url in js_endpoints:
            if url and "?" in url:
                candidates.append(url)
        if not candidates:
            context.logger.info("No parameterized URLs found")
            return
        candidates = list(dict.fromkeys(candidates))
        max_urls = int(getattr(context.runtime_config, "param_mining_max_urls", 150))
        candidates = candidates[:max_urls]
        params = Counter()
        examples: Dict[str, List[str]] = defaultdict(list)
        for url in candidates:
            parsed = urlparse(url)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                params[name] += 1
                if len(examples[name]) < 3:
                    examples[name].append(url)
        max_params = int(getattr(context.runtime_config, "param_mining_max_params", 60))
        for name, count in params.most_common(max_params):
            payload = {
                "type": "parameter",
                "source": "param-mining",
                "name": name,
                "count": count,
                "examples": examples.get(name, []),
                "score": min(50, 10 + count),
                "tags": ["param"],
            }
            context.results.append(payload)
        artifact_path = context.record.paths.artifact("param_mining.json")
        artifact_path.write_text(
            json.dumps(
                {
                    "params": params.most_common(max_params),
                    "examples": examples,
                    "candidates": candidates,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context.set_data("param_urls", candidates)
        stats = context.record.metadata.stats.setdefault("param_mining", {})
        stats["params"] = min(len(params), max_params)
        stats["urls"] = len(candidates)
        context.manager.update_metadata(context.record)
