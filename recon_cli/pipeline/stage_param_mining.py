from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Dict, List
from urllib.parse import parse_qsl, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class ParamMiningStage(Stage):
    name = "param_mining"
    requires = ["url", "api"]
    provides = ["parameter", "param_mutation"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_param_mining", False))

    def execute(self, context: PipelineContext) -> None:
        candidates: List[str] = []
        auth_inputs: Dict[str, List[str]] = defaultdict(list)
        value_examples: Dict[str, List[str]] = defaultdict(list)
        for entry in context.get_results():
            etype = entry.get("type")
            if etype == "url":
                url = entry.get("url")
                if url and "?" in url:
                    candidates.append(url)
                    parsed = urlparse(url)
                    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                        if value and len(value_examples[name]) < 8:
                            value_examples[name].append(value[:120])
                if isinstance(url, str) and "{" in url and "}" in url:
                    parsed = urlparse(url)
                    for token in parsed.path.split("/"):
                        if (
                            token.startswith("{")
                            and token.endswith("}")
                            and len(token) > 2
                        ):
                            name = token[1:-1]
                            auth_inputs.setdefault(name, []).append(url)
            elif etype == "auth_form":
                url = entry.get("url") or entry.get("action")
                inputs = entry.get("inputs") or []
                if isinstance(inputs, list):
                    for item in inputs:
                        if not isinstance(item, dict):
                            continue
                        name = item.get("name")
                        if name:
                            auth_inputs.setdefault(str(name), []).append(
                                str(url) if url else ""
                            )
        js_endpoints = context.get_data("js_endpoints", []) or []
        for url in js_endpoints:  # type: ignore[attr-defined]
            if url and "?" in url:
                candidates.append(url)
        js_param_hints = context.get_data("js_param_hints", []) or []
        if isinstance(js_param_hints, list):
            for name in js_param_hints:
                if isinstance(name, str) and name:
                    auth_inputs.setdefault(name, []).append("js:intel")
        elif isinstance(js_param_hints, dict):
            for name, urls in js_param_hints.items():
                if isinstance(name, str) and name:
                    if isinstance(urls, list):
                        for url in urls:
                            auth_inputs.setdefault(name, []).append(url)
                    else:
                        auth_inputs.setdefault(name, []).append("js:intel")
        if not candidates:
            context.logger.info("No parameterized URLs found")
            return
        candidates = list(dict.fromkeys(candidates))
        max_urls = int(getattr(context.runtime_config, "param_mining_max_urls", 150))
        candidates = candidates[:max_urls]
        params: Counter[str] = Counter()
        examples: Dict[str, List[str]] = defaultdict(list)
        for url in candidates:
            parsed = urlparse(url)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                params[name] += 1
                if len(examples[name]) < 3:
                    examples[name].append(url)
        for name, urls in auth_inputs.items():
            params[name] += len(urls)
            for url in urls[:3]:
                if url:
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
        mutation_catalog: Dict[str, Dict[str, object]] = {}
        if bool(
            getattr(context.runtime_config, "param_mining_generate_mutations", True)
        ):
            max_mutations = max(
                1,
                int(
                    getattr(
                        context.runtime_config, "param_mining_mutations_per_param", 8
                    )
                ),
            )
            for name, count in params.most_common(max_params):
                category = self._infer_param_category(
                    name, value_examples.get(name, [])
                )
                values = self._mutation_values_for_category(
                    category, max_mutations=max_mutations
                )
                mutation_catalog[name] = {
                    "category": category,
                    "values": values,
                    "count": count,
                }
                context.results.append(
                    {
                        "type": "param_mutation",
                        "source": "param-mining",
                        "name": name,
                        "category": category,
                        "values": values,
                        "count": count,
                        "score": min(65, 15 + count),
                        "tags": ["param", "mutation", f"category:{category}"],
                    }
                )
        artifact_path = context.record.paths.artifact("param_mining.json")
        artifact_path.write_text(
            json.dumps(
                {
                    "params": params.most_common(max_params),
                    "examples": examples,
                    "candidates": candidates,
                    "mutations": mutation_catalog,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context.set_data("param_urls", candidates)
        if mutation_catalog:
            context.set_data("param_mutations", mutation_catalog)
        stats = context.record.metadata.stats.setdefault("param_mining", {})
        stats["params"] = min(len(params), max_params)
        stats["urls"] = len(candidates)
        stats["mutation_params"] = len(mutation_catalog)
        stats["mutation_values"] = sum(
            len(item.get("values", [])) for item in mutation_catalog.values()  # type: ignore[misc, arg-type]
        )
        context.manager.update_metadata(context.record)

    def _infer_param_category(self, name: str, values: List[str]) -> str:
        lowered = (name or "").lower()
        observed = " ".join(values).lower()
        if lowered in {
            "id",
            "uid",
            "user_id",
            "account_id",
            "order_id",
        } or lowered.endswith("_id"):
            return "identifier"
        if any(
            token in lowered
            for token in {
                "url",
                "uri",
                "redirect",
                "callback",
                "next",
                "dest",
                "target",
            }
        ):
            return "url"
        if lowered in {"url", "uri", "dest", "target", "next", "redirect", "callback"}:
            return "url"
        if lowered in {"path", "file", "filename", "filepath"}:
            return "file_path"
        if lowered in {"email", "mail"}:
            return "email"
        if lowered in {"token", "auth", "apikey", "api_key", "key", "secret", "jwt"}:
            return "token"
        if lowered in {"page", "limit", "offset", "size"}:
            return "pagination"
        if lowered in {"debug", "admin", "is_admin", "enabled", "active", "internal"}:
            return "boolean_flag"
        if any(item.isdigit() for item in values[:3]):
            return "identifier"
        if "http://" in observed or "https://" in observed:
            return "url"
        return "generic"

    def _mutation_values_for_category(
        self, category: str, *, max_mutations: int
    ) -> List[str]:
        catalog = {
            "identifier": [
                "0",
                "1",
                "2",
                "999999",
                "-1",
                "00000000-0000-0000-0000-000000000000",
                "null",
            ],
            "url": [
                "https://example.org/cb",
                "//example.org/cb",
                "http://127.0.0.1/",
                "http://169.254.169.254/latest/meta-data/",
                "javascript:alert(1)",
            ],
            "file_path": [
                "../../etc/passwd",
                "/etc/passwd",
                "..\\..\\windows\\win.ini",
                "file:///etc/passwd",
            ],
            "email": [
                "attacker@example.org",
                "admin@example.org",
                "test+recon@example.org",
            ],
            "token": ["invalid-token", "A" * 40, "null", "undefined", ""],
            "pagination": ["0", "1", "100", "1000", "-1"],
            "boolean_flag": ["true", "false", "1", "0", "on", "off"],
            "generic": [
                "test",
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "${7*7}",
                "%0a",
                "",
            ],
        }
        return list(catalog.get(category, catalog["generic"]))[:max_mutations]
