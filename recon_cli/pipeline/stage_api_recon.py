from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class APIReconStage(Stage):
    name = "api_recon"

    PROBE_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/openapi.yaml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/swagger/v1/swagger.yaml",
        "/api-docs",
        "/graphql",
        "/graphiql",
        "/graphql/console",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_api_recon", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("api recon requires requests; skipping")
            return
        host_info = self._collect_hosts(context)
        if not host_info:
            return
        signal_index = context.signal_index()
        ranked_hosts = self._rank_hosts(host_info, signal_index)
        max_hosts = int(getattr(context.runtime_config, "api_recon_max_hosts", 50))
        timeout = int(getattr(context.runtime_config, "api_recon_timeout", 8))
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "api_recon",
            rps=float(getattr(runtime, "api_recon_rps", 0)),
            per_host=float(getattr(runtime, "api_recon_per_host_rps", 0)),
        )
        signaled_hosts: set[str] = set()
        specs_found = 0
        urls_added = 0
        for host in ranked_hosts[:max_hosts]:
            info = host_info.get(host, {})
            base_url = str(info.get("base_url") or f"https://{host}")
            parsed_base = urlparse(base_url)
            scheme = parsed_base.scheme or "https"
            base = f"{scheme}://{host}"
            for path in self.PROBE_PATHS:
                url = urljoin(base, path)
                if not context.url_allowed(url):
                    continue
                session = context.auth_session(url)
                headers = context.auth_headers({"User-Agent": "recon-cli api-recon"})
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                try:
                    if session:
                        resp = session.get(
                            url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers=headers,
                            verify=context.runtime_config.verify_tls,
                        )
                    else:
                        resp = requests.get(
                            url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers=headers,
                            verify=context.runtime_config.verify_tls,
                        )
                except Exception:
                    if limiter:
                        limiter.on_error(url)
                    continue
                if limiter:
                    limiter.on_response(url, resp.status_code)
                if resp.status_code >= 400:
                    continue
                text = resp.text or ""
                content_type = resp.headers.get("Content-Type", "").lower()
                if "graphql" in path:
                    if "graphql" in text.lower() or resp.status_code in {200, 400}:
                        payload = {
                            "type": "api",
                            "source": "api-recon",
                            "hostname": host,
                            "url": url,
                            "tags": ["api:graphql"],
                            "score": 40,
                        }
                        if context.results.append(payload):
                            urls_added += 1
                        if host not in signaled_hosts:
                            context.emit_signal(
                                "api_surface",
                                "host",
                                host,
                                confidence=0.6,
                                source="api-recon",
                                tags=["api:graphql"],
                                evidence={"url": url},
                            )
                            signaled_hosts.add(host)
                    continue
                data, spec_format = self._parse_spec(text, content_type)
                if isinstance(data, dict) and data:
                    specs_found += 1
                    paths = data.get("paths") or {}
                    if isinstance(paths, dict):
                        for api_path in list(paths.keys())[:200]:
                            full_url = urljoin(base, api_path)
                            if not context.url_allowed(full_url):
                                continue
                            payload = {
                                "type": "url",
                                "source": "api-spec",
                                "url": full_url,
                                "hostname": host,
                                "tags": ["api:spec"],
                                "score": 35,
                            }
                            if context.results.append(payload):
                                urls_added += 1
                    spec_payload = {
                        "type": "api_spec",
                        "source": "api-recon",
                        "hostname": host,
                        "url": url,
                        "tags": ["api:openapi"],
                        "score": 40,
                    }
                    if spec_format:
                        spec_payload["spec_format"] = spec_format
                    context.results.append(spec_payload)
                    if host not in signaled_hosts:
                        context.emit_signal(
                            "api_surface",
                            "host",
                            host,
                            confidence=0.7,
                            source="api-recon",
                            tags=["api:openapi"],
                            evidence={"url": url},
                        )
                        signaled_hosts.add(host)
        if specs_found or urls_added:
            stats = context.record.metadata.stats.setdefault("api_recon", {})
            stats["specs"] = specs_found
            stats["urls_added"] = urls_added
            context.manager.update_metadata(context.record)

    def _collect_hosts(self, context: PipelineContext) -> Dict[str, Dict[str, object]]:
        host_info: Dict[str, Dict[str, object]] = {}
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url_value = entry.get("url")
            host = entry.get("hostname") or (url_value and urlparse(url_value).hostname)
            if not host:
                continue
            info = host_info.setdefault(
                host,
                {"urls": [], "tags": set(), "score": 0, "base_url": None},
            )
            if url_value:
                info["urls"].append(url_value)
                if info["base_url"] is None:
                    info["base_url"] = url_value
                path = urlparse(url_value).path.lower()
                if "/api" in path or "/graphql" in path:
                    info["score"] = max(int(info.get("score", 0)), 10)
            for tag in entry.get("tags", []):
                if isinstance(tag, str):
                    info["tags"].add(tag)
            score = entry.get("score")
            if isinstance(score, int):
                info["score"] = max(int(info.get("score", 0)), score)
        return host_info

    @staticmethod
    def _rank_hosts(
        host_info: Dict[str, Dict[str, object]],
        signal_index: Dict[str, Dict[str, set[str]]],
    ) -> List[str]:
        scored: List[Tuple[str, int]] = []
        for host, info in host_info.items():
            score = int(info.get("score") or 0)
            tags = info.get("tags", set()) or set()
            if "service:api" in tags:
                score += 15
            if host.startswith("api."):
                score += 10
            host_signals = signal_index.get("by_host", {}).get(host, set())
            if "api_surface" in host_signals:
                score += 25
            scored.append((host, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        return [host for host, _ in scored]

    @staticmethod
    def _parse_spec(text: str, content_type: str) -> Tuple[Dict[str, object], Optional[str]]:
        if not text:
            return {}, None
        lowered = (content_type or "").lower()
        stripped = text.lstrip()
        if "json" in lowered or stripped.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return data, "json"
        if "yaml" in lowered or "yml" in lowered or "openapi:" in text or "swagger:" in text:
            try:
                import yaml  # type: ignore
            except Exception:
                if "openapi:" in text or "swagger:" in text:
                    return {"paths": {}}, "yaml"
                return {}, None
            try:
                data = yaml.safe_load(text)
            except Exception:
                return {}, None
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return data, "yaml"
        return {}, None
