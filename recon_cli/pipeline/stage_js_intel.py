from __future__ import annotations

import json
import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class JSIntelligenceStage(Stage):
    name = "js_intelligence"

    ENDPOINT_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
    RELATIVE_PATTERN = re.compile(r"/(?:api|graphql|v1|v2|v3|v4|auth|oauth|login|logout|register)[^\s\"'<>]*")
    SOURCEMAP_PATTERN = re.compile(r"sourceMappingURL=([^\s\"']+)")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_js_intel", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("js intelligence requires requests; skipping")
            return
        items = read_jsonl(context.record.paths.results_jsonl)
        js_urls = []
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url or not isinstance(url, str):
                continue
            if url.lower().endswith(".js") or "javascript" in str(entry.get("content_type", "")).lower():
                if entry.get("status_code") in {200, 302}:
                    js_urls.append(url)
        if not js_urls:
            context.logger.info("No JS URLs for intelligence stage")
            return
        max_files = int(getattr(context.runtime_config, "js_intel_max_files", 40))
        timeout = int(getattr(context.runtime_config, "js_intel_timeout", 12))
        max_urls = int(getattr(context.runtime_config, "js_intel_max_urls", 120))
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "js_intel",
            rps=float(getattr(runtime, "js_intel_rps", 0)),
            per_host=float(getattr(runtime, "js_intel_per_host_rps", 0)),
        )
        signaled_hosts: set[str] = set()
        js_urls = list(dict.fromkeys(js_urls))[:max_files]
        artifacts: List[Dict[str, object]] = []
        discovered_urls: List[str] = []
        for js_url in js_urls:
            session = context.auth_session(js_url)
            headers = context.auth_headers({"User-Agent": "recon-cli js-intel"})
            if limiter and not limiter.wait_for_slot(js_url, timeout=timeout):
                continue
            try:
                if session:
                    resp = session.get(
                        js_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
                else:
                    resp = requests.get(
                        js_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
            except Exception:
                if limiter:
                    limiter.on_error(js_url)
                continue
            if limiter:
                limiter.on_response(js_url, resp.status_code)
            if resp.status_code >= 400:
                continue
            content = resp.text or ""
            endpoints = set(self.ENDPOINT_PATTERN.findall(content))
            rels = set(self.RELATIVE_PATTERN.findall(content))
            for rel in rels:
                endpoints.add(urljoin(js_url, rel))
            source_map = None
            map_match = self.SOURCEMAP_PATTERN.search(content)
            if map_match:
                source_map = urljoin(js_url, map_match.group(1))
                if limiter and not limiter.wait_for_slot(source_map, timeout=timeout):
                    pass
                else:
                    try:
                        if session:
                            map_resp = session.get(
                                source_map,
                                timeout=timeout,
                                allow_redirects=True,
                                headers=headers,
                                verify=context.runtime_config.verify_tls,
                            )
                        else:
                            map_resp = requests.get(
                                source_map,
                                timeout=timeout,
                                allow_redirects=True,
                                headers=headers,
                                verify=context.runtime_config.verify_tls,
                            )
                        if map_resp.status_code < 400 and map_resp.text:
                            if limiter:
                                limiter.on_response(source_map, map_resp.status_code)
                            try:
                                map_data = json.loads(map_resp.text)
                            except json.JSONDecodeError:
                                map_data = {}
                            sources_content = map_data.get("sourcesContent") or []
                            for source_blob in sources_content[:5]:
                                if not source_blob or not isinstance(source_blob, str):
                                    continue
                                endpoints.update(self.ENDPOINT_PATTERN.findall(source_blob))
                                for rel in self.RELATIVE_PATTERN.findall(source_blob):
                                    endpoints.add(urljoin(js_url, rel))
                    except Exception:
                        if limiter:
                            limiter.on_error(source_map)
                        pass
            endpoints = list(endpoints)[:max_urls]
            artifacts.append(
                {
                    "js_url": js_url,
                    "endpoints": endpoints,
                    "source_map": source_map,
                }
            )
            for endpoint in endpoints:
                if not context.url_allowed(endpoint):
                    continue
                payload = {
                    "type": "url",
                    "source": "js-intel",
                    "url": endpoint,
                    "hostname": urlparse(endpoint).hostname,
                    "tags": ["js:discovered", "source:js"],
                    "score": 30,
                }
                if context.results.append(payload):
                    discovered_urls.append(endpoint)
                host = urlparse(endpoint).hostname
                if host:
                    context.emit_signal(
                        "js_endpoint",
                        "url",
                        endpoint,
                        confidence=0.4,
                        source="js-intel",
                        tags=["source:js"],
                    )
                    path = urlparse(endpoint).path.lower()
                    if ("/api" in path or "/graphql" in path) and host not in signaled_hosts:
                        context.emit_signal(
                            "api_surface",
                            "host",
                            host,
                            confidence=0.4,
                            source="js-intel",
                            tags=["api:js"],
                            evidence={"url": endpoint},
                        )
                        signaled_hosts.add(host)
        if artifacts:
            artifact_path = context.record.paths.artifact("js_intel.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")
            context.set_data("js_endpoints", discovered_urls)
            stats = context.record.metadata.stats.setdefault("js_intel", {})
            stats["files"] = len(artifacts)
            stats["endpoints"] = len(discovered_urls)
            context.manager.update_metadata(context.record)
