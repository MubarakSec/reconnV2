from __future__ import annotations

import json
from typing import List
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
        hosts: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            host = entry.get("hostname") or (entry.get("url") and urlparse(entry["url"]).hostname)
            if host:
                hosts.append(host)
        if not hosts:
            return
        hosts = list(dict.fromkeys(hosts))
        max_hosts = int(getattr(context.runtime_config, "api_recon_max_hosts", 50))
        timeout = int(getattr(context.runtime_config, "api_recon_timeout", 8))
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "api_recon",
            rps=float(getattr(runtime, "api_recon_rps", 0)),
            per_host=float(getattr(runtime, "api_recon_per_host_rps", 0)),
        )
        specs_found = 0
        urls_added = 0
        for host in hosts[:max_hosts]:
            base = f"https://{host}"
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
                    continue
                if "json" in content_type or text.strip().startswith("{"):
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        data = {}
                    if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
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
                        context.results.append(spec_payload)
        if specs_found or urls_added:
            stats = context.record.metadata.stats.setdefault("api_recon", {})
            stats["specs"] = specs_found
            stats["urls_added"] = urls_added
            context.manager.update_metadata(context.record)
