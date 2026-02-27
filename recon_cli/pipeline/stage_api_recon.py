from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class APIReconStage(Stage):
    name = "api_recon"

    PROBE_PATHS = [
        "/.well-known/openapi.json",
        "/.well-known/swagger.json",
        "/swagger.json",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/v1/api-docs",
        "/swagger/v1/swagger.json",
        "/swagger/v1/swagger.yaml",
        "/swagger-ui/index.html",
        "/api-docs",
        "/docs",
        "/redoc",
        "/graphql/schema.json",
        "/graphql/v1",
        "/graphql",
        "/graphiql",
        "/graphql/console",
        "/grpc.health.v1.Health/Check",
    ]
    SPEC_INDICATORS = ("openapi", "swagger", "\"openapi\"", "\"swagger\"")
    LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "sso", "oauth")
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

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
        if bool(getattr(context.runtime_config, "api_recon_enrich_from_js", True)):
            enriched_paths = self._build_host_enriched_paths(context, host_info)
        else:
            enriched_paths = {}
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
        probe_attempts = 0
        enriched_probe_count = 0
        for host in ranked_hosts[:max_hosts]:
            info = host_info.get(host, {})
            base_url = str(info.get("base_url") or f"https://{host}")
            parsed_base = urlparse(base_url)
            scheme = parsed_base.scheme or "https"
            base = f"{scheme}://{host}"
            host_probe_paths = list(dict.fromkeys(self.PROBE_PATHS + enriched_paths.get(host, [])))
            for path in host_probe_paths:
                probe_attempts += 1
                if path not in self.PROBE_PATHS:
                    enriched_probe_count += 1
                url = urljoin(base, path)
                if not context.url_allowed(url):
                    continue
                session = context.auth_session(url)
                headers = context.auth_headers(
                    {"User-Agent": "recon-cli api-recon", "Accept": "application/json"}
                )
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
                content_type = resp.headers.get("Content-Type", "").lower()
                status_code = int(resp.status_code or 0)
                text = resp.text or ""
                meta = self._response_meta(resp, text)
                if status_code >= 500:
                    continue
                text = resp.text or ""
                if "graphql" in path:
                    if "graphql" in text.lower() or status_code in {200, 400}:
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
                    elif status_code in {401, 403, 302}:
                        context.emit_signal(
                            "graphql_candidate",
                            "url",
                            url,
                            confidence=0.4,
                            source="api-recon",
                            tags=["api:graphql"],
                            evidence={"status_code": status_code, "location": meta.get("location")},
                        )
                    continue
                data, spec_format = self._parse_spec(text, content_type)
                spec_hint = self._looks_like_spec(path, text)
                if status_code in {401, 403, 302} and spec_hint:
                    spec_payload = {
                        "type": "api_spec",
                        "source": "api-recon",
                        "hostname": host,
                        "url": url,
                        "tags": ["api:openapi", "api:auth-required"],
                        "score": 30,
                        "status_code": status_code,
                        "content_type": content_type,
                        "title": meta.get("title"),
                        "location": meta.get("location"),
                    }
                    context.results.append(spec_payload)
                    signal_type = "api_spec_auth_required"
                    if status_code == 302 and self._looks_like_login(meta):
                        signal_type = "api_spec_auth_challenge"
                    context.emit_signal(
                        signal_type,
                        "url",
                        url,
                        confidence=0.5,
                        source="api-recon",
                        tags=["api:openapi"],
                        evidence={"status_code": status_code, "location": meta.get("location")},
                    )
                    if host not in signaled_hosts:
                        context.emit_signal(
                            "api_surface",
                            "host",
                            host,
                            confidence=0.5,
                            source="api-recon",
                            tags=["api:openapi"],
                            evidence={"url": url},
                        )
                        signaled_hosts.add(host)
                    continue
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
                        "status_code": status_code,
                        "content_type": content_type,
                        "title": meta.get("title"),
                        "location": meta.get("location"),
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
        stats = context.record.metadata.stats.setdefault("api_recon", {})
        stats["specs"] = specs_found
        stats["urls_added"] = urls_added
        stats["probe_attempts"] = probe_attempts
        stats["enriched_probe_paths"] = enriched_probe_count
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

    def _build_host_enriched_paths(
        self,
        context: PipelineContext,
        host_info: Dict[str, Dict[str, object]],
    ) -> Dict[str, List[str]]:
        per_host: Dict[str, set[str]] = {host: set() for host in host_info}
        candidate_urls: List[str] = []
        for host, info in host_info.items():
            urls = info.get("urls") or []
            if isinstance(urls, list):
                for value in urls:
                    if isinstance(value, str):
                        candidate_urls.append(value)
        js_endpoints = context.get_data("js_endpoints", []) or []
        if isinstance(js_endpoints, list):
            for value in js_endpoints:
                if isinstance(value, str):
                    candidate_urls.append(value)
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            source = str(entry.get("source") or "").lower()
            if source not in {"js-intel", "ws-grpc", "api-spec", "api-recon"}:
                continue
            url_value = entry.get("url")
            if isinstance(url_value, str):
                candidate_urls.append(url_value)
        for value in candidate_urls:
            try:
                parsed = urlparse(value)
            except ValueError:
                continue
            host = str(parsed.hostname or "")
            if not host or host not in per_host:
                continue
            norm = self._normalize_probe_path(parsed.path)
            if not norm:
                continue
            per_host[host].add(norm)
            if "/api/" in norm:
                base = norm.split("/api/", 1)[0] + "/api"
                per_host[host].add(f"{base}/openapi.json")
                per_host[host].add(f"{base}/docs")
            if "graphql" in norm:
                per_host[host].add("/graphql")
                per_host[host].add("/graphiql")
            if "grpc" in norm:
                per_host[host].add("/grpc.health.v1.Health/Check")
        max_enriched = max(0, int(getattr(context.runtime_config, "api_recon_max_enriched_paths", 40)))
        if max_enriched <= 0:
            return {}
        return {host: sorted(paths)[:max_enriched] for host, paths in per_host.items() if paths}

    def _normalize_probe_path(self, path: str) -> str:
        value = str(path or "").strip()
        if not value:
            return ""
        if not value.startswith("/"):
            value = "/" + value
        if value.endswith("/") and len(value) > 1:
            value = value[:-1]
        if value in {"/", "/index.html"}:
            return ""
        lowered = value.lower()
        if any(token in lowered for token in ("swagger", "openapi", "api-docs", "graphql", "grpc", "/api/")):
            return value
        return ""

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

    def _looks_like_spec(self, path: str, text: str) -> bool:
        lowered_path = path.lower()
        if any(token in lowered_path for token in ("swagger", "openapi", "api-docs")):
            return True
        lowered_text = (text or "").lower()
        if any(token in lowered_text for token in self.SPEC_INDICATORS):
            return True
        return False

    def _response_meta(self, resp, body: str) -> Dict[str, object]:
        content_type = resp.headers.get("Content-Type", "") if resp else ""
        location = resp.headers.get("Location", "") if resp else ""
        title = self._extract_title(body)
        return {
            "content_type": content_type,
            "location": location,
            "title": title,
        }

    def _extract_title(self, body: str) -> str:
        if not body:
            return ""
        match = self.TITLE_RE.search(body)
        if not match:
            return ""
        title = match.group(1)
        title = re.sub(r"\\s+", " ", title).strip()
        return title[:120]

    def _looks_like_login(self, meta: Dict[str, object]) -> bool:
        location = str(meta.get("location") or "").lower()
        title = str(meta.get("title") or "").lower()
        if any(hint in location for hint in self.LOGIN_HINTS):
            return True
        if any(hint in title for hint in self.LOGIN_HINTS):
            return True
        return False
