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
    RELATIVE_PATTERN = re.compile(
        r"/(?:api|graphql|v\\d+|auth|oauth|login|logout|register|admin|internal|debug|config|upload|media)[^\\s\"'<>]*"
    )
    SOURCEMAP_PATTERN = re.compile(r"sourceMappingURL=([^\s\"']+)")
    AUTH_HINTS = ("login", "signin", "sign-in", "signup", "sign-up", "register", "password", "reset", "forgot", "auth", "oauth", "sso")
    ADMIN_HINTS = ("admin", "dashboard", "console", "manage", "staff", "internal", "superuser")
    ACCOUNT_HINTS = ("account", "profile", "user", "customer", "member")
    BILLING_HINTS = ("billing", "invoice", "payment", "stripe", "checkout", "subscription", "plan")
    PII_HINTS = ("ssn", "passport", "token", "secret", "apikey", "api-key", "credit", "card")
    INTERNAL_HINTS = ("internal", "intranet", "employee", "corp", "backoffice")
    DEBUG_HINTS = ("debug", "trace", "health", "metrics", "status", "actuator")
    UPLOAD_HINTS = ("upload", "file", "attachment", "media", "avatar", "profile-picture")
    CONFIG_HINTS = ("config", "settings", "env", "secrets", "apikey", "token", "jwt")
    GRAPHQL_HINTS = ("graphql", "graphiql", "apollo")
    SPEC_HINTS = ("swagger", "openapi", "api-docs")
    STATIC_EXTENSIONS = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".css",
        ".map",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".webm",
        ".mov",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".7z",
    )

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
            normalized = []
            seen_norm = set()
            for endpoint in endpoints:
                norm = self._normalize_endpoint(endpoint)
                if not norm or norm in seen_norm:
                    continue
                seen_norm.add(norm)
                normalized.append(norm)
            endpoints = normalized[:max_urls]
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
                parsed = urlparse(endpoint)
                path = parsed.path.lower()
                if self._is_static_asset(path):
                    continue
                tags, score = self._classify_endpoint(path)
                payload = {
                    "type": "url",
                    "source": "js-intel",
                    "url": endpoint,
                    "hostname": parsed.hostname,
                    "tags": sorted(tags),
                    "score": score,
                }
                if context.results.append(payload):
                    discovered_urls.append(endpoint)
                host = parsed.hostname
                if host:
                    context.emit_signal(
                        "js_endpoint",
                        "url",
                        endpoint,
                        confidence=0.4,
                        source="js-intel",
                        tags=["source:js"],
                    )
                    if tags.intersection({"surface:login", "surface:register", "surface:password-reset"}):
                        context.emit_signal(
                            "auth_surface",
                            "url",
                            endpoint,
                            confidence=0.5,
                            source="js-intel",
                            tags=sorted(tags),
                            evidence={"url": endpoint},
                        )
                    if "surface:admin" in tags:
                        context.emit_signal(
                            "admin_surface",
                            "url",
                            endpoint,
                            confidence=0.5,
                            source="js-intel",
                            tags=sorted(tags),
                            evidence={"url": endpoint},
                        )
                    if "surface:internal" in tags:
                        context.emit_signal(
                            "internal_surface",
                            "url",
                            endpoint,
                            confidence=0.4,
                            source="js-intel",
                            tags=sorted(tags),
                            evidence={"url": endpoint},
                        )
                    if "surface:debug" in tags:
                        context.emit_signal(
                            "debug_surface",
                            "url",
                            endpoint,
                            confidence=0.4,
                            source="js-intel",
                            tags=sorted(tags),
                            evidence={"url": endpoint},
                        )
                    if tags.intersection({"surface:billing", "surface:pii", "surface:account"}):
                        context.emit_signal(
                            "sensitive_surface",
                            "url",
                            endpoint,
                            confidence=0.4,
                            source="js-intel",
                            tags=sorted(tags),
                            evidence={"url": endpoint},
                        )
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

    def _classify_endpoint(self, path: str) -> tuple[set[str], int]:
        tags = {"js:discovered", "source:js"}
        score = 30
        if "/api" in path or "/graphql" in path:
            tags.add("service:api")
        if any(hint in path for hint in self.GRAPHQL_HINTS):
            tags.add("api:graphql")
        if any(hint in path for hint in self.SPEC_HINTS) and path.endswith((".json", ".yaml", ".yml")):
            tags.add("api:spec")
        if any(hint in path for hint in self.AUTH_HINTS):
            tags.add("surface:login")
        if "reset" in path or "forgot" in path:
            tags.add("surface:password-reset")
        if "register" in path or "signup" in path:
            tags.add("surface:register")
        if any(hint in path for hint in self.ADMIN_HINTS):
            tags.add("surface:admin")
        if any(hint in path for hint in self.ACCOUNT_HINTS):
            tags.add("surface:account")
        if any(hint in path for hint in self.BILLING_HINTS):
            tags.add("surface:billing")
        if any(hint in path for hint in self.PII_HINTS):
            tags.add("surface:pii")
        if any(hint in path for hint in self.INTERNAL_HINTS):
            tags.add("surface:internal")
        if any(hint in path for hint in self.DEBUG_HINTS):
            tags.add("surface:debug")
        if any(hint in path for hint in self.UPLOAD_HINTS):
            tags.add("surface:upload")
        if any(hint in path for hint in self.CONFIG_HINTS):
            tags.add("surface:config")
        if "surface:admin" in tags:
            score += 15
        if "surface:login" in tags or "surface:register" in tags:
            score += 10
        if tags.intersection({"surface:billing", "surface:pii"}):
            score += 10
        if "surface:internal" in tags:
            score += 10
        if "surface:debug" in tags:
            score += 12
        if "surface:config" in tags:
            score += 8
        if "surface:upload" in tags:
            score += 6
        if "api:graphql" in tags:
            score += 5
        if "api:spec" in tags:
            score += 5
        return tags, score

    def _normalize_endpoint(self, endpoint: str) -> str:
        if not endpoint:
            return ""
        try:
            parsed = urlparse(endpoint)
        except Exception:
            return ""
        if not parsed.scheme or not parsed.netloc:
            return ""
        cleaned = parsed._replace(fragment="")
        return cleaned.geturl()

    def _is_static_asset(self, path: str) -> bool:
        if not path:
            return False
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False
