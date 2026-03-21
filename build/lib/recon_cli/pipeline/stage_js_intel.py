from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


@dataclass
class _JSSurfaceExtraction:
    endpoints: set[str] = field(default_factory=set)
    graphql_endpoints: set[str] = field(default_factory=set)
    graphql_operations: set[str] = field(default_factory=set)
    persisted_query_hints: set[str] = field(default_factory=set)
    ws_endpoints: set[str] = field(default_factory=set)
    high_value_strings: set[str] = field(default_factory=set)

    def merge(self, other: "_JSSurfaceExtraction") -> None:
        self.endpoints.update(other.endpoints)
        self.graphql_endpoints.update(other.graphql_endpoints)
        self.graphql_operations.update(other.graphql_operations)
        self.persisted_query_hints.update(other.persisted_query_hints)
        self.ws_endpoints.update(other.ws_endpoints)
        self.high_value_strings.update(other.high_value_strings)


class JSIntelligenceStage(Stage):
    name = "js_intelligence"
    requires = ["url"]
    provides = ["api", "parameter"]

    ENDPOINT_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
    WS_ENDPOINT_PATTERN = re.compile(r"wss?://[^\s\"'<>\\)]+", re.IGNORECASE)
    API_CALL_PATTERN = re.compile(
        r"(?:fetch|axios\.(?:get|post|put|patch|delete)|\$.ajax)\(\s*([\"'`])([^\"'`]+)\1",
        re.IGNORECASE,
    )
    RELATIVE_PATTERN = re.compile(
        r"(?<![A-Za-z0-9_])/(?:"
        r"api|graphql|gql|v\d+|admin|internal|export|download|uploads|files|"
        r"report|reports|billing|oauth|auth|login|logout|session|sessions|"
        r"token|tokens|users|user|account|accounts|tenant|tenants|org|orgs|"
        r"organization|organizations|project|projects|team|teams|workspace|workspaces|"
        r"invoice|invoices|payment|checkout|order|orders|cart|carts|subscription|subscriptions|"
        r"feature|features|flag|flags|debug|preview|staging|upload|media|ws|websocket|socket|sockjs|live|stream"
        r")(?:[A-Za-z0-9_\-./?=&%]*)",
        re.IGNORECASE,
    )
    DYNAMIC_ROUTE_PATTERN = re.compile(
        r"`(/(?:"
        r"api|graphql|gql|v\d+|admin|internal|export|download|uploads|files|"
        r"billing|oauth|auth|login|logout|session|token|users|user|account|accounts|"
        r"tenant|org|organization|project|team|workspace|invoice|payment|checkout|"
        r"order|cart|subscription|feature|flag|debug|preview|staging|upload|media|"
        r"ws|websocket|socket|sockjs|live|stream"
        r")[^`<>]*)`",
        re.IGNORECASE,
    )
    QUERY_PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_-]{1,40})=")
    PARAM_BLOCK_PATTERN = re.compile(
        r"(?:params|query|variables)\s*:\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL
    )
    PARAM_KEY_PATTERN = re.compile(r"([a-zA-Z_][a-zA-Z0-9_-]{1,40})\s*:")
    GRAPHQL_ENDPOINT_PATTERN = re.compile(r"/graphql\b|/gql\b", re.IGNORECASE)
    GRAPHQL_OPERATION_NAME_PATTERN = re.compile(
        r"operationName\s*[:=]\s*[\"']([A-Za-z0-9_]{2,})[\"']"
    )
    GRAPHQL_OPERATION_PATTERN = re.compile(
        r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]{2,})"
    )
    PERSISTED_QUERY_PATTERN = re.compile(
        r"sha256Hash\s*[:=]\s*[\"']([a-fA-F0-9]{16,64})[\"']"
    )
    SOURCEMAP_PATTERN = re.compile(r"sourceMappingURL=([^\s\"']+)")
    AUTH_HINTS = (
        "login",
        "signin",
        "sign-in",
        "signup",
        "sign-up",
        "register",
        "password",
        "reset",
        "forgot",
        "auth",
        "oauth",
        "sso",
    )
    ADMIN_HINTS = (
        "admin",
        "dashboard",
        "console",
        "manage",
        "staff",
        "internal",
        "superuser",
    )
    ACCOUNT_HINTS = ("account", "profile", "user", "customer", "member")
    BILLING_HINTS = (
        "billing",
        "invoice",
        "payment",
        "stripe",
        "checkout",
        "subscription",
        "plan",
    )
    PII_HINTS = (
        "ssn",
        "passport",
        "token",
        "secret",
        "apikey",
        "api-key",
        "credit",
        "card",
    )
    INTERNAL_HINTS = ("internal", "intranet", "employee", "corp", "backoffice")
    DEBUG_HINTS = ("debug", "trace", "health", "metrics", "status", "actuator")
    UPLOAD_HINTS = (
        "upload",
        "file",
        "attachment",
        "media",
        "avatar",
        "profile-picture",
    )
    CONFIG_HINTS = ("config", "settings", "env", "secrets", "apikey", "token", "jwt")
    GRAPHQL_HINTS = ("graphql", "graphiql", "apollo", "gql")
    WS_HINTS = ("ws", "websocket", "socket", "socket.io", "sockjs", "live", "stream")
    HIGH_VALUE_HINTS = (
        "admin",
        "entitlement",
        "featureflag",
        "feature_flag",
        "flag",
        "debug",
        "internal",
        "staging",
        "preview",
        "billing",
        "invoice",
        "payment",
        "export",
        "report",
        "impersonate",
        "impersonation",
        "role",
        "permission",
        "rbac",
        "tenant",
        "organization",
        "workspace",
    )
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
            pass
        except Exception:
            context.logger.warning("js intelligence requires requests; skipping")
            return

        items = context.get_results()
        js_urls, js_url_bases = self._collect_js_candidates(items, context)

        if not js_urls:
            context.logger.info("No JS URLs for intelligence stage")
            return

        max_files = int(getattr(context.runtime_config, "js_intel_max_files", 40))
        timeout = int(getattr(context.runtime_config, "js_intel_timeout", 12))
        max_urls = int(getattr(context.runtime_config, "js_intel_max_urls", 120))
        include_dynamic = bool(
            getattr(context.runtime_config, "js_intel_extract_dynamic_routes", True)
        )
        include_hidden = bool(
            getattr(context.runtime_config, "js_intel_extract_hidden_params", True)
        )
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "js_intel",
            rps=float(getattr(runtime, "js_intel_rps", 0)),
            per_host=float(getattr(runtime, "js_intel_per_host_rps", 0)),
        )
        signaled_hosts: set[str] = set()
        js_urls = js_urls[:max_files]
        artifacts: List[Dict[str, object]] = []
        discovered_urls: List[str] = []
        graphql_endpoints: set[str] = set()
        graphql_operations: set[str] = set()
        persisted_query_hints: set[str] = set()
        ws_endpoints: set[str] = set()
        high_value_strings: set[str] = set()
        hidden_param_hints: Dict[str, Set[str]] = defaultdict(set)

        verify_tls = getattr(context.runtime_config, "verify_tls", True)

        for js_url in js_urls:
            surface_base_url = js_url_bases.get(js_url) or js_url
            session = context.auth_session(js_url)
            headers = context.auth_headers({"User-Agent": "recon-cli js-intel"})

            content = self._fetch_content(
                js_url, session, headers, timeout, limiter, verify_tls
            )
            if not content:
                continue

            extraction = _JSSurfaceExtraction()
            self._process_js_file(
                js_url,
                surface_base_url,
                content,
                extraction,
                hidden_param_hints,
                include_hidden,
                include_dynamic,
            )

            source_map = self._process_source_map(
                js_url,
                surface_base_url,
                content,
                extraction,
                hidden_param_hints,
                session,
                headers,
                timeout,
                limiter,
                include_hidden,
                include_dynamic,
                verify_tls,
                context.logger,
            )

            endpoints = self._normalize_candidates(extraction.endpoints)
            graphql_candidates = set(
                self._normalize_candidates(extraction.graphql_endpoints)
            )
            ws_candidates = set(self._normalize_candidates(extraction.ws_endpoints))
            combined_candidates = endpoints + [
                candidate
                for candidate in sorted(ws_candidates)
                if candidate not in endpoints
            ]
            combined_candidates = [
                candidate
                for candidate in combined_candidates
                if context.url_in_scope(candidate)
            ]
            combined_candidates = combined_candidates[:max_urls]
            endpoint_set = set(combined_candidates)
            graphql_candidates &= endpoint_set
            ws_candidates &= endpoint_set
            graphql_endpoints.update(graphql_candidates)
            graphql_operations.update(extraction.graphql_operations)
            persisted_query_hints.update(extraction.persisted_query_hints)
            ws_endpoints.update(ws_candidates)
            high_value_strings.update(extraction.high_value_strings)

            artifacts.append(
                {
                    "js_url": js_url,
                    "surface_base_url": surface_base_url,
                    "endpoints": combined_candidates,
                    "graphql_endpoints": sorted(graphql_candidates),
                    "graphql_operations": sorted(extraction.graphql_operations),
                    "persisted_query_hints": sorted(extraction.persisted_query_hints),
                    "ws_endpoints": sorted(ws_candidates),
                    "high_value_strings": sorted(extraction.high_value_strings),
                    "source_map": source_map,
                }
            )

            self._emit_endpoint_results(
                context, js_url, combined_candidates, discovered_urls, signaled_hosts
            )

        if artifacts:
            artifact_path = context.record.paths.artifact("js_intel.json")
            artifact_path.write_text(
                json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8"
            )
            context.set_data("js_endpoints", discovered_urls)
            if hidden_param_hints:
                serializable_hints = {
                    k: sorted(v) for k, v in hidden_param_hints.items()
                }
                context.set_data("js_param_hints", serializable_hints)
            if graphql_endpoints:
                context.set_data("js_graphql_endpoints", sorted(graphql_endpoints))
            if graphql_operations:
                context.set_data("js_graphql_operations", sorted(graphql_operations))
            if persisted_query_hints:
                context.set_data(
                    "js_persisted_query_hints", sorted(persisted_query_hints)
                )
            if ws_endpoints:
                context.set_data("js_ws_endpoints", sorted(ws_endpoints))
            if high_value_strings:
                context.set_data("js_high_value_strings", sorted(high_value_strings))
            stats = context.record.metadata.stats.setdefault("js_intel", {})
            stats["files"] = len(artifacts)
            stats["endpoints"] = len(discovered_urls)
            stats["hidden_params"] = len(hidden_param_hints)
            stats["graphql_endpoints"] = len(graphql_endpoints)
            stats["graphql_operations"] = len(graphql_operations)
            stats["persisted_query_hints"] = len(persisted_query_hints)
            stats["ws_endpoints"] = len(ws_endpoints)
            stats["high_value_strings"] = len(high_value_strings)
            context.manager.update_metadata(context.record)

    def _collect_js_candidates(
        self, items: list, context: PipelineContext
    ) -> tuple[list[str], dict[str, str]]:
        js_url_bases: Dict[str, str] = {}
        js_urls: List[str] = []
        direct_js_urls: List[str] = []
        runtime_js_urls: List[str] = []
        for entry in items:
            etype = entry.get("type")
            if etype == "url":
                url = entry.get("url")
                if not url or not isinstance(url, str):
                    continue
                if not context.url_in_scope(url):
                    continue
                if (
                    url.lower().endswith(".js")
                    or "javascript" in str(entry.get("content_type", "")).lower()
                ):
                    if entry.get("status_code") in {200, 302}:
                        direct_js_urls.append(url)
                        if url not in js_url_bases:
                            js_urls.append(url)
                        js_url_bases.setdefault(url, url)
            elif etype == "runtime_crawl":
                page_url = str(entry.get("url") or "")
                js_files = entry.get("javascript_files") or []
                if not isinstance(js_files, list):
                    continue
                for js_url in js_files:
                    if not isinstance(js_url, str) or not js_url:
                        continue
                    if js_url.startswith(("http://", "https://")):
                        if not context.url_in_scope(js_url):
                            continue
                        runtime_js_urls.append(js_url)
                        if js_url not in js_url_bases:
                            js_urls.append(js_url)
                        js_url_bases.setdefault(js_url, page_url or js_url)

        if runtime_js_urls:
            context.logger.info(
                "JS intelligence candidates: %s direct + %s from runtime crawl",
                len(set(direct_js_urls)),
                len(set(runtime_js_urls)),
            )
        return js_urls, js_url_bases

    def _fetch_content(
        self,
        url: str,
        session,
        headers: dict,
        timeout: int,
        limiter,
        verify_tls: bool = True,
    ):
        import requests

        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return None
        try:
            if session:
                resp = session.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_tls,
                )
            else:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_tls,
                )
        except requests.exceptions.RequestException:
            if limiter:
                limiter.on_error(url)
            return None

        if limiter:
            limiter.on_response(url, resp.status_code)

        if resp.status_code >= 400:
            return None

        return resp.text

    def _process_js_file(
        self,
        js_url: str,
        surface_base_url: str,
        content: str,
        extraction,
        hidden_param_hints: dict,
        include_hidden: bool,
        include_dynamic: bool = True,
    ):
        new_extraction = self._extract_surface_from_blob(
            content,
            base_url=surface_base_url,
            include_dynamic=include_dynamic,
        )
        extraction.merge(new_extraction)
        if include_hidden:
            for hint in self._extract_param_hints(content):
                hidden_param_hints[hint].add(js_url)

    def _process_source_map(
        self,
        js_url: str,
        surface_base_url: str,
        content: str,
        extraction,
        hidden_param_hints: dict,
        session,
        headers: dict,
        timeout: int,
        limiter,
        include_hidden: bool,
        include_dynamic: bool = True,
        verify_tls: bool = True,
        logger=None,
    ):
        import requests

        map_match = self.SOURCEMAP_PATTERN.search(content)
        if not map_match:
            return None

        source_map = urljoin(js_url, map_match.group(1))
        if limiter and not limiter.wait_for_slot(source_map, timeout=timeout):
            if logger:
                logger.debug(
                    f"Limiter timeout waiting for source map slot: {source_map}"
                )
            return source_map

        try:
            if session:
                map_resp = session.get(
                    source_map,
                    timeout=timeout,
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_tls,
                )
            else:
                map_resp = requests.get(
                    source_map,
                    timeout=timeout,
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_tls,
                )

            if map_resp.status_code < 400 and map_resp.text:
                if limiter:
                    limiter.on_response(source_map, map_resp.status_code)
                try:
                    map_data = json.loads(map_resp.text)
                except json.JSONDecodeError as e:
                    if logger:
                        logger.debug(
                            f"Failed to decode source map JSON from {source_map}: {e}"
                        )
                    map_data = {}

                sources_content = map_data.get("sourcesContent") or []
                for source_blob in sources_content[:5]:
                    if not source_blob or not isinstance(source_blob, str):
                        continue
                    extraction.merge(
                        self._extract_surface_from_blob(
                            source_blob,
                            base_url=surface_base_url,
                            include_dynamic=include_dynamic,
                        )
                    )
                    if include_hidden:
                        for hint in self._extract_param_hints(source_blob):
                            hidden_param_hints[hint].add(js_url)
        except requests.exceptions.RequestException as e:
            if logger:
                logger.debug(f"Request error fetching source map {source_map}: {e}")
            if limiter:
                limiter.on_error(source_map)

        return source_map

    def _emit_endpoint_results(
        self,
        context: PipelineContext,
        js_url: str,
        combined_candidates: list,
        tags_results: list,
        signaled_hosts: set,
    ):
        for endpoint in combined_candidates:
            try:
                parsed = urlparse(endpoint)
            except ValueError:
                continue
            path = parsed.path.lower()
            if self._is_static_asset(path):
                continue
            tags, score = self._classify_endpoint(endpoint)
            if parsed.scheme in {"ws", "wss"}:
                if context.url_allowed(endpoint):
                    context.emit_signal(
                        "ws_hint",
                        "url",
                        endpoint,
                        confidence=0.5,
                        source="js-intel",
                        tags=sorted(tags),
                        evidence={"url": js_url},
                    )
                continue
            if not context.url_allowed(endpoint):
                continue
            payload = {
                "type": "url",
                "source": "js-intel",
                "url": endpoint,
                "hostname": parsed.hostname,
                "tags": sorted(tags),
                "score": score,
            }
            if context.results.append(payload):
                tags_results.append(endpoint)
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
                if tags.intersection(
                    {"surface:login", "surface:register", "surface:password-reset"}
                ):
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
                if tags.intersection(
                    {"surface:billing", "surface:pii", "surface:account"}
                ):
                    context.emit_signal(
                        "sensitive_surface",
                        "url",
                        endpoint,
                        confidence=0.4,
                        source="js-intel",
                        tags=sorted(tags),
                        evidence={"url": endpoint},
                    )
                if (
                    "/api" in path or "/graphql" in path
                ) and host not in signaled_hosts:
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

    def _classify_endpoint(self, endpoint: str) -> tuple[set[str], int]:
        try:
            parsed = urlparse(endpoint)
        except ValueError:
            parsed = urlparse("")
        path = parsed.path.lower()
        tags = {"js:discovered", "source:js"}
        score = 30
        if parsed.scheme in {"ws", "wss"}:
            tags.add("service:ws")
            score += 6
        if "/api" in path or self._is_graphql_candidate(path):
            tags.add("service:api")
        if self._is_graphql_candidate(path):
            tags.add("api:graphql")
        if any(hint in path for hint in self.SPEC_HINTS) and path.endswith(
            (".json", ".yaml", ".yml")
        ):
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
        if any(hint in path for hint in self.HIGH_VALUE_HINTS):
            tags.add("surface:high-value")
            score += 6
        if "api:graphql" in tags:
            score += 5
        if "api:spec" in tags:
            score += 5
        return tags, score

    def _normalize_endpoint(self, endpoint: str) -> str:
        if not endpoint:
            return ""
        endpoint = self._clean_endpoint_candidate(endpoint)
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

    def _normalize_candidates(self, endpoints: set[str]) -> List[str]:
        normalized: List[str] = []
        seen_norm = set()
        for endpoint in sorted(endpoints):
            norm = self._normalize_endpoint(endpoint)
            if not norm or norm in seen_norm:
                continue
            seen_norm.add(norm)
            normalized.append(norm)
        return normalized

    def _extract_surface_from_blob(
        self, content: str, *, base_url: str, include_dynamic: bool
    ) -> _JSSurfaceExtraction:
        extraction = _JSSurfaceExtraction()
        for absolute in self.ENDPOINT_PATTERN.findall(content):
            extraction.endpoints.add(absolute)
            if self._is_graphql_candidate(absolute):
                extraction.graphql_endpoints.add(absolute)
        for ws_endpoint in self.WS_ENDPOINT_PATTERN.findall(content):
            extraction.ws_endpoints.add(ws_endpoint)
        for rel in self.RELATIVE_PATTERN.findall(content):
            absolute = urljoin(base_url, rel)
            extraction.endpoints.add(absolute)
            if self._is_graphql_candidate(rel):
                extraction.graphql_endpoints.add(absolute)
        for _quote, candidate in self.API_CALL_PATTERN.findall(content):
            cleaned_candidate = self._clean_endpoint_candidate(candidate)
            if not cleaned_candidate:
                continue
            if cleaned_candidate.startswith(("http://", "https://")):
                extraction.endpoints.add(cleaned_candidate)
                if self._is_graphql_candidate(cleaned_candidate):
                    extraction.graphql_endpoints.add(cleaned_candidate)
                continue
            if cleaned_candidate.startswith(("ws://", "wss://")):
                extraction.ws_endpoints.add(cleaned_candidate)
                continue
            if cleaned_candidate.startswith("/"):
                absolute = urljoin(base_url, cleaned_candidate)
                extraction.endpoints.add(absolute)
                if self._is_graphql_candidate(cleaned_candidate):
                    extraction.graphql_endpoints.add(absolute)
        if include_dynamic:
            for dynamic in self.DYNAMIC_ROUTE_PATTERN.findall(content):
                materialized = self._materialize_dynamic_path(dynamic)
                if materialized:
                    absolute = urljoin(base_url, materialized)
                    extraction.endpoints.add(absolute)
                    if self._is_graphql_candidate(materialized):
                        extraction.graphql_endpoints.add(absolute)
        for operation_name in self.GRAPHQL_OPERATION_NAME_PATTERN.findall(content):
            extraction.graphql_operations.add(operation_name)
        for _kind, operation_name in self.GRAPHQL_OPERATION_PATTERN.findall(content):
            extraction.graphql_operations.add(operation_name)
        for persisted_query in self.PERSISTED_QUERY_PATTERN.findall(content):
            extraction.persisted_query_hints.add(persisted_query)
        lowered = content.lower()
        for hint in self.HIGH_VALUE_HINTS:
            if hint in lowered:
                extraction.high_value_strings.add(hint)
        return extraction

    def _extract_param_hints(self, content: str) -> set[str]:
        hints: set[str] = set()
        for name in self.QUERY_PARAM_PATTERN.findall(content):
            lowered = name.lower()
            if len(lowered) >= 2:
                hints.add(lowered)
        for block in self.PARAM_BLOCK_PATTERN.findall(content):
            for key in self.PARAM_KEY_PATTERN.findall(block):
                lowered = key.lower()
                if len(lowered) >= 2:
                    hints.add(lowered)
        return hints

    def _materialize_dynamic_path(self, path: str) -> str:
        if not path:
            return ""
        normalized = re.sub(r"\$\{[^}]+\}", "1", path)
        return self._clean_endpoint_candidate(normalized)

    def _clean_endpoint_candidate(self, value: str) -> str:
        cleaned = (value or "").strip().strip("\"'`")
        if not cleaned:
            return ""
        cleaned = re.sub(r"\$\{[^}]+\}", "1", cleaned)
        cleaned = cleaned.rstrip("),;")
        if cleaned.startswith("//"):
            cleaned = "https:" + cleaned
        return cleaned

    def _is_graphql_candidate(self, value: str) -> bool:
        return bool(self.GRAPHQL_ENDPOINT_PATTERN.search(value or ""))

    def _is_static_asset(self, path: str) -> bool:
        if not path:
            return False
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False
