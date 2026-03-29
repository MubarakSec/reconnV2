from __future__ import annotations

import json
import re
import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


@dataclass
class _JSSurfaceExtraction:
    endpoints: set[str] = field(default_factory=set)
    graphql_endpoints: set[str] = field(default_factory=set)
    graphql_operations: set[str] = field(default_factory=set)
    persisted_query_hints: set[str] = field(default_factory=set)
    ws_endpoints: set[str] = field(default_factory=set)
    high_value_strings: set[str] = field(default_factory=set)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    comments: set[str] = field(default_factory=set)

    def merge(self, other: "_JSSurfaceExtraction") -> None:
        self.endpoints.update(other.endpoints)
        self.graphql_endpoints.update(other.graphql_endpoints)
        self.graphql_operations.update(other.graphql_operations)
        self.persisted_query_hints.update(other.persisted_query_hints)
        self.ws_endpoints.update(other.ws_endpoints)
        self.high_value_strings.update(other.high_value_strings)
        self.secrets.extend(other.secrets)
        self.comments.update(other.comments)


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
    
    COMMENT_PATTERN = re.compile(r"//\s*(?:TODO|FIXME|DEBUG|INTERNAL|REMOVE|TEMP|DEV).*$", re.IGNORECASE | re.MULTILINE)
    ENV_LEAK_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+)", re.IGNORECASE)
    
    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_secret_key": re.compile(r"\"[0-9a-zA-Z/+]{40}\""),
        "google_api_key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
        "generic_secret": re.compile(r"(?:secret|token|auth|key|pass|pwd|api_key|apikey)\s*[:=]\s*[\"']([0-9a-zA-Z-_\.\+=]{8,})[\"']", re.IGNORECASE),
        "firebase_url": re.compile(r"https://[a-z0-9.-]+\.firebaseio\.com"),
        "jwt_token": re.compile(r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*")
    }
    AUTH_HINTS = (
        "login", "signin", "sign-in", "signup", "sign-up", "register",
        "password", "reset", "forgot", "auth", "oauth", "sso",
        "callback", "authorize", "token", "session", "userinfo",
    )
    ADMIN_HINTS = (
        "admin", "dashboard", "console", "manage", "staff", "internal", "superuser",
    )
    ACCOUNT_HINTS = ("account", "profile", "user", "customer", "member")
    BILLING_HINTS = (
        "billing", "invoice", "payment", "stripe", "checkout", "subscription", "plan",
    )
    PII_HINTS = (
        "ssn", "passport", "token", "secret", "apikey", "api-key", "credit", "card",
    )
    INTERNAL_HINTS = ("internal", "intranet", "employee", "corp", "backoffice")
    DEBUG_HINTS = ("debug", "trace", "health", "metrics", "status", "actuator")
    UPLOAD_HINTS = (
        "upload", "file", "attachment", "import", "export", "media", "avatar", "image",
    )
    HIGH_VALUE_HINTS = (
        "api_key", "apikey", "secret", "token", "password", "pwd", "auth", "access",
        "private", "internal", "admin", "config", "settings", "env", "production",
        "database", "db_", "staging", "dev_", "debug", "test", "root", "system",
    )
    STATIC_EXTENSIONS = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".eot", ".mp4", ".mp3", ".wav", ".pdf", ".zip", ".gz", ".map",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_js_intel", False))

    async def run_async(self, context: PipelineContext) -> bool:
        js_urls = self._collect_js_urls(context)
        if not js_urls:
            context.logger.info("No JavaScript URLs found for intelligence stage")
            return True

        runtime = context.runtime_config
        max_files = int(getattr(runtime, "js_intel_max_files", 150))
        timeout = int(getattr(runtime, "js_intel_timeout", 15))
        concurrency = int(getattr(runtime, "js_intel_concurrency", 15))
        
        config = HTTPClientConfig(
            max_concurrent=concurrency,
            total_timeout=float(timeout),
            verify_ssl=bool(getattr(runtime, "verify_tls", True))
        )

        signaled_hosts: set[str] = set()
        discovered_urls: set[str] = set()
        artifacts = []

        async with AsyncHTTPClient(config, context=context) as client:
            selected_urls = list(js_urls)[:max_files]
            context.logger.info("Analyzing %d JavaScript files", len(selected_urls))
            
            tasks = [client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli js-intel"})) for url in selected_urls]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for js_url, resp in zip(selected_urls, responses):
                if isinstance(resp, Exception) or resp.status != 200: continue
                
                content = resp.body
                if not content: continue
                
                surface_base_url = str(urlparse(js_url)._replace(path="", query="", fragment="").geturl())
                extraction = self._extract_surface_from_blob(content, base_url=surface_base_url, include_dynamic=True)
                
                # Check for Source Map
                source_map = None
                sm_match = self.SOURCEMAP_PATTERN.search(content)
                if sm_match:
                    sm_url = urljoin(js_url, sm_match.group(1))
                    try:
                        sm_resp = await client.get(sm_url, timeout=timeout)
                        if sm_resp.status == 200:
                            source_map = sm_url
                            sm_extraction = self._extract_surface_from_blob(sm_resp.body, base_url=surface_base_url, include_dynamic=True)
                            extraction.merge(sm_extraction)
                    except Exception as e:
                        logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                        try:
                            from recon_cli.utils.metrics import metrics
                            metrics.stage_errors.labels(stage="js_intelligence", error_type=type(e).__name__).inc()
                        except: pass

                combined_candidates = sorted([u for u in extraction.endpoints if context.url_allowed(u)])
                graphql_candidates = sorted([u for u in extraction.graphql_endpoints if context.url_allowed(u)])
                ws_candidates = sorted([u for u in extraction.ws_endpoints if context.url_allowed(u)])

                artifacts.append({
                    "js_url": js_url, "surface_base_url": surface_base_url,
                    "endpoints": combined_candidates, "graphql_endpoints": sorted(graphql_candidates),
                    "graphql_operations": sorted(extraction.graphql_operations),
                    "persisted_query_hints": sorted(extraction.persisted_query_hints),
                    "ws_endpoints": sorted(ws_candidates),
                    "high_value_strings": sorted(extraction.high_value_strings),
                    "secrets": extraction.secrets, "comments": sorted(extraction.comments),
                    "source_map": source_map,
                })

                for secret in extraction.secrets:
                    context.emit_signal("js_secret", "url", js_url, confidence=0.7, source=self.name, tags=["secret", secret["type"]], evidence=secret)
                for comment in extraction.comments:
                    context.emit_signal("js_comment", "url", js_url, confidence=0.4, source=self.name, tags=["comment", "leak"], evidence={"comment": comment})

                self._emit_endpoint_results(context, js_url, combined_candidates, discovered_urls, signaled_hosts)

        if artifacts:
            context.record.paths.artifact("js_intelligence.json").write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")
        
        context.update_stats(self.name,
            files=len(js_urls),
            files_analyzed=len(artifacts),
            endpoints=len(discovered_urls),
            endpoints_found=len(discovered_urls),
            status="completed"
        )
        return True

    def _collect_js_urls(self, context: PipelineContext) -> Set[str]:
        js_urls = set()
        for entry in context.iter_results():
            url = entry.get("url")
            if entry.get("type") == "runtime_crawl":
                for js_file in entry.get("javascript_files", []):
                    if isinstance(js_file, str) and context.url_allowed(js_file):
                        js_urls.add(js_file)
                continue

            if not isinstance(url, str) or not url: continue
            if context.url_allowed(url) and (url.lower().endswith(".js") or "javascript" in str(entry.get("content_type", "")).lower()):
                js_urls.add(url)
        
        runtime_js = context.get_data("runtime_discovered_js", [])
        if isinstance(runtime_js, list):
            for url in runtime_js:
                if isinstance(url, str) and context.url_allowed(url):
                    js_urls.add(url)
        return js_urls

    def _extract_surface_from_blob(self, content: str, *, base_url: str, include_dynamic: bool) -> _JSSurfaceExtraction:
        extraction = _JSSurfaceExtraction()
        for absolute in self.ENDPOINT_PATTERN.findall(content):
            extraction.endpoints.add(absolute)
            if self._is_graphql_candidate(absolute): extraction.graphql_endpoints.add(absolute)
        for ws_endpoint in self.WS_ENDPOINT_PATTERN.findall(content): extraction.ws_endpoints.add(ws_endpoint)
        for rel in self.RELATIVE_PATTERN.findall(content):
            abs_url = urljoin(base_url, rel)
            extraction.endpoints.add(abs_url)
            if self._is_graphql_candidate(rel): extraction.graphql_endpoints.add(abs_url)
        
        for _quote, candidate in self.API_CALL_PATTERN.findall(content):
            cleaned = self._clean_endpoint_candidate(candidate)
            if not cleaned: continue
            if cleaned.startswith(("http://", "https://")):
                extraction.endpoints.add(cleaned)
                if self._is_graphql_candidate(cleaned): extraction.graphql_endpoints.add(cleaned)
            elif cleaned.startswith(("ws://", "wss://")): extraction.ws_endpoints.add(cleaned)
            elif cleaned.startswith("/"):
                abs_url = urljoin(base_url, cleaned)
                extraction.endpoints.add(abs_url)
                if self._is_graphql_candidate(cleaned): extraction.graphql_endpoints.add(abs_url)

        if include_dynamic:
            for dynamic in self.DYNAMIC_ROUTE_PATTERN.findall(content):
                mat = self._materialize_dynamic_path(dynamic)
                if mat:
                    abs_url = urljoin(base_url, mat)
                    extraction.endpoints.add(abs_url)
                    if self._is_graphql_candidate(mat): extraction.graphql_endpoints.add(abs_url)

        for op in self.GRAPHQL_OPERATION_NAME_PATTERN.findall(content): extraction.graphql_operations.add(op)
        for _kind, op in self.GRAPHQL_OPERATION_PATTERN.findall(content): extraction.graphql_operations.add(op)
        for pq in self.PERSISTED_QUERY_PATTERN.findall(content): extraction.persisted_query_hints.add(pq)

        lowered = content.lower()
        for hint in self.HIGH_VALUE_HINTS:
            if hint in lowered: extraction.high_value_strings.add(hint)
        
        for label, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.findall(content):
                val = str(match).strip().strip("'\"")
                if len(val) < 12: continue
                ent = self._shannon_entropy(val)
                if label == "generic_secret" and ent < 3.5: continue
                extraction.secrets.append({"type": label, "value": val, "entropy": round(ent, 2)})
        
        for m in self.COMMENT_PATTERN.findall(content): extraction.comments.add(m.strip())
        for m in self.ENV_LEAK_PATTERN.findall(content): extraction.secrets.append({"type": "env_leak", "value": m})

        return extraction

    def _shannon_entropy(self, data: str) -> float:
        import math
        if not data: return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _emit_endpoint_results(self, context: PipelineContext, js_url: str, combined_candidates: List[str], discovered_urls: Set[str], signaled_hosts: Set[str]) -> None:
        source_host = urlparse(js_url).hostname
        for url in combined_candidates:
            if url in discovered_urls: continue
            if not context.url_allowed(url): continue
            
            parsed = urlparse(url)
            host = parsed.hostname
            if not host: continue
            
            discovered_urls.add(url)
            score = 35
            if "/api" in parsed.path.lower(): score += 10
            
            payload = {"type": "url", "source": "js-intel", "url": url, "hostname": host, "tags": ["source:js"], "score": score}
            context.results.append(payload)
            
            if host != source_host and host not in signaled_hosts:
                context.emit_signal("cross_domain_js_link", "host", host, confidence=0.4, source=self.name, tags=["js:cross-domain"], evidence={"js_url": js_url, "target_url": url})
                signaled_hosts.add(host)

    def _clean_endpoint_candidate(self, value: str) -> str:
        cleaned = (value or "").strip().strip("\"'`")
        if not cleaned: return ""
        cleaned = re.sub(r"\$\{[^}]+\}", "1", cleaned)
        cleaned = cleaned.rstrip("),;")
        if cleaned.startswith("//"): cleaned = "https:" + cleaned
        return cleaned

    def _materialize_dynamic_path(self, path: str) -> str:
        return self._clean_endpoint_candidate(re.sub(r"\$\{[^}]+\}", "1", path)) if path else ""

    def _is_graphql_candidate(self, value: str) -> bool:
        return bool(self.GRAPHQL_ENDPOINT_PATTERN.search(value or ""))

    def _is_static_asset(self, path: str) -> bool:
        if not path: return False
        return any(path.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS)
