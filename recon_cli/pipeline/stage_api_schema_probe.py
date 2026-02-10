from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class ApiSchemaProbeStage(Stage):
    name = "api_schema_probe"

    PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
    LOGIN_HINTS = ("login", "sign in", "signin", "auth", "password", "sso", "oauth")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_api_schema_probe", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("api schema probe requires requests; skipping")
            return

        runtime = context.runtime_config
        max_specs = int(getattr(runtime, "api_schema_max_specs", 25))
        max_endpoints = int(getattr(runtime, "api_schema_max_endpoints", 200))
        timeout = int(getattr(runtime, "api_schema_timeout", 10))
        limiter = context.get_rate_limiter(
            "api_schema_probe",
            rps=float(getattr(runtime, "api_schema_rps", 0)),
            per_host=float(getattr(runtime, "api_schema_per_host_rps", 0)),
        )

        spec_urls = self._collect_specs(context)
        if not spec_urls:
            context.logger.info("No API specs available for schema probing")
            return
        if max_specs > 0:
            spec_urls = spec_urls[:max_specs]

        probed = 0
        endpoints_added = 0
        auth_required = 0
        auth_weak = 0
        auth_challenge = 0
        public_hits = 0
        artifacts: List[Dict[str, object]] = []
        param_counts: Counter[str] = Counter()
        param_examples: Dict[str, List[str]] = defaultdict(list)

        for spec_url in spec_urls:
            if not context.url_allowed(spec_url):
                continue
            if limiter and not limiter.wait_for_slot(spec_url, timeout=timeout):
                continue
            session = context.auth_session(spec_url)
            headers = context.auth_headers({"User-Agent": "recon-cli api-schema"})
            try:
                if session:
                    resp = session.get(
                        spec_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
                else:
                    resp = requests.get(
                        spec_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
            except Exception:
                if limiter:
                    limiter.on_error(spec_url)
                continue
            if limiter:
                limiter.on_response(spec_url, resp.status_code)
            if resp.status_code >= 400:
                continue

            spec_data = self._parse_spec(resp.text or "", resp.headers.get("Content-Type", ""))
            if not spec_data:
                continue
            base_url = self._resolve_base_url(spec_data, spec_url)
            if not base_url:
                continue
            endpoints = self._extract_endpoints(spec_data)
            if not endpoints:
                continue

            for endpoint in endpoints[:max_endpoints]:
                url = self._build_url(base_url, endpoint)
                if not url or not context.url_allowed(url):
                    continue
                method = endpoint.get("method", "get")
                requires_auth = bool(endpoint.get("requires_auth"))
                tags = ["api:schema", f"method:{method}"]
                score = 35
                if requires_auth:
                    tags.append("api:auth-required")
                    score += 10
                payload = {
                    "type": "url",
                    "source": "api-schema",
                    "url": url,
                    "hostname": urlparse(url).hostname,
                    "tags": tags,
                    "score": score,
                }
                if context.results.append(payload):
                    endpoints_added += 1

                context.emit_signal(
                    "api_schema_endpoint",
                    "url",
                    url,
                    confidence=0.5,
                    source="api-schema",
                    tags=tags,
                    evidence={"method": method, "spec": spec_url},
                )

                for param in endpoint.get("params") or []:
                    if not isinstance(param, dict):
                        continue
                    name = param.get("name")
                    if not name:
                        continue
                    param_name = str(name)
                    param_counts[param_name] += 1
                    if len(param_examples[param_name]) < 3:
                        param_examples[param_name].append(url)

                if method not in {"get", "head"}:
                    continue
                if requires_auth and not context.auth_enabled():
                    continue

                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                probed += 1
                session = context.auth_session(url)
                headers = context.auth_headers({"User-Agent": "recon-cli api-schema-probe"})
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

                status = int(resp.status_code or 0)
                meta = self._response_meta(resp)
                auth_hint = self._looks_like_login(resp.text or "", meta)
                signal_type = None
                if requires_auth and status in {401, 403, 302}:
                    if status == 302 and auth_hint:
                        signal_type = "api_auth_challenge"
                        auth_challenge += 1
                    else:
                        signal_type = "api_auth_required"
                        auth_required += 1
                elif requires_auth and 200 <= status < 300:
                    if auth_hint:
                        signal_type = "api_auth_challenge"
                        auth_challenge += 1
                    else:
                        signal_type = "api_auth_weak"
                        auth_weak += 1
                elif not requires_auth and 200 <= status < 300:
                    signal_type = "api_public_endpoint"
                    public_hits += 1
                if signal_type:
                    context.emit_signal(
                        signal_type,
                        "url",
                        url,
                        confidence=0.6,
                        source="api-schema",
                        tags=tags,
                        evidence={
                            "status_code": status,
                            "method": method,
                            "spec": spec_url,
                            "content_type": meta.get("content_type"),
                            "content_length": meta.get("content_length"),
                            "title": meta.get("title"),
                            "location": meta.get("location"),
                        },
                    )

                artifacts.append(
                    {
                        "spec": spec_url,
                        "url": url,
                        "method": method,
                        "status": status,
                        "requires_auth": requires_auth,
                        "content_type": meta.get("content_type"),
                        "content_length": meta.get("content_length"),
                        "title": meta.get("title"),
                        "location": meta.get("location"),
                        "auth_hint": auth_hint,
                    }
                )

        max_params = int(getattr(runtime, "api_schema_param_max", 120))
        for name, count in param_counts.most_common(max_params):
            payload = {
                "type": "parameter",
                "source": "api-schema",
                "name": name,
                "count": count,
                "examples": param_examples.get(name, []),
                "score": min(45, 10 + count),
                "tags": ["param", "api"],
            }
            context.results.append(payload)

        if artifacts:
            artifact_path = context.record.paths.artifact("api_schema_probe.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("api_schema_probe", {})
        stats.update(
            {
                "specs": len(spec_urls),
                "endpoints": endpoints_added,
                "probed": probed,
                "auth_required": auth_required,
                "auth_weak": auth_weak,
                "auth_challenge": auth_challenge,
                "public": public_hits,
                "params": min(len(param_counts), max_params),
            }
        )
        context.manager.update_metadata(context.record)

    @staticmethod
    def _collect_specs(context: PipelineContext) -> List[str]:
        specs: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "api_spec":
                continue
            url = entry.get("url")
            if isinstance(url, str) and url:
                specs.append(url)
        return list(dict.fromkeys(specs))

    @staticmethod
    def _parse_spec(text: str, content_type: str) -> Dict[str, object]:
        if not text:
            return {}
        lowered = (content_type or "").lower()
        stripped = text.lstrip()
        if "json" in lowered or stripped.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return data
        if "yaml" in lowered or "yml" in lowered or "openapi:" in text or "swagger:" in text:
            try:
                import yaml  # type: ignore
            except Exception:
                return {}
            try:
                data = yaml.safe_load(text)
            except Exception:
                data = {}
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return data
        return {}

    @staticmethod
    def _resolve_base_url(spec: Dict[str, object], spec_url: str) -> str:
        parsed = urlparse(spec_url)
        fallback = f"{parsed.scheme or 'https'}://{parsed.hostname}" if parsed.hostname else ""
        servers = spec.get("servers")
        if isinstance(servers, list) and servers:
            server = servers[0] or {}
            if isinstance(server, dict):
                url_value = server.get("url")
                if isinstance(url_value, str) and url_value:
                    if url_value.startswith("/"):
                        return urljoin(fallback, url_value)
                    if url_value.startswith("http"):
                        return url_value.rstrip("/")
        swagger_host = spec.get("host")
        base_path = spec.get("basePath") or ""
        schemes = spec.get("schemes") if isinstance(spec.get("schemes"), list) else []
        scheme = schemes[0] if schemes else parsed.scheme or "https"
        if isinstance(swagger_host, str) and swagger_host:
            return f"{scheme}://{swagger_host}{base_path}".rstrip("/")
        return fallback.rstrip("/")

    def _extract_endpoints(self, spec: Dict[str, object]) -> List[Dict[str, object]]:
        endpoints: List[Dict[str, object]] = []
        paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
        global_security = spec.get("security") if isinstance(spec.get("security"), list) else None

        for path, methods in paths.items():
            if not isinstance(path, str) or not isinstance(methods, dict):
                continue
            path_parameters = self._parameters_from(methods.get("parameters"))
            for method, operation in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue
                op_parameters = self._parameters_from(operation.get("parameters"))
                params = path_parameters + op_parameters
                requires_auth = self._requires_auth(operation.get("security"), global_security)
                endpoints.append(
                    {
                        "path": path,
                        "method": method.lower(),
                        "params": params,
                        "requires_auth": requires_auth,
                    }
                )
        return endpoints

    @staticmethod
    def _parameters_from(raw: object) -> List[Dict[str, object]]:
        if not isinstance(raw, list):
            return []
        params: List[Dict[str, object]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            location = item.get("in")
            if not name or not location:
                continue
            params.append({"name": name, "in": location})
        return params

    @staticmethod
    def _requires_auth(operation_security: object, global_security: object) -> bool:
        if isinstance(operation_security, list):
            return len(operation_security) > 0
        if isinstance(global_security, list):
            return len(global_security) > 0
        return False

    def _build_url(self, base_url: str, endpoint: Dict[str, object]) -> str:
        path = endpoint.get("path") or ""
        if not isinstance(path, str):
            return ""
        url = urljoin(base_url + "/", path.lstrip("/"))
        if "{" in url:
            url = self.PATH_PARAM_RE.sub(lambda m: self._placeholder_value(m.group(1)), url)
        params = {}
        for param in endpoint.get("params") or []:
            if not isinstance(param, dict):
                continue
            if param.get("in") != "query":
                continue
            name = param.get("name")
            if not name:
                continue
            params[str(name)] = "1"
        if params:
            url = url + ("&" if "?" in url else "?") + urlencode(params)
        return url

    @staticmethod
    def _placeholder_value(name: str) -> str:
        lower = (name or "").lower()
        if "uuid" in lower:
            return "00000000-0000-0000-0000-000000000000"
        if lower.endswith("id") or lower in {"id", "uid", "user", "user_id", "account_id"}:
            return "1"
        if "slug" in lower or "name" in lower:
            return "test"
        return "1"

    def _response_meta(self, resp) -> Dict[str, object]:
        content_type = ""
        location = ""
        content_length = None
        title = ""
        try:
            content_type = resp.headers.get("Content-Type", "")
            location = resp.headers.get("Location", "")
            content_length = resp.headers.get("Content-Length")
        except Exception:
            pass
        body = ""
        try:
            body = resp.text or ""
        except Exception:
            body = ""
        if body:
            title = self._extract_title(body)
        return {
            "content_type": content_type,
            "location": location,
            "content_length": content_length,
            "title": title,
        }

    def _extract_title(self, body: str) -> str:
        if not body:
            return ""
        match = self.TITLE_RE.search(body)
        if not match:
            return ""
        title = match.group(1)
        title = re.sub(r"\s+", " ", title).strip()
        return title[:120]

    def _looks_like_login(self, body: str, meta: Dict[str, object]) -> bool:
        lowered = (body or "").lower()
        if any(hint in lowered for hint in self.LOGIN_HINTS):
            return True
        title = str(meta.get("title") or "").lower()
        if any(hint in title for hint in self.LOGIN_HINTS):
            return True
        location = str(meta.get("location") or "").lower()
        if "login" in location or "signin" in location or "auth" in location:
            return True
        return False
