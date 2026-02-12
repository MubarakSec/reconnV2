from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class ApiSchemaProbeStage(Stage):
    name = "api_schema_probe"

    PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
    LOGIN_HINTS = ("login", "sign in", "signin", "auth", "password", "sso", "oauth")
    READ_METHODS = {"get", "head", "options"}
    SAFE_WRITE_METHODS = {"post", "put", "patch"}
    PATH_HINTS = ("api", "user", "users", "account", "profile", "admin", "tenant", "org", "project")
    LOW_VALUE_HINTS = ("health", "status", "metrics", "ready", "live", "ping", "openapi", "swagger", "docs")

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
        max_per_host = max(0, int(getattr(runtime, "api_schema_max_per_host", 0)))
        timeout = int(getattr(runtime, "api_schema_timeout", 10))
        safe_writes = bool(getattr(runtime, "api_schema_probe_safe_writes", True))
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
        mutating_probed = 0
        artifacts: List[Dict[str, object]] = []
        param_counts: Counter[str] = Counter()
        param_examples: Dict[str, List[str]] = defaultdict(list)
        seen_endpoints: Set[Tuple[str, str]] = set()
        duplicate_skipped = 0
        host_cap_skipped = 0
        budget_used = 0
        budget_exhausted = False
        host_counts: Dict[str, int] = {}

        for spec_url in spec_urls:
            if max_endpoints > 0 and budget_used >= max_endpoints:
                budget_exhausted = True
                break
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
            endpoints = self._prioritize_endpoints(endpoints)

            for endpoint in endpoints:
                if max_endpoints > 0 and budget_used >= max_endpoints:
                    budget_exhausted = True
                    break
                url = self._build_url(base_url, endpoint)
                if not url or not context.url_allowed(url):
                    continue
                host = (urlparse(url).hostname or "").lower()
                if max_per_host > 0 and host and host_counts.get(host, 0) >= max_per_host:
                    host_cap_skipped += 1
                    continue
                method = str(endpoint.get("method") or "get").lower()
                endpoint_key = (method, url)
                if endpoint_key in seen_endpoints:
                    duplicate_skipped += 1
                    continue
                seen_endpoints.add(endpoint_key)
                budget_used += 1
                if host:
                    host_counts[host] = host_counts.get(host, 0) + 1

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
                for field_name in endpoint.get("body_fields") or []:
                    if not isinstance(field_name, str) or not field_name:
                        continue
                    param_counts[field_name] += 1
                    if len(param_examples[field_name]) < 3:
                        param_examples[field_name].append(url)

                should_probe = method in self.READ_METHODS or (safe_writes and method in self.SAFE_WRITE_METHODS)
                if not should_probe:
                    continue
                if requires_auth and not context.auth_enabled():
                    continue

                request_json: Optional[Dict[str, object]] = None
                request_data: Optional[Dict[str, object]] = None
                probe_mode = "read"
                if method in self.SAFE_WRITE_METHODS:
                    request_json, request_data = self._build_safe_body(endpoint)
                    probe_mode = "safe-write"
                    mutating_probed += 1

                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                probed += 1
                session = context.auth_session(url)
                headers = context.auth_headers({"User-Agent": "recon-cli api-schema-probe"})
                if method in self.SAFE_WRITE_METHODS:
                    headers["X-Recon-Safe-Probe"] = "1"
                if request_json is not None:
                    headers["Content-Type"] = "application/json"
                try:
                    if session:
                        resp = session.request(
                            method.upper(),
                            url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers=headers,
                            verify=context.runtime_config.verify_tls,
                            json=request_json,
                            data=request_data,
                        )
                    else:
                        resp = requests.request(
                            method.upper(),
                            url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers=headers,
                            verify=context.runtime_config.verify_tls,
                            json=request_json,
                            data=request_data,
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
                            "probe_mode": probe_mode,
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
                        "probe_mode": probe_mode,
                        "content_type": meta.get("content_type"),
                        "content_length": meta.get("content_length"),
                        "title": meta.get("title"),
                        "location": meta.get("location"),
                        "auth_hint": auth_hint,
                    }
                )

            if budget_exhausted:
                break

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
                "endpoints_budget_used": budget_used,
                "budget_exhausted": budget_exhausted,
                "duplicates_skipped": duplicate_skipped,
                "host_cap": max_per_host,
                "host_cap_skipped": host_cap_skipped,
                "probed": probed,
                "mutating_probed": mutating_probed,
                "safe_write_enabled": safe_writes,
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
                method_name = str(method).lower()
                if method_name not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                if not isinstance(operation, dict):
                    continue
                op_parameters = self._parameters_from(operation.get("parameters"))
                params = path_parameters + op_parameters
                body_fields = self._extract_request_body_fields(operation, params)
                requires_auth = self._requires_auth(operation.get("security"), global_security)
                endpoints.append(
                    {
                        "path": path,
                        "method": method_name,
                        "params": params,
                        "body_fields": body_fields,
                        "requires_auth": requires_auth,
                    }
                )
        return endpoints

    def _prioritize_endpoints(self, endpoints: List[Dict[str, object]]) -> List[Dict[str, object]]:
        def _score(endpoint: Dict[str, object]) -> int:
            method = str(endpoint.get("method") or "").lower()
            path = str(endpoint.get("path") or "").lower()
            params = endpoint.get("params") if isinstance(endpoint.get("params"), list) else []
            body_fields = endpoint.get("body_fields") if isinstance(endpoint.get("body_fields"), list) else []
            requires_auth = bool(endpoint.get("requires_auth"))
            score = 0
            if requires_auth:
                score += 25
            if method in self.SAFE_WRITE_METHODS:
                score += 14
            elif method in self.READ_METHODS:
                score += 10
            if any(hint in path for hint in self.PATH_HINTS):
                score += 14
            if any(low in path for low in self.LOW_VALUE_HINTS):
                score -= 20
            score += min(12, len(params) * 2)
            score += min(10, len(body_fields) * 2)
            return score

        return sorted(endpoints, key=_score, reverse=True)

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

    def _extract_request_body_fields(
        self,
        operation: Dict[str, object],
        params: List[Dict[str, object]],
    ) -> List[str]:
        body_fields: List[str] = []

        # OpenAPI 3.x
        request_body = operation.get("requestBody")
        if isinstance(request_body, dict):
            content = request_body.get("content")
            if isinstance(content, dict):
                schema = None
                if "application/json" in content and isinstance(content["application/json"], dict):
                    schema = content["application/json"].get("schema")
                if schema is None:
                    for payload in content.values():
                        if isinstance(payload, dict) and payload.get("schema"):
                            schema = payload.get("schema")
                            break
                if isinstance(schema, dict):
                    body_fields.extend(self._schema_field_names(schema, depth=0))

        # Swagger 2.0 body/formData parameters
        for item in params:
            if not isinstance(item, dict):
                continue
            location = str(item.get("in") or "")
            name = str(item.get("name") or "")
            if location == "formData" and name:
                body_fields.append(name)
        raw_parameters = operation.get("parameters")
        if isinstance(raw_parameters, list):
            for param in raw_parameters:
                if not isinstance(param, dict):
                    continue
                if str(param.get("in") or "") == "body":
                    schema = param.get("schema")
                    if isinstance(schema, dict):
                        body_fields.extend(self._schema_field_names(schema, depth=0))

        deduped: List[str] = []
        seen: Set[str] = set()
        for name in body_fields:
            cleaned = str(name).strip()
            if not cleaned or cleaned in seen:
                continue
            deduped.append(cleaned)
            seen.add(cleaned)
            if len(deduped) >= 20:
                break
        return deduped

    def _schema_field_names(self, schema: Dict[str, object], *, depth: int) -> List[str]:
        if depth > 3:
            return []
        fields: List[str] = []
        if "$ref" in schema:
            ref = str(schema.get("$ref") or "")
            if ref:
                fields.append(ref.rsplit("/", 1)[-1].lower())
            return fields
        schema_type = str(schema.get("type") or "").lower()
        if schema_type == "object" or "properties" in schema:
            properties = schema.get("properties")
            if isinstance(properties, dict):
                for key, value in properties.items():
                    fields.append(str(key))
                    if isinstance(value, dict):
                        fields.extend(self._schema_field_names(value, depth=depth + 1))
                    if len(fields) >= 20:
                        break
        elif schema_type == "array":
            items = schema.get("items")
            if isinstance(items, dict):
                fields.extend(self._schema_field_names(items, depth=depth + 1))
        return fields

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
        if "email" in lower:
            return "recon@example.com"
        return "1"

    def _build_safe_body(self, endpoint: Dict[str, object]) -> Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]:
        params = endpoint.get("params") or []
        form_fields: List[str] = []
        for item in params:
            if not isinstance(item, dict):
                continue
            if str(item.get("in") or "") == "formData":
                name = str(item.get("name") or "")
                if name:
                    form_fields.append(name)
        if form_fields:
            form_payload = {name: self._placeholder_value(name) for name in form_fields[:8]}
            form_payload.setdefault("recon_probe", "1")
            return None, form_payload

        body_fields = endpoint.get("body_fields") or []
        json_payload: Dict[str, object] = {}
        for name in body_fields[:8]:
            if not isinstance(name, str) or not name:
                continue
            json_payload[name] = self._placeholder_value(name)
        json_payload.setdefault("recon_probe", "1")
        return json_payload, None

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
