from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class ApiSchemaProbeStage(Stage):
    name = "api_schema_probe"

    PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
    LOGIN_HINTS = ("login", "sign in", "signin", "auth", "password", "sso", "oauth")
    READ_METHODS = {"get", "head", "options"}
    SAFE_WRITE_METHODS = {"post", "put", "patch"}
    PATH_HINTS = (
        "api",
        "user",
        "users",
        "account",
        "profile",
        "admin",
        "tenant",
        "org",
        "project",
    )
    LOW_VALUE_HINTS = (
        "health",
        "status",
        "metrics",
        "ready",
        "live",
        "ping",
        "openapi",
        "swagger",
        "docs",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_api_schema_probe", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_specs = int(getattr(runtime, "api_schema_max_specs", 25))
        max_endpoints = int(getattr(runtime, "api_schema_max_endpoints", 200))
        timeout = int(getattr(runtime, "api_schema_timeout", 10))
        
        spec_urls = self._collect_specs(context)
        if not spec_urls:
            context.logger.info("No API specs available for schema probing")
            return
        if max_specs > 0:
            spec_urls = spec_urls[:max_specs]

        client_config = HTTPClientConfig(
            max_concurrent=50,
            total_timeout=float(timeout),
            verify_ssl=runtime.verify_tls,
            requests_per_second=float(getattr(runtime, "api_schema_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
            for spec_url in spec_urls:
                # 1. Fetch and Parse Spec
                headers = context.auth_headers({"User-Agent": "recon-cli api-schema"})
                try:
                    resp = await client.get(spec_url, headers=headers)
                    if resp.status >= 400: continue
                    spec_data = self._parse_spec(resp.body or "", resp.headers.get("Content-Type", ""))
                    if not spec_data: continue
                except Exception: continue

                base_url = self._resolve_base_url(spec_data, spec_url)
                endpoints = self._extract_endpoints(spec_data)
                
                # Phase 3 Improvement: Infer Auth Expectations and Model Target
                for endpoint in endpoints:
                    url = self._build_url(base_url, endpoint)
                    method = str(endpoint.get("method") or "get").lower()
                    
                    # Add to Target Graph (Phase 2 integration)
                    context.target_graph.add_entity("api_endpoint", f"{method}:{url}", 
                                                   url=url, method=method, 
                                                   requires_auth=endpoint.get("requires_auth"))
                    
                    # Generate Attack Sequences (Adaptive)
                    await self._generate_attack_sequences(context, client, base_url, endpoint)

    async def _generate_attack_sequences(self, context: PipelineContext, client: AsyncHTTPClient, 
                                        base_url: str, endpoint: Dict[str, Any]) -> None:
        """Adaptive sequence generation: e.g., Create -> GET -> Delete."""
        method = str(endpoint.get("method") or "get").lower()
        path = str(endpoint.get("path") or "")
        
        # Identify 'collection' endpoints for IDOR feeding
        if method == "get" and "{" not in path:
            # Likely a list endpoint, use it to harvest IDs
            url = self._build_url(base_url, endpoint)
            resp = await client.get(url)
            if resp.status == 200:
                # Extract and feed to IDOR / Target Graph
                ids = self._extract_ids_from_body(resp.body)
                for obj_id in ids:
                    context.target_graph.add_entity("object_id", obj_id, 
                                                   source="api_schema_sequence", 
                                                   host=urlparse(url).hostname)

    def _extract_ids_from_body(self, body: str) -> List[str]:
        # Simple extraction logic for now
        found = []
        try:
            data = json.loads(body)
            # Recursive search for 'id' fields
            self._find_ids_recursive(data, found)
        except Exception:
            # Fallback to regex
            from recon_cli.pipeline.stage_idor import UUID_RE
            found.extend(UUID_RE.findall(body))
        return list(set(found))

    def _find_ids_recursive(self, data: Any, found: List[str]):
        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() in {"id", "uuid", "uid", "pk"} and isinstance(v, (str, int)):
                    found.append(str(v))
                else:
                    self._find_ids_recursive(v, found)
        elif isinstance(data, list):
            for item in data:
                self._find_ids_recursive(item, found)

    @staticmethod
    def _collect_specs(context: PipelineContext) -> List[str]:
        specs: List[str] = []
        for entry in context.get_results():
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
        if (
            "yaml" in lowered
            or "yml" in lowered
            or "openapi:" in text
            or "swagger:" in text
        ):
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
        fallback = (
            f"{parsed.scheme or 'https'}://{parsed.hostname}" if parsed.hostname else ""
        )
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
        scheme = schemes[0] if schemes else parsed.scheme or "https"  # type: ignore[index]
        if isinstance(swagger_host, str) and swagger_host:
            return f"{scheme}://{swagger_host}{base_path}".rstrip("/")
        return fallback.rstrip("/")

    def _extract_endpoints(self, spec: Dict[str, object]) -> List[Dict[str, object]]:
        endpoints: List[Dict[str, object]] = []
        paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
        global_security = (
            spec.get("security") if isinstance(spec.get("security"), list) else None
        )

        for path, methods in paths.items():  # type: ignore[attr-defined]
            if not isinstance(path, str) or not isinstance(methods, dict):
                continue
            path_parameters = self._parameters_from(methods.get("parameters"))
            for method, operation in methods.items():
                method_name = str(method).lower()
                if method_name not in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "head",
                    "options",
                }:
                    continue
                if not isinstance(operation, dict):
                    continue
                op_parameters = self._parameters_from(operation.get("parameters"))
                params = path_parameters + op_parameters
                body_fields = self._extract_request_body_fields(operation, params)
                requires_auth = self._requires_auth(
                    operation.get("security"), global_security
                )
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

    def _prioritize_endpoints(
        self, endpoints: List[Dict[str, object]]
    ) -> List[Dict[str, object]]:
        def _score(endpoint: Dict[str, object]) -> int:
            method = str(endpoint.get("method") or "").lower()
            path = str(endpoint.get("path") or "").lower()
            params = (
                endpoint.get("params")
                if isinstance(endpoint.get("params"), list)
                else []
            )
            body_fields = (
                endpoint.get("body_fields")
                if isinstance(endpoint.get("body_fields"), list)
                else []
            )
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
            score += min(12, len(params) * 2)  # type: ignore[arg-type]
            score += min(10, len(body_fields) * 2)  # type: ignore[arg-type]
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
                if "application/json" in content and isinstance(
                    content["application/json"], dict
                ):
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

    def _schema_field_names(
        self, schema: Dict[str, object], *, depth: int
    ) -> List[str]:
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
            url = self.PATH_PARAM_RE.sub(
                lambda m: self._placeholder_value(m.group(1)), url
            )
        params = {}
        for param in endpoint.get("params") or []:  # type: ignore[attr-defined]
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
        if lower.endswith("id") or lower in {
            "id",
            "uid",
            "user",
            "user_id",
            "account_id",
        }:
            return "1"
        if "slug" in lower or "name" in lower:
            return "test"
        if "email" in lower:
            return "recon@example.com"
        return "1"

    def _build_safe_body(
        self, endpoint: Dict[str, object]
    ) -> Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]:
        params = endpoint.get("params") or []
        form_fields: List[str] = []
        for item in params:  # type: ignore[attr-defined]
            if not isinstance(item, dict):
                continue
            if str(item.get("in") or "") == "formData":
                name = str(item.get("name") or "")
                if name:
                    form_fields.append(name)
        if form_fields:
            form_payload = {
                name: self._placeholder_value(name) for name in form_fields[:8]
            }
            form_payload.setdefault("recon_probe", "1")
            return None, form_payload  # type: ignore[return-value]

        body_fields = endpoint.get("body_fields") or []
        json_payload: Dict[str, object] = {}
        for name in body_fields[:8]:  # type: ignore[index]
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
            body = resp.body or ""
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
