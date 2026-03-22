from __future__ import annotations

import json
from typing import Dict, List
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class GraphQLReconStage(Stage):
    name = "graphql_recon"

    INTROSPECTION_QUERY = (
        "query IntrospectionQuery {"
        "__schema {"
        "queryType { name }"
        "mutationType { name }"
        "subscriptionType { name }"
        "types { name kind }"
        "directives { name }"
        "}"
        "}"
    )

    PROBE_PATHS = [
        "/graphql",
        "/graphiql",
        "/graphql/console",
        "/api/graphql",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_graphql_recon", False))

    COMMON_GQL_GUESSES = [
        "query { me { id username email } }",
        "query { users { id username } }",
        "query { config { version debug } }",
        "mutation { login(username: \"test\", password: \"test\") { token } }",
        "mutation { register(email: \"test@test.com\") { id } }",
    ]

    def execute(self, context: PipelineContext) -> None:
        # ... (rest of imports and setup same) ...
        try:
            import requests
        except Exception:
            context.logger.warning("graphql recon requires requests; skipping")
            return

        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "graphql_max_urls", 40))
        timeout = int(getattr(runtime, "graphql_timeout", 10))
        limiter = context.get_rate_limiter(
            "graphql_recon",
            rps=float(getattr(runtime, "graphql_rps", 0)),
            per_host=float(getattr(runtime, "graphql_per_host_rps", 0)),
        )

        candidates = self._collect_candidates(context)
        if not candidates:
            context.logger.info("No GraphQL candidates found")
            return
        if max_urls > 0:
            candidates = candidates[:max_urls]

        checked = 0
        graphql_found = 0
        introspection_enabled = 0
        brute_forced_hits = 0
        artifacts: List[str] = []

        for url in candidates:
            if not context.url_allowed(url):
                continue
            checked += 1
            session = context.auth_session(url)
            headers = context.auth_headers(
                {
                    "User-Agent": "recon-cli graphql-recon",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            )
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            
            # 1. Try Introspection
            try:
                payload = {"query": self.INTROSPECTION_QUERY}
                resp = self._do_request(requests, session, url, payload, headers, timeout, context)
            except Exception:
                if limiter: limiter.on_error(url)
                continue
            
            if limiter: limiter.on_response(url, resp.status_code)

            data = self._safe_json(resp.text or "")
            if not self._is_graphql_response(resp.status_code, resp.headers.get("Content-Type", ""), data):
                continue

            graphql_found += 1
            host = urlparse(url).hostname or ""
            
            if self._has_introspection_schema(data):
                introspection_enabled += 1
                self._save_schema(context, host, data, url, artifacts)
            else:
                # 2. Brute Force / Guessing Phase
                context.logger.info("Introspection disabled for %s, starting brute-force guessing...", url)
                for guess in self.COMMON_GQL_GUESSES:
                    try:
                        g_resp = self._do_request(requests, session, url, {"query": guess}, headers, timeout, context)
                        g_data = self._safe_json(g_resp.text or "")
                        if "errors" not in g_data or ("errors" in g_data and "not found" not in str(g_data["errors"]).lower()):
                            brute_forced_hits += 1
                            context.emit_signal(
                                "graphql_guess_hit", "url", url,
                                confidence=0.5, source=self.name,
                                tags=["api:graphql", "brute-force"],
                                evidence={"query": guess, "status": g_resp.status_code}
                            )
                    except Exception: pass

        if checked:
            stats = context.record.metadata.stats.setdefault("graphql_recon", {})
            stats.update({
                "checked": checked, "graphql_found": graphql_found,
                "introspection_enabled": introspection_enabled,
                "brute_forced_hits": brute_forced_hits
            })

    def _do_request(self, requests, session, url, payload, headers, timeout, context) -> Any:
        if session:
            return session.post(url, json=payload, timeout=timeout, allow_redirects=True, headers=headers, verify=context.runtime_config.verify_tls)
        return requests.post(url, json=payload, timeout=timeout, allow_redirects=True, headers=headers, verify=context.runtime_config.verify_tls)

    def _save_schema(self, context, host, data, url, artifacts) -> None:
        schema_path = context.record.paths.artifact(f"graphql_schema_{host or 'unknown'}.json")
        schema_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        artifacts.append(str(schema_path))
        context.emit_signal("graphql_introspection_enabled", "url", url, confidence=0.7, source=self.name, tags=["api:graphql", "introspection"], evidence={"schema_artifact": str(schema_path)})

    def _collect_candidates(self, context: PipelineContext) -> List[str]:
        candidates: List[str] = []
        urls_seen: set[str] = set()

        js_graphql_endpoints = context.get_data("js_graphql_endpoints", []) or []
        for url in js_graphql_endpoints:  # type: ignore[attr-defined]
            if isinstance(url, str) and url and url not in urls_seen:
                candidates.append(url)
                urls_seen.add(url)

        for entry in context.get_results():
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            tags = entry.get("tags", [])
            if "api:graphql" in tags or "graphql" in url.lower():
                if url not in urls_seen:
                    candidates.append(url)
                    urls_seen.add(url)

        js_endpoints = context.get_data("js_endpoints", []) or []
        for url in js_endpoints:  # type: ignore[attr-defined]
            if (
                isinstance(url, str)
                and "graphql" in url.lower()
                and url not in urls_seen
            ):
                candidates.append(url)
                urls_seen.add(url)

        signals = context.signal_index()
        for host in signals.get("by_host", {}):
            if "api_surface" not in signals.get("by_host", {}).get(host, set()):
                continue
            for path in self.PROBE_PATHS:
                url = urljoin(f"https://{host}", path)
                if url not in urls_seen:
                    candidates.append(url)
                    urls_seen.add(url)
        return candidates

    @staticmethod
    def _safe_json(text: str) -> Dict[str, object]:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}

    @staticmethod
    def _is_graphql_response(
        status_code: int, content_type: str, data: Dict[str, object]
    ) -> bool:
        if not data:
            return False
        if "application/json" in content_type or status_code in {200, 400}:
            if "data" in data or "errors" in data:
                return True
        return False

    @staticmethod
    def _has_introspection_schema(data: Dict[str, object]) -> bool:
        schema = (
            data.get("data", {}).get("__schema")  # type: ignore[attr-defined]
            if isinstance(data.get("data"), dict)
            else None
        )
        return isinstance(schema, dict) and bool(schema)
