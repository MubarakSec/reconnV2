from __future__ import annotations

import json
from typing import Dict, List
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class OAuthDiscoveryStage(Stage):
    name = "oauth_discovery"

    WELL_KNOWN_PATHS = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
    ]
    COMMON_ENDPOINTS = [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/authorize",
        "/oauth/token",
        "/oauth2/token",
        "/token",
        "/oauth/device/code",
        "/oauth/revoke",
        "/oauth/introspect",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_oauth_discovery", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("oauth discovery requires requests; skipping")
            return

        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "oauth_max_hosts", 50))
        timeout = int(getattr(runtime, "oauth_timeout", 8))
        limiter = context.get_rate_limiter(
            "oauth_discovery",
            rps=float(getattr(runtime, "oauth_rps", 0)),
            per_host=float(getattr(runtime, "oauth_per_host_rps", 0)),
        )

        hosts = self._collect_hosts(context)
        if not hosts:
            context.logger.info("No hosts available for oauth discovery")
            return
        if max_hosts > 0:
            hosts = hosts[:max_hosts]

        configs: List[Dict[str, object]] = []
        endpoints_found = 0
        configs_found = 0

        for host in hosts:
            base = f"https://{host}"
            for path in self.WELL_KNOWN_PATHS:
                url = urljoin(base, path)
                if not context.url_allowed(url):
                    continue
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                session = context.auth_session(url)
                headers = context.auth_headers({"User-Agent": "recon-cli oauth"})
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
                except requests.exceptions.RequestException:
                    if limiter:
                        limiter.on_error(url)
                    continue
                if limiter:
                    limiter.on_response(url, resp.status_code)
                if resp.status_code >= 400:
                    continue
                data = self._safe_json(resp.text or "")
                if not data:
                    continue
                configs_found += 1
                config_record = {
                    "host": host,
                    "url": url,
                    "keys": list(data.keys())[:40],
                }
                configs.append(config_record)
                if "openid-configuration" in path:
                    context.emit_signal(
                        "oidc_config",
                        "host",
                        host,
                        confidence=0.7,
                        source="oauth-discovery",
                        tags=["service:oidc"],
                        evidence={"url": url},
                    )
                else:
                    context.emit_signal(
                        "oauth_config",
                        "host",
                        host,
                        confidence=0.6,
                        source="oauth-discovery",
                        tags=["service:oauth"],
                        evidence={"url": url},
                    )
                endpoints_found += self._emit_endpoints_from_config(context, data)

            for path in self.COMMON_ENDPOINTS:
                url = urljoin(base, path)
                if not context.url_allowed(url):
                    continue
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                session = context.auth_session(url)
                headers = context.auth_headers({"User-Agent": "recon-cli oauth"})
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
                except requests.exceptions.RequestException:
                    if limiter:
                        limiter.on_error(url)
                    continue
                if limiter:
                    limiter.on_response(url, resp.status_code)
                if resp.status_code in {200, 400, 401, 403, 405, 302}:
                    endpoints_found += 1
                    tags = ["service:oauth"]
                    signal_type = "oauth_endpoint"
                    if "authorize" in path:
                        signal_type = "oauth_authorize_endpoint"
                        tags.append("surface:authorize")
                    elif "token" in path:
                        signal_type = "oauth_token_endpoint"
                        tags.append("surface:token")
                    payload = {
                        "type": "url",
                        "source": "oauth-discovery",
                        "url": url,
                        "hostname": host,
                        "tags": tags,
                        "score": 40,
                    }
                    context.results.append(payload)
                    context.emit_signal(
                        signal_type,
                        "url",
                        url,
                        confidence=0.5,
                        source="oauth-discovery",
                        tags=tags,
                        evidence={"status_code": resp.status_code},
                    )

        if configs:
            artifact_path = context.record.paths.artifact("oauth_discovery.json")
            artifact_path.write_text(json.dumps(configs, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("oauth_discovery", {})
        stats.update(
            {
                "hosts": len(hosts),
                "configs": configs_found,
                "endpoints": endpoints_found,
            }
        )
        context.manager.update_metadata(context.record)

    @staticmethod
    def _collect_hosts(context: PipelineContext) -> List[str]:
        hosts: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            etype = entry.get("type")
            if etype == "hostname":
                host = entry.get("hostname")
            elif etype == "url":
                url_value = entry.get("url")
                host = urlparse(url_value).hostname if isinstance(url_value, str) else None
            else:
                host = None
            if isinstance(host, str) and host:
                hosts.append(host)
        return list(dict.fromkeys(hosts))

    def _emit_endpoints_from_config(self, context: PipelineContext, data: Dict[str, object]) -> int:
        keys = [
            ("authorization_endpoint", "oauth_authorize_endpoint", "surface:authorize"),
            ("token_endpoint", "oauth_token_endpoint", "surface:token"),
            ("userinfo_endpoint", "oauth_userinfo_endpoint", "surface:userinfo"),
            ("jwks_uri", "oauth_jwks_uri", "surface:jwks"),
            ("revocation_endpoint", "oauth_revocation_endpoint", "surface:revoke"),
            ("introspection_endpoint", "oauth_introspection_endpoint", "surface:introspect"),
            ("device_authorization_endpoint", "oauth_device_endpoint", "surface:device"),
        ]
        found = 0
        for key, signal_type, tag in keys:
            url = data.get(key)
            if not isinstance(url, str) or not url:
                continue
            host = urlparse(url).hostname
            tags = ["service:oauth", tag]
            payload = {
                "type": "url",
                "source": "oauth-discovery",
                "url": url,
                "hostname": host,
                "tags": tags,
                "score": 45,
            }
            context.results.append(payload)
            context.emit_signal(
                signal_type,
                "url",
                url,
                confidence=0.6,
                source="oauth-discovery",
                tags=tags,
                evidence={"key": key},
            )
            found += 1
        return found

    @staticmethod
    def _safe_json(text: str) -> Dict[str, object]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(data, dict):
            return data
        return {}
