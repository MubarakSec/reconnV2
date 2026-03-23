from __future__ import annotations

import json
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class OAuthDiscoveryStage(Stage):
    name = "oauth_discovery"

    WELL_KNOWN_PATHS = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
    ]
    COMMON_ENDPOINTS = [
        "/oauth/authorize", "/oauth2/authorize", "/authorize",
        "/oauth/token", "/oauth2/token", "/token",
        "/oauth/device/code", "/oauth/revoke", "/oauth/introspect",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_oauth_discovery", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "oauth_max_hosts", 50))
        timeout = int(getattr(runtime, "oauth_timeout", 8))
        verify_tls = bool(getattr(runtime, "verify_tls", True))

        hosts = self._collect_hosts(context)
        if not hosts:
            context.logger.info("No hosts available for oauth discovery")
            return
        if max_hosts > 0: hosts = hosts[:max_hosts]

        configs: List[Dict[str, Any]] = []
        endpoints_found, configs_found = 0, 0

        config = HTTPClientConfig(
            max_concurrent=20,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "oauth_rps", 30.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            for host in hosts:
                base = f"https://{host}"
                
                # 1. Probe Well-Known
                for path in self.WELL_KNOWN_PATHS:
                    url = urljoin(base, path)
                    if not context.url_allowed(url): continue
                    
                    try:
                        resp = await client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli oauth"}), follow_redirects=True)
                        if resp.status >= 400: continue
                        
                        data = self._safe_json(resp.body)
                        if not data: continue
                        
                        configs_found += 1
                        configs.append({"host": host, "url": url, "keys": list(data.keys())[:40]})
                        
                        stype = "oidc_config" if "openid-configuration" in path else "oauth_config"
                        stag = "service:oidc" if "openid-configuration" in path else "service:oauth"
                        context.emit_signal(stype, "host", host, confidence=0.7, source=self.name, tags=[stag], evidence={"url": url})
                        endpoints_found += self._emit_endpoints_from_config(context, data)
                    except Exception: continue

                # 2. Probe Common Endpoints
                for path in self.COMMON_ENDPOINTS:
                    url = urljoin(base, path)
                    if not context.url_allowed(url): continue
                    
                    try:
                        resp = await client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli oauth"}), follow_redirects=True)
                        if resp.status in {200, 400, 401, 403, 405, 302}:
                            endpoints_found += 1
                            tags = ["service:oauth"]
                            stype = "oauth_endpoint"
                            if "authorize" in path:
                                stype, tag = "oauth_authorize_endpoint", "surface:authorize"
                            elif "token" in path:
                                stype, tag = "oauth_token_endpoint", "surface:token"
                            else: tag = None
                            if tag: tags.append(tag)
                            
                            context.results.append({"type": "url", "source": self.name, "url": url, "hostname": host, "tags": tags, "score": 40})
                            context.emit_signal(stype, "url", url, confidence=0.5, source=self.name, tags=tags, evidence={"status": resp.status})
                    except Exception: continue

        if configs:
            context.record.paths.artifact("oauth_discovery.json").write_text(json.dumps(configs, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("oauth_discovery", {})
        stats.update({"hosts": len(hosts), "configs": configs_found, "endpoints": endpoints_found})
        context.manager.update_metadata(context.record)

    def _collect_hosts(self, context: PipelineContext) -> List[str]:
        hosts = []
        for entry in context.filter_results("hostname"):
            h = entry.get("hostname") or (entry.get("url") and urlparse(entry["url"]).hostname)
            if h: hosts.append(h)
        return list(dict.fromkeys(hosts))

    def _emit_endpoints_from_config(self, context: PipelineContext, data: Dict[str, Any]) -> int:
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
        for k, stype, tag in keys:
            url = data.get(k)
            if not isinstance(url, str) or not url: continue
            host = urlparse(url).hostname
            tags = ["service:oauth", tag]
            context.results.append({"type": "url", "source": self.name, "url": url, "hostname": host, "tags": tags, "score": 45})
            context.emit_signal(stype, "url", url, confidence=0.6, source=self.name, tags=tags, evidence={"key": k})
            found += 1
        return found

    @staticmethod
    def _safe_json(text: str) -> Dict[str, Any]:
        try:
            d = json.loads(text)
            return d if isinstance(d, dict) else {}
        except Exception: return {}
