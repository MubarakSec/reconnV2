from __future__ import annotations

import base64
import os
from typing import Dict, List, Set
from urllib.parse import urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class WsGrpcDiscoveryStage(Stage):
    name = "ws_grpc_discovery"

    WS_HINTS = ("/ws", "/websocket", "/socket", "/socket.io", "/sockjs", "/live", "/stream")
    GRPC_PORTS = {50051, 50052, 50053}

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ws_grpc_discovery", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("ws/grpc discovery requires requests; skipping")
            return

        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "ws_grpc_max_urls", 80))
        timeout = int(getattr(runtime, "ws_grpc_timeout", 8))
        limiter = context.get_rate_limiter(
            "ws_grpc_discovery",
            rps=float(getattr(runtime, "ws_grpc_rps", 0)),
            per_host=float(getattr(runtime, "ws_grpc_per_host_rps", 0)),
        )

        ws_candidates = self._collect_ws_candidates(context)
        if max_urls > 0:
            ws_candidates = ws_candidates[:max_urls]

        ws_confirmed = 0
        ws_found = 0
        grpc_hosts: Set[str] = set()

        for url in ws_candidates:
            if not context.url_allowed(url):
                continue
            ws_found += 1
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            headers = {
                "User-Agent": "recon-cli ws-grpc",
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
            }
            session = context.auth_session(url)
            try:
                if session:
                    resp = session.get(
                        url,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False,
                        verify=context.runtime_config.verify_tls,
                    )
                else:
                    resp = requests.get(
                        url,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False,
                        verify=context.runtime_config.verify_tls,
                    )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)

            tags = ["service:ws"]
            signal_type = "ws_candidate"
            if resp.status_code == 101:
                ws_confirmed += 1
                signal_type = "ws_detected"
                tags.append("ws:confirmed")
            else:
                tags.append("ws:candidate")
            payload = {
                "type": "url",
                "source": "ws-grpc",
                "url": url,
                "hostname": urlparse(url).hostname,
                "tags": tags,
                "score": 30 if signal_type == "ws_detected" else 15,
            }
            context.results.append(payload)
            context.emit_signal(
                signal_type,
                "url",
                url,
                confidence=0.5,
                source="ws-grpc",
                tags=tags,
                evidence={"status_code": resp.status_code},
            )

        grpc_hosts.update(self._detect_grpc_from_urls(context))
        grpc_hosts.update(self._detect_grpc_from_services(context))
        for host in grpc_hosts:
            context.emit_signal(
                "grpc_detected",
                "host",
                host,
                confidence=0.5,
                source="ws-grpc",
                tags=["service:grpc"],
            )

        stats = context.record.metadata.stats.setdefault("ws_grpc", {})
        stats.update(
            {
                "ws_candidates": ws_found,
                "ws_confirmed": ws_confirmed,
                "grpc_hosts": len(grpc_hosts),
            }
        )
        context.manager.update_metadata(context.record)

    def _collect_ws_candidates(self, context: PipelineContext) -> List[str]:
        urls: List[str] = []
        js_ws_endpoints = context.get_data("js_ws_endpoints", []) or []
        for url in js_ws_endpoints:
            if isinstance(url, str) and url:
                urls.append(self._normalize_ws_url(url))
        js_endpoints = context.get_data("js_endpoints", []) or []
        for url in js_endpoints:
            if isinstance(url, str) and ("ws://" in url or "wss://" in url or self._has_ws_hint(url)):
                urls.append(self._normalize_ws_url(url))
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url_value = entry.get("url")
            if not isinstance(url_value, str):
                continue
            if self._has_ws_hint(url_value):
                urls.append(self._normalize_ws_url(url_value))
        return list(dict.fromkeys(urls))

    def _detect_grpc_from_urls(self, context: PipelineContext) -> Set[str]:
        hosts: Set[str] = set()
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            content_type = str(entry.get("content_type") or entry.get("content-type") or "").lower()
            url_value = entry.get("url")
            if "application/grpc" in content_type:
                host = entry.get("hostname") or (urlparse(url_value).hostname if isinstance(url_value, str) else None)
                if host:
                    hosts.add(host)
                    payload = {
                        "type": "url",
                        "source": "grpc-detect",
                        "url": url_value,
                        "hostname": host,
                        "tags": ["service:grpc"],
                        "score": 35,
                    }
                    context.results.append(payload)
        return hosts

    def _detect_grpc_from_services(self, context: PipelineContext) -> Set[str]:
        hosts: Set[str] = set()
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "service":
                continue
            port = entry.get("port")
            service = str(entry.get("service") or "").lower()
            product = str(entry.get("product") or "").lower()
            if (isinstance(port, int) and port in self.GRPC_PORTS) or "grpc" in service or "grpc" in product:
                host = entry.get("hostname")
                if host:
                    hosts.add(host)
        return hosts

    def _has_ws_hint(self, url: str) -> bool:
        lower = url.lower()
        return any(hint in lower for hint in self.WS_HINTS)

    def _normalize_ws_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme in {"ws", "wss"}:
            return url
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
