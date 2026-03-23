from __future__ import annotations

import base64
import os
import asyncio
from typing import List, Set, Any, Optional
from urllib.parse import urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class WsGrpcDiscoveryStage(Stage):
    name = "ws_grpc_discovery"

    WS_HINTS = ("/ws", "/websocket", "/socket", "/socket.io", "/sockjs", "/live", "/stream")
    GRPC_PORTS = {50051, 50052, 50053}

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ws_grpc_discovery", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "ws_grpc_max_urls", 80))
        timeout = int(getattr(runtime, "ws_grpc_timeout", 8))
        verify_tls = bool(getattr(runtime, "verify_tls", True))

        ws_candidates = self._collect_ws_candidates(context)
        if max_urls > 0: ws_candidates = ws_candidates[:max_urls]

        ws_confirmed, ws_found = 0, 0
        grpc_hosts: Set[str] = set()

        config = HTTPClientConfig(
            max_concurrent=20,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "ws_grpc_rps", 30.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            for url in ws_candidates:
                if not context.url_allowed(url): continue
                ws_found += 1
                
                # Convert ws/wss to http/https for AsyncHTTPClient probe
                probe_url = url.replace("wss://", "https://").replace("ws://", "http://")
                
                headers = context.auth_headers({
                    "User-Agent": "recon-cli ws-grpc",
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
                })
                
                try:
                    resp = await client.get(probe_url, headers=headers, follow_redirects=False)
                    tags = ["service:ws"]
                    stype = "ws_candidate"
                    if resp.status == 101:
                        ws_confirmed += 1; stype = "ws_detected"; tags.append("ws:confirmed")
                    else: tags.append("ws:candidate")
                    
                    context.results.append({"type": "url", "source": self.name, "url": url, "hostname": urlparse(url).hostname, "tags": tags, "score": 30 if stype == "ws_detected" else 15})
                    context.emit_signal(stype, "url", url, confidence=0.5, source=self.name, tags=tags, evidence={"status": resp.status})
                except Exception: continue

        grpc_hosts.update(self._detect_grpc_from_urls(context))
        grpc_hosts.update(self._detect_grpc_from_services(context))
        for h in grpc_hosts:
            context.emit_signal("grpc_detected", "host", h, confidence=0.5, source=self.name, tags=["service:grpc"])

        stats = context.record.metadata.stats.setdefault("ws_grpc", {})
        stats.update({"ws_candidates": ws_found, "ws_confirmed": ws_confirmed, "grpc_hosts": len(grpc_hosts)})
        context.manager.update_metadata(context.record)

    def _collect_ws_candidates(self, context: PipelineContext) -> List[str]:
        urls = []
        js_ws = context.get_data("js_ws_endpoints", []) or []
        for u in js_ws:
            if isinstance(u, str): urls.append(self._normalize_ws_url(u))
        for r in context.filter_results("url"):
            u = r.get("url")
            if isinstance(u, str) and (self._has_ws_hint(u) or "ws://" in u or "wss://" in u):
                urls.append(self._normalize_ws_url(u))
        return list(dict.fromkeys(urls))

    def _detect_grpc_from_urls(self, context: PipelineContext) -> Set[str]:
        hosts = set()
        for r in context.filter_results("url"):
            ct = str(r.get("content_type") or r.get("content-type") or "").lower()
            if "application/grpc" in ct:
                u = r.get("url")
                h = r.get("hostname") or (urlparse(u).hostname if isinstance(u, str) else None)
                if h:
                    hosts.add(h)
                    context.results.append({"type": "url", "source": "grpc-detect", "url": u, "hostname": h, "tags": ["service:grpc"], "score": 35})
        return hosts

    def _detect_grpc_from_services(self, context: PipelineContext) -> Set[str]:
        hosts = set()
        for r in context.filter_results("service"):
            p, s, prod = r.get("port"), str(r.get("service", "")).lower(), str(r.get("product", "")).lower()
            if (isinstance(p, int) and p in self.GRPC_PORTS) or "grpc" in s or "grpc" in prod:
                if r.get("hostname"): hosts.add(r["hostname"])
        return hosts

    def _has_ws_hint(self, url: str) -> bool:
        l_url = url.lower()
        return any(h in l_url for h in self.WS_HINTS)

    def _normalize_ws_url(self, url: str) -> str:
        p = urlparse(url)
        if p.scheme in {"ws", "wss"}: return url
        sch = "wss" if p.scheme == "https" else "ws"
        return urlunparse((sch, p.netloc, p.path, p.params, p.query, p.fragment))
