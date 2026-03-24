from __future__ import annotations

import base64
import os
import asyncio
from typing import List, Set, Any, Optional, Dict
from urllib.parse import urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
from recon_cli.utils.ws_fuzzer import WSFuzzer
from recon_cli.utils.grpc_fuzzer import GRPCFuzzer


class WsGrpcDiscoveryStage(Stage):
    """
    WebSocket & gRPC Discovery, Reflection Probe and Basic Fuzzing.
    Identifies endpoints and performs initial message-level security probes.
    """
    name = "ws_grpc_discovery"

    WS_HINTS = ("/ws", "/websocket", "/socket", "/socket.io", "/sockjs", "/live", "/stream")
    GRPC_PORTS = {50051, 50052, 50053}

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ws_grpc_discovery", True))

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

        fuzzer = WSFuzzer(timeout=float(timeout), verify_tls=verify_tls)
        grpc_fuzzer = GRPCFuzzer(timeout=float(timeout), verify_tls=verify_tls)

        async with AsyncHTTPClient(config, context=context) as client:
            for url in ws_candidates:
                if not context.url_allowed(url): continue
                ws_found += 1
                
                probe_url = url.replace("wss://", "https://").replace("ws://", "http://")
                headers = context.auth_headers({
                    "User-Agent": "recon-cli ws-grpc",
                    "Connection": "Upgrade", "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
                })
                
                try:
                    resp = await client.get(probe_url, headers=headers, follow_redirects=False)
                    is_detected = resp.status == 101
                    tags = ["service:ws"]
                    if is_detected:
                        ws_confirmed += 1; tags.append("ws:confirmed")
                        await self._perform_ws_fuzzing(context, fuzzer, url, headers)
                    else: tags.append("ws:candidate")
                    
                    context.results.append({"type": "url", "source": self.name, "url": url, "hostname": urlparse(url).hostname, "tags": tags, "score": 30 if is_detected else 15})
                    context.emit_signal("ws_detected" if is_detected else "ws_candidate", "url", url, confidence=0.5, source=self.name, tags=tags, evidence={"status": resp.status})
                except Exception: continue

        # gRPC Processing
        grpc_hosts.update(self._detect_grpc_from_urls(context))
        grpc_hosts.update(self._detect_grpc_from_services(context))
        
        for h in grpc_hosts:
            context.emit_signal("grpc_detected", "host", h, confidence=0.5, source=self.name, tags=["service:grpc"])
            # Probing gRPC reflection
            for port in self.GRPC_PORTS:
                is_vuln, reason, _ = await grpc_fuzzer.check_reflection(h, port)
                if is_vuln:
                    context.logger.warning("🚨 gRPC Reflection Enabled on %s:%d", h, port)
                    context.emit_signal("grpc_reflection_enabled", "host", h, confidence=0.8, source=self.name, tags=["grpc", "misconfiguration"], evidence={"port": port, "reason": reason})
                    context.results.append({
                        "type": "finding", "finding_type": "grpc_reflection",
                        "hostname": h, "description": f"gRPC Reflection is enabled on port {port}. This allows enumeration of all services and methods.",
                        "severity": "medium", "tags": ["grpc", "recon"]
                    })
                
                # Basic method fuzzing
                methods = await grpc_fuzzer.fuzz_methods(h, port, [])
                for m in methods:
                    context.emit_signal("grpc_method_exposed", "host", h, confidence=0.6, source=self.name, tags=["grpc", "leak"], evidence={"port": port, "method": m})

        stats = context.record.metadata.stats.setdefault("ws_grpc", {})
        stats.update({"ws_candidates": ws_found, "ws_confirmed": ws_confirmed, "grpc_hosts": len(grpc_hosts)})
        context.manager.update_metadata(context.record)

    async def _perform_ws_fuzzing(self, context: PipelineContext, fuzzer: WSFuzzer, url: str, headers: Dict[str, str]):
        findings = await fuzzer.fuzz_endpoint(url, headers)
        for f in findings:
            context.emit_signal(f["type"], "url", url, confidence=f["confidence"], source=self.name, tags=["websocket", "vulnerability"], evidence=f["evidence"])
            context.results.append({"type": "finding", "finding_type": f["type"], "url": url, "description": f["description"], "severity": "medium", "tags": ["websocket", "security"]})

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
