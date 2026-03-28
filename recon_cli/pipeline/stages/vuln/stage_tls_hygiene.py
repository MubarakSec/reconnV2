from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage


class TLSHygieneStage(Stage):
    name = "tls_hygiene"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_tls_hygiene", False))

    async def run_async(self, context: PipelineContext) -> None:
        import asyncio
        items = context.get_results()
        if not items:
            return

        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "tls_hygiene_max_hosts", 40))
        timeout = int(getattr(runtime, "tls_hygiene_timeout", 6))
        limiter = context.get_rate_limiter(
            "tls_hygiene",
            rps=float(getattr(runtime, "tls_hygiene_rps", 0)),
            per_host=float(getattr(runtime, "tls_hygiene_per_host_rps", 0)),
        )

        best_by_host: Dict[str, Tuple[int, str]] = {}
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            if parsed.scheme and parsed.scheme != "https":
                continue
            host = parsed.hostname or ""
            if not host:
                continue
            score = int(entry.get("score", 0))
            current = best_by_host.get(host)
            if current is None or score > current[0]:
                best_by_host[host] = (score, url)

        candidates = sorted(
            best_by_host.values(), key=lambda item: item[0], reverse=True
        )
        if max_hosts > 0:
            candidates = candidates[:max_hosts]
        if not candidates:
            return

        checked = 0
        findings = 0
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        for score, url in candidates:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or 443
            if not host:
                continue
            if limiter and not await limiter.wait_for_slot(url, timeout=timeout):
                continue
            checked += 1
            try:
                result = await asyncio.to_thread(self._probe_host, host, port, timeout, verify_tls)
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, 200)

            if not result:
                continue
            issues = []
            severity = "low"
            score_value = 30
            priority = "low"

            protocol = result.get("protocol")
            legacy_supported = result.get("legacy_protocols", [])
            expiry_days = result.get("cert_days_remaining")

            if protocol in {"TLSv1", "TLSv1.1"}:
                issues.append("negotiated_legacy_protocol")
                severity = "high"
                score_value = 80
                priority = "high"
            elif legacy_supported:
                issues.append("supports_legacy_protocols")
                if severity != "high":
                    severity = "medium"
                    score_value = max(score_value, 55)
                    priority = "medium"

            if expiry_days is not None:
                if expiry_days <= 7:  # type: ignore[operator]
                    issues.append("certificate_expiring_soon")
                    severity = "high"
                    score_value = max(score_value, 80)
                    priority = "high"
                elif expiry_days <= 30:  # type: ignore[operator]
                    issues.append("certificate_expiring_soon")
                    if severity != "high":
                        severity = "medium"
                        score_value = max(score_value, 55)
                        priority = "medium"

            if not issues:
                continue

            payload = {
                "type": "finding",
                "finding_type": "tls_hygiene",
                "source": "tls-hygiene",
                "hostname": host,
                "url": url,
                "description": "TLS hygiene issues detected",
                "details": {
                    "protocol": protocol,
                    "cipher": result.get("cipher"),
                    "legacy_protocols": legacy_supported,
                    "cert_days_remaining": expiry_days,
                    "issues": issues,
                },
                "tags": ["tls", "crypto"] + [f"tls:{item}" for item in issues],
                "score": score_value,
                "priority": priority,
                "severity": severity,
            }
            if context.results.append(payload):
                findings += 1

        if checked:
            stats = context.record.metadata.stats.setdefault("tls_hygiene", {})
            stats["checked"] = checked
            stats["findings"] = findings
            context.manager.update_metadata(context.record)

    def _probe_host(
        self, host: str, port: int, timeout: int, verify_tls: bool
    ) -> Optional[Dict[str, object]]:
        result: Dict[str, object] = {}
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                result["protocol"] = tls_sock.version()
                result["cipher"] = tls_sock.cipher()[0] if tls_sock.cipher() else None
                cert = tls_sock.getpeercert() or {}
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = self._parse_not_after(not_after)  # type: ignore[arg-type]
                    if expiry:
                        now = datetime.now(timezone.utc)
                        delta = expiry - now
                        result["cert_days_remaining"] = int(
                            delta.total_seconds() // 86400
                        )

        legacy = self._check_legacy_protocols(host, port, timeout, verify_tls)
        if legacy:
            result["legacy_protocols"] = legacy
        return result

    @staticmethod
    def _parse_not_after(value: str) -> Optional[datetime]:
        normalized = " ".join(value.split())
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
            try:
                parsed = datetime.strptime(normalized, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def _check_legacy_protocols(
        self, host: str, port: int, timeout: int, verify_tls: bool
    ) -> List[str]:
        supported: List[str] = []
        tls_version = getattr(ssl, "TLSVersion", None)
        if tls_version:
            for name, version in (
                ("TLSv1", tls_version.TLSv1),
                ("TLSv1.1", tls_version.TLSv1_1),
            ):
                if self._try_version(host, port, timeout, verify_tls, version):
                    supported.append(name)
            return supported

        # Fallback for older Python versions
        for proto, name in (
            (getattr(ssl, "PROTOCOL_TLSv1", None), "TLSv1"),
            (getattr(ssl, "PROTOCOL_TLSv1_1", None), "TLSv1.1"),
        ):
            if proto is None:
                continue
            try:
                ctx = ssl.SSLContext(proto)
                if not verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        supported.append(name)
            except Exception:
                continue
        return supported

    @staticmethod
    def _try_version(
        host: str,
        port: int,
        timeout: int,
        verify_tls: bool,
        version,
    ) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = version
            ctx.maximum_version = version
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False
