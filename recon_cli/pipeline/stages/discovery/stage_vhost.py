from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests  # type: ignore[import-untyped]

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage


@dataclass
class ResponseSig:
    status: int
    length: int
    title: str
    server: Optional[str] = None


class VHostDiscoveryStage(Stage):
    name = "vhost_discovery"

    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_vhost", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "vhost_max_hosts", 30))
        max_candidates = int(getattr(runtime, "vhost_max_candidates", 1500))
        timeout = int(getattr(runtime, "vhost_timeout", 8))
        max_probes = max(0, int(getattr(runtime, "vhost_max_probes", 1000)))
        max_duration = max(0, int(getattr(runtime, "vhost_max_duration", 1800)))
        progress_every = max(1, int(getattr(runtime, "vhost_progress_every", 100)))
        max_response_bytes = max(
            4096, int(getattr(runtime, "vhost_max_response_bytes", 65536))
        )
        verify_tls = bool(getattr(runtime, "verify_tls", True))

        base_hosts = self._select_base_hosts(context)
        if not base_hosts:
            context.logger.info("No hosts qualified for vhost discovery")
            return

        words = self._load_wordlist(runtime)
        if not words:
            context.logger.info("VHost wordlist empty; skipping")
            return
        if max_candidates > 0:
            words = words[:max_candidates]

        selected_hosts = base_hosts[:max_hosts]
        context.logger.info(
            "VHost discovery on %d hosts (wordlist=%d, probe_cap=%s, duration_cap=%ss)",
            len(selected_hosts),
            len(words),
            max_probes if max_probes else "unlimited",
            max_duration if max_duration else "unlimited",
        )

        checked_hosts, tested_probes, discovered, wildcard_filtered = 0, 0, 0, 0
        stage_started = time.monotonic()

        for host_index, (host, base_url, score) in enumerate(selected_hosts, 1):
            if (max_duration and (time.monotonic() - stage_started) >= max_duration) or (
                max_probes and tested_probes >= max_probes
            ):
                break

            checked_hosts += 1
            root = self._root_domain(host)
            candidates = self._build_candidates(words, root, host)
            if not candidates:
                continue

            if max_probes:
                remaining_hosts = max(1, len(selected_hosts) - host_index + 1)
                remaining_probes = max(0, max_probes - tested_probes)
                candidates = candidates[: max(1, remaining_probes // remaining_hosts)]

            context.logger.info(
                "VHost host %d/%d: %s (candidates=%d)",
                host_index,
                len(selected_hosts),
                host,
                len(candidates),
            )

            baseline_sig = await self._fetch_sig(
                base_url,
                {"User-Agent": "recon-cli vhost"},
                timeout=timeout,
                verify_tls=verify_tls,
                max_response_bytes=max_response_bytes,
            )
            if baseline_sig is None:
                continue

            wildcard_host = f"{uuid.uuid4().hex[:12]}.{root}"
            wildcard_sig = await self._fetch_sig(
                base_url,
                {
                    "User-Agent": "recon-cli vhost",
                    "Host": wildcard_host,
                    "X-Forwarded-Host": wildcard_host,
                },
                timeout=timeout,
                verify_tls=verify_tls,
                max_response_bytes=max_response_bytes,
            )

            for candidate in candidates:
                if (max_duration and (time.monotonic() - stage_started) >= max_duration) or (
                    max_probes and tested_probes >= max_probes
                ):
                    break

                tested_probes += 1
                if tested_probes % progress_every == 0:
                    context.logger.info("VHost probes tested=%d", tested_probes)

                sig = await self._fetch_sig(
                    base_url,
                    {
                        "User-Agent": "recon-cli vhost",
                        "Host": candidate,
                        "X-Forwarded-Host": candidate,
                    },
                    timeout=timeout,
                    verify_tls=verify_tls,
                    max_response_bytes=max_response_bytes,
                )
                if sig is None:
                    continue

                if not self._is_interesting(baseline_sig, sig):
                    continue
                if wildcard_sig and not self._is_interesting(wildcard_sig, sig):
                    wildcard_filtered += 1
                    continue

                candidate_url = self._candidate_url(base_url, candidate)
                if candidate_url and not context.url_allowed(candidate_url):
                    continue

                signal_id = context.emit_signal(
                    "vhost_found",
                    "host",
                    candidate,
                    confidence=0.6,
                    source=self.name,
                    tags=["vhost"],
                    evidence={
                        "base_url": base_url,
                        "baseline_status": baseline_sig.status,
                        "candidate_status": sig.status,
                    },
                )
                context.results.append(
                    {
                        "type": "hostname",
                        "source": "vhost",
                        "hostname": candidate,
                        "score": max(35, score),
                        "tags": ["vhost"],
                        "evidence_id": signal_id or None,
                    }
                )
                if candidate_url:
                    context.results.append(
                        {
                            "type": "url",
                            "source": "vhost",
                            "url": candidate_url,
                            "hostname": candidate,
                            "status_code": sig.status,
                            "title": sig.title,
                            "content_length": sig.length,
                            "server": sig.server,
                            "tags": ["vhost"],
                            "score": max(45, score),
                            "evidence_id": signal_id or None,
                        }
                    )
                discovered += 1

        stats = context.record.metadata.stats.setdefault("vhost", {})
        stats.update(
            {
                "checked_hosts": checked_hosts,
                "tested_candidates": tested_probes,
                "discovered": discovered,
                "wildcard_filtered": wildcard_filtered,
                "probe_cap": max_probes,
            }
        )
        context.manager.update_metadata(context.record)

    def _select_base_hosts(self, context: PipelineContext) -> List[Tuple[str, str, int]]:
        best: Dict[str, Tuple[str, int]] = {}
        for entry in context.filter_results("url"):
            url = entry.get("url")
            host = entry.get("hostname") or (url and urlparse(url).hostname)
            if not host or not url:
                continue
            if int(entry.get("status_code") or 0) not in {200, 301, 302, 401, 403}:
                continue
            score = int(entry.get("score", 0))
            if host not in best or score > best[host][1]:
                best[host] = (url, score)
        return [(host, details[0], details[1]) for host, details in best.items()]

    def _load_wordlist(self, runtime) -> List[str]:
        configured = getattr(runtime, "vhost_wordlist", None)
        if configured:
            configured_path = Path(str(configured))
            if configured_path.exists():
                return [
                    line.strip()
                    for line in configured_path.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                    if line.strip() and not line.startswith("#")
                ]

        base = runtime.seclists_root
        candidates = [
            base / "Discovery" / "Web-Content" / "vhost.txt",
            base / "Discovery" / "DNS" / "subdomains-top1million-20000.txt",
        ]
        for candidate in candidates:
            if candidate.exists():
                return [
                    line.strip()
                    for line in candidate.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                    if line.strip() and not line.startswith("#")
                ]
        return []

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    @staticmethod
    def _build_candidates(words: List[str], root: str, current_host: str) -> List[str]:
        results: List[str] = []
        seen: set[str] = set()
        for word in words:
            candidate = (
                word.replace("{root}", root)
                if "{root}" in word
                else (word if "." in word else f"{word}.{root}")
            )
            candidate = candidate.strip().lower()
            if candidate and candidate != current_host and candidate not in seen:
                seen.add(candidate)
                results.append(candidate)
        return results

    async def _fetch_sig(
        self,
        url: str,
        headers: Dict[str, str],
        *,
        timeout: int,
        verify_tls: bool,
        max_response_bytes: int,
    ) -> Optional[ResponseSig]:
        try:
            response = await asyncio.to_thread(
                requests.get,
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=verify_tls,
                headers=headers,
                stream=True,
            )
        except Exception:
            return None

        try:
            chunks: list[bytes] = []
            seen = 0
            for chunk in response.iter_content(chunk_size=4096):
                if not chunk:
                    continue
                remaining = max_response_bytes - seen
                if remaining <= 0:
                    break
                part = chunk[:remaining]
                chunks.append(part)
                seen += len(part)
                if seen >= max_response_bytes:
                    break

            body = b"".join(chunks).decode("utf-8", errors="ignore")
            title_match = self.TITLE_RE.search(body)

            header_len = (getattr(response, "headers", {}) or {}).get("Content-Length")
            try:
                content_length = int(header_len) if header_len is not None else len(body)
            except (TypeError, ValueError):
                content_length = len(body)

            return ResponseSig(
                status=int(getattr(response, "status_code", 0) or 0),
                length=content_length,
                title=title_match.group(1).strip() if title_match else "",
                server=(getattr(response, "headers", {}) or {}).get("Server"),
            )
        except Exception:
            return None
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    @staticmethod
    def _is_interesting(base: ResponseSig, cand: ResponseSig) -> bool:
        if base.status != cand.status and not ({base.status, cand.status} <= {301, 302}):
            return True
        if base.title and cand.title and base.title != cand.title:
            return True
        if base.length == 0 and cand.length > 0:
            return True
        return abs(base.length - cand.length) > max(200, int(base.length * 0.3))

    @staticmethod
    def _candidate_url(base_url: str, candidate: str) -> str:
        parsed = urlparse(base_url)
        return f"{parsed.scheme or 'https'}://{candidate}/"
