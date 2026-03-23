from __future__ import annotations

import re
import asyncio
import uuid
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig, HTTPResponse


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

        config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=float(getattr(runtime, "vhost_rps", 25.0))
        )

        checked_hosts, tested_probes, discovered, wildcard_filtered = 0, 0, 0, 0
        probe_cap_hit, duration_cap_hit = False, False
        stage_started = time.monotonic()

        async with AsyncHTTPClient(config, context=context) as client:
            for host_index, (host, base_url, score) in enumerate(selected_hosts, 1):
                if (max_duration and (time.monotonic() - stage_started) >= max_duration) or (max_probes and tested_probes >= max_probes):
                    break
                
                checked_hosts += 1
                root = self._root_domain(host)
                candidates = self._build_candidates(words, root, host)
                if not candidates: continue
                
                if max_probes:
                    remaining_hosts = max(1, len(selected_hosts) - host_index + 1)
                    remaining_probes = max(0, max_probes - tested_probes)
                    candidates = candidates[:max(1, remaining_probes // remaining_hosts)]

                context.logger.info("VHost host %d/%d: %s (candidates=%d)", host_index, len(selected_hosts), host, len(candidates))

                baseline_sig = await self._fetch_sig(context, client, base_url, {"User-Agent": "recon-cli vhost"}, max_response_bytes=max_response_bytes)
                if baseline_sig is None: continue
                
                wildcard_host = f"{uuid.uuid4().hex[:12]}.{root}"
                wildcard_sig = await self._fetch_sig(context, client, base_url, {"User-Agent": "recon-cli vhost", "Host": wildcard_host, "X-Forwarded-Host": wildcard_host}, max_response_bytes=max_response_bytes)

                for candidate in candidates:
                    if (max_duration and (time.monotonic() - stage_started) >= max_duration) or (max_probes and tested_probes >= max_probes):
                        break
                    
                    tested_probes += 1
                    sig = await self._fetch_sig(context, client, base_url, {"User-Agent": "recon-cli vhost", "Host": candidate, "X-Forwarded-Host": candidate}, max_response_bytes=max_response_bytes)
                    if sig is None: continue
                    
                    if not self._is_interesting(baseline_sig, sig): continue
                    if wildcard_sig and not self._is_interesting(wildcard_sig, sig):
                        wildcard_filtered += 1; continue

                    candidate_url = self._candidate_url(base_url, candidate)
                    if candidate_url and not context.url_allowed(candidate_url): continue

                    signal_id = context.emit_signal("vhost_found", "host", candidate, confidence=0.6, source=self.name, tags=["vhost"], evidence={"base_url": base_url, "baseline_status": baseline_sig.status, "candidate_status": sig.status})
                    context.results.append({"type": "hostname", "source": "vhost", "hostname": candidate, "score": max(35, score), "tags": ["vhost"], "evidence_id": signal_id or None})
                    if candidate_url:
                        context.results.append({"type": "url", "source": "vhost", "url": candidate_url, "hostname": candidate, "status_code": sig.status, "title": sig.title, "content_length": sig.length, "server": sig.server, "tags": ["vhost"], "score": max(45, score), "evidence_id": signal_id or None})
                    discovered += 1

        stats = context.record.metadata.stats.setdefault("vhost", {})
        stats.update({"checked_hosts": checked_hosts, "tested_candidates": tested_probes, "discovered": discovered, "wildcard_filtered": wildcard_filtered, "probe_cap": max_probes})
        context.manager.update_metadata(context.record)

    def _select_base_hosts(self, context: PipelineContext) -> List[Tuple[str, str, int]]:
        best: Dict[str, Tuple[str, int]] = {}
        for entry in context.filter_results("url"):
            url = entry.get("url")
            host = entry.get("hostname") or (url and urlparse(url).hostname)
            if not host or not url: continue
            if int(entry.get("status_code") or 0) not in {200, 301, 302, 401, 403}: continue
            score = int(entry.get("score", 0))
            if host not in best or score > best[host][1]: best[host] = (url, score)
        return [(h, d[0], d[1]) for h, d in best.items()]

    def _load_wordlist(self, runtime) -> List[str]:
        base = runtime.seclists_root
        cands = [base / "Discovery" / "Web-Content" / "vhost.txt", base / "Discovery" / "DNS" / "subdomains-top1million-20000.txt"]
        for c in cands:
            if c.exists(): return [l.strip() for l in c.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
        return []

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    @staticmethod
    def _build_candidates(words: List[str], root: str, current_host: str) -> List[str]:
        results, seen = [], set()
        for w in words:
            cand = w.replace("{root}", root) if "{root}" in w else (w if "." in w else f"{w}.{root}")
            cand = cand.strip().lower()
            if cand and cand != current_host and cand not in seen:
                seen.add(cand); results.append(cand)
        return results

    async def _fetch_sig(self, context: PipelineContext, client: AsyncHTTPClient, url: str, headers: Dict[str, str], max_response_bytes: int) -> Optional[ResponseSig]:
        try:
            resp = await client.get(url, headers=headers, follow_redirects=True)
            body = resp.body[:max_response_bytes]
            title_match = self.TITLE_RE.search(body)
            return ResponseSig(status=resp.status, length=len(resp.body), title=title_match.group(1).strip() if title_match else "", server=resp.headers.get("Server"))
        except Exception: return None

    @staticmethod
    def _is_interesting(base: ResponseSig, cand: ResponseSig) -> bool:
        if base.status != cand.status and not ({base.status, cand.status} <= {301, 302}): return True
        if base.title and cand.title and base.title != cand.title: return True
        if base.length == 0 and cand.length > 0: return True
        return abs(base.length - cand.length) > max(200, int(base.length * 0.3))

    @staticmethod
    def _candidate_url(base_url: str, candidate: str) -> str:
        p = urlparse(base_url)
        return f"{p.scheme or 'https'}://{candidate}/"
