from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


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

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("vhost discovery requires requests; skipping")
            return

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
        limiter = context.get_rate_limiter(
            "vhost_discovery",
            rps=float(getattr(runtime, "vhost_rps", 0)),
            per_host=float(getattr(runtime, "vhost_per_host_rps", 0)),
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
            "VHost discovery on %d hosts (wordlist=%d, probe_cap=%s, duration_cap=%ss, progress_every=%d)",
            len(selected_hosts),
            len(words),
            max_probes if max_probes else "unlimited",
            max_duration if max_duration else "unlimited",
            progress_every,
        )

        checked_hosts = 0
        tested_probes = 0
        discovered = 0
        wildcard_filtered = 0
        probe_cap_hit = False
        duration_cap_hit = False
        stage_started = time.monotonic()

        for host_index, (host, base_url, score) in enumerate(selected_hosts, 1):
            elapsed = time.monotonic() - stage_started
            if max_duration and elapsed >= max_duration:
                duration_cap_hit = True
                context.logger.warning(
                    "VHost duration cap reached (%ss); stopping stage", max_duration
                )
                break
            if max_probes and tested_probes >= max_probes:
                probe_cap_hit = True
                context.logger.warning(
                    "VHost probe cap reached (%d); stopping stage", max_probes
                )
                break
            checked_hosts += 1
            root = self._root_domain(host)
            candidates = self._build_candidates(words, root, host)
            if not candidates:
                context.logger.debug("No vhost candidates generated for %s", host)
                continue
            if max_probes:
                remaining_hosts = max(1, len(selected_hosts) - host_index + 1)
                remaining_probes = max(0, max_probes - tested_probes)
                host_budget = max(1, remaining_probes // remaining_hosts)
                candidates = candidates[:host_budget]

            context.logger.info(
                "VHost host %d/%d: %s (candidates=%d)",
                host_index,
                len(selected_hosts),
                host,
                len(candidates),
            )

            baseline = self._fetch_sig(
                context,
                requests,
                base_url,
                timeout,
                {"User-Agent": "recon-cli vhost"},
                max_response_bytes=max_response_bytes,
            )
            if baseline is None:
                context.logger.debug("Baseline fetch failed for %s", host)
                continue
            baseline_sig = baseline
            wildcard_host = f"{uuid.uuid4().hex[:12]}.{root}"
            wildcard_sig = self._fetch_sig(
                context,
                requests,
                base_url,
                timeout,
                {
                    "User-Agent": "recon-cli vhost",
                    "Host": wildcard_host,
                    "X-Forwarded-Host": wildcard_host,
                },
                max_response_bytes=max_response_bytes,
            )

            host_tested = 0
            host_discovered = 0
            for candidate in candidates:
                elapsed = time.monotonic() - stage_started
                if max_duration and elapsed >= max_duration:
                    duration_cap_hit = True
                    break
                if max_probes and tested_probes >= max_probes:
                    probe_cap_hit = True
                    break
                tested_probes += 1
                host_tested += 1
                if tested_probes % progress_every == 0:
                    context.logger.info(
                        "VHost progress: probes=%d discovered=%d elapsed=%.1fs current_host=%s",
                        tested_probes,
                        discovered,
                        elapsed,
                        host,
                    )
                headers = {
                    "User-Agent": "recon-cli vhost",
                    "Host": candidate,
                    "X-Forwarded-Host": candidate,
                }
                if limiter and not limiter.wait_for_slot(base_url, timeout=timeout):
                    continue
                response = self._fetch_sig(
                    context,
                    requests,
                    base_url,
                    timeout,
                    headers,
                    max_response_bytes=max_response_bytes,
                )
                if response is None:
                    if limiter:
                        limiter.on_error(base_url)
                    continue
                if limiter:
                    limiter.on_response(base_url, response.status)
                sig = response
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
                    source="vhost-discovery",
                    tags=["vhost"],
                    evidence={
                        "base_url": base_url,
                        "baseline_status": baseline_sig.status,
                        "candidate_status": sig.status,
                    },
                )

                hostname_payload = {
                    "type": "hostname",
                    "source": "vhost",
                    "hostname": candidate,
                    "score": max(35, score),
                    "tags": ["vhost"],
                    "evidence_id": signal_id or None,
                }
                context.results.append(hostname_payload)

                if candidate_url:
                    url_payload = {
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
                    context.results.append(url_payload)
                discovered += 1
                host_discovered += 1

            context.logger.info(
                "VHost host done: %s tested=%d found=%d",
                host,
                host_tested,
                host_discovered,
            )
            if probe_cap_hit:
                context.logger.warning(
                    "VHost probe cap reached (%d); stopping stage", max_probes
                )
                break
            if duration_cap_hit:
                context.logger.warning(
                    "VHost duration cap reached (%ss); stopping stage", max_duration
                )
                break

        stats = context.record.metadata.stats.setdefault("vhost", {})
        stats.update(
            {
                "checked_hosts": checked_hosts,
                "tested_candidates": tested_probes,
                "discovered": discovered,
                "wildcard_filtered": wildcard_filtered,
                "probe_cap": max_probes,
                "probe_cap_hit": probe_cap_hit,
                "duration_cap_seconds": max_duration,
                "duration_cap_hit": duration_cap_hit,
                "response_bytes_cap": max_response_bytes,
            }
        )
        context.manager.update_metadata(context.record)

    def _select_base_hosts(
        self, context: PipelineContext
    ) -> List[Tuple[str, str, int]]:
        """Pick highest-scoring URL per host to use as vhost baseline."""
        best: Dict[str, Tuple[str, int]] = {}
        for entry in context.get_results():
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            host = entry.get("hostname") or (url and urlparse(url).hostname)
            if not host or not url:
                continue
            status = int(entry.get("status_code") or 0)
            if status not in {200, 301, 302, 401, 403}:
                continue
            score = int(entry.get("score", 0))
            current = best.get(host)
            if current is None:
                best[host] = (url, score)
                continue
            current_url, current_score = current
            if score > current_score:
                best[host] = (url, score)
            elif (
                score == current_score
                and url.startswith("https://")
                and not current_url.startswith("https://")
            ):
                best[host] = (url, score)
        return [(host, data[0], data[1]) for host, data in best.items()]

    def _load_wordlist(self, runtime) -> List[str]:
        raw_path = getattr(runtime, "vhost_wordlist", None)
        candidates: List[Path] = []
        if raw_path:
            candidate = Path(raw_path).expanduser()
            if candidate.exists():
                candidates.append(candidate)
        base = runtime.seclists_root
        candidates.append(base / "Discovery" / "Web-Content" / "vhost.txt")
        candidates.append(
            base / "Discovery" / "DNS" / "subdomains-top1million-20000.txt"
        )
        for candidate in candidates:
            if candidate.exists():
                return self._read_wordlist(candidate)
        return []

    @staticmethod
    def _read_wordlist(path: Path) -> List[str]:
        words: List[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            words.append(line)
        return words

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    @staticmethod
    def _build_candidates(words: List[str], root: str, current_host: str) -> List[str]:
        results: List[str] = []
        seen: set[str] = set()
        for word in words:
            if "{root}" in word:
                candidate = word.replace("{root}", root)
            elif "." in word:
                candidate = word
            else:
                candidate = f"{word}.{root}"
            candidate = candidate.strip().lower()
            if not candidate or candidate == current_host:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            results.append(candidate)
        return results

    def _fetch_sig(
        self,
        context: PipelineContext,
        requests_mod,
        url: str,
        timeout: int,
        headers: Dict[str, str],
        *,
        max_response_bytes: int,
    ) -> Optional[ResponseSig]:
        session = context.auth_session(url)
        resp = None
        try:
            if session:
                resp = session.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers=headers,
                    stream=True,
                )
            else:
                resp = requests_mod.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers=headers,
                    stream=True,
                )
            body = b""
            for chunk in resp.iter_content(chunk_size=4096):
                if not chunk:
                    continue
                remaining = max_response_bytes - len(body)
                if remaining <= 0:
                    break
                if len(chunk) > remaining:
                    body += chunk[:remaining]
                    break
                body += chunk
            encoding = resp.encoding or "utf-8"
            try:
                text = body.decode(encoding, errors="ignore")
            except LookupError:
                text = body.decode("utf-8", errors="ignore")
            title_match = self.TITLE_RE.search(text)
            title = title_match.group(1).strip() if title_match else ""
            content_length = 0
            raw_length = resp.headers.get("Content-Length")
            if raw_length and raw_length.isdigit():
                content_length = int(raw_length)
            if content_length <= 0:
                content_length = len(body)
            return ResponseSig(
                status=int(resp.status_code or 0),
                length=content_length,
                title=title,
                server=resp.headers.get("Server"),
            )
        except requests.exceptions.RequestException:
            return None
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass

    @staticmethod
    def _is_interesting(base: ResponseSig, cand: ResponseSig) -> bool:
        if base.status != cand.status:
            if not ({base.status, cand.status} <= {301, 302}):
                return True
        if base.title and cand.title and base.title != cand.title:
            return True
        if base.length == 0:
            return cand.length > 0
        diff = abs(base.length - cand.length)
        if diff > max(200, int(base.length * 0.3)):
            return True
        return False

    @staticmethod
    def _candidate_url(base_url: str, candidate: str) -> str:
        parsed = urlparse(base_url)
        scheme = parsed.scheme or "https"
        return f"{scheme}://{candidate}/"
