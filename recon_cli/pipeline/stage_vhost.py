from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


@dataclass
class ResponseSig:
    status: int
    length: int
    title: str


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

        checked_hosts = 0
        tested_candidates = 0
        discovered = 0

        for host, base_url, score in base_hosts[:max_hosts]:
            checked_hosts += 1
            root = self._root_domain(host)
            candidates = self._build_candidates(words, root, host)
            if not candidates:
                continue

            baseline = self._fetch_sig(context, requests, base_url, timeout, {"User-Agent": "recon-cli vhost"})
            if baseline is None:
                continue
            baseline_sig, _ = baseline

            for candidate in candidates:
                tested_candidates += 1
                headers = {"User-Agent": "recon-cli vhost", "Host": candidate, "X-Forwarded-Host": candidate}
                if limiter and not limiter.wait_for_slot(base_url, timeout=timeout):
                    continue
                response = self._fetch_sig(context, requests, base_url, timeout, headers)
                if response is None:
                    if limiter:
                        limiter.on_error(base_url)
                    continue
                if limiter:
                    limiter.on_response(base_url, response[1].status_code)
                sig, resp = response
                if not self._is_interesting(baseline_sig, sig):
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
                        "server": resp.headers.get("Server"),
                        "tags": ["vhost"],
                        "score": max(45, score),
                        "evidence_id": signal_id or None,
                    }
                    context.results.append(url_payload)
                discovered += 1

        stats = context.record.metadata.stats.setdefault("vhost", {})
        stats.update(
            {
                "checked_hosts": checked_hosts,
                "tested_candidates": tested_candidates,
                "discovered": discovered,
            }
        )
        context.manager.update_metadata(context.record)

    def _select_base_hosts(self, context: PipelineContext) -> List[Tuple[str, str, int]]:
        """Pick highest-scoring URL per host to use as vhost baseline."""
        best: Dict[str, Tuple[str, int]] = {}
        for entry in read_jsonl(context.record.paths.results_jsonl):
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
            elif score == current_score and url.startswith("https://") and not current_url.startswith("https://"):
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
        candidates.append(base / "Discovery" / "DNS" / "subdomains-top1million-20000.txt")
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
    ) -> Optional[Tuple[ResponseSig, object]]:
        session = context.auth_session(url)
        try:
            if session:
                resp = session.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers=headers,
                )
            else:
                resp = requests_mod.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers=headers,
                )
        except Exception:
            return None
        text = resp.text or ""
        title_match = self.TITLE_RE.search(text)
        title = title_match.group(1).strip() if title_match else ""
        sig = ResponseSig(status=int(resp.status_code or 0), length=len(text), title=title)
        return sig, resp

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
