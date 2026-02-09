from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import time as time_utils
from recon_cli.utils.jsonl import iter_jsonl


class VerifyFindingsStage(Stage):
    name = "verify_findings"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_verification", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("verification requires requests; skipping")
            return

        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            context.logger.info("No results to verify")
            return

        runtime = context.runtime_config
        min_score = int(getattr(runtime, "verify_min_score", 80))
        top_per_host = int(getattr(runtime, "verify_top_per_host", 10))
        max_total = int(getattr(runtime, "verify_max_total", 200))
        timeout = int(getattr(runtime, "verify_timeout", 12))
        limiter = context.get_rate_limiter(
            "verify_findings",
            rps=float(getattr(runtime, "verify_rps", 0)),
            per_host=float(getattr(runtime, "verify_per_host_rps", 0)),
        )

        candidates_by_host: Dict[str, List[Tuple[int, str, Dict[str, object]]]] = defaultdict(list)
        for entry in iter_jsonl(results_path):
            if not isinstance(entry, dict):
                continue
            if not self._is_finding(entry):
                continue
            score = int(entry.get("score", 0))
            if score < min_score:
                continue
            url = self._extract_url(entry)
            if not url or not context.url_allowed(url):
                continue
            host = self._extract_host(url, entry)
            if not host:
                continue
            candidates_by_host[host].append((score, url, entry))

        selected: List[Tuple[int, str, Dict[str, object]]] = []
        for host, items in candidates_by_host.items():
            items.sort(key=lambda item: item[0], reverse=True)
            limit = len(items) if top_per_host <= 0 else min(top_per_host, len(items))
            selected.extend(items[:limit])

        selected.sort(key=lambda item: item[0], reverse=True)
        if max_total > 0:
            selected = selected[:max_total]

        if not selected:
            context.logger.info("No findings matched verification criteria")
            return

        attempted = len(selected)
        verified = 0
        failed = 0
        skipped = 0
        status_counts: Counter[str] = Counter()
        records: List[Dict[str, object]] = []
        headers = context.auth_headers({"User-Agent": "recon-cli verify"})

        for score, url, entry in selected:
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                skipped += 1
                continue
            session = context.auth_session(url)
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
                    resp = requests.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        verify=context.runtime_config.verify_tls,
                        headers=headers,
                        stream=True,
                    )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                failed += 1
                continue

            if limiter:
                limiter.on_response(url, resp.status_code)
            verified += 1
            status_counts[str(resp.status_code)] += 1
            final_url = str(getattr(resp, "url", "")) or url
            content_length = resp.headers.get("Content-Length")
            resp.close()
            signal_type = "verified_blocked" if resp.status_code in {401, 403, 429, 503} else "verified_live"
            signal_id = context.emit_signal(
                signal_type,
                "url",
                final_url,
                confidence=0.6,
                source="verification",
                evidence={"status_code": resp.status_code},
            )

            record = {
                "url": url,
                "final_url": final_url,
                "hostname": self._extract_host(final_url, entry),
                "status_code": resp.status_code,
                "content_length": content_length,
                "server": resp.headers.get("Server"),
                "score": score,
                "finding_type": entry.get("finding_type") or entry.get("type"),
                "source": entry.get("source"),
                "description": entry.get("description") or entry.get("title"),
                "timestamp": time_utils.iso_now(),
                "signal_id": signal_id or None,
                "signal_type": signal_type,
            }
            records.append(record)

        artifact_path = context.record.paths.artifact("verification.json")
        artifact_path.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("verification", {})
        stats.update(
            {
                "attempted": attempted,
                "verified": verified,
                "failed": failed,
                "skipped": skipped,
                "status_codes": dict(status_counts),
                "artifact": str(artifact_path),
            }
        )
        context.manager.update_metadata(context.record)

    @staticmethod
    def _is_finding(entry: Dict[str, object]) -> bool:
        if entry.get("finding_type"):
            return True
        entry_type = entry.get("type")
        if isinstance(entry_type, str) and entry_type in {"finding", "vulnerability", "vuln", "idor_suspect"}:
            return True
        return False

    @staticmethod
    def _extract_url(entry: Dict[str, object]) -> str:
        url = entry.get("url")
        if isinstance(url, str) and url:
            return url
        details = entry.get("details")
        if isinstance(details, dict):
            for key in ("url", "matched-at", "matched_at"):
                value = details.get(key)
                if isinstance(value, str) and value:
                    return value
        return ""

    @staticmethod
    def _extract_host(url: str, entry: Dict[str, object]) -> str:
        if url:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    return parsed.hostname
            except ValueError:
                pass
        host = entry.get("hostname")
        if isinstance(host, str):
            return host
        return ""
