from __future__ import annotations

import json
import asyncio
import uuid
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils import time as time_utils
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class VerifyFindingsStage(Stage):
    name = "verify_findings"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_verification", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        min_score = int(getattr(runtime, "verify_min_score", 80))
        top_per_host = int(getattr(runtime, "verify_top_per_host", 10))
        max_total = int(getattr(runtime, "verify_max_total", 200))
        timeout = int(getattr(runtime, "verify_timeout", 12))
        verify_tls = bool(getattr(runtime, "verify_tls", True))

        candidates_by_host: Dict[str, List[Tuple[int, str, Dict[str, Any]]]] = defaultdict(list)
        trash_count = 0
        for entry in context.iter_results():
            if not self._is_finding(entry): continue
            if self._is_trash_finding(entry):
                trash_count += 1; continue
            
            score = int(entry.get("score", 0))
            if score < min_score: continue
            
            url = self._extract_url(entry)
            if not url or not context.url_allowed(url): continue
            
            host = self._extract_host(url, entry)
            if host: candidates_by_host[host].append((score, url, entry))

        selected: List[Tuple[int, str, Dict[str, Any]]] = []
        for host, items in candidates_by_host.items():
            items.sort(key=lambda x: x[0], reverse=True)
            limit = len(items) if top_per_host <= 0 else min(top_per_host, len(items))
            selected.extend(items[:limit])

        selected.sort(key=lambda x: x[0], reverse=True)
        if max_total > 0: selected = selected[:max_total]

        if not selected:
            context.logger.info("No findings matched verification criteria")
            return

        attempted = len(selected)
        verified, failed, skipped = 0, 0, 0
        status_counts: Counter[str] = Counter()
        records: List[Dict[str, Any]] = []

        config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "verify_rps", 20.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            context.logger.info("Verifying %d findings concurrently", len(selected))
            
            tasks = [client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli verify"}), follow_redirects=True) for _, url, _ in selected]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for (score, url, entry), resp in zip(selected, responses):
                if isinstance(resp, Exception):
                    failed += 1; continue
                
                verified += 1
                status_counts[str(resp.status)] += 1
                final_url = url
                
                # ELITE: Deep Verification for High-Risk Findings
                finding_type = str(entry.get("finding_type") or entry.get("type")).lower()
                is_real = True
                verification_note = ""
                
                if resp.status == 200:
                    # Check for Soft-404 or generic landing pages
                    if len(resp.body) < 500 and any(h in resp.body.lower() for h in ["not found", "error", "invalid"]):
                        is_real = False
                        verification_note = "Soft-404 detected"
                    
                    # Backup/Archive Specific Deep Check
                    if any(ext in url.lower() for ext in [".zip", ".tar", ".gz", ".bak", ".sql", ".old"]):
                        ctype = resp.headers.get("Content-Type", "").lower()
                        # If it's a backup but returns text/html, it's likely a fake 200 (landing page)
                        if "text/html" in ctype and not any(m in resp.body for m in ["PK\x03\x04", "gzip", "SQL"]):
                            is_real = False
                            verification_note = "Backup URL returned HTML instead of binary data"
                        
                        # Check Magic Numbers in body for binary files
                        if ".zip" in url.lower() and not resp.body.startswith("PK"):
                            is_real = False
                            verification_note = "ZIP magic number missing"

                if not is_real:
                    signal_type = "verified_false_positive"
                    entry["score"] = 0 # Downgrade score
                    entry["tags"] = entry.get("tags", []) + ["false-positive", "soft-404"]
                else:
                    signal_type = "verified_blocked" if resp.status in {401, 403, 429, 503} else "verified_live"
                
                if is_real and resp.status == 200 and any(ext in url.lower() for ext in [".zip", ".bak", ".sql", ".env", ".php"]):
                    # Sample the first 1KB for evidence
                    sample = resp.body[:1024]
                    sample_file = context.record.paths.artifact(f"sample_{uuid.uuid4().hex[:8]}.txt")
                    sample_file.write_text(sample, encoding="utf-8", errors="ignore")
                    records[-1]["evidence_sample"] = str(sample_file.name)

                signal_id = context.emit_signal(signal_type, "url", final_url, confidence=0.9 if is_real else 0.1, source=self.name, evidence={"status_code": resp.status, "note": verification_note})

                records.append({
                    "url": url, "final_url": final_url,
                    "hostname": self._extract_host(final_url, entry),
                    "status_code": resp.status,
                    "content_length": len(resp.body),
                    "is_real": is_real,
                    "verification_note": verification_note,
                    "server": resp.headers.get("Server"),
                    "score": entry["score"],
                    "finding_type": finding_type,
                    "source": entry.get("source"),
                    "description": entry.get("description") or entry.get("title"),
                    "timestamp": time_utils.iso_now(),
                    "signal_id": signal_id or None, "signal_type": signal_type,
                })

        artifact_path = context.record.paths.artifact("verification.json")
        artifact_path.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("verification", {})
        stats.update({"attempted": attempted, "verified": verified, "failed": failed, "skipped": skipped, "trash_filtered": trash_count, "status_codes": dict(status_counts)})
        context.manager.update_metadata(context.record)

    @staticmethod
    def _is_trash_finding(entry: Dict[str, Any]) -> bool:
        etype = str(entry.get("type") or "").lower()
        if etype == "idor_suspect":
            details = entry.get("details")
            if isinstance(details, dict) and not details.get("reasons"): return True

        url = str(entry.get("url") or "").lower()
        static_noise = {"cloudfront.net", "s3.amazonaws.com", "storage.googleapis.com", "wp-content", "assets/"}
        if any(n in url for n in static_noise):
            if "confirmed" not in entry.get("tags", []): return True

        if int(entry.get("score", 0)) < 40: return True
        return False

    @staticmethod
    def _is_finding(entry: Dict[str, Any]) -> bool:
        return bool(entry.get("finding_type") or (isinstance(entry.get("type"), str) and entry["type"] in {"finding", "vulnerability", "vuln", "idor_suspect"}))

    @staticmethod
    def _extract_url(entry: Dict[str, Any]) -> str:
        u = entry.get("url")
        if isinstance(u, str) and u: return u
        details = entry.get("details")
        if isinstance(details, dict):
            for k in ("url", "matched-at", "matched_at"):
                if isinstance(details.get(k), str): return details[k]
        return ""

    @staticmethod
    def _extract_host(url: str, entry: Dict[str, Any]) -> str:
        if url:
            try:
                h = urlparse(url).hostname
                if h: return h
            except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="verify_findings", error_type=type(e).__name__).inc()
                except: pass
        return str(entry.get("hostname") or "")
