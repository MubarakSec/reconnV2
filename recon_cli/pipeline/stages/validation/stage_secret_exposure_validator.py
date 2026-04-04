from __future__ import annotations

import hashlib
import json
import asyncio
import logging
import requests  # type: ignore[import-untyped]
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.secrets.detector import SECRETS_PATTERNS, shannon_entropy
from recon_cli.utils import time as time_utils

logger = logging.getLogger(__name__)


class SecretExposureValidatorStage(Stage):
    name = "secret_exposure_validator"

    HIGH_CONF_PATTERNS = {"aws_access_key", "aws_secret_key", "rsa_private"}
    PLACEHOLDER_HINTS = ("example", "dummy", "sample", "test", "changeme", "placeholder", "xxxxx")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_secret_exposure_validator", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_findings = max(1, int(getattr(runtime, "secret_exposure_validator_max_findings", 40)))
        min_score = int(getattr(runtime, "secret_exposure_validator_min_score", 40))
        timeout = max(1, int(getattr(runtime, "secret_exposure_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        
        pattern_map = {name: regex for name, regex in SECRETS_PATTERNS}
        candidates = self._collect_candidates(context, min_score=min_score, max_findings=max_findings)
        
        stats = context.record.metadata.stats.setdefault("secret_exposure_validator", {})
        if not candidates:
            stats.update({"attempted": 0, "confirmed": 0, "stale": 0, "filtered_sanity": 0, "failed": 0, "skipped": 0})
            context.manager.update_metadata(context.record)
            return

        attempted, confirmed, stale, filtered_sanity, failed, skipped = 0, 0, 0, 0, 0, 0
        artifacts, seen_urls, content_cache = [], set(), {}

        for candidate in candidates:
            url = str(candidate.get("url") or "")
            if not url:
                continue

            if url not in content_cache:
                content, state = await self._fetch_url_text(
                    context, url, timeout=timeout, verify_tls=verify_tls
                )
                if state == "failed":
                    failed += 1
                elif state == "skipped":
                    skipped += 1
                else:
                    attempted += 1
                content_cache[url] = content

            text = content_cache.get(url)
            if not text:
                continue

            pattern = str(candidate.get("pattern") or "")
            expected_hash = str(candidate.get("value_hash") or "")
            start, end = candidate.get("start"), candidate.get("end")
            value = self._recover_value(
                text,
                expected_hash=expected_hash,
                pattern=pattern,
                start=start,
                end=end,
                pattern_map=pattern_map,
            )

            if not value:
                stale += 1
                continue

            sanity = self._sanity_check(pattern, value)
            if not sanity["valid"]:
                filtered_sanity += 1
                artifacts.append(
                    {
                        "timestamp": time_utils.iso_now(),
                        "url": url,
                        "pattern": pattern,
                        "value_hash": expected_hash,
                        "status": "filtered",
                        "reason": sanity["reason"],
                    }
                )
                continue

            conf_label = str(sanity["confidence"])
            signal_id = context.emit_signal(
                "secret_exposure_confirmed",
                "url",
                url,
                confidence=1.0 if conf_label == "verified" else 0.85,
                source=self.name,
                tags=["secret", "confirmed", "live"],
                evidence={"pattern": pattern, "value_hash": expected_hash},
            )

            finding = {
                "type": "finding",
                "finding_type": "exposed_secret",
                "source": "secret-validator",
                "parameter": f"{pattern}:{expected_hash}",
                "url": url,
                "hostname": urlparse(url).hostname,
                "description": f"Secret exposure reconfirmed live ({pattern})",
                "details": {
                    "pattern": pattern,
                    "value_hash": expected_hash,
                    "sanity_reason": sanity["reason"],
                    "location": {"start": start, "end": end},
                },
                "proof": f"live-hash:{expected_hash}",
                "tags": ["secret", "confirmed", "live", f"pattern:{pattern}"],
                "score": max(94 if conf_label == "verified" else 88, int(candidate.get("score", 0))),
                "priority": "critical" if conf_label == "verified" else "high",
                "severity": "critical" if conf_label == "verified" else "high",
                "confidence_label": conf_label,
                "evidence_id": signal_id or None,
            }
            if context.results.append(finding):
                confirmed += 1
                artifacts.append(
                    {
                        "timestamp": time_utils.iso_now(),
                        "url": url,
                        "pattern": pattern,
                        "value_hash": expected_hash,
                        "status": "confirmed",
                        "confidence": conf_label,
                    }
                )
                seen_urls.add(url)

        artifact_path = context.record.paths.artifact("secret_exposure_validator.json")
        artifact_path.write_text(json.dumps({"timestamp": time_utils.iso_now(), "attempted": attempted, "confirmed": confirmed, "stale": stale, "filtered_sanity": filtered_sanity, "validated_urls": sorted(seen_urls), "entries": artifacts}, indent=2, sort_keys=True), encoding="utf-8")
        
        stats.update({"attempted": attempted, "confirmed": confirmed, "stale": stale, "filtered_sanity": filtered_sanity, "failed": failed, "skipped": skipped, "candidates": len(candidates)})
        context.manager.update_metadata(context.record)

    def _collect_candidates(self, context: PipelineContext, *, min_score: int, max_findings: int) -> List[Dict[str, Any]]:
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        seen: Set[Tuple[str, str, str]] = set()
        for entry in context.iter_results():
            if str(entry.get("finding_type", "")).lower() != "exposed_secret": continue
            if str(entry.get("source", "")).lower() not in {"secrets-static", "secret-validator"}: continue
            url = str(entry.get("url", "")).strip()
            details = entry.get("details", {})
            pattern, v_hash = str(details.get("pattern", "")), str(details.get("value_hash", ""))
            score = int(entry.get("score", 0))
            if not url or not pattern or not v_hash or score < min_score: continue
            
            key = (url, pattern, v_hash)
            if key in seen: continue
            seen.add(key)
            
            host = str(urlparse(url).hostname or "")
            loc = details.get("location", {})
            priority = score + (20 if pattern in self.HIGH_CONF_PATTERNS else 0)
            grouped[host].append({"url": url, "pattern": pattern, "value_hash": v_hash, "start": loc.get("start"), "end": loc.get("end"), "score": score, "priority": priority})
        
        selected = []
        for items in grouped.values():
            items.sort(key=lambda x: x["priority"], reverse=True)
            selected.extend(items[:8])
        selected.sort(key=lambda x: x["priority"], reverse=True)
        return selected[:max_findings]

    async def _fetch_url_text(
        self,
        context: PipelineContext,
        url: str,
        *,
        timeout: int,
        verify_tls: bool,
    ) -> Tuple[Optional[str], str]:
        if not context.url_allowed(url):
            return None, "skipped"
        headers = context.auth_headers({"User-Agent": "recon-cli secret-validator"})
        try:
            resp = await asyncio.to_thread(
                requests.get,
                url,
                headers=headers,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=True,
            )
        except Exception:
            return None, "failed"

        try:
            status_code = int(getattr(resp, "status_code", 0) or 0)
            if status_code != 200:
                return None, "failed"
            text = getattr(resp, "text", None)
            if text is None:
                raw = getattr(resp, "content", b"")
                if isinstance(raw, (bytes, bytearray)):
                    text = raw.decode("utf-8", errors="ignore")
                else:
                    text = str(raw)
            return text, "ok"
        finally:
            close = getattr(resp, "close", None)
            if callable(close):
                close()

    def _recover_value(self, text: str, *, expected_hash: str, pattern: str, start: Optional[int], end: Optional[int], pattern_map: Dict[str, Any]) -> Optional[str]:
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text):
            cand = text[start:end]
            if self._hash_value(cand) == expected_hash: return cand
        regex = pattern_map.get(pattern)
        if not regex: return None
        try:
            for match in regex.finditer(text):
                val = match.group(0)
                if self._hash_value(val) == expected_hash: return val
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="secret_exposure_validator", error_type=type(e).__name__).inc()
                except: pass
        return None

    def _sanity_check(self, pattern: str, value: str) -> Dict[str, Any]:
        lowered = value.lower()
        if any(h in lowered for h in self.PLACEHOLDER_HINTS): return {"valid": False, "reason": "placeholder_token", "confidence": "high"}
        ent = shannon_entropy(value)
        if pattern == "aws_access_key":
            return {"valid": True, "reason": "aws_access_key_format", "confidence": "verified"} if (value.startswith("AKIA") and len(value) == 20) else {"valid": False, "reason": "invalid_aws_access_key_format", "confidence": "high"}
        if pattern == "aws_secret_key":
            return {"valid": True, "reason": "aws_secret_key_entropy", "confidence": "verified"} if (len(value) >= 40 and ent >= 3.5) else {"valid": False, "reason": "invalid_aws_secret_key", "confidence": "high"}
        if pattern == "rsa_private":
            return {"valid": True, "reason": "rsa_private_key_header", "confidence": "verified"} if "BEGIN RSA PRIVATE KEY" in value else {"valid": False, "reason": "invalid_rsa_private_key", "confidence": "high"}
        if len(value) >= 20 and ent >= 4.0: return {"valid": True, "reason": "generic_secret_entropy", "confidence": "high"}
        return {"valid": False, "reason": "low_entropy_or_length", "confidence": "high"}

    @staticmethod
    def _hash_value(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
