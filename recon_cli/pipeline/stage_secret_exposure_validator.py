from __future__ import annotations

import hashlib
import json
import requests
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.secrets.detector import SECRETS_PATTERNS, shannon_entropy
from recon_cli.utils import time as time_utils


class SecretExposureValidatorStage(Stage):
    name = "secret_exposure_validator"

    HIGH_CONF_PATTERNS = {"aws_access_key", "aws_secret_key", "rsa_private"}
    PLACEHOLDER_HINTS = (
        "example",
        "dummy",
        "sample",
        "test",
        "changeme",
        "placeholder",
        "xxxxx",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(
            getattr(context.runtime_config, "enable_secret_exposure_validator", True)
        )

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning(
                "secret exposure validator requires requests; skipping"
            )
            return

        runtime = context.runtime_config
        max_findings = max(
            1, int(getattr(runtime, "secret_exposure_validator_max_findings", 40))
        )
        min_score = int(getattr(runtime, "secret_exposure_validator_min_score", 40))
        timeout = max(1, int(getattr(runtime, "secret_exposure_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        limiter = context.get_rate_limiter(
            "secret_exposure_validator",
            rps=float(getattr(runtime, "secret_exposure_validator_rps", 0)),
            per_host=float(
                getattr(runtime, "secret_exposure_validator_per_host_rps", 0)
            ),
        )
        pattern_map = {name: regex for name, regex in SECRETS_PATTERNS}

        candidates = self._collect_candidates(
            context,
            min_score=min_score,
            max_findings=max_findings,
        )
        stats = context.record.metadata.stats.setdefault(
            "secret_exposure_validator", {}
        )
        if not candidates:
            stats.update(
                {
                    "attempted": 0,
                    "confirmed": 0,
                    "stale": 0,
                    "filtered_sanity": 0,
                    "failed": 0,
                    "skipped": 0,
                }
            )
            context.manager.update_metadata(context.record)
            context.logger.info("No secret exposure validator candidates")
            return

        attempted = 0
        confirmed = 0
        stale = 0
        filtered_sanity = 0
        failed = 0
        skipped = 0
        artifacts: List[Dict[str, object]] = []
        seen_urls: Set[str] = set()
        content_cache: Dict[str, Optional[str]] = {}

        for candidate in candidates:
            url = str(candidate.get("url") or "")
            if not url:
                continue
            if url not in content_cache:
                content, state = self._fetch_url_text(
                    context,
                    requests,
                    url,
                    timeout=timeout,
                    verify_tls=verify_tls,
                    limiter=limiter,
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
            start = candidate.get("start")
            end = candidate.get("end")
            value = self._recover_value(
                text,
                expected_hash=expected_hash,
                pattern=pattern,
                start=start if isinstance(start, int) else None,
                end=end if isinstance(end, int) else None,
                pattern_map=pattern_map,  # type: ignore[arg-type]
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

            confidence_label = str(sanity["confidence"])
            severity = "critical" if confidence_label == "verified" else "high"
            score_floor = 94 if confidence_label == "verified" else 88
            signal_id = context.emit_signal(
                "secret_exposure_confirmed",
                "url",
                url,
                confidence=1.0 if confidence_label == "verified" else 0.85,
                source="secret-validator",
                tags=["secret", "confirmed", "live"],
                evidence={"pattern": pattern, "value_hash": expected_hash},
            )
            finding = {
                "type": "finding",
                "finding_type": "exposed_secret",
                "source": "secret-validator",
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
                "score": max(score_floor, int(candidate.get("score", 0) or 0)),  # type: ignore[call-overload]
                "priority": "critical" if confidence_label == "verified" else "high",
                "severity": severity,
                "confidence_label": confidence_label,
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
                        "confidence": confidence_label,
                    }
                )
                seen_urls.add(url)

        artifacts_dir = context.record.paths.ensure_subdir("secret_exposure_validator")
        artifact_path = artifacts_dir / "secret_exposure_validator.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "timestamp": time_utils.iso_now(),
                    "attempted": attempted,
                    "confirmed": confirmed,
                    "stale": stale,
                    "filtered_sanity": filtered_sanity,
                    "validated_urls": sorted(seen_urls),
                    "entries": artifacts,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        stats.update(
            {
                "attempted": attempted,
                "confirmed": confirmed,
                "stale": stale,
                "filtered_sanity": filtered_sanity,
                "failed": failed,
                "skipped": skipped,
                "candidates": len(candidates),
                "artifact": str(artifact_path.relative_to(context.record.paths.root)),
            }
        )
        context.manager.update_metadata(context.record)

    def _collect_candidates(
        self,
        context: PipelineContext,
        *,
        min_score: int,
        max_findings: int,
    ) -> List[Dict[str, object]]:
        grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        seen: Set[Tuple[str, str, str]] = set()
        for entry in context.iter_results():
            if not isinstance(entry, dict):
                continue
            if str(entry.get("finding_type") or "").lower() != "exposed_secret":
                continue
            source = str(entry.get("source") or "").lower()
            if source not in {"secrets-static", "secret-validator"}:
                continue
            url = str(entry.get("url") or "").strip()
            if not url:
                continue
            details = entry.get("details")
            if not isinstance(details, dict):
                continue
            pattern = str(details.get("pattern") or "").strip()
            value_hash = str(details.get("value_hash") or "").strip()
            location = details.get("location")
            score = int(entry.get("score", 0) or 0)
            if score < min_score:
                continue
            if not pattern or not value_hash:
                continue
            key = (url, pattern, value_hash)
            if key in seen:
                continue
            try:
                host = str(urlparse(url).hostname or "")
            except ValueError:
                continue
            start = location.get("start") if isinstance(location, dict) else None
            end = location.get("end") if isinstance(location, dict) else None
            priority = score + (20 if pattern in self.HIGH_CONF_PATTERNS else 0)
            grouped[host].append(
                {
                    "url": url,
                    "pattern": pattern,
                    "value_hash": value_hash,
                    "start": int(start) if isinstance(start, int) else None,
                    "end": int(end) if isinstance(end, int) else None,
                    "score": score,
                    "priority": priority,
                }
            )
            seen.add(key)
        selected: List[Dict[str, object]] = []
        for _host, items in grouped.items():
            items.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)  # type: ignore[call-overload]
            selected.extend(items[:8])
        selected.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)  # type: ignore[call-overload]
        return selected[:max_findings]

    def _fetch_url_text(
        self,
        context: PipelineContext,
        requests_mod,
        url: str,
        *,
        timeout: int,
        verify_tls: bool,
        limiter,
    ) -> Tuple[Optional[str], str]:
        if not context.url_allowed(url):
            return None, "skipped"
        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return None, "skipped"
        headers = context.auth_headers({"User-Agent": "recon-cli secret-validator"})
        session = context.auth_session(url)
        try:
            if session:
                resp = session.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=verify_tls,
                )
            else:
                resp = requests_mod.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=verify_tls,
                )
        except requests.exceptions.RequestException:
            if limiter:
                limiter.on_error(url)
            return None, "failed"
        status = int(getattr(resp, "status_code", 0) or 0)
        if limiter:
            limiter.on_response(url, status)
        text = str(getattr(resp, "text", "") or "")
        resp.close()
        if status != 200:
            return None, "failed"
        return text, "ok"

    def _recover_value(
        self,
        text: str,
        *,
        expected_hash: str,
        pattern: str,
        start: Optional[int],
        end: Optional[int],
        pattern_map: Dict[str, object],
    ) -> Optional[str]:
        if start is not None and end is not None and 0 <= start < end <= len(text):
            candidate = text[start:end]
            if self._hash_value(candidate) == expected_hash:
                return candidate
        regex = pattern_map.get(pattern)
        if regex is None:
            return None
        try:
            matches = regex.finditer(text)  # type: ignore[attr-defined]
        except Exception:
            return None
        for match in matches:
            value = match.group(0)
            if self._hash_value(value) == expected_hash:
                return value
        return None

    def _sanity_check(self, pattern: str, value: str) -> Dict[str, object]:
        lowered = value.lower()
        if any(hint in lowered for hint in self.PLACEHOLDER_HINTS):
            return {"valid": False, "reason": "placeholder_token", "confidence": "high"}
        entropy = shannon_entropy(value)
        if pattern == "aws_access_key":
            if value.startswith("AKIA") and len(value) == 20:
                return {
                    "valid": True,
                    "reason": "aws_access_key_format",
                    "confidence": "verified",
                }
            return {
                "valid": False,
                "reason": "invalid_aws_access_key_format",
                "confidence": "high",
            }
        if pattern == "aws_secret_key":
            if len(value) >= 40 and entropy >= 3.5:
                return {
                    "valid": True,
                    "reason": "aws_secret_key_entropy",
                    "confidence": "verified",
                }
            return {
                "valid": False,
                "reason": "invalid_aws_secret_key",
                "confidence": "high",
            }
        if pattern == "google_api_key":
            if value.startswith("AIza") and len(value) >= 39:
                return {
                    "valid": True,
                    "reason": "google_api_key_format",
                    "confidence": "high",
                }
            return {
                "valid": False,
                "reason": "invalid_google_api_key",
                "confidence": "high",
            }
        if pattern == "slack_token":
            if value.startswith("xox") and len(value) >= 20:
                return {
                    "valid": True,
                    "reason": "slack_token_format",
                    "confidence": "high",
                }
            return {
                "valid": False,
                "reason": "invalid_slack_token",
                "confidence": "high",
            }
        if pattern == "jwt":
            if value.count(".") == 2 and len(value) >= 40:
                return {"valid": True, "reason": "jwt_structure", "confidence": "high"}
            return {
                "valid": False,
                "reason": "invalid_jwt_structure",
                "confidence": "high",
            }
        if pattern == "rsa_private":
            if "BEGIN RSA PRIVATE KEY" in value:
                return {
                    "valid": True,
                    "reason": "rsa_private_key_header",
                    "confidence": "verified",
                }
            return {
                "valid": False,
                "reason": "invalid_rsa_private_key",
                "confidence": "high",
            }
        if len(value) >= 20 and entropy >= 4.0:
            return {
                "valid": True,
                "reason": "generic_secret_entropy",
                "confidence": "high",
            }
        return {"valid": False, "reason": "low_entropy_or_length", "confidence": "high"}

    @staticmethod
    def _hash_value(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
