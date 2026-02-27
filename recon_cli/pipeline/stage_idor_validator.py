from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.utils import time as time_utils
from recon_cli.utils.jsonl import iter_jsonl


class IDORValidatorStage(Stage):
    name = "idor_validator"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_idor_validator", True))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("idor validator requires requests; skipping")
            return

        runtime = context.runtime_config
        max_candidates = max(1, int(getattr(runtime, "idor_validator_max_candidates", 40)))
        max_per_host = max(1, int(getattr(runtime, "idor_validator_max_per_host", 8)))
        min_score = int(getattr(runtime, "idor_validator_min_score", 60))
        timeout = max(1, int(getattr(runtime, "idor_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        retry_count = max(0, int(getattr(runtime, "retry_count", 1)))
        retry_backoff_base = float(getattr(runtime, "retry_backoff_base", 1.0))
        retry_backoff_factor = float(getattr(runtime, "retry_backoff_factor", 2.0))
        limiter = context.get_rate_limiter(
            "idor_validator",
            rps=float(getattr(runtime, "idor_validator_rps", 0)),
            per_host=float(getattr(runtime, "idor_validator_per_host_rps", 0)),
        )

        candidates = self._collect_candidates(
            context,
            min_score=min_score,
            max_candidates=max_candidates,
            max_per_host=max_per_host,
        )
        stats = context.record.metadata.stats.setdefault("idor_validator", {})
        if not candidates:
            stats.update({"attempted": 0, "confirmed": 0, "failed": 0, "skipped": 0})
            context.manager.update_metadata(context.record)
            context.logger.info("No IDOR validator candidates")
            return

        helper = IDORStage()
        session = requests.Session()
        attempted = 0
        confirmed = 0
        failed = 0
        skipped = 0
        artifacts: List[Dict[str, object]] = []
        seen: Set[Tuple[str, str]] = set()

        for candidate in candidates:
            variant_url = str(candidate.get("url") or "")
            auth_label = str(candidate.get("auth") or "anon")
            baseline_url = str(candidate.get("baseline_url") or "")
            key = (variant_url, auth_label)
            if not variant_url or not baseline_url or key in seen:
                continue
            seen.add(key)

            token = self._resolve_token(auth_label, runtime)
            if auth_label in {"token-a", "token-b"} and not token:
                skipped += 1
                continue

            baseline_profile, baseline_state = self._fetch_profile(
                context,
                session,
                helper,
                baseline_url,
                auth_label=auth_label,
                token=token,
                timeout=timeout,
                verify_tls=verify_tls,
                retries=retry_count,
                backoff_base=retry_backoff_base,
                backoff_factor=retry_backoff_factor,
                limiter=limiter,
            )
            attempted += 1
            if baseline_profile is None:
                if baseline_state == "failed":
                    failed += 1
                else:
                    skipped += 1
                continue

            variant_profile, variant_state = self._fetch_profile(
                context,
                session,
                helper,
                variant_url,
                auth_label=auth_label,
                token=token,
                timeout=timeout,
                verify_tls=verify_tls,
                retries=retry_count,
                backoff_base=retry_backoff_base,
                backoff_factor=retry_backoff_factor,
                limiter=limiter,
            )
            attempted += 1
            if variant_profile is None:
                if variant_state == "failed":
                    failed += 1
                else:
                    skipped += 1
                continue

            reasons = helper._semantic_reasons(baseline_profile, variant_profile)
            if not reasons:
                continue

            confidence_label = "verified" if any(
                reason in reasons for reason in {"subject_identifier_changed", "auth_bypass_status_change"}
            ) else "high"
            severity = "critical" if confidence_label == "verified" else "high"
            score_floor = 92 if confidence_label == "verified" else 86
            signal_id = context.emit_signal(
                "idor_confirmed",
                "url",
                variant_url,
                confidence=1.0 if confidence_label == "verified" else 0.8,
                source="idor-validator",
                tags=["idor", "confirmed"],
                evidence={
                    "reasons": reasons,
                    "baseline_status": baseline_profile["status"],
                    "variant_status": variant_profile["status"],
                },
            )
            finding = {
                "type": "finding",
                "finding_type": "idor",
                "source": "idor-validator",
                "url": variant_url,
                "hostname": urlparse(variant_url).hostname,
                "description": "IDOR confirmed by dedicated validator replay",
                "details": {
                    "reasons": reasons,
                    "auth": auth_label,
                    "baseline_url": baseline_url,
                    "variant_url": variant_url,
                    "baseline_status": baseline_profile["status"],
                    "variant_status": variant_profile["status"],
                    "baseline_subject_ids": sorted(set(baseline_profile.get("subject_ids") or []))[:20],
                    "variant_subject_ids": sorted(set(variant_profile.get("subject_ids") or []))[:20],
                },
                "proof": self._safe_poc(variant_url, auth_label),
                "tags": ["idor", "confirmed", "validator:idor", *reasons],
                "score": max(score_floor, int(candidate.get("score", 0) or 0)),
                "priority": "high",
                "severity": severity,
                "confidence_label": confidence_label,
                "evidence_id": signal_id or None,
            }
            if context.results.append(finding):
                confirmed += 1
                artifacts.append(
                    {
                        "timestamp": time_utils.iso_now(),
                        "url": variant_url,
                        "baseline_url": baseline_url,
                        "auth": auth_label,
                        "reasons": reasons,
                        "baseline_status": baseline_profile["status"],
                        "variant_status": variant_profile["status"],
                    }
                )

        artifacts_dir = context.record.paths.ensure_subdir("idor_validator")
        artifact_path = artifacts_dir / "idor_validator.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "timestamp": time_utils.iso_now(),
                    "confirmed": confirmed,
                    "attempted": attempted,
                    "replays": artifacts,
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
        max_candidates: int,
        max_per_host: int,
    ) -> List[Dict[str, object]]:
        grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        seen: Set[Tuple[str, str]] = set()
        for entry in iter_jsonl(context.record.paths.results_jsonl):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("type") or "").lower() != "idor_suspect":
                continue
            url = str(entry.get("url") or "").strip()
            if not url:
                continue
            auth_label = str(entry.get("auth") or "anon").strip().lower()
            key = (url, auth_label)
            if key in seen:
                continue
            details = entry.get("details")
            if not isinstance(details, dict):
                continue
            baseline_url = self._derive_baseline_url(url, details)
            if not baseline_url:
                continue
            score = int(entry.get("score", 0) or 0)
            if score < min_score:
                continue
            reasons = details.get("reasons")
            priority = score
            if isinstance(reasons, list):
                reason_set = {str(reason) for reason in reasons}
                if "subject_identifier_changed" in reason_set:
                    priority += 12
                if "auth_bypass_status_change" in reason_set:
                    priority += 15
            try:
                host = str(urlparse(url).hostname or "")
            except ValueError:
                continue
            grouped[host].append(
                {
                    "url": url,
                    "auth": auth_label,
                    "details": details,
                    "score": score,
                    "priority": priority,
                    "poc": str(entry.get("poc") or ""),
                    "baseline_url": baseline_url,
                }
            )
            seen.add(key)

        selected: List[Dict[str, object]] = []
        for _host, items in grouped.items():
            items.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)
        return selected[:max_candidates]

    def _fetch_profile(
        self,
        context: PipelineContext,
        session: "requests.Session",
        helper: IDORStage,
        url: str,
        *,
        auth_label: str,
        token: Optional[str],
        timeout: int,
        verify_tls: bool,
        retries: int,
        backoff_base: float,
        backoff_factor: float,
        limiter,
    ) -> Tuple[Optional[Dict[str, object]], str]:
        if not context.url_allowed(url):
            return None, "skipped"
        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return None, "skipped"
        headers = {"User-Agent": "recon-cli idor-validator"}
        if token:
            headers["Authorization"] = token
        resp = self._request_with_retries(
            session,
            url,
            headers,
            timeout,
            verify_tls,
            retries,
            backoff_base,
            backoff_factor,
        )
        if resp is None:
            if limiter:
                limiter.on_error(url)
            return None, "failed"
        if limiter:
            limiter.on_response(url, int(resp.status_code or 0))

        status = int(resp.status_code or 0)
        body = resp.content or b""
        text = str(getattr(resp, "text", "") or "")[:4000]
        data_json = helper._safe_json_dict(resp)
        resp.close()
        return (
            {
                "status": status,
                "body_md5": hashlib.md5(body).hexdigest(),
                "sensitive": helper._extract_sensitive(data_json, text),
                "subject_ids": helper._extract_subject_ids(data_json, text),
                "text_sample": text,
                "url": url,
                "auth": auth_label,
            },
            "ok",
        )

    @staticmethod
    def _request_with_retries(
        session: "requests.Session",
        url: str,
        headers: Dict[str, str],
        timeout: int,
        verify_tls: bool,
        retries: int,
        backoff_base: float,
        backoff_factor: float,
    ):
        attempt = 0
        while attempt <= retries:
            try:
                return session.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=verify_tls,
                    allow_redirects=True,
                )
            except Exception:
                if attempt >= retries:
                    return None
                delay = backoff_base * (backoff_factor ** attempt)
                time.sleep(max(0.1, delay))
                attempt += 1
        return None

    @staticmethod
    def _derive_baseline_url(url: str, details: Dict[str, object]) -> str:
        try:
            parsed = urlparse(url)
        except ValueError:
            return ""
        original = str(details.get("original") or "")
        if not original:
            return ""
        parameter = str(details.get("parameter") or "")
        if parameter:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            replaced = False
            updated: List[Tuple[str, str]] = []
            for key, value in params:
                if key == parameter and not replaced:
                    updated.append((key, original))
                    replaced = True
                else:
                    updated.append((key, value))
            if replaced:
                return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
        path_index = details.get("path_index")
        if isinstance(path_index, int):
            parts = [part for part in (parsed.path or "").split("/") if part]
            if 0 <= path_index < len(parts):
                parts[path_index] = original
                return urlunparse(parsed._replace(path="/" + "/".join(parts)))
        return ""

    @staticmethod
    def _resolve_token(auth_label: str, runtime) -> Optional[str]:
        if auth_label == "token-a":
            token = str(getattr(runtime, "idor_token_a", "") or "").strip()
            return token or None
        if auth_label == "token-b":
            token = str(getattr(runtime, "idor_token_b", "") or "").strip()
            return token or None
        return None

    @staticmethod
    def _safe_poc(url: str, auth_label: str) -> str:
        if auth_label == "token-a":
            return f"curl -k '{url}' # replay with Token-A profile"
        if auth_label == "token-b":
            return f"curl -k '{url}' # replay with Token-B profile"
        return f"curl -k '{url}'"
