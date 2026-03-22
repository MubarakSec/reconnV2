from __future__ import annotations

import hashlib
import json
import time
import requests
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.utils import time as time_utils


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
        max_candidates = max(
            1, int(getattr(runtime, "idor_validator_max_candidates", 40))
        )
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

            # Triple-Check Validation for Honesty:
            # 1. Fetch victim data with Token A (should succeed)
            # 2. Fetch victim data with Token B (if it succeeds and matches A, it's an IDOR)
            # 3. Fetch victim data with Anon (if it succeeds and matches A, it's a Public Access/IDOR)

            host = urlparse(baseline_url).hostname or ""
            token_a = self._resolve_token(context, "token-a", host, runtime)
            token_b = self._resolve_token(context, "token-b", host, runtime)

            if not token_a:
                skipped += 1
                continue

            # Step 1: Baseline for User A (The legitimate owner)
            profile_a, state_a = self._fetch_profile(
                context,
                session,
                helper,
                baseline_url,
                auth_label="token-a",
                token=token_a,
                timeout=timeout,
                verify_tls=verify_tls,
                retries=retry_count,
                backoff_base=retry_backoff_base,
                backoff_factor=retry_backoff_factor,
                limiter=limiter,
            )
            if not profile_a or profile_a["status"] >= 400:  # type: ignore[operator]
                skipped += 1
                continue

            # Step 2: Cross-check with User B (The attacker)
            profile_b = None
            if token_b:
                profile_b, state_b = self._fetch_profile(
                    context,
                    session,
                    helper,
                    baseline_url,
                    auth_label="token-b",
                    token=token_b,
                    timeout=timeout,
                    verify_tls=verify_tls,
                    retries=retry_count,
                    backoff_base=retry_backoff_base,
                    backoff_factor=retry_backoff_factor,
                    limiter=limiter,
                )

            # Step 3: check with Anon
            profile_anon, state_anon = self._fetch_profile(
                context,
                session,
                helper,
                baseline_url,
                auth_label="anon",
                token=None,
                timeout=timeout,
                verify_tls=verify_tls,
                retries=retry_count,
                backoff_base=retry_backoff_base,
                backoff_factor=retry_backoff_factor,
                limiter=limiter,
            )

            # HONESTY CHECK:
            # If Token B or Anon gets the same data (MD5 + Status) as Token A, it's a confirmed IDOR.
            # If they get 401/403 or different data, it's NOT a confirmed IDOR.

            is_confirmed = False
            reasons = []
            final_profile = None
            final_auth = "none"

            if (
                profile_b
                and profile_b["status"] == profile_a["status"]
                and profile_b["body_md5"] == profile_a["body_md5"]
            ):
                is_confirmed = True
                reasons.append("cross_user_access_confirmed")
                final_profile = profile_b
                final_auth = "token-b"
            elif (
                profile_anon
                and profile_anon["status"] == profile_a["status"]
                and profile_anon["body_md5"] == profile_a["body_md5"]
            ):
                is_confirmed = True
                reasons.append("unauthenticated_access_confirmed")
                final_profile = profile_anon
                final_auth = "anon"

            if not is_confirmed:
                # Still check semantic reasons if status changed from 403 to 200,
                # but be more conservative.
                if profile_b:
                    semantic = helper._semantic_reasons(profile_a, profile_b)
                    if semantic:
                        reasons.extend(semantic)
                        final_profile = profile_b
                        final_auth = "token-b"

            if not final_profile or not reasons:
                continue

            confidence_label = "verified" if is_confirmed else "high"
            severity = "critical" if is_confirmed else "high"
            score_floor = 95 if is_confirmed else 85

            signal_id = context.emit_signal(
                "idor_confirmed",
                "url",
                baseline_url,
                confidence=1.0 if is_confirmed else 0.8,
                source="idor-validator",
                tags=["idor", "confirmed"]
                + (["cross-user"] if final_auth == "token-b" else []),
                evidence={
                    "reasons": reasons,
                    "baseline_status": profile_a["status"],
                    "variant_status": final_profile["status"],
                    "auth": final_auth,
                },
            )

            finding = {
                "type": "finding",
                "finding_type": "idor",
                "source": "idor-validator",
                "url": baseline_url,
                "hostname": urlparse(baseline_url).hostname,
                "description": f"IDOR confirmed via {final_auth} cross-check",
                "details": {
                    "reasons": reasons,
                    "auth": final_auth,
                    "baseline_status": profile_a["status"],
                    "variant_status": final_profile["status"],
                    "baseline_subject_ids": sorted(
                        set(profile_a.get("subject_ids") or [])  # type: ignore[call-overload]
                    )[:20],
                    "variant_subject_ids": sorted(
                        set(final_profile.get("subject_ids") or [])  # type: ignore[call-overload]
                    )[:20],
                },
                "proof": self._safe_poc(baseline_url, final_auth),
                "tags": ["idor", "confirmed", "validator:idor", *reasons],
                "score": max(score_floor, int(candidate.get("score", 0) or 0)),  # type: ignore[call-overload]
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
                        "baseline_status": profile_a["status"],
                        "variant_status": final_profile["status"],
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
        for entry in context.iter_results():
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
            items.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)  # type: ignore[call-overload]
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)  # type: ignore[call-overload]
        return selected[:max_candidates]

    def _fetch_profile(
        self,
        context: PipelineContext,
        session: Any,
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
                "body_md5": hashlib.md5(body, usedforsecurity=False).hexdigest(),
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
        session: Any,
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
            except requests.exceptions.RequestException:
                if attempt >= retries:
                    return None
                delay = backoff_base * (backoff_factor**attempt)
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

    def _resolve_token(self, context: PipelineContext, auth_label: str, host: str, runtime) -> Optional[str]:
        # 1. Try manual override
        if auth_label == "token-a":
            token = str(getattr(runtime, "idor_token_a", "") or "").strip()
            if token: return token
        elif auth_label == "token-b":
            token = str(getattr(runtime, "idor_token_b", "") or "").strip()
            if token: return token

        # 2. Try captured sessions
        try:
            art_path = context.record.paths.artifact(f"sessions_{host}.json")
            if art_path.exists():
                from recon_cli.utils import fs
                sessions = fs.read_json(art_path)
                if not isinstance(sessions, list) or not sessions:
                    return None
                
                # Use first session as token-a, second as token-b
                idx = 0 if auth_label == "token-a" else 1
                if idx < len(sessions):
                    sess = sessions[idx]
                    tokens = sess.get("tokens", {})
                    if "access_token" in tokens:
                        return f"Bearer {tokens['access_token']}"
                    
                    cookies = sess.get("cookies", {})
                    if cookies:
                        return "; ".join([f"{k}={v}" for k, v in cookies.items()])
        except Exception: pass
        return None

    @staticmethod
    def _safe_poc(url: str, auth_label: str) -> str:
        if auth_label == "token-a":
            return f"curl -k '{url}' # replay with Token-A profile"
        if auth_label == "token-b":
            return f"curl -k '{url}' # replay with Token-B profile"
        return f"curl -k '{url}'"
