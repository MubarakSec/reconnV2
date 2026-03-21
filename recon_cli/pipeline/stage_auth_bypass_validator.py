from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import time as time_utils


class AuthBypassValidatorStage(Stage):
    name = "auth_bypass_validator"

    SUCCESS_STATUS = {200, 201, 202, 204, 206}
    AUTH_BLOCK_STATUS = {401, 403}
    AUTH_HINTS = (
        "unauthorized",
        "forbidden",
        "access denied",
        "login required",
        "authentication required",
    )
    SENSITIVE_PATH_HINTS = (
        "/admin",
        "/internal",
        "/manage",
        "/management",
        "/dashboard",
        "/account",
        "/settings",
        "/tenant",
        "/billing",
        "/api/private",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(
            getattr(context.runtime_config, "enable_auth_bypass_validator", True)
        )

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("auth bypass validator requires requests; skipping")
            return

        runtime = context.runtime_config
        max_urls = max(1, int(getattr(runtime, "auth_bypass_validator_max_urls", 25)))
        max_per_host = max(
            1, int(getattr(runtime, "auth_bypass_validator_max_per_host", 6))
        )
        min_score = int(getattr(runtime, "auth_bypass_validator_min_score", 35))
        timeout = max(1, int(getattr(runtime, "auth_bypass_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        retry_count = max(0, int(getattr(runtime, "retry_count", 1)))
        retry_backoff_base = float(getattr(runtime, "retry_backoff_base", 1.0))
        retry_backoff_factor = float(getattr(runtime, "retry_backoff_factor", 2.0))
        enable_forced_browse = bool(
            getattr(runtime, "auth_bypass_validator_enable_forced_browse", True)
        )
        enable_boundary = bool(
            getattr(runtime, "auth_bypass_validator_enable_privilege_boundary", True)
        )
        limiter = context.get_rate_limiter(
            "auth_bypass_validator",
            rps=float(getattr(runtime, "auth_bypass_validator_rps", 0)),
            per_host=float(getattr(runtime, "auth_bypass_validator_per_host_rps", 0)),
        )

        candidates = self._collect_candidates(
            context,
            min_score=min_score,
            max_urls=max_urls,
            max_per_host=max_per_host,
        )
        stats = context.record.metadata.stats.setdefault("auth_bypass_validator", {})
        if not candidates:
            stats.update(
                {
                    "attempted": 0,
                    "confirmed": 0,
                    "confirmed_forced": 0,
                    "confirmed_boundary": 0,
                    "failed": 0,
                    "skipped": 0,
                }
            )
            context.manager.update_metadata(context.record)
            context.logger.info("No auth bypass validator candidates")
            return

        tokens: List[Tuple[str, str]] = []
        token_a = str(getattr(runtime, "idor_token_a", "") or "").strip()
        token_b = str(getattr(runtime, "idor_token_b", "") or "").strip()
        if token_a:
            tokens.append(("token-a", token_a))
        if token_b:
            tokens.append(("token-b", token_b))

        attempted = 0
        confirmed = 0
        confirmed_forced = 0
        confirmed_boundary = 0
        failed = 0
        skipped = 0
        artifacts: List[Dict[str, object]] = []

        for candidate in candidates:
            url = str(candidate.get("url") or "")
            if not url:
                continue
            parsed_url = urlparse(url)
            path = str(parsed_url.path or "/")
            if not context.url_allowed(url):
                skipped += 1
                continue

            baseline_resp = self._fetch(
                context,
                requests,
                "get",
                url,
                headers={"User-Agent": "recon-cli auth-bypass-validator"},
                timeout=timeout,
                verify_tls=verify_tls,
                retries=retry_count,
                backoff_base=retry_backoff_base,
                backoff_factor=retry_backoff_factor,
                limiter=limiter,
            )
            attempted += 1
            if baseline_resp is None:
                failed += 1
                continue

            baseline_status = baseline_resp["status"]
            baseline_text = baseline_resp["text"]
            restricted = self._is_auth_restricted(
                status=baseline_status,  # type: ignore[arg-type]
                text=baseline_text,  # type: ignore[arg-type]
                location=baseline_resp.get("location", ""),  # type: ignore[arg-type]
                hinted=bool(candidate.get("restricted_hint")),
            )

            finding: Optional[Dict[str, object]] = None

            if enable_forced_browse and restricted:
                for technique in self._forced_browse_techniques(url, path):
                    test_url = str(technique["url"])
                    if not context.url_allowed(test_url):
                        skipped += 1
                        continue
                    headers = {"User-Agent": "recon-cli auth-bypass-validator"}
                    headers.update(dict(technique.get("headers") or {}))  # type: ignore[call-overload]
                    resp = self._fetch(
                        context,
                        requests,
                        "get",
                        test_url,
                        headers=headers,
                        timeout=timeout,
                        verify_tls=verify_tls,
                        retries=retry_count,
                        backoff_base=retry_backoff_base,
                        backoff_factor=retry_backoff_factor,
                        limiter=limiter,
                    )
                    attempted += 1
                    if resp is None:
                        failed += 1
                        continue
                    artifacts.append(
                        {
                            "timestamp": time_utils.iso_now(),
                            "kind": "forced_browse_probe",
                            "url": url,
                            "test_url": test_url,
                            "technique": technique["name"],
                            "headers": technique.get("headers", {}),
                            "status": resp["status"],
                            "location": resp.get("location", ""),
                        }
                    )
                    if self._is_auth_restricted(
                        status=resp["status"],  # type: ignore[arg-type]
                        text=resp["text"],  # type: ignore[arg-type]
                        location=resp.get("location", ""),  # type: ignore[arg-type]
                        hinted=False,
                    ):
                        continue
                    if int(resp["status"]) not in self.SUCCESS_STATUS:  # type: ignore[call-overload]
                        continue
                    signal_id = context.emit_signal(
                        "auth_bypass_confirmed",
                        "url",
                        url,
                        confidence=1.0,
                        source="auth-bypass-validator",
                        tags=["auth-bypass", "forced-browse", "confirmed"],
                        evidence={
                            "technique": technique["name"],
                            "status_code": resp["status"],
                        },
                    )
                    finding = {
                        "type": "finding",
                        "finding_type": "auth_bypass",
                        "source": "auth-bypass-validator",
                        "url": url,
                        "hostname": urlparse(url).hostname,
                        "description": "Authentication bypass confirmed using forced-browse technique",
                        "details": {
                            "reason": "forced_browse_bypass",
                            "technique": technique["name"],
                            "probe_url": test_url,
                            "baseline_status": baseline_status,
                            "bypass_status": resp["status"],
                        },
                        "proof": f"{technique['name']} -> {resp['status']}",
                        "tags": ["auth-bypass", "forced-browse", "confirmed"],
                        "score": max(90, int(candidate.get("score", 0) or 0)),  # type: ignore[call-overload]
                        "priority": "high",
                        "severity": "critical",
                        "confidence_label": "verified",
                        "evidence_id": signal_id or None,
                    }
                    break

            if (
                finding is None
                and enable_boundary
                and len(tokens) >= 2
                and self._is_sensitive_target(url)
            ):
                auth_profiles: Dict[str, Dict[str, object]] = {}
                for label, token in tokens:
                    headers = {
                        "User-Agent": "recon-cli auth-bypass-validator",
                        "Authorization": token,
                    }
                    resp = self._fetch(
                        context,
                        requests,
                        "get",
                        url,
                        headers=headers,
                        timeout=timeout,
                        verify_tls=verify_tls,
                        retries=retry_count,
                        backoff_base=retry_backoff_base,
                        backoff_factor=retry_backoff_factor,
                        limiter=limiter,
                    )
                    attempted += 1
                    if resp is None:
                        failed += 1
                        continue
                    auth_profiles[label] = resp
                finding = self._evaluate_boundary_issue(
                    url, candidate, baseline_resp, auth_profiles
                )
                if finding:
                    artifacts.append(
                        {
                            "timestamp": time_utils.iso_now(),
                            "kind": "privilege_boundary_probe",
                            "url": url,
                            "baseline_status": baseline_status,
                            "token_a_status": int(  # type: ignore[call-overload]
                                auth_profiles.get("token-a", {}).get("status", 0) or 0
                            ),
                            "token_b_status": int(  # type: ignore[call-overload]
                                auth_profiles.get("token-b", {}).get("status", 0) or 0
                            ),
                            "reason": finding.get("details", {}).get("reason"),  # type: ignore[attr-defined]
                        }
                    )

            if finding and context.results.append(finding):
                confirmed += 1
                reason = str((finding.get("details") or {}).get("reason") or "")  # type: ignore[attr-defined]
                if reason == "forced_browse_bypass":
                    confirmed_forced += 1
                else:
                    confirmed_boundary += 1

        artifacts_dir = context.record.paths.ensure_subdir("auth_bypass_validator")
        artifact_path = artifacts_dir / "auth_bypass_validator.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "timestamp": time_utils.iso_now(),
                    "probes": artifacts,
                    "confirmed": confirmed,
                    "confirmed_forced": confirmed_forced,
                    "confirmed_boundary": confirmed_boundary,
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
                "confirmed_forced": confirmed_forced,
                "confirmed_boundary": confirmed_boundary,
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
        max_urls: int,
        max_per_host: int,
    ) -> List[Dict[str, object]]:
        grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        seen: Set[str] = set()
        for entry in context.iter_results():
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or "").strip()
            if not url or url in seen:
                continue
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            if not parsed.scheme or not parsed.netloc:
                continue
            score = int(entry.get("score", 0) or 0)
            finding_type = str(
                entry.get("finding_type") or entry.get("type") or ""
            ).lower()
            source = str(entry.get("source") or "").lower()
            status = int(entry.get("status_code") or entry.get("variant_status") or 0)
            raw_tags = entry.get("tags")
            tags = (
                {str(tag).lower() for tag in raw_tags}
                if isinstance(raw_tags, list)
                else set()
            )
            restricted_hint = status in self.AUTH_BLOCK_STATUS
            if (
                "auth:challenge" in tags
                or "auth" in source
                or finding_type in {"auth_matrix_issue", "idor_suspect"}
            ):
                restricted_hint = True
                score = max(score, 70)
            sensitive_target = self._is_sensitive_target(url)
            if score < min_score and not restricted_hint:
                continue
            if not restricted_hint and not sensitive_target:
                continue
            seen.add(url)
            priority = score
            if restricted_hint:
                priority += 30
            if sensitive_target:
                priority += 20
            grouped[parsed.hostname or ""].append(
                {
                    "url": url,
                    "score": score,
                    "priority": priority,
                    "restricted_hint": restricted_hint,
                }
            )
        selected: List[Dict[str, object]] = []
        for _host, items in grouped.items():
            items.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)  # type: ignore[call-overload]
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)  # type: ignore[call-overload]
        return selected[:max_urls]

    def _fetch(
        self,
        context: PipelineContext,
        requests_mod,
        method: str,
        url: str,
        *,
        headers: Dict[str, str],
        timeout: int,
        verify_tls: bool,
        retries: int,
        backoff_base: float,
        backoff_factor: float,
        limiter,
    ) -> Optional[Dict[str, object]]:
        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return None
        resp = self._request_with_retries(
            requests_mod,
            method,
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
            return None
        status = int(getattr(resp, "status_code", 0) or 0)
        if limiter:
            limiter.on_response(url, status)
        text = str(getattr(resp, "text", "") or "")[:4000]
        location = str(getattr(resp, "headers", {}).get("Location", "") or "")
        body_hash = (
            hashlib.md5(
                text.encode("utf-8", errors="ignore"), usedforsecurity=False
            ).hexdigest()
            if text
            else ""
        )
        resp.close()
        return {"status": status, "text": text, "location": location, "hash": body_hash}

    @staticmethod
    def _request_with_retries(
        requests_mod,
        method: str,
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
                return requests_mod.request(
                    method,
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=verify_tls,
                )
            except Exception:
                if attempt >= retries:
                    return None
                delay = backoff_base * (backoff_factor**attempt)
                time.sleep(max(0.1, delay))
                attempt += 1
        return None

    def _forced_browse_techniques(
        self, base_url: str, path: str
    ) -> List[Dict[str, object]]:
        safe_path = path if path.startswith("/") else f"/{path}"
        path_dot = safe_path.rstrip("/") + "/."
        path_encoded = safe_path.rstrip("/") + "/%2e/"
        parsed = urlparse(base_url)
        base_clean = urlunparse(parsed._replace(path=safe_path, query="", fragment=""))
        path_dot_url = urlunparse(parsed._replace(path=path_dot, query="", fragment=""))
        path_encoded_url = urlunparse(
            parsed._replace(path=path_encoded, query="", fragment="")
        )
        return [
            {
                "name": "x_original_url",
                "url": base_clean,
                "headers": {"X-Original-URL": safe_path},
            },
            {
                "name": "x_rewrite_url",
                "url": base_clean,
                "headers": {"X-Rewrite-URL": safe_path},
            },
            {
                "name": "x_custom_ip_auth",
                "url": base_clean,
                "headers": {"X-Custom-IP-Authorization": "127.0.0.1"},
            },
            {
                "name": "x_forwarded_for",
                "url": base_clean,
                "headers": {"X-Forwarded-For": "127.0.0.1"},
            },
            {"name": "path_dot_bypass", "url": path_dot_url, "headers": {}},
            {"name": "path_encoded_dot_bypass", "url": path_encoded_url, "headers": {}},
        ]

    def _evaluate_boundary_issue(
        self,
        url: str,
        candidate: Dict[str, object],
        baseline: Dict[str, object],
        profiles: Dict[str, Dict[str, object]],
    ) -> Optional[Dict[str, object]]:
        token_a = profiles.get("token-a")
        token_b = profiles.get("token-b")
        if not token_a or not token_b:
            return None
        token_a_ok = int(token_a.get("status", 0) or 0) in self.SUCCESS_STATUS  # type: ignore[call-overload]
        token_b_ok = int(token_b.get("status", 0) or 0) in self.SUCCESS_STATUS  # type: ignore[call-overload]
        if not token_a_ok or not token_b_ok:
            return None
        token_match = bool(token_a.get("hash")) and str(token_a.get("hash")) == str(
            token_b.get("hash")
        )
        if not token_match:
            return None

        baseline_status = int(baseline.get("status", 0) or 0)  # type: ignore[call-overload]
        baseline_ok = baseline_status in self.SUCCESS_STATUS
        baseline_hash = str(baseline.get("hash") or "")
        reason = "token_boundary_indistinguishable"
        severity = "high"
        score = max(82, int(candidate.get("score", 0) or 0))  # type: ignore[call-overload]
        tags = ["auth-bypass", "privilege-boundary", "confirmed"]
        if baseline_ok and baseline_hash and baseline_hash == str(token_a.get("hash")):
            reason = "unauthenticated_matches_authenticated"
            severity = "critical"
            score = max(90, int(candidate.get("score", 0) or 0))  # type: ignore[call-overload]
            tags = ["auth-bypass", "unauthenticated", "confirmed"]
        return {
            "type": "finding",
            "finding_type": "auth_bypass",
            "source": "auth-bypass-validator",
            "url": url,
            "hostname": urlparse(url).hostname,
            "description": "Authorization boundary weakness confirmed by token profile parity",
            "details": {
                "reason": reason,
                "baseline_status": baseline_status,
                "token_a_status": int(token_a.get("status", 0) or 0),  # type: ignore[call-overload]
                "token_b_status": int(token_b.get("status", 0) or 0),  # type: ignore[call-overload]
            },
            "proof": reason,
            "tags": tags,
            "score": score,
            "priority": "high",
            "severity": severity,
            "confidence_label": "verified",
        }

    def _is_sensitive_target(self, url: str) -> bool:
        lower = url.lower()
        return any(hint in lower for hint in self.SENSITIVE_PATH_HINTS)

    def _is_auth_restricted(
        self, *, status: int, text: str, location: str, hinted: bool
    ) -> bool:
        if status in self.AUTH_BLOCK_STATUS:
            return True
        lowered = (text or "").lower()
        if any(hint in lowered for hint in self.AUTH_HINTS):
            return True
        location_lower = (location or "").lower()
        if "login" in location_lower or "signin" in location_lower:
            return True
        return hinted and status not in self.SUCCESS_STATUS
