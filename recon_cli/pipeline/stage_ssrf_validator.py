from __future__ import annotations

import json
import time
import uuid
import requests
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.utils import time as time_utils
from recon_cli.utils.oast import InteractshSession


class SSRFValidatorStage(Stage):
    name = "ssrf_validator"

    SSRF_PARAMS = {
        "url",
        "uri",
        "link",
        "host",
        "domain",
        "site",
        "callback",
        "dest",
        "next",
    }
    INTERNAL_PAYLOADS = (
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
    )
    INTERNAL_INDICATORS = (
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "latest/meta-data",
        "instance-id",
        "ami-id",
        "connection refused",
        "econnrefused",
        "no route to host",
        "dial tcp",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ssrf_validator", True))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("ssrf validator requires requests; skipping")
            return

        runtime = context.runtime_config
        max_urls = max(1, int(getattr(runtime, "ssrf_validator_max_urls", 25)))
        max_per_host = max(1, int(getattr(runtime, "ssrf_validator_max_per_host", 6)))
        min_score = int(getattr(runtime, "ssrf_validator_min_score", 40))
        timeout = max(1, int(getattr(runtime, "ssrf_validator_timeout", 10)))
        retry_count = max(0, int(getattr(runtime, "retry_count", 1)))
        retry_backoff_base = float(getattr(runtime, "retry_backoff_base", 1.0))
        retry_backoff_factor = float(getattr(runtime, "retry_backoff_factor", 2.0))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        enable_oast = bool(getattr(runtime, "ssrf_validator_enable_oast", True))
        enable_internal = bool(getattr(runtime, "ssrf_validator_enable_internal", True))
        oast_backend = str(getattr(runtime, "oast_backend", "interactsh")).lower()
        limiter = context.get_rate_limiter(
            "ssrf_validator",
            rps=float(getattr(runtime, "ssrf_validator_rps", 0)),
            per_host=float(getattr(runtime, "ssrf_validator_per_host_rps", 0)),
        )

        candidates = self._collect_candidates(
            context, min_score=min_score, max_urls=max_urls, max_per_host=max_per_host
        )
        stats = context.record.metadata.stats.setdefault("ssrf_validator", {})
        if not candidates:
            stats.update(
                {
                    "attempted": 0,
                    "confirmed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "candidates": 0,
                }
            )
            context.manager.update_metadata(context.record)
            context.logger.info("No SSRF validator candidates")
            return

        artifacts_dir = context.record.paths.ensure_subdir("ssrf_validator")
        probes: List[Dict[str, object]] = []
        interactions: List[Dict[str, object]] = []
        confirmed = 0
        confirmed_oast = 0
        confirmed_internal = 0
        failed = 0
        skipped = 0
        attempted = 0
        confirmed_keys: Set[Tuple[str, str]] = set()

        if enable_oast and oast_backend == "interactsh":
            output_path = artifacts_dir / "interactsh.json"
            session = InteractshSession(
                output_path,
                logger=context.logger,
                wait_seconds=int(
                    getattr(runtime, "ssrf_validator_oast_wait_seconds", 45)
                ),
                poll_interval=int(
                    getattr(runtime, "ssrf_validator_oast_poll_interval", 5)
                ),
                timeout=8,
                domain_override=getattr(runtime, "oast_domain", None),
            )
            if not session.start():
                context.logger.warning(
                    "SSRF OAST session failed; skipping callback validation"
                )
                note_missing_tool(context, "interactsh-client")
            else:
                try:
                    oast_tokens: Dict[str, Dict[str, object]] = {}
                    for entry in candidates:
                        url = str(entry.get("url") or "")
                        param = str(entry.get("param") or "")
                        key = (url, param)
                        if key in confirmed_keys:
                            continue
                        token = uuid.uuid4().hex[:10]
                        oast_url = session.make_url(token)
                        if not oast_url:
                            continue
                        test_url, method, data, json_body = (
                            self._prepare_payload_request(entry, oast_url)
                        )
                        if not context.url_allowed(test_url):
                            skipped += 1
                            continue
                        if limiter and not limiter.wait_for_slot(
                            test_url, timeout=timeout
                        ):
                            skipped += 1
                            continue
                        attempted += 1
                        headers = context.auth_headers(
                            {"User-Agent": "recon-cli ssrf-validator-oast"}
                        )
                        session_http = context.auth_session(test_url)
                        resp = self._request_with_retries(
                            requests,
                            session_http,
                            method,
                            test_url,
                            headers,
                            data,
                            json_body,
                            timeout,
                            True,
                            verify_tls,
                            retry_count,
                            retry_backoff_base,
                            retry_backoff_factor,
                        )
                        if resp is None:
                            if limiter:
                                limiter.on_error(test_url)
                            failed += 1
                            continue
                        if limiter:
                            limiter.on_response(test_url, int(resp.status_code or 0))
                        probes.append(
                            {
                                "type": "ssrf_oast_probe",
                                "url": test_url,
                                "base_url": url,
                                "param": param,
                                "status": int(resp.status_code or 0),
                                "method": method,
                                "oast_url": oast_url,
                            }
                        )
                        oast_tokens[token] = {
                            "url": url,
                            "param": param,
                            "probe": test_url,
                            "method": method,
                            "payload": oast_url,
                        }
                        resp.close()

                    if oast_tokens:
                        collected = session.collect_interactions(
                            list(oast_tokens.keys())
                        )
                        interactions = [interaction.raw for interaction in collected]
                        for interaction in collected:
                            info = oast_tokens.get(interaction.token)
                            if not info:
                                continue
                            key = (str(info["url"]), str(info["param"]))
                            if key in confirmed_keys:
                                continue
                            confirmed_keys.add(key)
                            signal_id = context.emit_signal(
                                "ssrf_confirmed",
                                "url",
                                str(info["url"]),
                                confidence=1.0,
                                source="ssrf-validator",
                                tags=["ssrf", "confirmed", "oast"],
                                evidence={"interaction": interaction.raw},
                            )
                            finding = {
                                "type": "finding",
                                "finding_type": "ssrf",
                                "source": "ssrf-validator",
                                "url": info["url"],
                                "hostname": urlparse(str(info["url"])).hostname,
                                "description": "SSRF confirmed via OAST interaction",
                                "details": {
                                    "probe": info.get("probe"),
                                    "parameter": info.get("param"),
                                    "interaction": interaction.raw,
                                },
                                "proof": interaction.raw,
                                "tags": ["ssrf", "confirmed", "oast"],
                                "score": 92,
                                "priority": "high",
                                "severity": "critical",
                                "confidence_label": "verified",
                                "evidence_id": signal_id or None,
                            }
                            if context.results.append(finding):
                                confirmed += 1
                                confirmed_oast += 1
                finally:
                    session.stop()

        if enable_internal:
            for entry in candidates:
                url = str(entry.get("url") or "")
                param = str(entry.get("param") or "")
                key = (url, param)
                if key in confirmed_keys:
                    continue
                baseline_url, baseline_method, baseline_data, baseline_json = (
                    self._prepare_payload_request(
                        entry,
                        "https://example.com/",
                    )
                )
                baseline_status, baseline_body = self._fetch_response(
                    context,
                    requests,
                    baseline_url,
                    baseline_method,
                    baseline_data,
                    baseline_json,
                    timeout=timeout,
                    verify_tls=verify_tls,
                    retries=retry_count,
                    backoff_base=retry_backoff_base,
                    backoff_factor=retry_backoff_factor,
                    limiter=limiter,
                )
                for payload in self.INTERNAL_PAYLOADS:
                    test_url, method, data, json_body = self._prepare_payload_request(
                        entry, payload
                    )
                    if not context.url_allowed(test_url):
                        skipped += 1
                        continue
                    attempted += 1
                    status, body = self._fetch_response(
                        context,
                        requests,
                        test_url,
                        method,
                        data,
                        json_body,
                        timeout=timeout,
                        verify_tls=verify_tls,
                        retries=retry_count,
                        backoff_base=retry_backoff_base,
                        backoff_factor=retry_backoff_factor,
                        limiter=limiter,
                    )
                    if status == 0 and body == "":
                        failed += 1
                        continue
                    matched = self._looks_internal(
                        body,
                        baseline_body=baseline_body,
                        status=status,
                        baseline_status=baseline_status,
                    )
                    probes.append(
                        {
                            "type": "ssrf_internal_probe",
                            "url": test_url,
                            "base_url": url,
                            "param": param,
                            "status": status,
                            "method": method,
                            "payload": payload,
                            "matched": matched,
                        }
                    )
                    if not matched:
                        continue
                    confirmed_keys.add(key)
                    signal_id = context.emit_signal(
                        "ssrf_internal_confirmed",
                        "url",
                        url,
                        confidence=0.8,
                        source="ssrf-validator",
                        tags=["ssrf", "confirmed", "internal"],
                        evidence={"payload": payload, "status_code": status},
                    )
                    finding = {
                        "type": "finding",
                        "finding_type": "ssrf",
                        "source": "ssrf-validator",
                        "url": url,
                        "hostname": urlparse(url).hostname,
                        "description": "SSRF likely confirmed by internal target response signature",
                        "details": {
                            "probe": test_url,
                            "parameter": param,
                            "payload": payload,
                            "status_code": status,
                            "response_snippet": body[:600],
                        },
                        "proof": body[:600],
                        "tags": ["ssrf", "confirmed", "internal"],
                        "score": 86,
                        "priority": "high",
                        "severity": "high",
                        "confidence_label": "high",
                        "evidence_id": signal_id or None,
                    }
                    if context.results.append(finding):
                        confirmed += 1
                        confirmed_internal += 1
                    break

        artifact_path = artifacts_dir / "ssrf_validator.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "probes": probes,
                    "interactions": interactions,
                    "confirmed": confirmed,
                    "confirmed_oast": confirmed_oast,
                    "confirmed_internal": confirmed_internal,
                    "timestamp": time_utils.iso_now(),
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
                "confirmed_oast": confirmed_oast,
                "confirmed_internal": confirmed_internal,
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
        seen: Set[Tuple[str, str, str, str]] = set()
        for entry in context.iter_results():
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or "").strip()
            if not url:
                continue
            try:
                host = str(urlparse(url).hostname or "")
            except ValueError:
                continue
            score = int(entry.get("score", 0) or 0)
            if score < min_score:
                continue
            method = str(entry.get("method") or "get").lower()
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
            for key, _value in params:
                name = str(key).strip().lower()
                if name not in self.SSRF_PARAMS:
                    continue
                candidate_key = (url, name, "query", method)
                if candidate_key in seen:
                    continue
                seen.add(candidate_key)
                grouped[host].append(
                    {
                        "url": url,
                        "param": name,
                        "location": "query",
                        "method": method,
                        "score": score,
                    }
                )

            finding_type = str(entry.get("finding_type") or "").lower()
            if finding_type == "ssrf":
                param_name = str(
                    entry.get("parameter") or entry.get("param") or "url"
                ).lower()
                if param_name in self.SSRF_PARAMS:
                    candidate_key = (url, param_name, "query", method)
                    if candidate_key not in seen:
                        seen.add(candidate_key)
                        grouped[host].append(
                            {
                                "url": url,
                                "param": param_name,
                                "location": "query",
                                "method": method,
                                "score": max(score, 80),
                            }
                        )

        selected: List[Dict[str, object]] = []
        for _host, items in grouped.items():
            items.sort(key=lambda item: int(item.get("score", 0)), reverse=True)  # type: ignore[call-overload]
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda item: int(item.get("score", 0)), reverse=True)  # type: ignore[call-overload]
        return selected[:max_urls]

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        updated: List[Tuple[str, str]] = []
        for key, current in pairs:
            if key == param and not replaced:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, current))
        if not replaced:
            updated.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    def _prepare_payload_request(
        self,
        entry: Dict[str, object],
        payload: str,
    ) -> Tuple[str, str, Optional[Dict[str, str]], Optional[Dict[str, str]]]:
        url = str(entry.get("url") or "")
        param = str(entry.get("param") or "url")
        location = str(entry.get("location") or "query").lower()
        method = str(entry.get("method") or "get").lower()
        if location == "query" or method == "get":
            return self._inject_param(url, param, payload), "get", None, None
        if location == "json":
            return url, method, None, {param: payload}
        return url, method, {param: payload}, None

    def _request_with_retries(
        self,
        requests_mod,
        session,
        method: str,
        url: str,
        headers: Dict[str, str],
        data: Optional[object],
        json_body: Optional[Dict[str, str]],
        timeout: int,
        allow_redirects: bool,
        verify_tls: bool,
        retries: int,
        backoff_base: float,
        backoff_factor: float,
    ):
        attempt = 0
        while attempt <= retries:
            try:
                if session:
                    return session.request(
                        method,
                        url,
                        data=data,
                        json=json_body,
                        timeout=timeout,
                        allow_redirects=allow_redirects,
                        headers=headers,
                        verify=verify_tls,
                    )
                return requests_mod.request(
                    method,
                    url,
                    data=data,
                    json=json_body,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    headers=headers,
                    verify=verify_tls,
                )
            except requests.exceptions.RequestException:
                if attempt >= retries:
                    return None
                delay = backoff_base * (backoff_factor**attempt)
                time.sleep(max(0.1, delay))
                attempt += 1
        return None

    def _fetch_response(
        self,
        context: PipelineContext,
        requests_mod,
        url: str,
        method: str,
        data: Optional[Dict[str, str]],
        json_body: Optional[Dict[str, str]],
        *,
        timeout: int,
        verify_tls: bool,
        retries: int,
        backoff_base: float,
        backoff_factor: float,
        limiter,
    ) -> Tuple[int, str]:
        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return 0, ""
        headers = context.auth_headers(
            {"User-Agent": "recon-cli ssrf-validator-internal"}
        )
        session_http = context.auth_session(url)
        resp = self._request_with_retries(
            requests_mod,
            session_http,
            method,
            url,
            headers,
            data,
            json_body,
            timeout,
            True,
            verify_tls,
            retries,
            backoff_base,
            backoff_factor,
        )
        if resp is None:
            if limiter:
                limiter.on_error(url)
            return 0, ""
        status = int(getattr(resp, "status_code", 0) or 0)
        if limiter:
            limiter.on_response(url, status)
        body = str(getattr(resp, "text", "") or "")[:4000]
        resp.close()
        return status, body

    def _looks_internal(
        self,
        body: str,
        *,
        baseline_body: str,
        status: int,
        baseline_status: int,
    ) -> bool:
        lowered = (body or "").lower()
        if any(indicator in lowered for indicator in self.INTERNAL_INDICATORS):
            return True
        if baseline_body and lowered and lowered != baseline_body.lower():
            if "internal" in lowered and status != baseline_status:
                return True
        return False
