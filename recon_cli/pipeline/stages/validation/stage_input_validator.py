from __future__ import annotations

import json
import asyncio
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class InputValidatorStage(Stage):
    """
    Differential Analysis for Input Validation Flaws (SQLi, XSS, Template Injection clues).
    Follows the 'Honest Recon' standard by requiring evidence of response change.
    """
    name = "input_validator"

    # Minimal payloads designed to trigger differential response without heavy payloads
    DIFF_PAYLOADS = [
        "'\"", # Generic SQL/String break
        "${{7*7}}", # Template injection clue
        "<reconn>", # XSS/HTML clue
        "../../etc/passwd", # Path traversal clue
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_input_validator", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_candidates = max(1, int(getattr(runtime, "input_validator_max_candidates", 50)))
        max_per_host = max(1, int(getattr(runtime, "input_validator_max_per_host", 10)))
        min_score = int(getattr(runtime, "input_validator_min_score", 40))
        timeout = max(1, int(getattr(runtime, "input_validator_timeout", 8)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        
        candidates = self._collect_candidates(
            context,
            min_score=min_score,
            max_candidates=max_candidates,
            max_per_host=max_per_host,
        )
        
        stats = context.record.metadata.stats.setdefault("input_validator", {})
        if not candidates:
            stats.update({"attempted": 0, "confirmed": 0, "candidates": 0})
            context.manager.update_metadata(context.record)
            return

        attempted = 0
        confirmed = 0
        findings_added = 0

        config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "input_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            for candidate in candidates:
                url = str(candidate.get("url") or "")
                param = str(candidate.get("param") or "")
                if not url or not param:
                    continue

                # 1. Baseline Request
                baseline_resp = await self._fetch(context, client, url)
                if not baseline_resp:
                    continue
                
                baseline_status = baseline_resp["status"]
                baseline_len = baseline_resp["length"]
                baseline_time = baseline_resp["time"]
                
                attempted += 1
                
                for payload in self.DIFF_PAYLOADS:
                    test_url = self._inject_param(url, param, payload)
                    resp = await self._fetch(context, client, test_url)
                    
                    if not resp:
                        continue
                    
                    status = resp["status"]
                    length = resp["length"]
                    rtime = resp["time"]
                    
                    # DIFFERENTIAL ANALYSIS
                    is_diff = False
                    reasons = []
                    
                    # Status Code Change (e.g. 200 -> 500)
                    if status != baseline_status and status in {500, 502, 503, 504}:
                        is_diff = True
                        reasons.append(f"status_change_{baseline_status}_to_{status}")
                    
                    # Significant Content Length Change (> 10% and > 100 bytes)
                    len_diff = abs(length - baseline_len)
                    if baseline_len > 0 and (len_diff / baseline_len) > 0.1 and len_diff > 100:
                        is_diff = True
                        reasons.append("significant_length_change")
                    
                    # Response Time Anomaly (> 2x baseline and > 2s)
                    if rtime > (baseline_time * 2) and rtime > 2.0:
                        is_diff = True
                        reasons.append("response_time_anomaly")

                    if is_diff:
                        confirmed += 1
                        signal_id = context.emit_signal(
                            "input_anomaly_detected",
                            "url",
                            url,
                            confidence=0.7,
                            source="input-validator",
                            tags=["injection", "anomaly", "confirmed"],
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "reasons": reasons,
                                "baseline": {"status": baseline_status, "len": baseline_len, "time": baseline_time},
                                "variant": {"status": status, "len": length, "time": rtime}
                            },
                        )
                        
                        finding = {
                            "type": "finding",
                            "finding_type": "input_anomaly",
                            "source": "input-validator",
                            "url": url,
                            "hostname": urlparse(url).hostname,
                            "description": f"Input validation anomaly detected in parameter '{param}'",
                            "details": {
                                "parameter": param,
                                "payload": payload,
                                "reasons": reasons,
                                "baseline_status": baseline_status,
                                "variant_status": status,
                                "baseline_length": baseline_len,
                                "variant_length": length,
                            },
                            "proof": f"curl -k '{test_url}'",
                            "tags": ["injection", "anomaly", "validator:input"],
                            "score": 65,
                            "priority": "medium",
                            "severity": "medium",
                            "confidence_label": "high",
                            "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding):
                            findings_added += 1
                        break # Move to next candidate after first confirmed diff

        stats.update({
            "attempted": attempted,
            "confirmed": confirmed,
            "findings_added": findings_added,
            "candidates": len(candidates),
        })
        context.manager.update_metadata(context.record)

    def _collect_candidates(self, context: PipelineContext, *, min_score: int, max_candidates: int, max_per_host: int) -> List[Dict[str, Any]]:
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        seen: Set[Tuple[str, str]] = set()
        
        for entry in context.iter_results():
            if not isinstance(entry, dict): continue
            url = str(entry.get("url") or "").strip()
            if not url or "?" not in url: continue
            
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                params = parse_qsl(parsed.query, keep_blank_values=True)
            except ValueError: continue
            
            score = int(entry.get("score", 0) or 0)
            if score < min_score: continue
            
            for key, _value in params:
                param_name = str(key).strip()
                item_key = (url, param_name)
                if item_key in seen: continue
                seen.add(item_key)
                
                grouped[host].append({
                    "url": url,
                    "param": param_name,
                    "score": score
                })

        selected: List[Dict[str, Any]] = []
        for _host, items in grouped.items():
            items.sort(key=lambda x: int(x["score"]), reverse=True)
            selected.extend(items[:max_per_host])
        
        selected.sort(key=lambda x: int(x["score"]), reverse=True)
        return selected[:max_candidates]

    async def _fetch(self, context: PipelineContext, client: AsyncHTTPClient, url: str) -> Optional[Dict[str, Any]]:
        headers = context.auth_headers({"User-Agent": "recon-cli input-validator"})
        start = time.monotonic()
        try:
            resp = await client.get(url, headers=headers, follow_redirects=False)
            elapsed = time.monotonic() - start
            return {
                "status": resp.status,
                "length": len(resp.body),
                "time": elapsed,
                "body": resp.body[:2000]
            }
        except Exception:
            return None

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated = []
        replaced = False
        for key, current in params:
            if key == param and not replaced:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, current))
        if not replaced:
            updated.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
