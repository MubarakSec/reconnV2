from __future__ import annotations

import hashlib
import json
import asyncio
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
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
        context.update_stats(self.name, attempted=0, confirmed=0)
        if not candidates:
            return

        client_config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "auth_bypass_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
            # 1. Identity Matrix (Phase 1 integration)
            identities = context._auth_manager.get_all_identities()
            
            for candidate in candidates:
                url = str(candidate.get("url") or "")
                if not url or not context.url_allowed(url):
                    continue
                
                host = urlparse(url).hostname or ""
                path = urlparse(url).path or "/"

                # 2. Baseline: Anonymous/Unauthenticated
                baseline_resp = await self._fetch(client, context, "GET", url, identity_id=None)
                if baseline_resp is None:
                    continue

                restricted = self._is_auth_restricted(
                    status=baseline_resp["status"], text=baseline_resp["text"], 
                    location=baseline_resp.get("location", ""), hinted=bool(candidate.get("restricted_hint"))
                )

                # 3. Forced Browse Techniques (Path/Header Confusion)
                if enable_forced_browse and restricted:
                    for technique in self._forced_browse_techniques(url, path):
                        test_url = str(technique["url"])
                        headers = technique.get("headers", {})
                        
                        resp = await self._fetch(client, context, "GET", test_url, headers=headers)
                        if resp is None: continue
                        
                        if not self._is_auth_restricted(status=resp["status"], text=resp["text"], location=resp.get("location", ""), hinted=False) and int(resp["status"]) in self.SUCCESS_STATUS:
                            self._report_bypass(context, url, "forced_browse", technique["name"], baseline_resp, resp)
                            break

                # 4. Privilege Boundary Matrix (Adaptive role comparison)
                if enable_boundary and identities:
                    role_responses = {}
                    for identity in identities:
                        # Only test relevant identities for this host
                        if identity.host and identity.host != host: continue
                        
                        resp = await self._fetch(client, context, "GET", url, identity_id=identity.identity_id)
                        if resp: role_responses[identity.identity_id] = resp
                    
                    # Analyze the matrix
                    self._analyze_boundary_matrix(context, url, candidate, baseline_resp, role_responses)

    async def _fetch(
        self,
        client: AsyncHTTPClient,
        context: PipelineContext,
        method: str,
        url: str,
        identity_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            # Multi-identity replay (Phase 1)
            resp = await client._request(method=method, url=url, headers=headers, identity_id=identity_id, follow_redirects=False)
        except Exception:
            return None
            
        status = resp.status
        text = resp.body[:4000]
        location = str(resp.headers.get("Location", ""))
        body_hash = hashlib.md5(text.encode("utf-8", errors="ignore"), usedforsecurity=False).hexdigest() if text else ""
        
        return {"status": status, "text": text, "location": location, "hash": body_hash, "identity_id": identity_id}

    def _analyze_boundary_matrix(self, context: PipelineContext, url: str, candidate: Dict[str, Any], 
                                baseline: Dict[str, Any], role_responses: Dict[str, Dict[str, Any]]) -> None:
        """Adaptive analysis of response equivalence across different roles."""
        identities_tested = list(role_responses.keys())
        
        for i, id_a_name in enumerate(identities_tested):
            resp_a = role_responses[id_a_name]
            identity_a = context._auth_manager.get_identity(id_a_name)
            if not identity_a: continue

            # 1. Unauthenticated-to-Authenticated Leak
            if baseline["status"] in self.SUCCESS_STATUS and baseline["hash"] == resp_a["hash"]:
                if self._is_sensitive_target(url):
                    self._report_bypass(context, url, "boundary_leak", f"unauth_matches_{identity_a.role}", baseline, resp_a)
            
            # 2. Cross-Role Equivalence (Boundary Indistinguishable)
            for id_b_name in identities_tested[i+1:]:
                resp_b = role_responses[id_b_name]
                identity_b = context._auth_manager.get_identity(id_b_name)
                if not identity_b: continue
                
                # If two DIFFERENT roles see the exact same thing, and it's a success
                if identity_a.role != identity_b.role and resp_a["status"] in self.SUCCESS_STATUS and resp_a["hash"] == resp_b["hash"]:
                    # This suggests the privilege boundary is weak or non-existent for this resource
                    if self._is_sensitive_target(url):
                        self._report_bypass(context, url, "boundary_weakness", f"{identity_a.role}_matches_{identity_b.role}", resp_a, resp_b)

    def _report_bypass(self, context: PipelineContext, url: str, kind: str, technique: str, 
                       baseline: Dict[str, Any], bypass: Dict[str, Any]) -> None:
        host = urlparse(url).hostname
        signal_id = context.emit_signal(
            "auth_bypass_confirmed", "url", url, 
            confidence=1.0, source=self.name, 
            tags=["auth-bypass", kind, "confirmed"], 
            evidence={"technique": technique, "status_code": bypass["status"]}
        )
        
        finding = {
            "type": "finding", "finding_type": "auth_bypass", "source": self.name, "url": url, "hostname": host,
            "description": f"Authentication bypass confirmed via {kind} ({technique})",
            "details": {"reason": f"{kind}_bypass", "technique": technique, "baseline_status": baseline["status"], "bypass_status": bypass["status"]},
            "proof": f"{technique} -> {bypass['status']}", "tags": ["auth-bypass", kind, "confirmed"],
            "score": 90, "priority": "high", "severity": "critical", "evidence_id": signal_id or None,
        }
        if context.results.append(finding):
            context.update_stats(self.name, confirmed=1)

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
