from __future__ import annotations

import json
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import fs
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class MassAssignmentStage(Stage):
    """
    Dedicated Mass Assignment Testing Stage.
    Systematically probes JSON endpoints by adding privileged/internal fields.
    """
    name = "mass_assignment"
    requires = ["api_recon", "http_probe"]

    # High-priority administrative and sensitive fields
    PRIVILEGED_FIELDS = [
        "role", "admin", "is_admin", "is_verified", "verified", 
        "plan", "credits", "balance", "points", "premium", 
        "permissions", "privileges", "access_level", "group",
        "owner_id", "user_id", "email_verified", "subscription_status"
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_mass_assignment", True))

    async def run_async(self, context: PipelineContext) -> bool:
        targets = self._collect_api_endpoints(context)
        if not targets:
            context.logger.info("No suitable API endpoints found for mass assignment testing")
            return True

        sessions = self._load_sessions(context)
        context.logger.info("Starting Mass Assignment testing on %d endpoints", len(targets))

        config = HTTPClientConfig(max_concurrent=5, total_timeout=15.0)
        async with AsyncHTTPClient(config, context=context) as client:
            for url, method in targets:
                host = urlparse(url).hostname or ""
                host_sessions = sessions.get(host, [None])
                
                # Test with first available session (or no session)
                await self._test_endpoint(context, client, url, method, host_sessions[0])

        return True

    async def _test_endpoint(self, context: PipelineContext, client: AsyncHTTPClient, url: str, method: str, session: Optional[Dict[str, Any]]) -> None:
        headers = self._get_auth_headers(context, session)
        headers["Content-Type"] = "application/json"
        
        # 1. Baseline Request
        base_payload = {"test_recon": "probe"}
        try:
            base_resp = await client.request(method, url, json=base_payload, headers=headers)
            if base_resp.status not in [200, 201, 204]:
                return
            base_text = base_resp.body.lower()
        except Exception: return

        # 2. Probing with Privileged Fields
        # We split into groups to avoid overly large payloads
        field_groups = [
            self.PRIVILEGED_FIELDS[:7],
            self.PRIVILEGED_FIELDS[7:14],
            self.PRIVILEGED_FIELDS[14:]
        ]

        for group in field_groups:
            probe_payload = dict(base_payload)
            for field in group:
                if any(x in field for x in ["is_", "verified", "premium"]):
                    probe_payload[field] = True
                elif any(x in field for x in ["balance", "credits", "points", "id"]):
                    probe_payload[field] = 9999
                else:
                    probe_payload[field] = "admin"

            try:
                resp = await client.request(method, url, json=probe_payload, headers=headers)
                if resp.status in [200, 201, 204]:
                    resp_text = resp.body.lower()
                    
                    detected = []
                    for field in group:
                        f_lower = field.lower()
                        # Evidence: Field is reflected in response but WAS NOT in baseline
                        if f_lower in resp_text and f_lower not in base_text:
                            detected.append(field)
                    
                    if detected:
                        context.logger.info("🚨 Potential Mass Assignment on %s: %s", url, ", ".join(detected))
                        context.results.append({
                            "type": "finding",
                            "finding_type": "mass_assignment",
                            "url": url,
                            "hostname": urlparse(url).hostname,
                            "description": f"Potential Mass Assignment: Privileged fields reflected in {method} response: {', '.join(detected)}",
                            "severity": "high" if any(f in ["role", "admin", "is_admin"] for f in detected) else "medium",
                            "tags": ["api", "mass-assignment", "business-logic"],
                            "evidence": {
                                "method": method,
                                "detected_fields": detected,
                                "probe_payload": probe_payload
                            }
                        })
                        context.emit_signal("mass_assignment_detected", "url", url, confidence=0.7, source=self.name)
                        break # Found on this endpoint, move to next
            except Exception: continue

    def _collect_api_endpoints(self, context: PipelineContext) -> List[Tuple[str, str]]:
        endpoints = []
        # 1. Check reconstructed API schemas
        for art in context.record.paths.artifacts_dir.glob("openapi_reconstructed_*.json"):
            try:
                schema = json.loads(art.read_text())
                host = art.name.replace("openapi_reconstructed_", "").replace(".json", "")
                for path, methods in schema.get("paths", {}).items():
                    for method in methods:
                        if method.upper() in ["POST", "PUT", "PATCH"]:
                            endpoints.append((f"https://{host}{path}", method.upper()))
            except Exception: pass

        # 2. Check discovered URLs that look like APIs
        for r in context.filter_results("url"):
            url = r.get("url", "")
            if "/api/" in url.lower() and "?" not in url:
                # We don't know the method for sure if it's just a URL result, 
                # but we can try POST/PUT if it's high score
                if int(r.get("score", 0)) > 50:
                    endpoints.append((url, "POST"))
                    endpoints.append((url, "PUT"))

        # Dedupe
        return sorted(list(set(endpoints)))[:40]

    def _load_sessions(self, context: PipelineContext) -> Dict[str, List[Dict[str, Any]]]:
        sessions = {}
        for art in context.record.paths.artifacts_dir.glob("sessions_*.json"):
            host = art.name.replace("sessions_", "").replace(".json", "")
            try:
                data = fs.read_json(art)
                if isinstance(data, list): sessions[host] = data
            except Exception: pass
        return sessions

    def _get_auth_headers(self, context: PipelineContext, session: Optional[Dict[str, Any]]) -> Dict[str, str]:
        headers = {"User-Agent": "Mozilla/5.0 (ReconnV2 Mass-Assignment)"}
        if not session:
            return context.auth_headers(headers)
        
        cookies = session.get("cookies", {})
        if cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            
        tokens = session.get("tokens", {})
        if "access_token" in tokens:
            headers["Authorization"] = f"Bearer {tokens['access_token']}"
        elif "token" in tokens:
            headers["Authorization"] = f"Token {tokens['token']}"
            
        return headers
