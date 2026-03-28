from __future__ import annotations

import json
import re
import uuid
import httpx
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, urljoin, urlencode, urlunparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils import fs


class ApiLogicFuzzerStage(Stage):
    """
    Intelligent API Logic Fuzzer.
    Uses reconstructed API schemas to detect BOLA (Broken Object Level Authorization).
    """
    name = "api_logic_fuzzer"

    # Common ID patterns in paths (e.g. /api/v1/user/123 or /api/v1/order/uuid)
    ID_PATTERN = re.compile(r"/(?:[0-9]+|[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})(?=/|$)")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_api_logic_fuzzer", True))

    async def run_async(self, context: PipelineContext) -> None:
        # 1. Find reconstructed schemas
        artifacts = context.record.paths.artifacts_dir
        schema_files = list(artifacts.glob("openapi_reconstructed_*.json"))
        
        if not schema_files:
            context.logger.info("No reconstructed API schemas found for logic fuzzing")
            return

        # 2. Get multiple sessions if available for BOLA
        sessions_by_host = self._load_all_sessions(context)

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for schema_file in schema_files:
                host = schema_file.name.replace("openapi_reconstructed_", "").replace(".json", "")
                try:
                    schema = json.loads(schema_file.read_text())
                    await self._fuzz_schema(context, client, host, schema, sessions_by_host.get(host, []))
                except Exception as e:
                    context.logger.debug("Failed to fuzz schema %s: %s", host, e)

    def _load_all_sessions(self, context: PipelineContext) -> Dict[str, List[Dict[str, Any]]]:
        sessions_by_host = {}
        # Scan artifacts for sessions_{host}.json
        for art in context.record.paths.artifacts_dir.glob("sessions_*.json"):
            host = art.name.replace("sessions_", "").replace(".json", "")
            try:
                data = fs.read_json(art)
                if isinstance(data, list):
                    sessions_by_host[host] = data
            except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="api_logic_fuzzer", error_type=type(e).__name__).inc()
                except: pass
        return sessions_by_host

    async def _fuzz_schema(self, context: PipelineContext, client: httpx.AsyncClient, host: str, schema: Dict[str, Any], sessions: List[Dict[str, Any]]) -> None:
        paths = schema.get("paths", {})
        
        for path, methods in paths.items():
            for method, info in methods.items():
                full_url = f"https://{host}{path}"
                
                # Test for BOLA (if ID found in path and we have 2+ sessions)
                if len(sessions) >= 2 and self.ID_PATTERN.search(path):
                    await self._test_bola(context, client, full_url, method, sessions)

    async def _test_bola(self, context: PipelineContext, client: httpx.AsyncClient, url: str, method: str, sessions: List[Dict[str, Any]]) -> None:
        """
        Broken Object Level Authorization Test.
        Uses Session A to access an object ID belonging to Session B.
        """
        # Heuristic: we need to find the ID in the path and replace it
        matches = list(self.ID_PATTERN.finditer(url))
        if not matches: return

        # For simplicity, we try to swap the first ID found
        # In a real scenario, we'd need to know which ID belongs to which user.
        # Here we assume if we can access ANY ID from User A with User B's token, it's a BOLA risk.
        
        user_a = sessions[0]
        user_b = sessions[1]
        
        # Get baseline with User A (should be 200)
        headers_a = self._get_headers(user_a)
        try:
            resp_a = await client.request(method, url, headers=headers_a)
            if resp_a.status_code != 200: return # Baseline failed
            
            # Now try with User B's token
            headers_b = self._get_headers(user_b)
            resp_b = await client.request(method, url, headers=headers_b)
            
            # If User B gets a 200 for User A's object, it's a BOLA suspect
            if resp_b.status_code == 200 and len(resp_b.content) > 0:
                self._report_logic_finding(context, url, "bola", f"Potential BOLA detected via {method}", "high", {"user_a": user_a.get("session_id"), "user_b": user_b.get("session_id")})
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="api_logic_fuzzer", error_type=type(e).__name__).inc()
                except: pass

    def _get_headers(self, session_data: Optional[Dict[str, Any]]) -> Dict[str, str]:
        headers = {"User-Agent": "Mozilla/5.0 (ReconnV2 API-Fuzzer)"}
        if not session_data: return headers
        
        cookies = session_data.get("cookies", {})
        if cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            
        tokens = session_data.get("tokens", {})
        if "access_token" in tokens:
            headers["Authorization"] = f"Bearer {tokens['access_token']}"
        elif "token" in tokens:
            headers["Authorization"] = f"Token {tokens['token']}"
            
        return headers

    def _report_logic_finding(self, context: PipelineContext, url: str, f_type: str, desc: str, severity: str, details: Dict[str, Any]) -> None:
        finding = {
            "type": "finding",
            "finding_type": f_type,
            "source": self.name,
            "url": url,
            "hostname": urlparse(url).hostname,
            "description": desc,
            "severity": severity,
            "score": 85 if severity == "high" else 70,
            "details": details,
            "tags": ["api", "logic", "confirmed" if severity == "high" else "suspect"]
        }
        context.results.append(finding)
        context.emit_signal(f"{f_type}_detected", "url", url, confidence=0.7, source=self.name)
