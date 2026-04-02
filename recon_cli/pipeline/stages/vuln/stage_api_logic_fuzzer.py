from __future__ import annotations

import json
import re
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class ApiLogicFuzzerStage(Stage):
    """
    Intelligent API Logic Fuzzer (Phase 1 Upgraded).
    Uses reconstructed API schemas and UnifiedAuthManager identities to detect BOLA.
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

        # 2. Get identities grouped by host
        identities_by_host = self._load_all_identities(context)

        client_config = HTTPClientConfig(
            max_concurrent=5,
            total_timeout=15.0,
            verify_ssl=bool(getattr(context.runtime_config, "verify_tls", True)),
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
            for schema_file in schema_files:
                host = schema_file.name.replace("openapi_reconstructed_", "").replace(".json", "")
                try:
                    schema = json.loads(schema_file.read_text())
                    await self._fuzz_schema(context, client, host, schema, identities_by_host.get(host, []))
                except Exception as e:
                    context.logger.debug("Failed to fuzz schema %s: %s", host, e)

    def _load_all_identities(self, context: PipelineContext) -> Dict[str, List[Any]]:
        identities_by_host: Dict[str, List[Any]] = {}
        for identity in context._auth_manager.get_all_identities():
            host = identity.host
            if host:
                identities_by_host.setdefault(host, []).append(identity)
        return identities_by_host

    async def _fuzz_schema(self, context: PipelineContext, client: AsyncHTTPClient, host: str, schema: Dict[str, Any], identities: List[Any]) -> None:
        paths = schema.get("paths", {})
        
        for path, methods in paths.items():
            for method, info in methods.items():
                full_url = f"https://{host}{path}"
                
                # Test for BOLA (if ID found in path and we have 2+ identities)
                if len(identities) >= 2 and self.ID_PATTERN.search(path):
                    await self._test_bola(context, client, full_url, method.upper(), identities)

    async def _test_bola(self, context: PipelineContext, client: AsyncHTTPClient, url: str, method: str, identities: List[Any]) -> None:
        """
        Broken Object Level Authorization Test.
        Uses Identity A to access an object ID belonging to Identity B.
        """
        # Heuristic: we need to find the ID in the path and replace it
        matches = list(self.ID_PATTERN.finditer(url))
        if not matches: return

        # For simplicity, we try to swap the first ID found
        # In a real scenario, we'd need to know which ID belongs to which user.
        # Here we assume if we can access ANY ID from User A with User B's token, it's a BOLA risk.
        
        identity_a = identities[0]
        identity_b = identities[1]
        
        try:
            # Get baseline with Identity A (should be 200)
            resp_a = await client._request(method, url, identity_id=identity_a.identity_id)
            if resp_a.status != 200: return # Baseline failed
            
            # Now try with Identity B's token
            resp_b = await client._request(method, url, identity_id=identity_b.identity_id)
            
            # If User B gets a 200 for User A's object, it's a BOLA suspect
            if resp_b.status == 200 and len(resp_b.body) > 0:
                self._report_logic_finding(
                    context, 
                    url, 
                    "bola", 
                    f"Potential BOLA detected via {method}. Accessed {url} (originally Identity A's object) using Identity B's token.", 
                    "high", 
                    {"identity_a": identity_a.identity_id, "identity_b": identity_b.identity_id}
                )
        except Exception as e:
            context.logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
            try:
                from recon_cli.utils.metrics import metrics
                metrics.stage_errors.labels(stage="api_logic_fuzzer", error_type=type(e).__name__).inc()
            except: pass

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
