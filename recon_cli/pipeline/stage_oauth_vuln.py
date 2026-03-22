from __future__ import annotations

import json
import time
import uuid
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class OAuthVulnerabilityStage(Stage):
    """
    Advanced OAuth Vulnerability Scanner.
    Tests for redirect_uri hijacking, state parameter omission, and other common OAuth flaws.
    """
    name = "oauth_vuln"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_oauth_vuln", True))

    def execute(self, context: PipelineContext) -> None:
        results = context.get_results()
        # Find OAuth authorize endpoints discovered earlier
        authorize_endpoints = [
            r for r in results 
            if r.get("type") == "url" and "surface:authorize" in r.get("tags", [])
        ]
        
        if not authorize_endpoints:
            context.logger.info("No OAuth authorize endpoints found for vulnerability testing")
            return

        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 recon-cli/2.0 OAuth-Scanner"})
        session.verify = getattr(context.runtime_config, "verify_tls", True)

        for endpoint in authorize_endpoints:
            url = endpoint.get("url")
            if not url: continue
            
            # 1. Test for state parameter requirement
            self._test_state_omission(context, session, url)
            
            # 2. Test for redirect_uri hijacking (basic patterns)
            self._test_redirect_hijacking(context, session, url)

    def _test_state_omission(self, context: PipelineContext, session: requests.Session, url: str) -> None:
        """Checks if the application accepts authorization requests without a state parameter."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        if "state" not in params:
            # If state isn't there, we can't test omission, but it's already a weakness
            return

        # Create a URL without the state parameter
        test_params = {k: v for k, v in params.items() if k != "state"}
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
        
        try:
            resp = session.get(test_url, timeout=15, allow_redirects=False)
            # If it redirects to a login or consent page without error, state might be optional
            if resp.status_code in [200, 302] and "error" not in resp.text.lower():
                context.emit_signal(
                    "oauth_weakness", "url", url, 
                    confidence=0.6, source=self.name,
                    tags=["oauth", "weakness", "no-state"],
                    evidence={"description": "Authorization request accepted without state parameter"}
                )
        except Exception: pass

    def _test_redirect_hijacking(self, context: PipelineContext, session: requests.Session, url: str) -> None:
        """Tests if the redirect_uri can be pointed to an external domain."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        if "redirect_uri" not in params:
            return

        original_redirect = params["redirect_uri"]
        attacker_domain = f"evil-{uuid.uuid4().hex[:6]}.com"
        
        # Test patterns:
        # 1. Absolute replacement
        # 2. Path traversal: original.com/callback/../../evil.com
        # 3. Parameter pollution
        test_redirects = [
            f"https://{attacker_domain}/callback",
            f"{original_redirect}.{attacker_domain}",
            f"{original_redirect}@{attacker_domain}"
        ]

        for payload in test_redirects:
            test_params = dict(params)
            test_params["redirect_uri"] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            
            try:
                resp = session.get(test_url, timeout=15, allow_redirects=False)
                # If the server redirects to our payload or doesn't throw a 400/403, it's suspicious
                location = resp.headers.get("Location", "")
                if payload in location:
                    context.emit_signal(
                        "oauth_vuln_confirmed", "url", url,
                        confidence=0.9, source=self.name,
                        tags=["oauth", "vulnerability", "redirect-hijack"],
                        evidence={"payload": payload, "location": location}
                    )
                    # Create a finding
                    context.results.append({
                        "type": "finding",
                        "finding_type": "oauth_redirect_hijack",
                        "url": url,
                        "severity": "high",
                        "description": f"OAuth redirect_uri hijacking confirmed with payload: {payload}",
                        "proof": f"Redirected to: {location}",
                        "tags": ["oauth", "confirmed", "critical"]
                    })
                    break
            except Exception: pass
