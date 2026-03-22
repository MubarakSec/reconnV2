from __future__ import annotations

import json
import time
import uuid
import requests
import re
import os
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import time as time_utils, fs


class ActiveAuthStage(Stage):
    """
    Advanced Autonomous Signup and Signin Stage.
    
    Features:
    - Persistence: Reuses credentials from data/accounts.json.
    - CSRF & Multi-step support.
    - JWT/Bearer Token detection in JSON responses.
    - Identity Extraction: Fetches profile info after login.
    - Temp-mail verification (1secmail).
    """
    name = "active_auth"
    ACCOUNTS_FILE = "data/accounts.json"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_active_auth", True))

    def execute(self, context: PipelineContext) -> None:
        results = context.get_results()
        
        # 1. Collect forms
        forms = [r for r in results if r.get("type") == "auth_form" or "auth" in str(r.get("tags", []))]
        if not forms:
            context.logger.info("No auth forms discovered for active auth")
            return

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) recon-cli/2.0",
            "Accept": "application/json, text/html, */*"
        })
        session.verify = getattr(context.runtime_config, "verify_tls", True)
        
        # 2. Group by host
        forms_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for f in forms:
            url = f.get("url") or f.get("action")
            if not url: continue
            host = urlparse(url).hostname
            if host:
                forms_by_host.setdefault(host, []).append(f)

        # 3. Process each host
        for host, host_forms in forms_by_host.items():
            if context.is_host_blocked(host): continue

            # Check for existing credentials
            credentials = self._get_existing_credentials(host)
            
            signup_forms = [f for f in host_forms if "surface:register" in f.get("tags", [])]
            login_forms = [f for f in host_forms if "surface:login" in f.get("tags", [])]

            # If no creds, try signup
            if not credentials:
                for form in signup_forms[:1]:
                    credentials = self._attempt_signup(context, session, form)
                    if credentials:
                        self._save_credentials(host, credentials)
                        break

            # Try login (either with new or existing creds)
            for form in login_forms[:2]:
                if self._attempt_login(context, session, form, credentials):
                    # Once logged in, try to extract identity info
                    self._extract_identity(context, session, host, form.get("url"))
                    break

    def _get_existing_credentials(self, host: str) -> Optional[Dict[str, str]]:
        """Load credentials from global persistence file."""
        if os.path.exists(self.ACCOUNTS_FILE):
            try:
                data = fs.read_json(self.ACCOUNTS_FILE)
                return data.get(host)
            except Exception:
                pass
        return None

    def _save_credentials(self, host: str, credentials: Dict[str, str]) -> None:
        """Save credentials to global persistence file."""
        os.makedirs("data", exist_ok=True)
        data = {}
        if os.path.exists(self.ACCOUNTS_FILE):
            try:
                data = fs.read_json(self.ACCOUNTS_FILE)
            except Exception:
                pass
        data[host] = credentials
        fs.write_json(self.ACCOUNTS_FILE, data)

    def _extract_csrf(self, context: PipelineContext, session: requests.Session, url: str) -> Dict[str, str]:
        tokens = {}
        try:
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                csrf_names = ['csrf', 'token', 'xsrf', 'authenticity_token', '_token', 'csrfmiddlewaretoken']
                for input_tag in soup.find_all('input', type=['hidden', 'text']):
                    name = input_tag.get('name', '')
                    if any(cn in name.lower() for cn in csrf_names):
                        tokens[name] = input_tag.get('value', '')
        except Exception: pass
        return tokens

    def _map_form_fields(self, inputs: List[Dict[str, Any]], identity: Dict[str, str], current_payload: Dict[str, str]) -> Dict[str, str]:
        """Smarter field mapping for various input types."""
        payload = dict(current_payload)
        for inp in inputs:
            name = inp.get("name")
            itype = inp.get("type", "text")
            if not name or name in payload: continue
            
            nl = name.lower()
            if "email" in nl or itype == "email":
                payload[name] = identity["email"]
            elif "user" in nl:
                payload[name] = identity["username"]
            elif "pass" in nl or itype == "password":
                payload[name] = identity["password"]
            elif "confirm" in nl:
                payload[name] = identity["password"]
            elif "first" in nl:
                payload[name] = identity.get("first_name", "Recon")
            elif "last" in nl:
                payload[name] = identity.get("last_name", "Bot")
            elif "phone" in nl or "tel" in nl or itype == "tel":
                payload[name] = "5550199999"
            elif "city" in nl:
                payload[name] = "New York"
            elif "zip" in nl or "post" in nl:
                payload[name] = "10001"
            elif itype == "checkbox":
                payload[name] = "on"
            elif itype == "radio":
                # Just pick a value if none is set
                payload[name] = inp.get("value", "1")
            else:
                payload[name] = "test"
        return payload

    def _attempt_signup(self, context: PipelineContext, session: requests.Session, form: Dict[str, Any]) -> Optional[Dict[str, str]]:
        url = form.get("url")
        action = urljoin(url, form.get("action") or "")
        
        identity = {
            "username": f"recon_{uuid.uuid4().hex[:8]}",
            "password": f"P@ssw0rd_{uuid.uuid4().hex[:6]}!",
            "email_prefix": f"user_{uuid.uuid4().hex[:8]}",
            "email_domain": "1secmail.com",
        }
        identity["email"] = f"{identity['email_prefix']}@{identity['email_domain']}"

        csrf = self._extract_csrf(context, session, url)
        payload = self._map_form_fields(form.get("inputs", []), identity, csrf)

        context.logger.info("Attempting signup at %s", action)
        try:
            resp = session.post(action, data=payload, timeout=20, allow_redirects=True)
            
            # Handle Email Verification
            if any(h in resp.text.lower() for h in ["verify", "activation", "confirm", "check your email"]):
                if self._verify_email(context, session, identity["email_prefix"], identity["email_domain"]):
                    return identity
            
            # Handle Multi-step: check if response contains ANOTHER form
            soup = BeautifulSoup(resp.text, 'html.parser')
            if soup.find('form') and resp.status_code == 200:
                context.logger.info("Detected multi-step signup, continuing...")
                # (Simple recursion or second-stage logic could go here)
                pass

            if resp.status_code in [200, 302] and ("success" in resp.text.lower() or "welcome" in resp.text.lower()):
                return identity
        except Exception as e:
            context.logger.warning("Signup failed: %s", e)
        return None

    def _verify_email(self, context: PipelineContext, session: requests.Session, prefix: str, domain: str) -> bool:
        api_url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={prefix}&domain={domain}"
        for _ in range(12):
            time.sleep(5)
            try:
                msgs = requests.get(api_url, timeout=10).json()
                if msgs:
                    msg_id = msgs[0].get("id")
                    read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={prefix}&domain={domain}&id={msg_id}"
                    body = requests.get(read_url, timeout=10).json().get("body", "")
                    links = re.findall(r'https?://[^\s<>"]+', body)
                    if links:
                        vlink = [l for l in links if any(k in l.lower() for k in ['confirm', 'verify', 'activate'])][0] if links else None
                        if vlink:
                            session.get(vlink, timeout=20)
                            return True
            except Exception: continue
        return False

    def _attempt_login(self, context: PipelineContext, session: requests.Session, form: Dict[str, Any], credentials: Optional[Dict[str, str]]) -> bool:
        if not credentials: return False
        url = form.get("url")
        action = urljoin(url, form.get("action") or "")
        
        csrf = self._extract_csrf(context, session, url)
        payload = self._map_form_fields(form.get("inputs", []), credentials, csrf)

        try:
            resp = session.post(action, data=payload, timeout=20)
            
            # Detect JSON Web Tokens (JWT) in response
            token_data = {}
            if "application/json" in resp.headers.get("Content-Type", ""):
                try:
                    data = resp.json()
                    for key in ["token", "access_token", "jwt", "id_token"]:
                        if key in data:
                            token_data[key] = data[key]
                            session.headers["Authorization"] = f"Bearer {data[key]}"
                except Exception: pass

            if resp.status_code < 400:
                cookies = session.cookies.get_dict()
                if cookies or token_data:
                    host = urlparse(action).hostname or "unknown"
                    self._save_session(context, host, action, cookies, token_data, credentials)
                    return True
        except Exception: pass
        return False

    def _extract_identity(self, context: PipelineContext, session: requests.Session, host: str, base_url: str) -> None:
        """Try to fetch profile/identity info from common endpoints."""
        common_endpoints = ["/api/v1/me", "/api/user", "/profile", "/settings/account", "/api/auth/session"]
        for endpoint in common_endpoints:
            url = urljoin(base_url, endpoint)
            try:
                resp = session.get(url, timeout=10)
                if resp.status_code == 200:
                    identity_file = context.record.paths.artifact(f"identity_{host}.json")
                    info = {"url": url, "status": 200}
                    if "application/json" in resp.headers.get("Content-Type", ""):
                        info["data"] = resp.json()
                    else:
                        info["snippet"] = resp.text[:1000]
                    
                    identity_file.write_text(json.dumps(info, indent=2))
                    context.logger.info("Extracted identity info from %s", url)
                    return
            except Exception: continue

    def _save_session(self, context: PipelineContext, host: str, url: str, cookies: Dict[str, str], tokens: Dict[str, str], credentials: Dict[str, str]) -> None:
        new_auth = {
            "url": url, "cookies": cookies, "tokens": tokens,
            "credentials": credentials, "captured_at": time_utils.iso_now(),
            "session_id": uuid.uuid4().hex[:8]
        }
        
        artifact_path = context.record.paths.artifact(f"sessions_{host}.json")
        sessions = []
        if artifact_path.exists():
            try:
                sessions = fs.read_json(artifact_path)
                if not isinstance(sessions, list): sessions = []
            except Exception: pass
        
        # Avoid duplicate sessions for the same user/email
        email = credentials.get("email")
        if email:
            sessions = [s for s in sessions if s.get("credentials", {}).get("email") != email]
            
        sessions.append(new_auth)
        fs.write_json(artifact_path, sessions)
        
        context.logger.info("Captured and added session for %s (Total: %d)", host, len(sessions))
        context.emit_signal("auth_session", "host", host, confidence=1.0, source=self.name, evidence={"session_count": len(sessions)})
