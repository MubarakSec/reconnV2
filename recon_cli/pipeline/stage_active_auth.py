from __future__ import annotations

import json
import uuid
import re
import os
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import time as time_utils, fs
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


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
    ACCOUNTS_FILE = Path("data/accounts.json")

    # ELITE: Email Provider Pool to bypass blacklists
    EMAIL_DOMAINS = [
        "1secmail.com", "1secmail.net", "1secmail.org",
        "guerrillamail.com", "sharklasers.com", "guerrillamail.info",
        "grr.la", "guerrillamail.biz", "mailnull.com"
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_active_auth", True))

    async def run_async(self, context: PipelineContext) -> None:
        # 1. Collect potential auth forms efficiently
        forms = [r for r in context.filter_results("auth_form")]
        
        # Also check urls with auth tags
        for url_entry in context.filter_results("url"):
            if "auth" in str(url_entry.get("tags", [])):
                forms.append(url_entry)

        if not forms:
            context.logger.info("No auth forms discovered for active auth")
            return

        client_config = HTTPClientConfig(
            max_concurrent=10,
            total_timeout=20.0,
            verify_ssl=bool(getattr(context.runtime_config, "verify_tls", True)),
            requests_per_second=5.0
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
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

                credentials = self._get_existing_credentials(host)
                
                signup_forms = [f for f in host_forms if "surface:register" in f.get("tags", [])]
                login_forms = [f for f in host_forms if "surface:login" in f.get("tags", [])]

                if not credentials:
                    for form in signup_forms[:1]:
                        credentials = await self._attempt_signup(context, client, form)
                        if credentials:
                            self._save_credentials(host, credentials)
                            break

                for form in login_forms[:2]:
                    if await self._attempt_login(context, client, form, credentials):
                        await self._extract_identity(context, client, host, form.get("url"))
                        break

    def _get_existing_credentials(self, host: str) -> Optional[Dict[str, str]]:
        if os.path.exists(self.ACCOUNTS_FILE):
            try:
                data = fs.read_json(self.ACCOUNTS_FILE)
                return data.get(host)
            except Exception: pass
        return None

    def _save_credentials(self, host: str, credentials: Dict[str, str]) -> None:
        os.makedirs("data", exist_ok=True)
        data = {}
        if os.path.exists(self.ACCOUNTS_FILE):
            try:
                data = fs.read_json(self.ACCOUNTS_FILE)
            except Exception: pass
        data[host] = credentials
        fs.write_json(self.ACCOUNTS_FILE, data)

    async def _extract_csrf(self, context: PipelineContext, client: AsyncHTTPClient, url: str) -> Dict[str, str]:
        tokens = {}
        try:
            resp = await client.get(url)
            if resp.status == 200:
                soup = BeautifulSoup(resp.body, 'html.parser')
                csrf_names = ['csrf', 'token', 'xsrf', 'authenticity_token', '_token', 'csrfmiddlewaretoken']
                for input_tag in soup.find_all('input', type=['hidden', 'text']):
                    name = input_tag.get('name', '')
                    if any(cn in name.lower() for cn in csrf_names):
                        tokens[name] = input_tag.get('value', '')
        except Exception: pass
        return tokens

    def _map_form_fields(self, inputs: List[Dict[str, Any]], identity: Dict[str, str], current_payload: Dict[str, str]) -> Dict[str, str]:
        payload = dict(current_payload)
        for inp in inputs:
            name = inp.get("name")
            itype = inp.get("type", "text")
            if not name or name in payload: continue
            
            nl = name.lower()
            if "email" in nl or itype == "email": payload[name] = identity["email"]
            elif "user" in nl: payload[name] = identity["username"]
            elif "pass" in nl or itype == "password": payload[name] = identity["password"]
            elif "confirm" in nl: payload[name] = identity["password"]
            elif "first" in nl: payload[name] = identity.get("first_name", "Recon")
            elif "last" in nl: payload[name] = identity.get("last_name", "Bot")
            elif "phone" in nl or "tel" in nl or itype == "tel": payload[name] = "5550199999"
            elif "city" in nl: payload[name] = "New York"
            elif "zip" in nl or "post" in nl: payload[name] = "10001"
            elif itype == "checkbox": payload[name] = "on"
            elif itype == "radio": payload[name] = inp.get("value", "1")
            else: payload[name] = "test"
        return payload

    async def _attempt_signup(self, context: PipelineContext, client: AsyncHTTPClient, form: Dict[str, Any]) -> Optional[Dict[str, str]]:
        url = form.get("url")
        action = urljoin(url, form.get("action") or "")
        
        # Select domain (prefer custom, fallback to pool)
        runtime_domain = getattr(context.runtime_config, "auth_email_domain", "1secmail.com")
        if runtime_domain == "1secmail.com":
            import random
            domain = random.choice(self.EMAIL_DOMAINS)
        else:
            domain = runtime_domain

        identity = {
            "username": f"recon_{uuid.uuid4().hex[:8]}",
            "password": f"P@ssw0rd_{uuid.uuid4().hex[:6]}!",
            "email_prefix": f"user_{uuid.uuid4().hex[:8]}",
            "email_domain": domain,
        }
        identity["email"] = f"{identity['email_prefix']}@{identity['email_domain']}"

        csrf = await self._extract_csrf(context, client, url)
        payload = self._map_form_fields(form.get("inputs", []), identity, csrf)

        context.logger.info("Attempting signup at %s with email %s", action, identity["email"])
        try:
            resp = await client.post(action, data=payload, follow_redirects=True)
            
            if any(h in resp.body.lower() for h in ["verify", "activation", "confirm", "check your email"]):
                # verification currently only supports 1secmail API
                if "1secmail" in identity["email_domain"]:
                    if await self._verify_email(context, client, identity["email_prefix"], identity["email_domain"]):
                        return identity
                else:
                    context.logger.warning("Signup requires verification, but custom/pool domain %s has no auto-verification handler.", identity["email_domain"])
            
            if resp.status in [200, 302] and ("success" in resp.body.lower() or "welcome" in resp.body.lower()):
                return identity
        except Exception as e:
            context.logger.warning("Signup failed: %s", e)
        return None

    async def _verify_email(self, context: PipelineContext, client: AsyncHTTPClient, prefix: str, domain: str) -> bool:
        api_url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={prefix}&domain={domain}"
        for _ in range(12):
            await asyncio.sleep(5)
            try:
                msg_resp = await client.get(api_url)
                msgs = json.loads(msg_resp.body)
                if msgs:
                    msg_id = msgs[0].get("id")
                    read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={prefix}&domain={domain}&id={msg_id}"
                    read_resp = await client.get(read_url)
                    body = json.loads(read_resp.body).get("body", "")
                    links = re.findall(r'https?://[^\s<>"]+', body)
                    if links:
                        vlink = [l for l in links if any(k in l.lower() for k in ['confirm', 'verify', 'activate'])][0] if links else None
                        if vlink:
                            await client.get(vlink)
                            return True
            except Exception: continue
        return False

    async def _attempt_login(self, context: PipelineContext, client: AsyncHTTPClient, form: Dict[str, Any], credentials: Optional[Dict[str, str]]) -> bool:
        if not credentials: return False
        url = form.get("url")
        action = urljoin(url, form.get("action") or "")
        
        csrf = await self._extract_csrf(context, client, url)
        payload = self._map_form_fields(form.get("inputs", []), credentials, csrf)

        try:
            resp = await client.post(action, data=payload)
            
            token_data = {}
            if "application/json" in resp.headers.get("Content-Type", "").lower():
                try:
                    data = json.loads(resp.body)
                    for key in ["token", "access_token", "jwt", "id_token"]:
                        if key in data:
                            token_data[key] = data[key]
                except Exception: pass

            if resp.status < 400:
                cookies = {c.name: c.value for c in resp.cookies}
                if cookies or token_data:
                    host = urlparse(action).hostname or "unknown"
                    self._save_session(context, host, action, cookies, token_data, credentials)
                    return True
        except Exception: pass
        return False

    async def _extract_identity(self, context: PipelineContext, client: AsyncHTTPClient, host: str, base_url: str) -> None:
        common_endpoints = ["/api/v1/me", "/api/user", "/profile", "/settings/account", "/api/auth/session"]
        for endpoint in common_endpoints:
            url = urljoin(base_url, endpoint)
            try:
                resp = await client.get(url)
                if resp.status == 200:
                    identity_file = context.record.paths.artifact(f"identity_{host}.json")
                    info = {"url": url, "status": 200}
                    if "application/json" in resp.headers.get("Content-Type", "").lower(): info["data"] = json.loads(resp.body)
                    else: info["snippet"] = resp.body[:1000]
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
        
        email = credentials.get("email")
        if email: sessions = [s for s in sessions if s.get("credentials", {}).get("email") != email]
            
        sessions.append(new_auth)
        fs.write_json(artifact_path, sessions)
        context.logger.info("Captured and added session for %s (Total: %d)", host, len(sessions))
        context.emit_signal("auth_session", "host", host, confidence=1.0, source=self.name, evidence={"session_count": len(sessions)})
