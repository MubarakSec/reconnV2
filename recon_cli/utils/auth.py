from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from recon_cli.utils.sanitizer import redact_json_value

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore


_KV_SPLIT_RE = re.compile(r"[;\n]+")


def _string_map(value: Dict[str, object]) -> Dict[str, str]:
    return {str(k): str(v) for k, v in value.items() if v is not None}


def _parse_kv_pairs(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for chunk in _KV_SPLIT_RE.split(text):
        item = chunk.strip()
        if not item:
            continue
        if ":" in item:
            key, val = item.split(":", 1)
        elif "=" in item:
            key, val = item.split("=", 1)
        else:
            continue
        key = key.strip()
        val = val.strip()
        if key:
            result[key] = val
    return result


def parse_headers(value: object) -> Dict[str, str]:
    if not value:
        return {}
    if isinstance(value, dict):
        return _string_map(value)
    if isinstance(value, list):
        result: Dict[str, str] = {}
        for item in value:
            if isinstance(item, dict):
                result.update(_string_map(item))
        return result
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return _string_map(parsed)
            except json.JSONDecodeError:
                pass
        return _parse_kv_pairs(text)
    return {}


def parse_cookies(value: object) -> Dict[str, str]:
    if not value:
        return {}
    if isinstance(value, dict):
        return _string_map(value)
    if isinstance(value, list):
        result: Dict[str, str] = {}
        for item in value:
            if isinstance(item, dict):
                result.update(_string_map(item))
        return result
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return _string_map(parsed)
            except json.JSONDecodeError:
                pass
        cookie = SimpleCookie()
        cookie.load(text)
        return {key: morsel.value for key, morsel in cookie.items()}
    return {}


def parse_cookie_names(value: object) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def parse_payload(value: object) -> Optional[object]:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        pairs = parse_qsl(text, keep_blank_values=True)
        if pairs:
            return {k: v for k, v in pairs}
        return text
    return value


@dataclass
class LoginConfig:
    url: str
    method: str = "POST"
    payload: Optional[object] = None
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    success_regex: Optional[str] = None
    fail_regex: Optional[str] = None
    cookie_names: List[str] = field(default_factory=list)
    timeout: int = 15

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "LoginConfig":
        return cls(
            url=str(payload.get("url") or ""),
            method=str(payload.get("method") or "POST").upper(),
            payload=parse_payload(payload.get("payload")),
            headers=parse_headers(payload.get("headers")),
            content_type=payload.get("content_type") or payload.get("contentType"),  # type: ignore[arg-type]
            success_regex=payload.get("success_regex") or payload.get("successRegex"),  # type: ignore[arg-type]
            fail_regex=payload.get("fail_regex") or payload.get("failRegex"),  # type: ignore[arg-type]
            cookie_names=parse_cookie_names(
                payload.get("cookie_names") or payload.get("cookieNames")
            ),
            timeout=int(payload.get("timeout") or 15),  # type: ignore[call-overload]
        )


@dataclass
class AuthProfile:
    name: str = "default"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    bearer: Optional[str] = None
    basic_user: Optional[str] = None
    basic_pass: Optional[str] = None
    login: Optional[LoginConfig] = None

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "AuthProfile":
        login_payload = payload.get("login")
        login_config = None
        if isinstance(login_payload, dict) and login_payload.get("url"):
            login_config = LoginConfig.from_dict(login_payload)
        return cls(
            name=str(payload.get("name") or "default"),
            headers=parse_headers(payload.get("headers")),
            cookies=parse_cookies(payload.get("cookies")),
            bearer=payload.get("bearer") or payload.get("token"),  # type: ignore[arg-type]
            basic_user=payload.get("basic_user") or payload.get("basic_username"),  # type: ignore[arg-type]
            basic_pass=payload.get("basic_pass") or payload.get("basic_password"),  # type: ignore[arg-type]
            login=login_config,
        )


def build_profiles(runtime_config) -> List[AuthProfile]:
    profiles: List[AuthProfile] = []
    raw_profiles = getattr(runtime_config, "auth_profiles", None)
    if isinstance(raw_profiles, list) and raw_profiles:
        for entry in raw_profiles:
            if isinstance(entry, dict):
                profiles.append(AuthProfile.from_dict(entry))
    if profiles:
        return profiles

    # Legacy single-profile fields
    headers = parse_headers(getattr(runtime_config, "auth_headers", None))
    cookies = parse_cookies(getattr(runtime_config, "auth_cookies", None))
    bearer = getattr(runtime_config, "auth_bearer_token", None)
    basic_user = getattr(runtime_config, "auth_basic_user", None)
    basic_pass = getattr(runtime_config, "auth_basic_pass", None)
    login_url = getattr(runtime_config, "auth_login_url", None)
    login_config = None
    if login_url:
        login_config = LoginConfig(
            url=str(login_url),
            method=str(getattr(runtime_config, "auth_login_method", "POST")).upper(),
            payload=parse_payload(getattr(runtime_config, "auth_login_payload", None)),
            headers=parse_headers(getattr(runtime_config, "auth_login_headers", None)),
            content_type=getattr(runtime_config, "auth_login_content_type", None),
            success_regex=getattr(runtime_config, "auth_login_success_regex", None),
            fail_regex=getattr(runtime_config, "auth_login_fail_regex", None),
            cookie_names=parse_cookie_names(
                getattr(runtime_config, "auth_login_cookie_names", None)
            ),
            timeout=int(getattr(runtime_config, "auth_login_timeout", 15)),
        )
    if headers or cookies or bearer or basic_user or basic_pass or login_config:
        profiles.append(
            AuthProfile(
                name="default",
                headers=headers,
                cookies=cookies,
                bearer=bearer,
                basic_user=basic_user,
                basic_pass=basic_pass,
                login=login_config,
            )
        )
    return profiles


def select_profile(
    profiles: List[AuthProfile], name: Optional[str]
) -> Optional[AuthProfile]:
    if not profiles:
        return None
    if name:
        for profile in profiles:
            if profile.name == name:
                return profile
    return profiles[0]


class AuthSessionManager:
    def __init__(
        self,
        profile: AuthProfile,
        *,
        verify_tls: bool = True,
        default_host: Optional[str] = None,
        logger=None,
        record=None,
        manager=None,
    ) -> None:
        if requests is None:  # pragma: no cover
            raise RuntimeError("requests not available")
        self.profile = profile
        self.verify_tls = verify_tls
        self.default_host = default_host
        self.logger = logger
        self.record = record
        self.manager = manager
        self.session = requests.Session()
        self.session.verify = verify_tls
        if not verify_tls:
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            except Exception:
                pass
        if profile.headers:
            self.session.headers.update(profile.headers)
        if profile.cookies:
            self.session.cookies.update(profile.cookies)
        self._apply_auth_headers()
        self._login_cache: Dict[str, bool] = {}
        self._stats = None
        if record is not None:
            self._stats = record.metadata.stats.setdefault("auth", {})
            self._stats.setdefault("profile", profile.name)
            self._stats.setdefault("login_success", 0)
            self._stats.setdefault("login_failed", 0)
            self._stats["enabled"] = True
            if manager:
                manager.update_metadata(record)

    def _apply_auth_headers(self) -> None:
        headers_lower = {
            key.lower(): value for key, value in self.session.headers.items()
        }
        if self.profile.bearer and "authorization" not in headers_lower:
            self.session.headers["Authorization"] = f"Bearer {self.profile.bearer}"
            headers_lower["authorization"] = "Bearer"
        if (
            self.profile.basic_user
            and self.profile.basic_pass
            and "authorization" not in headers_lower
        ):
            token = f"{self.profile.basic_user}:{self.profile.basic_pass}".encode(
                "utf-8"
            )
            basic = base64.b64encode(token).decode("ascii")
            self.session.headers["Authorization"] = f"Basic {basic}"

    def prepare_headers(self, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = dict(self.profile.headers or {})
        if base:
            headers.update(base)
        if self.profile.bearer and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = f"Bearer {self.profile.bearer}"
        if (
            self.profile.basic_user
            and self.profile.basic_pass
            and "authorization" not in {k.lower() for k in headers}
        ):
            token = f"{self.profile.basic_user}:{self.profile.basic_pass}".encode(
                "utf-8"
            )
            headers["Authorization"] = (
                f"Basic {base64.b64encode(token).decode('ascii')}"
            )
        return headers

    def _resolve_login_url(self, host: Optional[str]) -> Optional[str]:
        if not self.profile.login or not self.profile.login.url:
            return None
        template = self.profile.login.url
        resolved_host = host or self.default_host
        if "{host}" in template and resolved_host:
            return template.format(host=resolved_host)
        if template.startswith("http://") or template.startswith("https://"):
            return template
        if resolved_host:
            scheme = "https" if self.verify_tls else "http"
            if template.startswith("/"):
                return f"{scheme}://{resolved_host}{template}"
            return f"{scheme}://{resolved_host}/{template}"
        return None

    def _login_host(self, url: Optional[str]) -> Optional[str]:
        if url:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    return parsed.hostname
            except ValueError:
                pass
        return self.default_host

    def ensure_login(self, url: Optional[str]) -> bool:
        if not self.profile.login:
            return True
        host = self._login_host(url)
        if host and host in self._login_cache:
            return self._login_cache[host]
        login_url = self._resolve_login_url(host)
        if not login_url:
            return False
        headers = self.prepare_headers(self.profile.login.headers)
        payload = self.profile.login.payload
        content_type = (
            self.profile.login.content_type or headers.get("Content-Type", "")
        ).lower()
        request_kwargs: Dict[str, object] = {
            "timeout": self.profile.login.timeout,
            "allow_redirects": True,
            "headers": headers,
        }
        if payload is not None:
            if isinstance(payload, (dict, list)):
                if "json" in content_type:
                    request_kwargs["json"] = payload
                else:
                    request_kwargs["data"] = payload
            else:
                request_kwargs["data"] = payload
        success = False
        try:
            response = self.session.request(
                self.profile.login.method,
                login_url,
                **request_kwargs,  # type: ignore[arg-type]
            )
            body = response.text or ""
            if self.profile.login.fail_regex and re.search(
                self.profile.login.fail_regex, body, re.IGNORECASE
            ):
                success = False
            elif self.profile.login.success_regex and not re.search(
                self.profile.login.success_regex, body, re.IGNORECASE
            ):
                success = False
            elif self.profile.login.cookie_names:
                success = all(
                    name in self.session.cookies.get_dict()
                    for name in self.profile.login.cookie_names
                )
            else:
                success = response.status_code < 400
        except Exception as exc:
            if self.logger:
                self.logger.debug("Auth login failed (%s): %s", login_url, exc)
            success = False
        if host:
            self._login_cache[host] = success
        if self._stats is not None:
            key = "login_success" if success else "login_failed"
            self._stats[key] = int(self._stats.get(key, 0)) + 1
            self._stats["login_url"] = login_url
            if self.manager and self.record:
                self.manager.update_metadata(self.record)
        return success

    def get_session(self, url: Optional[str] = None):
        if self.profile.login:
            self.ensure_login(url)
        return self.session

    def export_cookies(
        self, default_domain: Optional[str] = None
    ) -> List[Dict[str, object]]:
        cookies: List[Dict[str, object]] = []
        for cookie in self.session.cookies:
            domain = cookie.domain or default_domain
            if not domain:
                continue
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": domain,
                    "path": cookie.path or "/",
                    "secure": bool(cookie.secure),
                    "httpOnly": bool(
                        getattr(cookie, "rest", {}).get("HttpOnly", False)
                    ),
                }
            )
        return cookies

    def cookie_header(self) -> Optional[str]:
        cookie_dict = self.session.cookies.get_dict()
        if not cookie_dict:
            return None
        return "; ".join(f"{key}={value}" for key, value in cookie_dict.items())

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass


class UnifiedAuthManager:
    """
    Manages multiple authentication identities for a single job.
    Supports cookies, bearer tokens, basic auth, and role-based replay.
    """

    def __init__(self, context: "PipelineContext") -> None:
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from recon_cli.pipeline.context import PipelineContext
        
        self.context = context
        self._identities: Dict[str, IdentityRecord] = {}
        self._legacy_manager: Optional[AuthSessionManager] = None
        
        # Load existing identities from job record
        if context.record:
            from recon_cli.jobs.models import IdentityRecord
            for identity in context.record.metadata.identities:
                self._identities[identity.identity_id] = identity
        
        # Build legacy manager for backward compatibility if configured
        self._legacy_manager = build_auth_manager(context.runtime_config, 
                                                logger=getattr(context, "logger", None),
                                                record=getattr(context, "record", None),
                                                manager=getattr(context, "manager", None))

    @staticmethod
    def _sanitize_auth_material(auth_material: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = redact_json_value(auth_material)
        if isinstance(sanitized, dict):
            return sanitized
        return {}

    def _sync_identity_to_metadata(self, identity) -> None:
        if not self.context.record:
            return

        from recon_cli.jobs.models import IdentityRecord

        persisted_identity = IdentityRecord(
            identity_id=identity.identity_id,
            role=identity.role,
            auth_material=self._sanitize_auth_material(identity.auth_material),
            source=identity.source,
            verified=identity.verified,
            last_seen=identity.last_seen,
            reachable_surfaces=list(identity.reachable_surfaces),
            host=identity.host,
        )

        found = False
        for i, existing in enumerate(self.context.record.metadata.identities):
            if existing.identity_id == identity.identity_id:
                self.context.record.metadata.identities[i] = persisted_identity
                found = True
                break
        if not found:
            self.context.record.metadata.identities.append(persisted_identity)

    def register_identity(self, 
                          identity_id: str, 
                          role: str, 
                          auth_material: Dict[str, Any], 
                          source: str = "active_auth",
                          host: Optional[str] = None) -> IdentityRecord:
        """Register a new identity or update an existing one."""
        from recon_cli.jobs.models import IdentityRecord
        
        identity = IdentityRecord(
            identity_id=identity_id,
            role=role,
            auth_material=dict(auth_material or {}),
            source=source,
            host=host,
            verified=True # Usually verified if coming from active_auth
        )
        self._identities[identity_id] = identity
        
        # Sync back to job metadata
        if self.context.record:
            self._sync_identity_to_metadata(identity)
            
            if self.context.manager:
                self.context.manager.update_metadata(self.context.record)
        
        return identity

    def get_identity(self, identity_id: str) -> Optional[IdentityRecord]:
        return self._identities.get(identity_id)

    def get_identities_by_role(self, role: str) -> List[IdentityRecord]:
        return [i for i in self._identities.values() if i.role == role]

    def get_all_identities(self) -> List[IdentityRecord]:
        return list(self._identities.values())

    def ensure_login(self, url: Optional[str] = None, identity_id: Optional[str] = None) -> bool:
        """Attempt to re-authenticate or renew session."""
        if identity_id:
            identity = self.get_identity(identity_id)
            if identity:
                # Check if we have the material to re-auth
                material = identity.auth_material
                login_url = material.get("login_url")
                login_payload = material.get("login_payload")
                
                if login_url and login_payload:
                    try:
                        import requests
                        session = requests.Session()
                        session.verify = getattr(self.context.runtime_config, "verify_tls", True)
                        
                        # Apply stealth headers
                        headers = {}
                        if self.context.stealth_manager:
                            headers = self.context.stealth_manager.wrap_headers(headers)
                            
                        # Apply jitter
                        if self.context.stealth_manager:
                            self.context.stealth_manager.apply_jitter()
                        
                        resp = session.post(login_url, data=login_payload, headers=headers, allow_redirects=True, timeout=15)
                        
                        if resp.status_code < 400:
                            # Update auth material
                            cookies = session.cookies.get_dict()
                            token_data = {}
                            if "application/json" in resp.headers.get("Content-Type", "").lower():
                                try:
                                    data = resp.json()
                                    for key in ["token", "access_token", "jwt", "id_token"]:
                                        if key in data:
                                            token_data[key] = data[key]
                                except Exception:
                                    pass
                                    
                            if cookies or token_data:
                                material["cookies"] = cookies
                                material["tokens"] = token_data
                                identity.verified = True
                                identity.last_seen = time_utils.iso_now()
                                
                                # Sync back to job metadata
                                if self.context.manager and self.context.record:
                                    self._sync_identity_to_metadata(identity)
                                    self.context.manager.update_metadata(self.context.record)
                                    
                                return True
                    except Exception as e:
                        if hasattr(self.context, "logger") and self.context.logger:
                            self.context.logger.debug(f"Identity {identity_id} re-auth failed: {e}")
                
                identity.verified = False
                
        if self._legacy_manager:
            return self._legacy_manager.ensure_login(url)
            
        return False

    async def verify_identity(self, identity_id: str) -> bool:
        """Actively verify if an identity's session is still valid."""
        identity = self.get_identity(identity_id)
        if not identity:
            return False
            
        # Basic verification: check a common profile endpoint
        # In a real scenario, we might want to use a specific endpoint provided during registration
        host = identity.host or self.context.record.spec.target if self.context.record else "unknown"
        scheme = "https" if self.context.runtime_config.verify_tls else "http"
        url = f"{scheme}://{host}/api/v1/me" # Default probe
        
        try:
            from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
            config = HTTPClientConfig(total_timeout=10.0, max_retries=0)
            async with AsyncHTTPClient(config, context=self.context) as client:
                resp = await client.get(url, identity_id=identity_id)
                is_valid = resp.status == 200
                
                # Update identity status
                identity.verified = is_valid
                identity.last_seen = time_utils.iso_now()
                
                # If invalid and we have credentials, we could attempt re-login here
                # But for now, we just mark it as unverified
                
                return is_valid
        except Exception:
            return False

    def get_auth_headers(self, identity_id: Optional[str] = None, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get headers for a specific identity, or fall back to legacy manager."""
        headers = dict(base or {})
        
        if identity_id:
            identity = self.get_identity(identity_id)
            if identity:
                material = identity.auth_material
                if "headers" in material:
                    headers.update(material["headers"])
                if "bearer" in material:
                    headers["Authorization"] = f"Bearer {material['bearer']}"
                if "token" in material:
                    headers["Authorization"] = f"Bearer {material['token']}"
                if "basic_user" in material and "basic_pass" in material:
                    token = f"{material['basic_user']}:{material['basic_pass']}".encode("utf-8")
                    headers["Authorization"] = f"Basic {base64.b64encode(token).decode('ascii')}"
                return headers

        # Fallback to legacy
        if self._legacy_manager:
            return self._legacy_manager.prepare_headers(base)
            
        return headers

    def get_cookie_header(self, identity_id: Optional[str] = None) -> Optional[str]:
        """Get Cookie header string for a specific identity."""
        if identity_id:
            identity = self.get_identity(identity_id)
            if identity:
                cookies = identity.auth_material.get("cookies", {})
                if cookies:
                    return "; ".join(f"{k}={v}" for k, v in cookies.items())
        
        # Fallback to legacy
        if self._legacy_manager:
            return self._legacy_manager.cookie_header()
            
        return None

    def close(self) -> None:
        if self._legacy_manager:
            self._legacy_manager.close()


def build_auth_manager(
    runtime_config,
    *,
    logger=None,
    record=None,
    manager=None,
    default_host: Optional[str] = None,
) -> Optional[AuthSessionManager]:
    enabled = bool(getattr(runtime_config, "enable_authenticated_scan", False))
    profiles = build_profiles(runtime_config)
    if profiles and not enabled:
        enabled = True
    if not enabled or not profiles:
        return None
    selected = select_profile(
        profiles, getattr(runtime_config, "auth_profile_name", None)
    )
    if not selected:
        return None
    return AuthSessionManager(
        selected,
        verify_tls=bool(getattr(runtime_config, "verify_tls", True)),
        default_host=default_host,
        logger=logger,
        record=record,
        manager=manager,
    )
