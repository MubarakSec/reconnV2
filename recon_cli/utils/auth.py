from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

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
            content_type=payload.get("content_type") or payload.get("contentType"),
            success_regex=payload.get("success_regex") or payload.get("successRegex"),
            fail_regex=payload.get("fail_regex") or payload.get("failRegex"),
            cookie_names=parse_cookie_names(payload.get("cookie_names") or payload.get("cookieNames")),
            timeout=int(payload.get("timeout") or 15),
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
            bearer=payload.get("bearer") or payload.get("token"),
            basic_user=payload.get("basic_user") or payload.get("basic_username"),
            basic_pass=payload.get("basic_pass") or payload.get("basic_password"),
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
            cookie_names=parse_cookie_names(getattr(runtime_config, "auth_login_cookie_names", None)),
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


def select_profile(profiles: List[AuthProfile], name: Optional[str]) -> Optional[AuthProfile]:
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
        headers_lower = {key.lower(): value for key, value in self.session.headers.items()}
        if self.profile.bearer and "authorization" not in headers_lower:
            self.session.headers["Authorization"] = f"Bearer {self.profile.bearer}"
            headers_lower["authorization"] = "Bearer"
        if self.profile.basic_user and self.profile.basic_pass and "authorization" not in headers_lower:
            token = f"{self.profile.basic_user}:{self.profile.basic_pass}".encode("utf-8")
            basic = base64.b64encode(token).decode("ascii")
            self.session.headers["Authorization"] = f"Basic {basic}"

    def prepare_headers(self, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = dict(self.profile.headers or {})
        if base:
            headers.update(base)
        if self.profile.bearer and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = f"Bearer {self.profile.bearer}"
        if self.profile.basic_user and self.profile.basic_pass and "authorization" not in {k.lower() for k in headers}:
            token = f"{self.profile.basic_user}:{self.profile.basic_pass}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(token).decode('ascii')}"
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
        content_type = (self.profile.login.content_type or headers.get("Content-Type", "")).lower()
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
            response = self.session.request(self.profile.login.method, login_url, **request_kwargs)
            body = response.text or ""
            if self.profile.login.fail_regex and re.search(self.profile.login.fail_regex, body, re.IGNORECASE):
                success = False
            elif self.profile.login.success_regex and not re.search(self.profile.login.success_regex, body, re.IGNORECASE):
                success = False
            elif self.profile.login.cookie_names:
                success = all(
                    name in self.session.cookies.get_dict() for name in self.profile.login.cookie_names
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

    def export_cookies(self, default_domain: Optional[str] = None) -> List[Dict[str, object]]:
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
                    "httpOnly": bool(getattr(cookie, "rest", {}).get("HttpOnly", False)),
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


def build_auth_manager(runtime_config, *, logger=None, record=None, manager=None, default_host: Optional[str] = None) -> Optional[AuthSessionManager]:
    enabled = bool(getattr(runtime_config, "enable_authenticated_scan", False))
    profiles = build_profiles(runtime_config)
    if profiles and not enabled:
        enabled = True
    if not enabled or not profiles:
        return None
    selected = select_profile(profiles, getattr(runtime_config, "auth_profile_name", None))
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
