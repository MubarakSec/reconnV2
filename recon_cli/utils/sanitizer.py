from __future__ import annotations

import re
from typing import Callable, Tuple

_PLACEHOLDER = "***"

_SENSITIVE_KEYS = [
    "authorization",
    "proxy-authorization",
    "set-cookie",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "api_key",
    "api-key",
    "apikey",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "auth-token",
    "bearer_token",
    "token",
    "session_token",
    "sessionid",
    "session_id",
    "client_secret",
    "client-secret",
    "secret",
    "password",
]

_KEY_PATTERN = "|".join(re.escape(key) for key in _SENSITIVE_KEYS)

_HEADER_PATTERN = re.compile(r'(?i)(\b(?:{keys})\b\s*[:=]\s*)([^\r\n]+)'.format(keys=_KEY_PATTERN))
_JSON_DOUBLE_PATTERN = re.compile(r'(?i)("(?:{keys})"\s*:\s*")([^"\r\n]*)(")'.format(keys=_KEY_PATTERN))
_JSON_SINGLE_PATTERN = re.compile(r"(?i)('(?:{keys})'\s*:\s*')([^'\r\n]*)(')".format(keys=_KEY_PATTERN))
_ASSIGN_PATTERN = re.compile(r"(?i)(\b(?:{keys})\b\s*(?:=|:)\s*)([^\s,'\";]+)".format(keys=_KEY_PATTERN))
_QUERY_PATTERN = re.compile(r'(?i)((?:\?|&)(?:{keys})=)([^&\s]+)'.format(keys=_KEY_PATTERN))
_BEARER_PATTERN = re.compile(r'(?i)(bearer\s+)([A-Za-z0-9._\-]+)')
_BASIC_PATTERN = re.compile(r'(?i)(basic\s+)([A-Za-z0-9+/=]+)')

_REPLACEMENTS: Tuple[Tuple[re.Pattern[str], Callable[[re.Match[str]], str]], ...] = (
    (_HEADER_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}"),
    (_JSON_DOUBLE_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}{m.group(3)}"),
    (_JSON_SINGLE_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}{m.group(3)}"),
    (_ASSIGN_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}"),
    (_QUERY_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}"),
    (_BEARER_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}"),
    (_BASIC_PATTERN, lambda m: f"{m.group(1)}{_PLACEHOLDER}"),
)


def redact(text: str | None) -> str | None:
    """Mask sensitive tokens (API keys, cookies, tokens) from text output."""
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    redacted = text
    for pattern, replacer in _REPLACEMENTS:
        redacted = pattern.sub(replacer, redacted)
    return redacted


__all__ = ["redact"]
