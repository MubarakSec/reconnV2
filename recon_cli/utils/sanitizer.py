from __future__ import annotations

import html
import json
import re
from typing import Any, Callable, Dict, Sequence, Tuple

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
_CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_REPLACEMENTS: Sequence[Tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = (
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


def redact_json_value(value: Any) -> Any:
    """Recursively redact sensitive material from structured payloads."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_json_value(item) for item in value]
    if isinstance(value, dict):
        redacted_dict: Dict[str, Any] = {}
        for key, item in value.items():
            safe_key = redact(str(key)) if not isinstance(key, str) else key
            if isinstance(safe_key, str) and safe_key.lower() in _SENSITIVE_KEYS:
                redacted_dict[safe_key] = _PLACEHOLDER
                continue
            redacted_dict[safe_key] = redact_json_value(item)
        return redacted_dict
    return value


def sanitize_text(value: Any, *, collapse_ws: bool = False) -> str:
    """Normalize untrusted text for user-facing output."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(redact_json_value(value), ensure_ascii=True, separators=(",", ":"))
    else:
        text = redact(str(value)) or ""
    text = _CONTROL_CHARS_PATTERN.sub(" ", text)
    if collapse_ws:
        text = " ".join(text.split())
    return text


def escape_html_text(value: Any, *, collapse_ws: bool = False) -> str:
    """Escape untrusted text for HTML or ReportLab paragraph contexts."""
    return html.escape(sanitize_text(value, collapse_ws=collapse_ws), quote=True)


__all__ = ["redact", "redact_json_value", "sanitize_text", "escape_html_text"]
