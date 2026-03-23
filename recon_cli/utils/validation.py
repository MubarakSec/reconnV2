from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from typing import List

LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _encode_idna(value: str) -> str:
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid hostname characters: {value}") from exc
    return ascii_value


def normalize_hostname(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value:
        raise ValueError("Hostname cannot be empty")
        
    port_part = ""
    if ":" in value and not (value.startswith("[") and "]" in value):
        parts = value.rsplit(":", 1)
        if parts[1].isdigit():
            value = parts[0]
            port_part = f":{parts[1]}"
            
    ascii_value = _encode_idna(value)
    labels = ascii_value.split(".")
    if len(ascii_value) > 253:
        raise ValueError("Hostname exceeds 253 characters")
    for label in labels:
        if not LABEL_RE.match(label):
            raise ValueError(f"Invalid hostname label: {label}")
            
    return ascii_value.lower() + port_part


def is_ip(value: str) -> bool:
    host_part = value
    if ":" in value and not (value.startswith("[") and "]" in value):
        parts = value.rsplit(":", 1)
        if parts[1].isdigit():
            host_part = parts[0]
    try:
        ipaddress.ip_address(host_part)
        return True
    except ValueError:
        return False


def _coerce_hostname(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return candidate
    parsed = None
    if "://" in candidate:
        parsed = urlparse(candidate)
    else:
        # Treat host:port or host/path as URL-like input.
        if any(ch in candidate for ch in ("/", "?", "#")) or (
            ":" in candidate and not is_ip(candidate)
        ):
            parsed = urlparse(f"http://{candidate}")
    if parsed and parsed.hostname:
        if parsed.port and parsed.port not in (80, 443):
            return f"{parsed.hostname}:{parsed.port}"
        return parsed.hostname
    return candidate


def validate_target(value: str, allow_ip: bool = False) -> str:
    candidate = _coerce_hostname(value)
    if not candidate:
        raise ValueError("Target cannot be empty")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    elif candidate == "*":
        raise ValueError("Wildcard target must include a domain (e.g., *.example.com)")

    # Handle host:port
    host_part = candidate
    port_part = None
    if ":" in candidate and not (candidate.startswith("[") and "]" in candidate): # Not IPv6
        parts = candidate.rsplit(":", 1)
        if parts[1].isdigit():
            host_part = parts[0]
            port_part = parts[1]

    if is_ip(host_part):
        if allow_ip:
            return candidate
        raise ValueError("IP targets require --allow-ip")

    normalized = normalize_hostname(host_part)
    if port_part:
        return f"{normalized}:{port_part}"
    return normalized


def load_targets_from_file(path: str, allow_ip: bool = False) -> List[str]:
    targets: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            targets.append(validate_target(stripped, allow_ip=allow_ip))
    return targets
