from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List

LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _encode_idna(value: str) -> str:
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid hostname characters: {value}") from exc
    return ascii_value


def normalize_hostname(value: str) -> str:
    value = value.strip().rstrip('.')
    if not value:
        raise ValueError("Hostname cannot be empty")
    ascii_value = _encode_idna(value)
    labels = ascii_value.split('.')
    if len(ascii_value) > 253:
        raise ValueError("Hostname exceeds 253 characters")
    for label in labels:
        if not LABEL_RE.match(label):
            raise ValueError(f"Invalid hostname label: {label}")
    return ascii_value.lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_target(value: str, allow_ip: bool = False) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("Target cannot be empty")
    if is_ip(candidate):
        if allow_ip:
            return candidate
        raise ValueError("IP targets require --allow-ip")
    return normalize_hostname(candidate)


def load_targets_from_file(path: str, allow_ip: bool = False) -> List[str]:
    targets: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            targets.append(validate_target(stripped, allow_ip=allow_ip))
    return targets
