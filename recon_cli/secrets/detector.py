from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import requests

SECRETS_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,4})?secret(.{0,4})?=\s*['\"]([A-Za-z0-9/+]{40})['\"]")),
    ("slack_token", re.compile(r"xox[pboa]\-[A-Za-z0-9-]{10,48}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_=-]{10,}")),
    ("rsa_private", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("generic_secret", re.compile(r"(?i)(api|secret|token|key)[\w-]{0,10}\s*[:=]\s*['\"][A-Za-z0-9_\-/]{16,}['\"]")),
]

TEXT_LIKE_EXTENSIONS = {"js", "json", "env", "config", "ini", "txt"}
USER_AGENT = "recon-cli-secrets/0.1"


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class SecretMatch:
    pattern: str
    value: str
    entropy: float
    start: int
    end: int

    @property
    def confidence(self) -> str:
        if self.pattern in {"rsa_private", "aws_access_key", "aws_secret_key"}:
            return "high"
        if self.entropy >= 3.5:
            return "medium"
        return "low"


class SecretsDetector:
    def __init__(self, timeout: int = 10) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.timeout = timeout

    def fetch(self, url: str) -> Optional[str]:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code != 200:
                return None
            content_type = resp.headers.get("Content-Type", "")
            if "text" not in content_type and not url.split("?")[0].split(".")[-1].lower() in TEXT_LIKE_EXTENSIONS:
                return None
            resp.encoding = resp.encoding or "utf-8"
            return resp.text
        except requests.RequestException:
            return None

    def scan_text(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for name, pattern in SECRETS_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                entropy = shannon_entropy(value)
                matches.append(
                    SecretMatch(
                        pattern=name,
                        value=value[:120],
                        entropy=entropy,
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return matches

    def scan_urls(self, urls: Iterable[str], limit: int) -> Dict[str, List[SecretMatch]]:
        results: Dict[str, List[SecretMatch]] = {}
        count = 0
        for url in urls:
            if count >= limit:
                break
            content = self.fetch(url)
            if not content:
                continue
            matches = self.scan_text(content)
            if matches:
                results[url] = matches
            count += 1
        return results

    def scan_text_artifacts(self, items: Dict[str, str]) -> Dict[str, List[SecretMatch]]:
        results: Dict[str, List[SecretMatch]] = {}
        for key, text in items.items():
            matches = self.scan_text(text)
            if matches:
                results[key] = matches
        return results
