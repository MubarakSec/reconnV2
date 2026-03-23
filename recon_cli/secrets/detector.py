from __future__ import annotations

import math
import re
import hashlib
import logging
import asyncio
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Any

from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig

"""
Elite Secrets Detector Module.
Optimized for high-throughput and low false-positives via Shannon Entropy.
"""

logger = logging.getLogger(__name__)

SECRETS_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,4})?secret(.{0,4})?=\s*['\"]([A-Za-z0-9/+]{40})['\"]")),
    ("slack_token", re.compile(r"xox[pboa]\-[A-Za-z0-9-]{10,48}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_=-]{10,}\.eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}")),
    ("rsa_private", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    # Elite: increased min length to 20 to kill noise
    ("generic_secret", re.compile(r"(?i)(api|secret|token|key)[\w-]{0,10}\s*[:=]\s*['\"][A-Za-z0-9_\-/]{20,}['\"]")),
]

TEXT_LIKE_EXTENSIONS = {"js", "json", "env", "config", "ini", "txt", "yml", "yaml"}

def shannon_entropy(data: str) -> float:
    if not data: return 0.0
    freq: Dict[str, int] = {}
    for char in data: freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

@dataclass
class SecretMatch:
    pattern: str
    value_hash: str
    length: int
    entropy: float
    start: int
    end: int

    @property
    def confidence(self) -> str:
        # confirmed patterns are high
        if self.pattern in {"rsa_private", "aws_access_key", "aws_secret_key", "slack_token"}:
            return "high"
        # Entropy check for generic secrets
        if self.entropy >= 3.8: return "high"
        if self.entropy >= 3.2: return "medium"
        return "low"

class SecretsDetector:
    def __init__(
        self,
        timeout: int = 10,
        verify_tls: bool = True,
        max_concurrent: int = 20
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.max_concurrent = max_concurrent

    async def scan_urls(self, urls: Iterable[str], limit: int) -> Dict[str, List[SecretMatch]]:
        results: Dict[str, List[SecretMatch]] = {}
        client_config = HTTPClientConfig(
            max_concurrent=self.max_concurrent,
            total_timeout=float(self.timeout),
            verify_ssl=self.verify_tls
        )
        
        async with AsyncHTTPClient(client_config) as client:
            selected = list(urls)[:limit]
            tasks = [client.get(url) for url in selected]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for url, resp in zip(selected, responses):
                if isinstance(resp, Exception) or resp.status != 200: continue
                
                content = resp.body
                if not content: continue
                
                matches = self.scan_text(content)
                if matches:
                    # Filter out low confidence findings to reduce noise as per audit
                    results[url] = [m for m in matches if m.confidence != "low"]
        return results

    def scan_text(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for name, pattern in SECRETS_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                entropy = shannon_entropy(value)
                value_hash = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
                matches.append(SecretMatch(
                    pattern=name, value_hash=value_hash, length=len(value),
                    entropy=entropy, start=match.start(), end=match.end()
                ))
        return matches
