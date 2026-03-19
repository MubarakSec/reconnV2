from __future__ import annotations

import math
import re
import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import requests

"""
Secrets Detector Module - كشف الأسرار والبيانات الحساسة

يكتشف الأسرار المخزنة بشكل خاطئ في الكود مثل:
- AWS Access Keys و Secret Keys
- Slack Tokens
- Google API Keys
- JWT Tokens
- RSA Private Keys
- أي secret/token/api_key عام

يستخدم:
1. Pattern Matching (Regex) للأنماط المعروفة
2. Shannon Entropy لاكتشاف السلاسل العشوائية

Example:
    >>> detector = SecretsDetector()
    >>> matches = detector.scan_text("const API_KEY = 'AKIAIOSFODNN7EXAMPLE'")
    >>> for m in matches:
    ...     print(f"{m.pattern}: confidence={m.confidence}")
"""

# ═══════════════════════════════════════════════════════════
#                     Secret Patterns
# ═══════════════════════════════════════════════════════════

SECRETS_PATTERNS = [
    # AWS Access Key: AKIA followed by 16 alphanumeric characters
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    
    # AWS Secret Key: typically 40 base64-like characters
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,4})?secret(.{0,4})?=\s*['\"]([A-Za-z0-9/+]{40})['\"]")),
    
    # Slack Token
    ("slack_token", re.compile(r"xox[pboa]\-[A-Za-z0-9-]{10,48}")),
    
    # Google API Key
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),

    # Google Cloud OAuth Client Secret
    ("google_oauth_secret", re.compile(r"GOCSPX-[A-Za-z0-9\-_]{28}")),
    
    # JWT Token: eye followed by a long base64 string, usually with dots
    ("jwt", re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")),
    
    # RSA Private Key
    ("rsa_private", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    
    # Generic Secret: Must be high entropy and at least 20 chars long, excluding common False Positives
    ("generic_secret", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|token|auth[_-]?key)[\w-]{0,5}\s*[:=]\s*['\"]([A-Za-z0-9_\-/]{20,})['\"]")),
]

# امتدادات الملفات النصية التي يُحتمل أن تحتوي أسرار
TEXT_LIKE_EXTENSIONS = {"js", "json", "env", "config", "ini", "txt"}

def shannon_entropy(data: str) -> float:
    """حساب entropy لسلسلة نصية"""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy

@dataclass
class SecretMatch:
    pattern: str
    value: str
    entropy: float
    line_number: Optional[int] = None
    
    @property
    def confidence(self) -> str:
        """تحديد مستوى الثقة في أن هذا سر حقيقي"""
        if self.pattern in {"rsa_private", "aws_access_key", "aws_secret_key", "google_oauth_secret"}:
            return "high"
        
        if self.pattern == "generic_secret":
            if self.entropy >= 4.0:
                return "medium"
            return "low"

        if self.entropy >= 3.5:
            return "medium"
        return "low"

class SecretsDetector:
    def __init__(self, patterns: Optional[List[tuple]] = None):
        self.patterns = patterns or SECRETS_PATTERNS

    def scan_text(self, text: str) -> List[SecretMatch]:
        results = []
        for name, regex in self.patterns:
            for match in regex.finditer(text):
                # إذا كان الـ regex يحتوي على مجموعات (Groups)، نأخذ المجموعة الأخيرة (عادة القيمة)
                value = match.group(len(match.groups())) if match.groups() else match.group(0)
                entropy = shannon_entropy(value)
                results.append(SecretMatch(
                    pattern=name,
                    value=value,
                    entropy=entropy
                ))
        return results

    def scan_file(self, path: Path) -> List[SecretMatch]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return self.scan_text(content)
        except Exception as e:
            _MODULE_LOGGER.error("Failed to scan file %s: %s", path, e)
            return []
