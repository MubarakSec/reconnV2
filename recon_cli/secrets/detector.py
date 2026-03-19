from __future__ import annotations

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

import math
import re
import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import requests

# ═══════════════════════════════════════════════════════════
#                     Secret Patterns
# ═══════════════════════════════════════════════════════════
# كل pattern يتكون من (اسم, regex)
# الترتيب مهم: الأنماط الأكثر تحديداً أولاً

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

USER_AGENT = "recon-cli-secrets/0.1"


# ═══════════════════════════════════════════════════════════
#                     Shannon Entropy
# ═══════════════════════════════════════════════════════════

def shannon_entropy(data: str) -> float:
    """
    حساب Shannon Entropy لسلسلة نصية.
    
    Shannon Entropy تقيس مدى "عشوائية" النص:
    - نص عادي (مثل "hello") له entropy منخفضة (~2-3 bits)
    - نص عشوائي (مثل API keys) له entropy عالية (~4-5 bits)
    
    الصيغة الرياضية:
        H = -Σ p(x) * log2(p(x))
    
    حيث p(x) هي احتمالية ظهور كل حرف.
    
    Args:
        data: السلسلة النصية للتحليل
        
    Returns:
        قيمة الـ entropy بالـ bits (0.0 إلى ~8.0)
        
    Example:
        >>> shannon_entropy("aaaa")      # منخفضة: 0.0
        >>> shannon_entropy("abcd")      # متوسطة: 2.0
        >>> shannon_entropy("aB3$xY9!")  # عالية: ~3.0
        
    لماذا 3.5 كحد أدنى للأسرار؟
    - الكلمات الإنجليزية العادية: ~2.5-3.0
    - الأسرار والـ tokens: ~3.5-5.0
    - Base64 عشوائي: ~4.0-5.0
    """
    if not data:
        return 0.0
    
    # Step 1: حساب تكرار كل حرف
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Step 2: حساب الـ entropy
    entropy = 0.0
    length = len(data)
    
    for count in freq.values():
        # p = احتمالية ظهور الحرف
        p = count / length
        # إضافة مساهمة هذا الحرف في الـ entropy
        # نستخدم -= لأن log2(p) سالب عندما p < 1
        entropy -= p * math.log2(p)
    
    return entropy


# ═══════════════════════════════════════════════════════════
#                     Data Classes
# ═══════════════════════════════════════════════════════════

@dataclass
class SecretMatch:
    """
    نتيجة مطابقة سر.
    
    Attributes:
        pattern: اسم النمط المطابق (مثل "aws_access_key")
        value_hash: SHA256 hash للقيمة (لا نحفظ القيمة الفعلية!)
        length: طول القيمة
        entropy: Shannon entropy للقيمة
        start: موقع البداية في النص
        end: موقع النهاية في النص
    """
    pattern: str
    value_hash: str
    length: int
    entropy: float
    start: int
    end: int

    @property
    def confidence(self) -> str:
        """
        تحديد مستوى الثقة في أن هذا سر حقيقي.
        """
        # الأنماط المؤكدة دائماً high
        if self.pattern in {"rsa_private", "aws_access_key", "aws_secret_key", "google_oauth_secret"}:
            return "high"
        
        # entropy عالية تعني على الأرجح سر حقيقي
        if self.pattern == "generic_secret":
            if self.entropy >= 4.0:
                return "medium"
            return "low"

        if self.entropy >= 3.5:
            return "medium"
        # قد يكون false positive
        return "low"


class SecretsDetector:
    def __init__(
        self,
        timeout: int = 10,
        verify_tls: bool = True,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.session = session or requests.Session()
        self.session.verify = verify_tls
        if not verify_tls:
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            except Exception:
                pass
        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": USER_AGENT})
        self.timeout = timeout

    def fetch(self, url: str) -> Optional[str]:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code != 200:
                return None
            content_type = resp.headers.get("Content-Type", "")
            if "text" not in content_type and url.split("?")[0].split(".")[-1].lower() not in TEXT_LIKE_EXTENSIONS:
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
                value_hash = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
                matches.append(
                    SecretMatch(
                        pattern=name,
                        value_hash=value_hash,
                        length=len(value),
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
