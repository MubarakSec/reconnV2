from __future__ import annotations

import re
from typing import Dict, List, Optional


class CaptchaDetector:
    """
    Detects common CAPTCHA providers in page content.
    """
    PATTERNS = {
        "recaptcha": re.compile(r"google\.com/recaptcha", re.IGNORECASE),
        "hcaptcha": re.compile(r"hcaptcha\.com", re.IGNORECASE),
        "turnstile": re.compile(r"challenges\.cloudflare\.com/turnstile", re.IGNORECASE),
        "generic": re.compile(r"captcha|robot|verify you are human", re.IGNORECASE)
    }

    @classmethod
    def detect(cls, html: str) -> Optional[str]:
        for name, pattern in cls.PATTERNS.items():
            if pattern.search(html):
                return name
        return None


class CaptchaSolver:
    """
    Base class for CAPTCHA solving.
    Can be extended to support 2Captcha, Anti-Captcha, etc.
    """
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def solve_recaptcha(self, site_key: str, url: str) -> Optional[str]:
        # Placeholder for API integration
        return None

    def solve_hcaptcha(self, site_key: str, url: str) -> Optional[str]:
        # Placeholder for API integration
        return None
