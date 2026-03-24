from __future__ import annotations

import re
import time
import requests
from typing import Dict, List, Optional


class CaptchaDetector:
    """
    Detects common CAPTCHA providers in page content.
    """
    PATTERNS = {
        "recaptcha": re.compile(r"google\.com/recaptcha|g-recaptcha|recaptcha-anchor", re.IGNORECASE),
        "hcaptcha": re.compile(r"hcaptcha\.com|h-captcha", re.IGNORECASE),
        "turnstile": re.compile(r"challenges\.cloudflare\.com/turnstile|cf-turnstile", re.IGNORECASE),
        "generic": re.compile(r"captcha|robot|verify you are human", re.IGNORECASE)
    }

    @classmethod
    def detect(cls, html: str) -> Optional[str]:
        for name, pattern in cls.PATTERNS.items():
            if pattern.search(html):
                return name
        return None

    @classmethod
    def extract_site_key(cls, html: str, provider: str) -> Optional[str]:
        """Extracts the site key for the given provider from HTML."""
        if provider == "recaptcha":
            match = re.search(r'data-sitekey=["\']([a-zA-Z0-9_-]+)["\']', html)
            if not match:
                match = re.search(r'recaptcha\.render\([^,]+,\s*{\s*[\'"]sitekey[\'"]\s*:\s*[\'"]([a-zA-Z0-9_-]+)[\'"]', html)
            return match.group(1) if match else None
        elif provider == "hcaptcha":
            match = re.search(r'data-sitekey=["\']([a-zA-Z0-9_-]+)["\']', html)
            if not match:
                match = re.search(r'hcaptcha\.render\([^,]+,\s*{\s*[\'"]sitekey[\'"]\s*:\s*[\'"]([a-zA-Z0-9_-]+)[\'"]', html)
            return match.group(1) if match else None
        elif provider == "turnstile":
            match = re.search(r'data-sitekey=["\']([a-zA-Z0-9_-]+)["\']', html)
            return match.group(1) if match else None
        return None


class CaptchaSolver:
    """
    Standard CAPTCHA solver using 2Captcha API.
    """
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key
        self.base_url = "https://2captcha.com"

    def solve_recaptcha(self, site_key: str, url: str) -> Optional[str]:
        if not self.api_key:
            return None
        return self._solve_v2(method="userrecaptcha", sitekey=site_key, pageurl=url)

    def solve_hcaptcha(self, site_key: str, url: str) -> Optional[str]:
        if not self.api_key:
            return None
        return self._solve_v2(method="hcaptcha", sitekey=site_key, pageurl=url)

    def solve_turnstile(self, site_key: str, url: str) -> Optional[str]:
        if not self.api_key:
            return None
        return self._solve_v2(method="turnstile", sitekey=site_key, pageurl=url)

    def _solve_v2(self, **params) -> Optional[str]:
        try:
            params.update({"key": self.api_key, "json": 1})
            res = requests.post(f"{self.base_url}/in.php", data=params, timeout=10).json()
            if res.get("status") != 1:
                return None
            
            job_id = res.get("request")
            for _ in range(30): # Wait up to 150 seconds
                time.sleep(5)
                res = requests.get(
                    f"{self.base_url}/res.php", 
                    params={"key": self.api_key, "action": "get", "id": job_id, "json": 1},
                    timeout=10
                ).json()
                if res.get("status") == 1:
                    return res.get("request")
                if res.get("request") == "CAPCHA_NOT_READY":
                    continue
                break
        except Exception:
            pass
        return None
