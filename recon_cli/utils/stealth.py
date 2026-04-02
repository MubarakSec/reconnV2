from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class StealthConfig:
    proxies: List[str] = field(default_factory=list)
    jitter_min: float = 0.1
    jitter_max: float = 1.0
    rotate_user_agents: bool = True


class StealthManager:
    """
    Manages proxy rotation, jitter, and request stealth.
    """
    # Expanded UA pool with 15+ entries and matching Sec-Ch-Ua metadata
    UA_POOL = [
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "platform": "Windows",
            "brands": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "platform": "macOS",
            "brands": '"Chromium";v="121", "Not(A:Brand";v="24", "Google Chrome";v="121"'
        },
        {
            "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "platform": "Linux",
            "brands": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
        },
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "platform": "Windows",
            "brands": '"Chromium";v="120", "Not(A:Brand";v="24", "Google Chrome";v="120"'
        },
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "platform": "Windows",
            "brands": None # Firefox doesn't use Sec-Ch-Ua by default
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
            "platform": "macOS",
            "brands": None
        },
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "platform": "Windows",
            "brands": '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"'
        },
        {
            "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "platform": "Linux",
            "brands": '"Chromium";v="121", "Not(A:Brand";v="24", "Google Chrome";v="121"'
        },
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "platform": "Windows",
            "brands": '"Chromium";v="119", "Not(A:Brand";v="24", "Google Chrome";v="119"'
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "platform": "macOS",
            "brands": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
        },
        {
            "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "platform": "Linux",
            "brands": None
        },
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63",
            "platform": "Windows",
            "brands": '"Chromium";v="122", "Not(A:Brand";v="24", "Vivaldi";v="6.5"'
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "platform": "macOS",
            "brands": None # Safari doesn't use Sec-Ch-Ua
        },
        {
            "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "platform": "iOS",
            "brands": None
        },
        {
            "ua": "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "platform": "iOS",
            "brands": None
        },
        {
            "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
            "platform": "Android",
            "brands": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
        },
        {
            "ua": "Mozilla/5.0 (Android 14; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",
            "platform": "Android",
            "brands": None
        }
    ]

    def __init__(self, config: StealthConfig) -> None:
        self.config = config

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.config.proxies:
            return None
        proxy = random.choice(self.config.proxies)
        return {"http": proxy, "https": proxy}

    def get_random_ua(self) -> str:
        return str(random.choice(self.UA_POOL)["ua"])

    def get_random_ua_data(self) -> Dict[str, Optional[str]]:
        return random.choice(self.UA_POOL)

    def apply_jitter(self) -> None:
        if self.config.jitter_max > 0:
            delay = random.uniform(self.config.jitter_min, self.config.jitter_max)
            time.sleep(delay)

    async def apply_jitter_async(self) -> None:
        if self.config.jitter_max > 0:
            delay = random.uniform(self.config.jitter_min, self.config.jitter_max)
            import asyncio
            await asyncio.sleep(delay)

    def wrap_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        new_headers = dict(headers)
        if self.config.rotate_user_agents:
            ua_data = self.get_random_ua_data()
            new_headers["User-Agent"] = str(ua_data["ua"])
            
            # Synchronize Sec-Ch-Ua headers with chosen UA
            if ua_data["brands"]:
                new_headers["Sec-Ch-Ua"] = str(ua_data["brands"])
            else:
                new_headers.pop("Sec-Ch-Ua", None)
                
            if ua_data["platform"]:
                new_headers["Sec-Ch-Ua-Platform"] = f'"{ua_data["platform"]}"'
            else:
                new_headers.pop("Sec-Ch-Ua-Platform", None)

            # Mobile flag
            if ua_data["platform"] in {"Android", "iOS"}:
                new_headers["Sec-Ch-Ua-Mobile"] = "?1"
            else:
                new_headers["Sec-Ch-Ua-Mobile"] = "?0"

        # Add common stealthy headers if not present
        new_headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        new_headers.setdefault("Upgrade-Insecure-Requests", "1")
        new_headers.setdefault("Sec-Fetch-Site", "none")
        new_headers.setdefault("Sec-Fetch-Mode", "navigate")
        new_headers.setdefault("Sec-Fetch-User", "?1")
        new_headers.setdefault("Sec-Fetch-Dest", "document")
        
        return new_headers
