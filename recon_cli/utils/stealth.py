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
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    ]

    def __init__(self, config: StealthConfig) -> None:
        self.config = config

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.config.proxies:
            return None
        proxy = random.choice(self.config.proxies)
        return {"http": proxy, "https": proxy}

    def get_random_ua(self) -> str:
        return random.choice(self.USER_AGENTS)

    def apply_jitter(self) -> None:
        if self.config.jitter_max > 0:
            delay = random.uniform(self.config.jitter_min, self.config.jitter_max)
            time.sleep(delay)

    def wrap_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        new_headers = dict(headers)
        if self.config.rotate_user_agents:
            new_headers["User-Agent"] = self.get_random_ua()
        
        # Add some stealthy headers
        new_headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        new_headers.setdefault("Sec-Ch-Ua", '"Not_A Brand";v="8", "Chromium";v="120"')
        
        return new_headers
