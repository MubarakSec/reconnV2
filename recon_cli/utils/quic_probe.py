from __future__ import annotations

import asyncio
import httpx
from typing import Tuple, Optional

class QUICDetector:
    """
    Detects HTTP/3 (QUIC) support.
    """
    def __init__(self, timeout: float = 5.0, verify_tls: bool = False):
        self.timeout = timeout
        self.verify_tls = verify_tls

    async def check_quic(self, url: str) -> Tuple[bool, str]:
        """
        Probes for HTTP/3 support.
        Many servers signal H3 support via 'Alt-Svc' header.
        """
        try:
            # 1. Check Alt-Svc header in standard request
            async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=self.timeout) as client:
                resp = await client.get(url)
                alt_svc = resp.headers.get("alt-svc", "")
                if "h3" in alt_svc:
                    return True, f"Found Alt-Svc header: {alt_svc}"
                
            # 2. Try direct H3 if library supports it (requires aioquic)
            # httpx requires 'http3=True' and aioquic installed
            try:
                async with httpx.AsyncClient(http3=True, verify=self.verify_tls, timeout=self.timeout) as client:
                    resp = await client.get(url)
                    if resp.http_version == "HTTP/3":
                        return True, "Direct HTTP/3 connection successful"
            except Exception:
                pass

        except Exception as e:
            return False, str(e)

        return False, "No HTTP/3 indicators found"
