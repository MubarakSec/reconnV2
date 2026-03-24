from __future__ import annotations

import asyncio
import time
import httpx
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse


class H2SmugglingDetector:
    """
    Detects HTTP/2 Request Smuggling (H2.CL and H2.TE desync).
    Uses httpx with HTTP/2 support to craft desync payloads.
    """

    def __init__(self, timeout: float = 10.0, verify_tls: bool = False):
        self.timeout = timeout
        self.verify_tls = verify_tls

    async def check_h2_support(self, url: str) -> bool:
        """Verifies if the target supports HTTP/2."""
        try:
            async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=self.timeout) as client:
                resp = await client.get(url)
                return resp.http_version == "HTTP/2"
        except Exception:
            return False

    async def detect_h2_cl(self, url: str) -> Tuple[bool, str]:
        """
        Detects H2.CL desync.
        Sends an H2 request with a 'content-length' header that contradicts the actual body.
        Front-end (H2) might ignore CL, but back-end (H1.1) might honor it.
        """
        # Payload: actual body is small, but CL header is large.
        # If back-end honors CL, it will wait for more bytes -> TIMEOUT.
        headers = {
            "content-length": "100", # Contradictory CL
            "user-agent": "recon-cli/2.0 h2-hunter"
        }
        body = b"x=1"
        
        try:
            start = time.time()
            async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=5.0) as client:
                # We expect a timeout if vulnerable
                try:
                    resp = await client.post(url, headers=headers, content=body)
                    # If it returns 400 immediately, front-end might be validating CL
                    if resp.status_code == 400:
                        return False, "Front-end rejected invalid CL"
                    return False, f"Received {resp.status_code} without timeout"
                except (httpx.TimeoutException, asyncio.TimeoutError):
                    # Potential hit! Now verify with a normal request
                    if await self._verify_normal(url):
                        return True, "H2.CL desync: Timeout on contradictory CL"
                    return False, "False positive: Normal request also timed out"
        except Exception as e:
            return False, str(e)

    async def detect_h2_te(self, url: str) -> Tuple[bool, str]:
        """
        Detects H2.TE desync.
        Sends an H2 request with a 'transfer-encoding' header.
        H2 forbids TE, but if front-end passes it and back-end honors it -> desync.
        """
        # Payload: TE header present. Back-end might wait for chunks.
        headers = {
            "transfer-encoding": "chunked",
            "user-agent": "recon-cli/2.0 h2-hunter"
        }
        body = b"0\r\n\r\n" # Empty chunk
        
        try:
            async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=5.0) as client:
                try:
                    # In H2, TE header should technically be an error or stripped.
                    # If it's passed to an H1.1 back-end, it might wait for more data.
                    resp = await client.post(url, headers=headers, content=b"x=1") 
                    # If vulnerable, back-end might wait for the rest of the "chunked" body.
                    # Here we send a non-chunked body but tell it it IS chunked.
                    return False, f"Received {resp.status_code} - TE likely ignored or stripped"
                except (httpx.TimeoutException, asyncio.TimeoutError):
                    if await self._verify_normal(url):
                        return True, "H2.TE desync: Timeout on TE: chunked header"
                    return False, "False positive: Normal request also timed out"
        except Exception as e:
            # Some H2 implementations might throw an error if we try to send TE
            return False, f"Error (likely protection): {e}"

    async def _verify_normal(self, url: str) -> bool:
        """Verifies that a normal request succeeds quickly."""
        try:
            async with httpx.AsyncClient(http2=True, verify=self.verify_tls, timeout=2.0) as client:
                resp = await client.get(url)
                return resp.status_code < 500
        except Exception:
            return False
