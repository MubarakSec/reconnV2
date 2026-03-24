from __future__ import annotations

import asyncio
import aiohttp
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse


class WSFuzzer:
    """
    WebSocket Fuzzer for message tampering and security testing.
    Attempts to find IDORs, unauthenticated access, and logic flaws in WS streams.
    """

    def __init__(self, timeout: float = 10.0, verify_tls: bool = False):
        self.timeout = timeout
        self.verify_tls = verify_tls

    async def fuzz_endpoint(
        self, 
        url: str, 
        headers: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Connects to a WS endpoint, listens for messages, and attempts basic tampering.
        """
        findings = []
        
        # 1. Test unauthenticated access (if headers provided, try without them)
        if headers and any(h.lower() in ["authorization", "cookie"] for h in headers):
            is_vuln, info = await self.test_unauth_access(url)
            if is_vuln:
                findings.append({
                    "type": "ws_unauth",
                    "confidence": 0.8,
                    "description": "WebSocket endpoint allows unauthenticated connection",
                    "evidence": info
                })

        # 2. Connect and Intercept/Fuzz messages
        try:
            connector = aiohttp.TCPConnector(ssl=self.verify_tls)
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                async with session.ws_connect(url, timeout=self.timeout) as ws:
                    # Send a generic "hello" or probe message if it's a known type
                    # (In a real scenario, we'd adapt to socket.io etc.)
                    
                    # Listen for a few initial messages to understand the protocol
                    initial_messages = []
                    try:
                        for _ in range(3):
                            msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                initial_messages.append(msg.data)
                            elif msg.type == aiohttp.WSMsgType.CLOSED:
                                break
                    except asyncio.TimeoutError:
                        pass

                    for msg_data in initial_messages:
                        # Attempt to parse as JSON for IDOR testing
                        try:
                            data = json.loads(msg_data)
                            idor_vuln = self._check_json_for_ids(data)
                            if idor_vuln:
                                findings.append({
                                    "type": "ws_info_leak",
                                    "confidence": 0.6,
                                    "description": "WebSocket leaked potential sensitive IDs in initial stream",
                                    "evidence": {"data": data}
                                })
                                
                            # Tampering Test: If it looks like a subscription/request, try to modify it
                            # This is complex without a full proxy, but we can try basic "re-send with change"
                        except json.JSONDecodeError:
                            pass
                            
        except Exception as e:
            # Connection failed or timed out
            pass

        return findings

    async def test_unauth_access(self, url: str) -> Tuple[bool, Dict[str, Any]]:
        """Checks if the WS endpoint accepts connections without credentials."""
        try:
            connector = aiohttp.TCPConnector(ssl=self.verify_tls)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.ws_connect(url, timeout=3.0) as ws:
                    return True, {"status": "Connected without headers"}
        except Exception as e:
            return False, {"error": str(e)}

    def _check_json_for_ids(self, data: Any) -> bool:
        """Heuristic check for sensitive-looking IDs in JSON."""
        if isinstance(data, dict):
            for k, v in data.items():
                k_low = k.lower()
                if any(x in k_low for x in ["id", "user", "account", "email", "secret"]):
                    # Simple check: if it's a number or a long hex string
                    if isinstance(v, (int, float)) or (isinstance(v, str) and len(v) > 8):
                        return True
                if self._check_json_for_ids(v): return True
        elif isinstance(data, list):
            for item in data:
                if self._check_json_for_ids(item): return True
        return False
