from __future__ import annotations

import asyncio
import ssl
from typing import Optional, Tuple, Dict
from urllib.parse import urlparse


class RawHTTPResponse:
    def __init__(self, status: int, headers: Dict[str, str], body: str, elapsed: float):
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed = elapsed


async def send_raw_http(
    url: str, 
    raw_payload: bytes, 
    timeout: float = 10.0
) -> Tuple[Optional[RawHTTPResponse], Optional[str]]:
    """
    Sends a raw bytes payload over a TCP/TLS socket.
    Returns (Response, ErrorMessage).
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    if not host:
        return None, "Invalid host"

    start_time = asyncio.get_event_loop().time()
    reader = None
    writer = None
    
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            # For some bug bounty targets, we might need to be lenient
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

        writer.write(raw_payload)
        await writer.drain()

        # Read response
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line:
                return None, "Empty response"
            
            # Parse Status Line
            parts = line.decode('utf-8', errors='ignore').split(' ', 2)
            if len(parts) < 2:
                return None, "Invalid HTTP response"
            
            status = int(parts[1])
            headers = {}
            
            # Read Headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if not line or line == b'\r\n':
                    break
                header_line = line.decode('utf-8', errors='ignore').strip()
                if ':' in header_line:
                    k, v = header_line.split(':', 1)
                    headers[k.strip()] = v.strip()

            # Read Body (limit to 1MB)
            body_bytes = await asyncio.wait_for(reader.read(1024 * 1024), timeout=timeout)
            body = body_bytes.decode('utf-8', errors='ignore')
            
            elapsed = asyncio.get_event_loop().time() - start_time
            return RawHTTPResponse(status, headers, body, elapsed), None

        except asyncio.TimeoutError:
            # For Smuggling, a timeout is often a SIGN of a vulnerability (TE.CL or CL.TE desync)
            return None, "TIMEOUT"
            
    except Exception as e:
        return None, str(e)
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
