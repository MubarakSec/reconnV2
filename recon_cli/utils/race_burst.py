from __future__ import annotations

import asyncio
import ssl
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse


class BurstResponse:
    def __init__(self, status: int, headers: Dict[str, str], body: str, elapsed: float):
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed = elapsed


class RaceBurstClient:
    """
    Implements 'Last-Byte Sync' technique for precise race condition testing.
    Sends all but the last byte of multiple requests, then releases them all at once.
    """

    def __init__(self, timeout: float = 20.0, verify_tls: bool = False):
        self.timeout = timeout
        self.verify_tls = verify_tls

    async def sync_burst(
        self, 
        url: str, 
        method: str = "POST", 
        headers: Dict[str, str] = None, 
        body: bytes = b"", 
        count: int = 20
    ) -> List[Tuple[Optional[BurstResponse], Optional[str]]]:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if not host:
            return [(None, "Invalid host")] * count

        # Prepare base headers
        base_headers = {
            "Host": host,
            "User-Agent": "recon-cli/2.0 race-burst",
            "Connection": "close",
            "Content-Length": str(len(body))
        }
        if headers:
            base_headers.update(headers)

        # Construct raw request
        header_str = f"{method} {path} HTTP/1.1\r\n"
        for k, v in base_headers.items():
            header_str += f"{k}: {v}\r\n"
        header_str += "\r\n"
        
        full_payload = header_str.encode("utf-8") + body
        if not full_payload:
            return [(None, "Empty payload")] * count

        # Split into all-but-last and last byte
        pre_payload = full_payload[:-1]
        last_byte = full_payload[-1:]

        # 1. Open all connections
        connections = []
        try:
            connect_tasks = []
            for _ in range(count):
                connect_tasks.append(self._open_connection(host, port, parsed.scheme == "https"))
            
            connections = await asyncio.gather(*connect_tasks, return_exceptions=True)
            
            # Filter successful connections
            valid_conns = []
            results = [None] * count
            for i, conn in enumerate(connections):
                if isinstance(conn, Exception):
                    results[i] = (None, str(conn))
                elif isinstance(conn, tuple):
                    valid_conns.append((i, conn[0], conn[1]))
                else:
                    results[i] = (None, "Unknown connection error")

            if not valid_conns:
                return results

            # 2. Send pre-payload to all
            for idx, reader, writer in valid_conns:
                writer.write(pre_payload)
                # No await drain here to keep buffers filled but not necessarily flushed to wire yet
                # actually drain is probably good to ensure it's sitting in OS buffers

            await asyncio.gather(*[w.drain() for _, r, w in valid_conns], return_exceptions=True)

            # Small sleep to ensure server is ready and waiting
            await asyncio.sleep(0.1)

            # 3. Release LAST BYTE simultaneously
            start_time = time.time()
            for idx, reader, writer in valid_conns:
                writer.write(last_byte)
            
            # Final flush
            await asyncio.gather(*[w.drain() for _, r, w in valid_conns], return_exceptions=True)

            # 4. Read responses
            read_tasks = []
            for idx, reader, writer in valid_conns:
                read_tasks.append(self._read_response(reader, writer, start_time))
            
            read_results = await asyncio.gather(*read_tasks, return_exceptions=True)
            
            for (idx, r, w), res in zip(valid_conns, read_results):
                if isinstance(res, Exception):
                    results[idx] = (None, str(res))
                else:
                    results[idx] = res

            return results

        finally:
            # Clean up all writers
            for conn in connections:
                if isinstance(conn, tuple) and len(conn) == 2:
                    _, writer = conn
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except: pass

    async def _open_connection(self, host: str, port: int, is_https: bool):
        if is_https:
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=self.timeout
            )
        else:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )

    async def _read_response(self, reader, writer, start_time) -> Tuple[Optional[BurstResponse], Optional[str]]:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            if not line: return None, "Empty response"
            
            parts = line.decode('utf-8', errors='ignore').split(' ', 2)
            if len(parts) < 2: return None, "Invalid response"
            
            status = int(parts[1])
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
                if not line or line == b'\r\n': break
                header_line = line.decode('utf-8', errors='ignore').strip()
                if ':' in header_line:
                    k, v = header_line.split(':', 1)
                    headers[k.strip()] = v.strip()

            body_bytes = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
            body = body_bytes.decode('utf-8', errors='ignore')
            
            return BurstResponse(status, headers, body, time.time() - start_time), None
        except Exception as e:
            return None, str(e)
