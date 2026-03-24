from __future__ import annotations

import base64
import mmh3
import codecs
from typing import Optional

def calculate_favicon_hash(data: bytes) -> int:
    """
    Calculates the MMH3 hash of a favicon, Shodan-style.
    Shodan encodes the file in base64 and inserts newlines every 76 characters.
    """
    # Shodan's algorithm:
    # 1. Base64 encode the binary data
    # 2. Insert newlines every 76 characters (RFC 2045)
    # 3. Calculate MMH3 hash of that string
    
    b64 = base64.encodebytes(data)
    return mmh3.hash(b64)

async def fetch_favicon_hash(url: str, client: Any) -> Optional[int]:
    """Fetches a favicon from a URL and returns its hash."""
    try:
        resp = await client.get(url)
        if resp.status == 200 and resp.body:
            # Body might be string if AsyncHTTPClient auto-decodes
            # but favicons are binary. We need bytes.
            # Assuming AsyncHTTPClient needs a small fix to return bytes
            # or we use standard requests/httpx if needed.
            data = resp.body if isinstance(resp.body, bytes) else resp.body.encode('latin-1')
            return calculate_favicon_hash(data)
    except Exception:
        pass
    return None
