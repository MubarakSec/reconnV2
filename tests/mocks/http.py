"""
HTTP Mocks - Mocks للـ HTTP clients

للاختبار بدون اتصال حقيقي
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union
from unittest.mock import AsyncMock, MagicMock, patch


# ═══════════════════════════════════════════════════════════
#                     Mock Response
# ═══════════════════════════════════════════════════════════

@dataclass
class MockResponse:
    """Mock لـ HTTP Response"""
    
    status: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    json_data: Optional[Dict[str, Any]] = None
    text_data: Optional[str] = None
    raise_on_read: Optional[Exception] = None
    
    def __post_init__(self):
        if not self.headers:
            self.headers = {
                "content-type": "application/json",
                "server": "test-server",
            }
        
        if self.json_data and not self.body:
            self.body = json.dumps(self.json_data).encode()
        elif self.text_data and not self.body:
            self.body = self.text_data.encode()
    
    # Properties
    @property
    def status_code(self) -> int:
        return self.status
    
    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300
    
    @property
    def content_length(self) -> int:
        return len(self.body)
    
    # Async methods
    async def read(self) -> bytes:
        if self.raise_on_read:
            raise self.raise_on_read
        return self.body
    
    async def text(self) -> str:
        if self.text_data:
            return self.text_data
        return self.body.decode()
    
    async def json(self) -> Any:
        if self.json_data:
            return self.json_data
        return json.loads(self.body)
    
    # Context manager
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        pass
    
    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise Exception(f"HTTP {self.status}")


# ═══════════════════════════════════════════════════════════
#                     Mock HTTP Client
# ═══════════════════════════════════════════════════════════

class MockHTTPClient:
    """Mock لـ HTTP Client"""
    
    def __init__(self):
        self.responses: Dict[str, MockResponse] = {}
        self.default_response = MockResponse()
        self.call_history: List[Dict[str, Any]] = []
        self.closed = False
    
    # ─────────────────────────────────────────────────────────
    #                     Setup
    # ─────────────────────────────────────────────────────────
    
    def set_response(self, url: str, response: MockResponse) -> None:
        """تعيين response لـ URL"""
        self.responses[url] = response
    
    def set_responses(self, responses: Dict[str, MockResponse]) -> None:
        """تعيين responses متعددة"""
        self.responses.update(responses)
    
    def set_default(self, response: MockResponse) -> None:
        """تعيين default response"""
        self.default_response = response
    
    def mock_success(self, url: str, data: Any) -> None:
        """Mock لـ success response"""
        self.responses[url] = MockResponse(
            status=200,
            json_data=data if isinstance(data, dict) else None,
            text_data=data if isinstance(data, str) else None,
        )
    
    def mock_error(self, url: str, status: int = 500, message: str = "Error") -> None:
        """Mock لـ error response"""
        self.responses[url] = MockResponse(
            status=status,
            json_data={"error": message},
        )
    
    # ─────────────────────────────────────────────────────────
    #                     HTTP Methods
    # ─────────────────────────────────────────────────────────
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> MockResponse:
        """GET request"""
        return await self._request("GET", url, headers=headers, **kwargs)
    
    async def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> MockResponse:
        """POST request"""
        return await self._request(
            "POST", url,
            data=data, json=json, headers=headers,
            **kwargs
        )
    
    async def put(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> MockResponse:
        """PUT request"""
        return await self._request(
            "PUT", url,
            data=data, json=json, headers=headers,
            **kwargs
        )
    
    async def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> MockResponse:
        """DELETE request"""
        return await self._request("DELETE", url, headers=headers, **kwargs)
    
    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> MockResponse:
        """HEAD request"""
        return await self._request("HEAD", url, headers=headers, **kwargs)
    
    async def _request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> MockResponse:
        """تنفيذ request"""
        self.call_history.append({
            "method": method,
            "url": url,
            **kwargs,
        })
        
        # Find matching response
        response = self.responses.get(url, self.default_response)
        
        # Allow pattern matching
        for pattern, resp in self.responses.items():
            if "*" in pattern:
                import fnmatch
                if fnmatch.fnmatch(url, pattern):
                    response = resp
                    break
        
        return response
    
    # ─────────────────────────────────────────────────────────
    #                     Context Manager
    # ─────────────────────────────────────────────────────────
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()
    
    async def close(self) -> None:
        self.closed = True
    
    # ─────────────────────────────────────────────────────────
    #                     Inspection
    # ─────────────────────────────────────────────────────────
    
    def get_calls(self, method: Optional[str] = None) -> List[Dict[str, Any]]:
        """الحصول على الاستدعاءات"""
        if method:
            return [c for c in self.call_history if c["method"] == method]
        return self.call_history
    
    def was_called(self, url: str, method: Optional[str] = None) -> bool:
        """التحقق من استدعاء URL"""
        for call in self.call_history:
            if call["url"] == url:
                if method is None or call["method"] == method:
                    return True
        return False
    
    def call_count(self, url: Optional[str] = None) -> int:
        """عدد الاستدعاءات"""
        if url:
            return sum(1 for c in self.call_history if c["url"] == url)
        return len(self.call_history)
    
    def reset(self) -> None:
        """إعادة تعيين"""
        self.call_history.clear()


# ═══════════════════════════════════════════════════════════
#                     Mock Session
# ═══════════════════════════════════════════════════════════

class MockClientSession:
    """Mock لـ aiohttp.ClientSession"""
    
    def __init__(self):
        self._client = MockHTTPClient()
        self._closed = False
    
    def get(self, url: str, **kwargs):
        return _MockContextManager(self._client.get(url, **kwargs))
    
    def post(self, url: str, **kwargs):
        return _MockContextManager(self._client.post(url, **kwargs))
    
    def put(self, url: str, **kwargs):
        return _MockContextManager(self._client.put(url, **kwargs))
    
    def delete(self, url: str, **kwargs):
        return _MockContextManager(self._client.delete(url, **kwargs))
    
    def head(self, url: str, **kwargs):
        return _MockContextManager(self._client.head(url, **kwargs))
    
    async def close(self):
        self._closed = True
    
    @property
    def closed(self) -> bool:
        return self._closed
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()


class _MockContextManager:
    """Context manager للـ requests"""
    
    def __init__(self, coro):
        self._coro = coro
    
    def __await__(self):
        return self._coro.__await__()
    
    async def __aenter__(self):
        return await self._coro
    
    async def __aexit__(self, *args):
        pass


# ═══════════════════════════════════════════════════════════
#                     Patchers
# ═══════════════════════════════════════════════════════════

def mock_aiohttp_session(responses: Optional[Dict[str, MockResponse]] = None):
    """Mock لـ aiohttp session"""
    session = MockClientSession()
    if responses:
        session._client.set_responses(responses)
    
    return patch("aiohttp.ClientSession", return_value=session)


def mock_httpx_client(responses: Optional[Dict[str, MockResponse]] = None):
    """Mock لـ httpx client"""
    client = MockHTTPClient()
    if responses:
        client.set_responses(responses)
    
    return patch("httpx.AsyncClient", return_value=client)


# ═══════════════════════════════════════════════════════════
#                     Predefined Responses
# ═══════════════════════════════════════════════════════════

def success_response(data: Any = None) -> MockResponse:
    """إنشاء success response"""
    return MockResponse(
        status=200,
        json_data=data if isinstance(data, dict) else {"data": data},
    )


def error_response(status: int = 500, message: str = "Error") -> MockResponse:
    """إنشاء error response"""
    return MockResponse(
        status=status,
        json_data={"error": message},
    )


def timeout_response() -> MockResponse:
    """إنشاء timeout response"""
    return MockResponse(
        status=408,
        raise_on_read=asyncio.TimeoutError("Request timed out"),
    )


def not_found_response() -> MockResponse:
    """إنشاء 404 response"""
    return MockResponse(
        status=404,
        json_data={"error": "Not found"},
    )


def rate_limit_response() -> MockResponse:
    """إنشاء rate limit response"""
    return MockResponse(
        status=429,
        headers={"retry-after": "60"},
        json_data={"error": "Rate limit exceeded"},
    )


# ═══════════════════════════════════════════════════════════
#                     Response Builder
# ═══════════════════════════════════════════════════════════

class ResponseBuilder:
    """Builder لإنشاء responses"""
    
    def __init__(self):
        self._status = 200
        self._headers = {}
        self._body = b""
        self._json = None
        self._text = None
    
    def status(self, code: int) -> "ResponseBuilder":
        self._status = code
        return self
    
    def header(self, key: str, value: str) -> "ResponseBuilder":
        self._headers[key] = value
        return self
    
    def json(self, data: Dict) -> "ResponseBuilder":
        self._json = data
        return self
    
    def text(self, text: str) -> "ResponseBuilder":
        self._text = text
        return self
    
    def body(self, data: bytes) -> "ResponseBuilder":
        self._body = data
        return self
    
    def build(self) -> MockResponse:
        return MockResponse(
            status=self._status,
            headers=self._headers,
            body=self._body,
            json_data=self._json,
            text_data=self._text,
        )
