"""
Async HTTP Client - عميل HTTP غير متزامن

يوفر طلبات HTTP متزامنة وسريعة مع:
- Connection pooling
- Rate limiting مدمج
- Retry مع exponential backoff
- Timeout قابل للتخصيص
- دعم للـ concurrent requests
- ELITE: 401 Auto Re-auth logic
"""

from __future__ import annotations

import asyncio
import inspect
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Any, AsyncIterator, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse
import logging

if TYPE_CHECKING:
    from recon_cli.pipeline.context import PipelineContext

try:
    import aiohttp
    from aiohttp import ClientTimeout, TCPConnector

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None

logger = logging.getLogger(__name__)


@dataclass
class HTTPClientConfig:
    """إعدادات عميل HTTP"""

    # Concurrency
    max_concurrent: int = 50  # الحد الأقصى للطلبات المتزامنة
    max_per_host: int = 10  # الحد الأقصى لكل مضيف

    # Timeouts (بالثواني)
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    total_timeout: float = 60.0

    # Retry
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_multiplier: float = 2.0

    # Rate limiting
    requests_per_second: float = 20.0

    # Connection
    keep_alive: bool = True
    verify_ssl: bool = True

    # Headers
    user_agent: str = "ReconnV2/0.1.0"
    default_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class RetryConfig:
    """Backward-compatible retry configuration."""

    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0

    def get_delay(self, attempt: int) -> float:
        delay = self.base_delay * (self.exponential_base**attempt)
        return min(delay, self.max_delay)


@dataclass
class HTTPResponse:
    """نتيجة طلب HTTP"""

    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        """هل الطلب ناجح (2xx)"""
        return 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        """هل تم التحويل (3xx)"""
        return 300 <= self.status < 400

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body_length": len(self.body),
            "elapsed": self.elapsed,
            "error": self.error,
        }


class RateLimiter:
    """Rate limiter بسيط للـ async requests"""

    def __init__(
        self,
        rate: Optional[float] = None,
        requests_per_second: Optional[float] = None,
        burst_size: int = 1,
    ):
        """
        Args:
            rate: الطلبات في الثانية
        """
        effective_rate = (
            requests_per_second if requests_per_second is not None else rate
        )
        self.rate = float(effective_rate or 0.0)
        self.burst_size = max(1, int(burst_size))
        self._lock = asyncio.Lock()
        self._host_tokens: Dict[str, float] = {}
        self._host_updated: Dict[str, float] = {}

    async def acquire(self, host: str = "") -> None:
        """انتظار حتى يُسمح بالطلب"""
        async with self._lock:
            now = time.monotonic()
            tokens = self._host_tokens.get(host, float(self.burst_size))
            last = self._host_updated.get(host, now)

            if self.rate > 0:
                elapsed = max(0.0, now - last)
                tokens = min(float(self.burst_size), tokens + (elapsed * self.rate))
                if tokens < 1.0:
                    wait_time = (1.0 - tokens) / self.rate
                    await asyncio.sleep(wait_time)
                    now = time.monotonic()
                    elapsed = max(0.0, now - last)
                    tokens = min(float(self.burst_size), tokens + (elapsed * self.rate))
            tokens = max(0.0, tokens - 1.0)
            self._host_tokens[host] = tokens
            self._host_updated[host] = time.monotonic()


class AsyncHTTPClient:
    """
    Async HTTP Client with Connection Pooling and Rate Limiting.
    Elite: Added 401 Re-auth support.
    """

    def __init__(
        self,
        config: Optional[HTTPClientConfig] = None,
        *,
        context: Optional["PipelineContext"] = None,
        timeout: Optional[float] = None,
        max_connections: Optional[int] = None,
        rate_limit: Optional[float] = None,
        retry_config: Optional[RetryConfig] = None,
    ):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp not installed. Run: pip install aiohttp")

        base_config = replace(config) if config else HTTPClientConfig()
        if timeout is not None:
            timeout = float(timeout)
            base_config.total_timeout = timeout
            base_config.connect_timeout = min(base_config.connect_timeout, timeout)
            base_config.read_timeout = min(base_config.read_timeout, timeout)
        if max_connections is not None:
            base_config.max_concurrent = int(max_connections)
        if rate_limit is not None:
            base_config.requests_per_second = float(rate_limit)
        if retry_config is not None:
            base_config.max_retries = int(retry_config.max_retries)
            base_config.retry_delay = float(retry_config.base_delay)
            base_config.retry_multiplier = float(retry_config.exponential_base)

        self.config = base_config
        self.context = context
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._rate_limiter = RateLimiter(self.config.requests_per_second)
        self._stats = {
            "requests": 0,
            "successes": 0,
            "failures": 0,
            "retries": 0,
            "auth_401_count": 0,
            "reauth_success": 0,
            "total_time": 0.0,
        }

    async def __aenter__(self) -> "AsyncHTTPClient":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def start(self) -> None:
        if self._session is not None:
            return

        timeout = ClientTimeout(
            connect=self.config.connect_timeout,
            sock_read=self.config.read_timeout,
            total=self.config.total_timeout,
        )

        connector = TCPConnector(
            limit=self.config.max_concurrent,
            limit_per_host=self.config.max_per_host,
            keepalive_timeout=30 if self.config.keep_alive else 0,
            ssl=self.config.verify_ssl,
        )

        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            **self.config.default_headers,
        }

        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
        )

        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    def _get_host(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            return ""

    def _get_host_semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_semaphores:
            self._host_semaphores[host] = asyncio.Semaphore(self.config.max_per_host)
        return self._host_semaphores[host]

    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, follow_redirects: bool = True) -> HTTPResponse:
        return await self._request("GET", url, headers=headers, follow_redirects=follow_redirects)

    async def post(self, url: str, headers: Optional[Dict[str, str]] = None, follow_redirects: bool = True, **kwargs: Any) -> HTTPResponse:
        return await self._request("POST", url, headers=headers, follow_redirects=follow_redirects, **kwargs)

    async def _request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, follow_redirects: bool = True, **kwargs: Any) -> HTTPResponse:
        if not self._session:
            await self.start()

        host = self._get_host(url)
        host_sem = self._get_host_semaphore(host)

        async with self._semaphore:
            async with host_sem:
                await self._rate_limiter.acquire(host)
                resp = await self._request_with_retry(method=method, url=url, headers=headers, follow_redirects=follow_redirects, **kwargs)
                
                # ELITE: Handle Session Expiry (401)
                if resp.status == 401 and self.context and self.context.auth_enabled():
                    self._stats["auth_401_count"] += 1
                    logger.warning("Session expired (401) for %s. Attempting auto re-auth...", url)
                    
                    # Run re-auth logic
                    reauth_success = await asyncio.to_thread(self.context._auth_manager.ensure_login, url)
                    if reauth_success:
                        self._stats["reauth_success"] += 1
                        logger.info("Auto re-auth SUCCESS. Retrying original request...")
                        # Refresh headers with new token
                        new_headers = self.context.auth_headers(headers)
                        return await self._request_with_retry(method=method, url=url, headers=new_headers, follow_redirects=follow_redirects, **kwargs)
                    else:
                        logger.error("Auto re-auth FAILED for %s", url)
                
                return resp

    async def _request_with_retry(self, method: str, url: str, headers: Optional[Dict[str, str]], follow_redirects: bool, **kwargs: Any) -> HTTPResponse:
        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries + 1):
            try:
                return await self._do_request(method=method, url=url, headers=headers, follow_redirects=follow_redirects, **kwargs)
            except Exception as e:
                last_error = e
                self._stats["retries"] += 1
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (self.config.retry_multiplier**attempt)
                    await asyncio.sleep(delay)

        self._stats["failures"] += 1
        if last_error is None: raise RuntimeError("Request failed")
        raise last_error

    async def _do_request(self, method: str, url: str, headers: Optional[Dict[str, str]], follow_redirects: bool, **kwargs: Any) -> HTTPResponse:
        start_time = time.monotonic()
        self._stats["requests"] += 1
        try:
            request_method = getattr(self._session, method.lower(), self._session.request)
            async with request_method(url, headers=headers, allow_redirects=follow_redirects, **kwargs) as response:
                body = await response.text()
                elapsed = time.monotonic() - start_time
                self._stats["total_time"] += elapsed
                self._stats["successes"] += 1
                return HTTPResponse(url=str(response.url), status=response.status, headers=dict(response.headers), body=body, elapsed=elapsed)
        except asyncio.TimeoutError: raise Exception(f"Timeout after {self.config.total_timeout}s")
        except Exception as e:
            if AIOHTTP_AVAILABLE and isinstance(e, aiohttp.ClientError): raise Exception(f"Client error: {e}")
            raise

    async def head(self, url: str) -> HTTPResponse:
        return await self._request("HEAD", url, follow_redirects=True)

    async def get_many(self, urls: List[str], headers: Optional[Dict[str, str]] = None, follow_redirects: bool = True, return_exceptions: bool = True) -> List[HTTPResponse]:
        if not self._session: await self.start()
        tasks = [self.get(url, headers, follow_redirects) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=return_exceptions)
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(HTTPResponse(url=urls[i], status=0, headers={}, body="", elapsed=0, error=str(result)))
            else: processed.append(result)
        return processed

    def get_stats(self) -> Dict[str, Any]:
        avg_time = self._stats["total_time"] / max(1, self._stats["requests"])
        return {**self._stats, "avg_response_time": round(avg_time, 3), "success_rate": round(self._stats["successes"] / max(1, self._stats["requests"]) * 100, 1)}
