"""
Async HTTP Client - عميل HTTP غير متزامن

يوفر طلبات HTTP متزامنة وسريعة مع:
- Connection pooling
- Rate limiting مدمج
- Retry مع exponential backoff
- Timeout قابل للتخصيص
- دعم للـ concurrent requests

Example:
    >>> async with AsyncHTTPClient() as client:
    ...     results = await client.get_many(["https://example.com", "https://test.com"])
    ...     for result in results:
    ...         print(f"{result['url']}: {result['status']}")
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
import logging

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
    
    def __init__(self, rate: float):
        """
        Args:
            rate: الطلبات في الثانية
        """
        self.rate = rate
        self.min_interval = 1.0 / rate if rate > 0 else 0
        self._last_request: Dict[str, float] = {}
        self._lock = asyncio.Lock()
    
    async def acquire(self, host: str = "") -> None:
        """انتظار حتى يُسمح بالطلب"""
        async with self._lock:
            now = time.monotonic()
            last = self._last_request.get(host, 0)
            wait_time = self.min_interval - (now - last)
            
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            
            self._last_request[host] = time.monotonic()


class AsyncHTTPClient:
    """
    عميل HTTP غير متزامن عالي الأداء.
    
    الميزات:
    - Connection pooling مع حد لكل مضيف
    - Rate limiting تلقائي
    - Retry مع exponential backoff
    - دعم طلبات متعددة متزامنة
    
    Example:
        >>> config = HTTPClientConfig(max_concurrent=100)
        >>> async with AsyncHTTPClient(config) as client:
        ...     # طلب واحد
        ...     response = await client.get("https://example.com")
        ...     
        ...     # طلبات متعددة
        ...     urls = ["https://a.com", "https://b.com", "https://c.com"]
        ...     responses = await client.get_many(urls)
    """
    
    def __init__(self, config: Optional[HTTPClientConfig] = None):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp not installed. Run: pip install aiohttp")
        
        self.config = config or HTTPClientConfig()
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._rate_limiter = RateLimiter(self.config.requests_per_second)
        self._stats = {
            "requests": 0,
            "successes": 0,
            "failures": 0,
            "retries": 0,
            "total_time": 0.0,
        }
    
    async def __aenter__(self) -> "AsyncHTTPClient":
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
    
    async def start(self) -> None:
        """بدء العميل وإنشاء الـ session"""
        if self._session is not None:
            return
        
        # Timeout configuration
        timeout = ClientTimeout(
            connect=self.config.connect_timeout,
            sock_read=self.config.read_timeout,
            total=self.config.total_timeout,
        )
        
        # Connection pool
        connector = TCPConnector(
            limit=self.config.max_concurrent,
            limit_per_host=self.config.max_per_host,
            keepalive_timeout=30 if self.config.keep_alive else 0,
            ssl=self.config.verify_ssl,
        )
        
        # Default headers
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
        
        logger.debug(
            "AsyncHTTPClient started: max_concurrent=%d, max_per_host=%d",
            self.config.max_concurrent,
            self.config.max_per_host,
        )
    
    async def close(self) -> None:
        """إغلاق العميل"""
        if self._session:
            await self._session.close()
            self._session = None
        
        logger.debug(
            "AsyncHTTPClient closed: %d requests, %d successes, %d failures",
            self._stats["requests"],
            self._stats["successes"],
            self._stats["failures"],
        )
    
    def _get_host(self, url: str) -> str:
        """استخراج الـ host من URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            return ""
    
    def _get_host_semaphore(self, host: str) -> asyncio.Semaphore:
        """الحصول على semaphore لمضيف محدد"""
        if host not in self._host_semaphores:
            self._host_semaphores[host] = asyncio.Semaphore(self.config.max_per_host)
        return self._host_semaphores[host]
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
    ) -> HTTPResponse:
        """
        تنفيذ طلب GET.
        
        Args:
            url: الـ URL المطلوب
            headers: headers إضافية
            follow_redirects: متابعة التحويلات
            
        Returns:
            HTTPResponse مع النتيجة
        """
        if not self._session:
            await self.start()
        
        host = self._get_host(url)
        host_sem = self._get_host_semaphore(host)
        
        async with self._semaphore:
            async with host_sem:
                await self._rate_limiter.acquire(host)
                return await self._request_with_retry(url, headers, follow_redirects)
    
    async def _request_with_retry(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        follow_redirects: bool,
    ) -> HTTPResponse:
        """تنفيذ طلب مع retry"""
        last_error = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                return await self._do_request(url, headers, follow_redirects)
            except Exception as e:
                last_error = str(e)
                self._stats["retries"] += 1
                
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (self.config.retry_multiplier ** attempt)
                    logger.debug("Retry %d for %s after %.1fs: %s", attempt + 1, url, delay, e)
                    await asyncio.sleep(delay)
        
        self._stats["failures"] += 1
        return HTTPResponse(
            url=url,
            status=0,
            headers={},
            body="",
            elapsed=0,
            error=last_error,
        )
    
    async def _do_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        follow_redirects: bool,
    ) -> HTTPResponse:
        """تنفيذ طلب واحد"""
        start_time = time.monotonic()
        self._stats["requests"] += 1
        
        try:
            async with self._session.get(
                url,
                headers=headers,
                allow_redirects=follow_redirects,
            ) as response:
                body = await response.text()
                elapsed = time.monotonic() - start_time
                self._stats["total_time"] += elapsed
                self._stats["successes"] += 1
                
                return HTTPResponse(
                    url=str(response.url),
                    status=response.status,
                    headers=dict(response.headers),
                    body=body,
                    elapsed=elapsed,
                )
        except asyncio.TimeoutError:
            raise Exception(f"Timeout after {self.config.total_timeout}s")
        except aiohttp.ClientError as e:
            raise Exception(f"Client error: {e}")
    
    async def get_many(
        self,
        urls: List[str],
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        return_exceptions: bool = True,
    ) -> List[HTTPResponse]:
        """
        تنفيذ طلبات متعددة بشكل متزامن.
        
        Args:
            urls: قائمة الـ URLs
            headers: headers مشتركة
            follow_redirects: متابعة التحويلات
            return_exceptions: إرجاع الأخطاء بدلاً من رفعها
            
        Returns:
            قائمة HTTPResponse بنفس ترتيب الـ URLs
            
        Example:
            >>> urls = ["https://a.com", "https://b.com"]
            >>> responses = await client.get_many(urls)
            >>> for resp in responses:
            ...     if resp.error:
            ...         print(f"Error: {resp.error}")
            ...     else:
            ...         print(f"{resp.url}: {resp.status}")
        """
        if not self._session:
            await self.start()
        
        tasks = [
            self.get(url, headers, follow_redirects)
            for url in urls
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=return_exceptions)
        
        # تحويل الاستثناءات إلى HTTPResponse
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(HTTPResponse(
                    url=urls[i],
                    status=0,
                    headers={},
                    body="",
                    elapsed=0,
                    error=str(result),
                ))
            else:
                processed.append(result)
        
        return processed
    
    async def head(self, url: str) -> HTTPResponse:
        """تنفيذ طلب HEAD"""
        if not self._session:
            await self.start()
        
        host = self._get_host(url)
        host_sem = self._get_host_semaphore(host)
        start_time = time.monotonic()
        
        async with self._semaphore:
            async with host_sem:
                await self._rate_limiter.acquire(host)
                
                try:
                    async with self._session.head(url, allow_redirects=True) as response:
                        elapsed = time.monotonic() - start_time
                        return HTTPResponse(
                            url=str(response.url),
                            status=response.status,
                            headers=dict(response.headers),
                            body="",
                            elapsed=elapsed,
                        )
                except Exception as e:
                    return HTTPResponse(
                        url=url,
                        status=0,
                        headers={},
                        body="",
                        elapsed=0,
                        error=str(e),
                    )
    
    def get_stats(self) -> Dict[str, Any]:
        """إحصائيات العميل"""
        avg_time = 0.0
        if self._stats["requests"] > 0:
            avg_time = self._stats["total_time"] / self._stats["requests"]
        
        return {
            **self._stats,
            "avg_response_time": round(avg_time, 3),
            "success_rate": round(
                self._stats["successes"] / max(1, self._stats["requests"]) * 100, 1
            ),
        }


# ═══════════════════════════════════════════════════════════
#                     Convenience Functions
# ═══════════════════════════════════════════════════════════

async def fetch_urls(
    urls: List[str],
    max_concurrent: int = 50,
    timeout: float = 30.0,
) -> List[HTTPResponse]:
    """
    جلب URLs متعددة بسهولة.
    
    Args:
        urls: قائمة الـ URLs
        max_concurrent: الحد الأقصى للطلبات المتزامنة
        timeout: timeout لكل طلب
        
    Returns:
        قائمة HTTPResponse
        
    Example:
        >>> responses = await fetch_urls([
        ...     "https://example.com",
        ...     "https://test.com",
        ... ])
    """
    config = HTTPClientConfig(
        max_concurrent=max_concurrent,
        total_timeout=timeout,
    )
    
    async with AsyncHTTPClient(config) as client:
        return await client.get_many(urls)


async def check_urls_alive(
    urls: List[str],
    max_concurrent: int = 100,
) -> Dict[str, bool]:
    """
    فحص URLs حية أم لا.
    
    Args:
        urls: قائمة الـ URLs
        max_concurrent: الحد الأقصى
        
    Returns:
        Dict من URL -> bool (حي أم لا)
    """
    config = HTTPClientConfig(
        max_concurrent=max_concurrent,
        total_timeout=10.0,
    )
    
    async with AsyncHTTPClient(config) as client:
        tasks = [client.head(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        alive = {}
        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                alive[url] = False
            else:
                alive[url] = result.ok
        
        return alive


def run_fetch(urls: List[str], **kwargs) -> List[HTTPResponse]:
    """
    Synchronous wrapper لـ fetch_urls.
    
    Example:
        >>> responses = run_fetch(["https://example.com"])
    """
    return asyncio.run(fetch_urls(urls, **kwargs))
