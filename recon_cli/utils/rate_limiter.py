"""
Rate Limiter - للتحكم في سرعة الطلبات
يمنع الحظر من الخوادم ويحافظ على أداء مستقر
"""

from __future__ import annotations

import asyncio
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional
from functools import wraps


@dataclass
class RateLimitConfig:
    """إعدادات Rate Limiting"""

    requests_per_second: float = 10.0  # الطلبات في الثانية
    burst_size: int = 20  # الحد الأقصى للطلبات المتتالية
    per_host_limit: float = 5.0  # الطلبات لكل مضيف
    cooldown_on_429: float = 30.0  # الانتظار عند 429
    cooldown_on_error: float = 5.0  # الانتظار عند الخطأ
    backoff_factor: float = 2.0
    max_backoff: float = 60.0


@dataclass
class TokenBucket:
    """Token Bucket Algorithm للتحكم في معدل الطلبات"""

    capacity: float
    rate: float  # tokens per second
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        self.tokens = self.capacity
        self.last_update = time.monotonic()

    def _refill(self) -> None:
        """إعادة ملء الـ tokens"""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now

    def acquire(self, tokens: float = 1.0, timeout: Optional[float] = None) -> bool:
        """الحصول على tokens للسماح بالطلب"""
        deadline = time.monotonic() + timeout if timeout else None

        with self.lock:
            while True:
                self._refill()

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                if deadline and time.monotonic() >= deadline:
                    return False

                # حساب وقت الانتظار
                wait_time = (tokens - self.tokens) / self.rate
                if deadline:
                    wait_time = min(wait_time, deadline - time.monotonic())

                if wait_time > 0:
                    time.sleep(min(wait_time, 0.1))  # انتظار قصير

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """محاولة الحصول على tokens بدون انتظار"""
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def consume(self, tokens: float = 1.0) -> bool:
        """استهلاك tokens بدون انتظار (متوافق مع الاختبارات)"""
        with self.lock:
            self._refill()
            if tokens <= 0:
                return True
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class RateLimiter:
    """
    مُحدد معدل الطلبات الذكي

    الميزات:
    - Token Bucket لكل مضيف
    - تتبع الأخطاء والاستجابات 429
    - Adaptive rate limiting
    - دعم الهيكلية الهرمية (Parent/Child)
    """

    def __init__(
        self,
        config: Optional[RateLimitConfig] = None,
        parent: Optional[RateLimiter] = None,
    ):
        self.config = config or RateLimitConfig()
        self.parent = parent
        self._global_bucket = TokenBucket(
            capacity=self.config.burst_size, rate=self.config.requests_per_second
        )
        self._host_buckets: Dict[str, TokenBucket] = {}
        self._host_cooldowns: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
        self._stats = {
            "total_requests": 0,
            "total_429s": 0,
            "total_errors": 0,
        }

    def _get_host_bucket(self, host: str) -> TokenBucket:
        """الحصول على bucket خاص بالمضيف"""
        with self._lock:
            if host not in self._host_buckets:
                self._host_buckets[host] = TokenBucket(
                    capacity=max(1, self.config.burst_size // 2),
                    rate=self.config.per_host_limit,
                )
            return self._host_buckets[host]

    def _extract_host(self, url: str) -> str:
        """استخراج المضيف من URL"""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            return (
                parsed.hostname
                or parsed.netloc
                or parsed.path.split("/")[0]
                or "unknown"
            )
        except Exception:
            return url

    def is_cooled_down(self, host: str) -> bool:
        """التحقق من انتهاء فترة التهدئة"""
        if self.parent and not self.parent.is_cooled_down(host):
            return False
        cooldown_until = self._host_cooldowns.get(host, 0)
        return time.monotonic() >= cooldown_until

    def set_cooldown(self, host: str, duration: float) -> None:
        """تعيين فترة تهدئة للمضيف وللأب إذا وجد"""
        with self._lock:
            self._host_cooldowns[host] = time.monotonic() + duration
        if self.parent:
            self.parent.set_cooldown(host, duration)

    def wait_for_slot(self, url: str, timeout: Optional[float] = 30.0) -> bool:
        """
        انتظار حتى يُسمح بالطلب

        Returns:
            True إذا تم الحصول على إذن، False إذا انتهى الوقت
        """
        host = self._extract_host(url)
        start_time = time.monotonic()

        # 1. التنسيق مع الأب أولاً (إذا وجد)
        if self.parent:
            if not self.parent.wait_for_slot(url, timeout=timeout):
                return False
            # تحديث الوقت المتبقي
            if timeout:
                elapsed = time.monotonic() - start_time
                timeout = max(0.1, timeout - elapsed)

        # 2. التحقق من التهدئة الخاصة بنا
        if not self.is_cooled_down(host):
            remaining = self._host_cooldowns[host] - time.monotonic()
            if remaining > 0:
                if timeout and remaining > timeout:
                    return False
                time.sleep(remaining)

        # 3. الحصول على إذن عام من الـ bucket الخاص بنا
        if not self._global_bucket.acquire(timeout=timeout):
            return False

        # 4. الحصول على إذن للمضيف من الـ bucket الخاص بنا
        host_bucket = self._get_host_bucket(host)
        allowed = host_bucket.acquire(timeout=timeout)
        if allowed:
            self._stats["total_requests"] += 1
        return allowed

    def on_response(self, url: str, status_code: int) -> None:
        """تحديث بناءً على الاستجابة وتمريرها للأب"""
        host = self._extract_host(url)

        if status_code == 429:
            self.set_cooldown(host, self.config.cooldown_on_429)
            self._stats["total_429s"] += 1
        elif status_code >= 500:
            self.set_cooldown(host, self.config.cooldown_on_error)

        if self.parent:
            self.parent.on_response(url, status_code)

    def on_error(self, url: str) -> None:
        """تحديث عند حدوث خطأ وتمريره للأب"""
        host = self._extract_host(url)
        self.set_cooldown(host, self.config.cooldown_on_error)
        self._stats["total_errors"] += 1

        if self.parent:
            self.parent.on_error(url)

    def stats(self) -> Dict[str, object]:
        """إحصائيات Rate Limiter"""
        stats = dict(self._stats)
        stats.update(
            {
                "global_tokens": self._global_bucket.tokens,
                "host_count": len(self._host_buckets),
                "hosts_tracked": len(self._host_buckets),
                "cooldowns_active": sum(
                    1 for t in self._host_cooldowns.values() if time.monotonic() < t
                ),
            }
        )
        return stats


# Decorator للاستخدام السهل
def rate_limited(limiter: RateLimiter):
    """
    Decorator لتطبيق Rate Limiting على دوال

    مثال:
        limiter = RateLimiter()

        @rate_limited(limiter)
        def fetch_url(url):
            return requests.get(url)
    """

    def decorator(func):
        @wraps(func)
        def wrapper(url, *args, **kwargs):
            if not limiter.wait_for_slot(url):
                raise TimeoutError(f"Rate limit timeout for {url}")

            try:
                result = func(url, *args, **kwargs)
                # استخراج status code إذا كان response
                if hasattr(result, "status_code"):
                    limiter.on_response(url, result.status_code)
                return result
            except Exception:
                limiter.on_error(url)
                raise

        return wrapper

    return decorator


# Async version
class AsyncRateLimiter:
    """نسخة async من Rate Limiter"""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._semaphore = asyncio.Semaphore(self.config.burst_size)
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._last_request: Dict[str, float] = defaultdict(float)

    def _get_host_semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_semaphores:
            self._host_semaphores[host] = asyncio.Semaphore(
                max(1, self.config.burst_size // 4)
            )
        return self._host_semaphores[host]

    async def acquire(self, url: str) -> None:
        """الحصول على إذن للطلب (async)"""
        from urllib.parse import urlparse

        host = urlparse(url).netloc

        # الانتظار للـ semaphore العام
        await self._semaphore.acquire()

        # الانتظار للـ semaphore الخاص بالمضيف
        host_sem = self._get_host_semaphore(host)
        await host_sem.acquire()

        # الانتظار بين الطلبات
        min_interval = 1.0 / self.config.per_host_limit
        elapsed = time.monotonic() - self._last_request[host]
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        self._last_request[host] = time.monotonic()

    def release(self, url: str) -> None:
        """تحرير الإذن"""
        from urllib.parse import urlparse

        host = urlparse(url).netloc

        self._semaphore.release()
        if host in self._host_semaphores:
            self._host_semaphores[host].release()
