"""
Circuit Breaker Pattern - نمط قاطع الدائرة

يمنع الفشل المتتالي عن طريق "فتح الدائرة" عند تكرار الأخطاء.

States:
    CLOSED: طبيعي، الطلبات تمر
    OPEN: مفتوح، الطلبات تُرفض مباشرة
    HALF_OPEN: نصف مفتوح، يختبر إذا تعافى

Example:
    >>> breaker = CircuitBreaker("external-api")
    >>> async with breaker:
    ...     response = await call_external_api()
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, Optional, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """حالات الـ Circuit"""

    CLOSED = "closed"  # طبيعي
    OPEN = "open"  # مفتوح (يرفض الطلبات)
    HALF_OPEN = "half_open"  # نصف مفتوح (يختبر)


@dataclass
class CircuitStats:
    """إحصائيات الـ Circuit"""

    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    state_changes: int = 0

    @property
    def failure_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.failed_calls / self.total_calls

    @property
    def success_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.successful_calls / self.total_calls


class CircuitBreakerError(Exception):
    """Generic circuit breaker error."""


class CircuitOpenError(CircuitBreakerError):
    """خطأ: الـ Circuit مفتوح"""

    def __init__(self, name: str, retry_after: float):
        self.name = name
        self.retry_after = retry_after
        super().__init__(f"Circuit '{name}' is open. Retry after {retry_after:.1f}s")


@dataclass
class CircuitBreakerConfig:
    """إعدادات الـ Circuit Breaker"""

    # عتبة الفتح
    failure_threshold: int = 5
    """عدد الفشل المتتالي لفتح الـ circuit"""

    failure_rate_threshold: float = 0.5
    """نسبة الفشل لفتح الـ circuit (0.0 - 1.0)"""

    # مدة الفتح
    open_timeout: float = 30.0
    """مدة بقاء الـ circuit مفتوحاً (ثواني)"""

    # عتبة الإغلاق
    success_threshold: int = 3
    """عدد النجاح المتتالي في half-open لإغلاق الـ circuit"""

    # نافذة الحساب
    window_size: int = 10
    """عدد الطلبات لحساب نسبة الفشل"""

    # استثناءات للاستبعاد
    excluded_exceptions: tuple = ()
    """استثناءات لا تُحسب كفشل"""


class CircuitBreaker:
    """
    Circuit Breaker لحماية الخدمات الخارجية.

    Example:
        >>> breaker = CircuitBreaker("api", failure_threshold=3)
        >>>
        >>> # كـ context manager
        >>> async with breaker:
        ...     result = await external_call()
        >>>
        >>> # كـ decorator
        >>> @breaker.protect
        ... async def call_api():
        ...     return await http_client.get(url)
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        **kwargs,
    ):
        """
        Args:
            name: اسم الـ circuit
            config: الإعدادات
            **kwargs: إعدادات مباشرة
        """
        if "recovery_timeout" in kwargs and "open_timeout" not in kwargs:
            kwargs["open_timeout"] = kwargs.pop("recovery_timeout")
        self.name = name
        self.config = config or CircuitBreakerConfig(**kwargs)

        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._opened_at: float = 0.0
        self._lock = asyncio.Lock()
        self._recent_results: list = []

    @property
    def state(self) -> CircuitState:
        """الحالة الحالية"""
        return self._state

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        return self._state == CircuitState.HALF_OPEN

    @property
    def stats(self) -> CircuitStats:
        return self._stats

    @property
    def failure_threshold(self) -> int:
        return self.config.failure_threshold

    @property
    def success_threshold(self) -> int:
        return self.config.success_threshold

    @property
    def recovery_timeout(self) -> float:
        return self.config.open_timeout

    @property
    def success_count(self) -> int:
        return self._stats.successful_calls

    @property
    def failure_count(self) -> int:
        return self._stats.failed_calls

    def _should_open(self) -> bool:
        """هل يجب فتح الـ circuit"""
        # Check consecutive failures
        if self._stats.consecutive_failures >= self.config.failure_threshold:
            return True

        # Check failure rate
        if len(self._recent_results) >= self.config.window_size:
            failures = sum(1 for r in self._recent_results if not r)
            rate = failures / len(self._recent_results)
            if rate >= self.config.failure_rate_threshold:
                return True

        return False

    def _should_close(self) -> bool:
        """هل يجب إغلاق الـ circuit"""
        return self._stats.consecutive_successes >= self.config.success_threshold

    def _should_attempt_reset(self) -> bool:
        """هل يجب محاولة الإعادة"""
        if self._state != CircuitState.OPEN:
            return False

        elapsed = time.time() - self._opened_at
        return elapsed >= self.config.open_timeout

    def _record_success(self) -> None:
        """تسجيل نجاح"""
        self._stats.total_calls += 1
        self._stats.successful_calls += 1
        self._stats.consecutive_successes += 1
        self._stats.consecutive_failures = 0
        self._stats.last_success_time = time.time()

        self._recent_results.append(True)
        if len(self._recent_results) > self.config.window_size:
            self._recent_results.pop(0)

    def _record_failure(self) -> None:
        """تسجيل فشل"""
        self._stats.total_calls += 1
        self._stats.failed_calls += 1
        self._stats.consecutive_failures += 1
        self._stats.consecutive_successes = 0
        self._stats.last_failure_time = time.time()

        self._recent_results.append(False)
        if len(self._recent_results) > self.config.window_size:
            self._recent_results.pop(0)

    def _transition_to(self, new_state: CircuitState) -> None:
        """تغيير الحالة"""
        old_state = self._state
        self._state = new_state
        self._stats.state_changes += 1

        logger.info(
            "Circuit '%s' state changed: %s → %s",
            self.name,
            old_state.value,
            new_state.value,
        )

        if new_state == CircuitState.OPEN:
            self._opened_at = time.time()
        elif new_state == CircuitState.CLOSED:
            self._stats.consecutive_failures = 0
            self._stats.consecutive_successes = 0

    def allow_request(self) -> bool:
        """Synchronous state gate used by legacy callers/tests."""
        if self._state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._transition_to(CircuitState.HALF_OPEN)
                return True
            self._stats.rejected_calls += 1
            return False
        return True

    def record_success(self) -> None:
        self._record_success()
        if self._state == CircuitState.HALF_OPEN and self._should_close():
            self._transition_to(CircuitState.CLOSED)

    def record_failure(self) -> None:
        self._record_failure()
        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED and self._should_open():
            self._transition_to(CircuitState.OPEN)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self._state.value,
            "total_calls": self._stats.total_calls,
            "success_count": self._stats.successful_calls,
            "failure_count": self._stats.failed_calls,
            "rejected_calls": self._stats.rejected_calls,
            "failure_rate": self._stats.failure_rate,
            "success_rate": self._stats.success_rate,
            "state_changes": self._stats.state_changes,
            "last_failure_time": self._stats.last_failure_time,
            "last_success_time": self._stats.last_success_time,
        }

    async def _before_call(self) -> None:
        """قبل الاتصال"""
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to(CircuitState.HALF_OPEN)
                else:
                    retry_after = self.config.open_timeout - (
                        time.time() - self._opened_at
                    )
                    self._stats.rejected_calls += 1
                    raise CircuitOpenError(self.name, retry_after)

    async def _after_success(self) -> None:
        """بعد النجاح"""
        async with self._lock:
            self.record_success()

    async def _after_failure(self, error: Exception) -> None:
        """بعد الفشل"""
        # Check if excluded
        if isinstance(error, self.config.excluded_exceptions):
            return

        async with self._lock:
            self.record_failure()

    async def __aenter__(self) -> "CircuitBreaker":
        await self._before_call()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> bool:
        if exc_val is None:
            await self._after_success()
        elif not isinstance(exc_val, CircuitOpenError):
            await self._after_failure(exc_val)  # type: ignore[arg-type]
        return False

    def protect(
        self,
        func: Callable[[Any], T],
    ) -> Callable[[Any], T]:
        """
        Decorator لحماية function.

        Example:
            >>> @breaker.protect
            ... async def call_api():
            ...     return await http.get(url)
        """
        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs) -> T:
                async with self:
                    return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        return self.protect_sync(func)

    def protect_sync(self, func: Callable[[Any], T]) -> Callable[[Any], T]:
        """Decorator لحماية sync function."""

        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not self.allow_request():
                retry_after = max(
                    0.0, self.config.open_timeout - (time.time() - self._opened_at)
                )
                raise CircuitOpenError(self.name, retry_after)
            try:
                result = func(*args, **kwargs)
            except Exception:
                self.record_failure()
                raise
            self.record_success()
            return result

        return wrapper

    def reset(self) -> None:
        """إعادة تعيين الـ circuit"""
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._opened_at = 0.0
        self._recent_results.clear()
        logger.info("Circuit '%s' reset", self.name)


# ═══════════════════════════════════════════════════════════
#                     Circuit Breaker Registry
# ═══════════════════════════════════════════════════════════


class CircuitBreakerRegistry:
    """
    سجل مركزي للـ Circuit Breakers.

    Example:
        >>> registry = CircuitBreakerRegistry()
        >>> breaker = registry.get_or_create("api")
        >>>
        >>> # أو كـ singleton
        >>> from recon_cli.utils.circuit_breaker import registry
        >>> breaker = registry.get("api")
    """

    def __init__(self, default_config: Optional[CircuitBreakerConfig] = None):
        self.default_config = default_config or CircuitBreakerConfig()
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """الحصول على circuit موجود"""
        return self._breakers.get(name)

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> CircuitBreaker:
        """الحصول أو إنشاء circuit"""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                name,
                config or self.default_config,
            )
        return self._breakers[name]

    def all(self) -> Dict[str, CircuitBreaker]:
        """جميع الـ circuits"""
        return self._breakers.copy()

    def stats(self) -> Dict[str, Dict[str, Any]]:
        """إحصائيات جميع الـ circuits"""
        return {
            name: {
                "state": breaker.state.value,
                "total_calls": breaker.stats.total_calls,
                "failed_calls": breaker.stats.failed_calls,
                "rejected_calls": breaker.stats.rejected_calls,
                "failure_rate": breaker.stats.failure_rate,
            }
            for name, breaker in self._breakers.items()
        }

    def reset_all(self) -> None:
        """إعادة تعيين جميع الـ circuits"""
        for breaker in self._breakers.values():
            breaker.reset()


# Singleton instance
registry = CircuitBreakerRegistry()


# ═══════════════════════════════════════════════════════════
#                     Retry with Circuit Breaker
# ═══════════════════════════════════════════════════════════


async def retry_with_circuit_breaker(
    func: Callable[[Any], T],
    *args,
    circuit_name: str,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    **kwargs,
) -> T:
    """
    Retry مع Circuit Breaker.

    Example:
        >>> result = await retry_with_circuit_breaker(
        ...     call_api,
        ...     circuit_name="api",
        ...     max_retries=3,
        ... )
    """
    breaker = registry.get_or_create(circuit_name)
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            async with breaker:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

        except CircuitOpenError:
            raise

        except Exception as e:
            last_error = e

            if attempt < max_retries:
                wait_time = delay * (backoff**attempt)
                logger.warning(
                    "Attempt %d/%d failed for '%s': %s. Retrying in %.1fs",
                    attempt + 1,
                    max_retries + 1,
                    circuit_name,
                    e,
                    wait_time,
                )
                await asyncio.sleep(wait_time)
            else:
                raise

    raise last_error
