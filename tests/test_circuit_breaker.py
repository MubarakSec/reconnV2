"""
Unit Tests for Circuit Breaker

اختبارات:
- State transitions
- Failure thresholds
- Recovery
- Half-open state
"""

import asyncio

import pytest


# ═══════════════════════════════════════════════════════════
#                     Import Module
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.utils.circuit_breaker import (
        CircuitBreaker,
        CircuitState,
        CircuitBreakerError,
        CircuitOpenError,
    )

    HAS_CIRCUIT_BREAKER = True
except ImportError:
    HAS_CIRCUIT_BREAKER = False


pytestmark = [
    pytest.mark.skipif(not HAS_CIRCUIT_BREAKER, reason="circuit_breaker not available"),
]


# ═══════════════════════════════════════════════════════════
#                     Circuit State Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitState:
    """اختبارات حالات الدائرة"""

    def test_states_exist(self):
        """الحالات موجودة"""
        assert CircuitState.CLOSED is not None
        assert CircuitState.OPEN is not None
        assert CircuitState.HALF_OPEN is not None

    def test_initial_state_is_closed(self):
        """الحالة الأولية مغلقة"""
        breaker = CircuitBreaker("test")
        assert breaker.state == CircuitState.CLOSED


# ═══════════════════════════════════════════════════════════
#                     Basic Circuit Breaker Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerBasic:
    """اختبارات أساسية"""

    def test_create_breaker(self):
        """إنشاء circuit breaker"""
        breaker = CircuitBreaker(
            name="test",
            failure_threshold=5,
            recovery_timeout=30.0,
        )

        assert breaker.name == "test"
        assert breaker.failure_threshold == 5
        assert breaker.state == CircuitState.CLOSED

    def test_breaker_allows_calls_when_closed(self):
        """يسمح بالاستدعاءات عند الإغلاق"""
        breaker = CircuitBreaker("test")

        assert breaker.allow_request()

    def test_breaker_tracks_success(self):
        """تتبع النجاح"""
        breaker = CircuitBreaker("test")

        breaker.record_success()

        assert breaker.success_count >= 1
        assert breaker.state == CircuitState.CLOSED

    def test_breaker_tracks_failure(self):
        """تتبع الفشل"""
        breaker = CircuitBreaker("test", failure_threshold=5)

        breaker.record_failure()

        assert breaker.failure_count >= 1


# ═══════════════════════════════════════════════════════════
#                     State Transition Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitStateTransitions:
    """اختبارات انتقالات الحالة"""

    def test_opens_after_threshold(self):
        """يفتح بعد الحد"""
        breaker = CircuitBreaker("test", failure_threshold=3)

        # Record failures up to threshold
        for _ in range(3):
            breaker.record_failure()

        assert breaker.state == CircuitState.OPEN

    def test_blocks_calls_when_open(self):
        """يحظر الاستدعاءات عند الفتح"""
        breaker = CircuitBreaker("test", failure_threshold=1)

        breaker.record_failure()  # Opens the circuit

        assert breaker.state == CircuitState.OPEN
        assert not breaker.allow_request()

    def test_transitions_to_half_open(self):
        """ينتقل إلى نصف مفتوح"""
        breaker = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.1,
        )

        breaker.record_failure()  # Opens
        assert breaker.state == CircuitState.OPEN

        # Wait for recovery timeout
        import time

        time.sleep(0.15)

        # Should transition to half-open
        assert breaker.allow_request()
        assert breaker.state == CircuitState.HALF_OPEN

    def test_closes_after_success_in_half_open(self):
        """يغلق بعد النجاح في نصف مفتوح"""
        breaker = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.1,
            success_threshold=1,
        )

        breaker.record_failure()  # Opens

        import time

        time.sleep(0.15)

        breaker.allow_request()  # Transitions to half-open
        breaker.record_success()  # Should close

        assert breaker.state == CircuitState.CLOSED

    def test_reopens_on_failure_in_half_open(self):
        """يعيد الفتح عند الفشل في نصف مفتوح"""
        breaker = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.1,
        )

        breaker.record_failure()  # Opens

        import time

        time.sleep(0.15)

        breaker.allow_request()  # Transitions to half-open
        breaker.record_failure()  # Should reopen

        assert breaker.state == CircuitState.OPEN


# ═══════════════════════════════════════════════════════════
#                     Decorator Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerDecorator:
    """اختبارات Decorator"""

    @pytest.mark.asyncio
    async def test_decorator_protects_async_function(self):
        """Decorator يحمي async function"""
        breaker = CircuitBreaker("test", failure_threshold=3)

        call_count = 0

        @breaker.protect
        async def protected_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await protected_func()

        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_decorator_records_failure(self):
        """Decorator يسجل الفشل"""
        breaker = CircuitBreaker("test", failure_threshold=3)

        @breaker.protect
        async def failing_func():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            await failing_func()

        assert breaker.failure_count >= 1

    @pytest.mark.asyncio
    async def test_decorator_raises_when_open(self):
        """Decorator يرفع استثناء عند الفتح"""
        breaker = CircuitBreaker("test", failure_threshold=1)

        @breaker.protect
        async def protected_func():
            raise ValueError("Test error")

        # First call fails and opens circuit
        with pytest.raises(ValueError):
            await protected_func()

        # Second call should be blocked
        with pytest.raises((CircuitOpenError, CircuitBreakerError)):
            await protected_func()

    def test_decorator_protects_sync_function(self):
        """Decorator يحمي sync function"""
        breaker = CircuitBreaker("test", failure_threshold=3)

        @breaker.protect_sync
        def protected_func():
            return "success"

        result = protected_func()

        assert result == "success"


# ═══════════════════════════════════════════════════════════
#                     Metrics Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerMetrics:
    """اختبارات المقاييس"""

    def test_tracks_total_calls(self):
        """تتبع إجمالي الاستدعاءات"""
        breaker = CircuitBreaker("test")

        for _ in range(5):
            breaker.record_success()
        for _ in range(3):
            breaker.record_failure()

        stats = breaker.get_stats()

        assert stats["total_calls"] == 8
        assert stats["success_count"] == 5
        assert stats["failure_count"] >= 3

    def test_calculates_failure_rate(self):
        """حساب معدل الفشل"""
        breaker = CircuitBreaker("test", failure_threshold=10)

        for _ in range(7):
            breaker.record_success()
        for _ in range(3):
            breaker.record_failure()

        stats = breaker.get_stats()

        # 3/10 = 30% failure rate
        assert stats["failure_rate"] == pytest.approx(0.3, rel=0.1)

    def test_tracks_state_changes(self):
        """تتبع تغييرات الحالة"""
        breaker = CircuitBreaker(
            "test",
            failure_threshold=2,
            recovery_timeout=0.1,
        )

        # Close -> Open
        breaker.record_failure()
        breaker.record_failure()

        stats = breaker.get_stats()

        assert stats["state"] == "open"
        assert stats["state_changes"] >= 1


# ═══════════════════════════════════════════════════════════
#                     Configuration Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerConfiguration:
    """اختبارات التكوين"""

    def test_custom_failure_threshold(self):
        """حد فشل مخصص"""
        breaker = CircuitBreaker("test", failure_threshold=10)

        # Should not open until 10 failures
        for _ in range(9):
            breaker.record_failure()

        assert breaker.state == CircuitState.CLOSED

        breaker.record_failure()

        assert breaker.state == CircuitState.OPEN

    def test_custom_recovery_timeout(self):
        """timeout استرداد مخصص"""
        breaker = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.05,
        )

        breaker.record_failure()

        import time

        time.sleep(0.06)

        # Should allow request after timeout
        assert breaker.allow_request()

    def test_custom_success_threshold(self):
        """حد نجاح مخصص"""
        breaker = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.05,
            success_threshold=3,
        )

        breaker.record_failure()  # Opens

        import time

        time.sleep(0.06)

        breaker.allow_request()  # Half-open

        # Need 3 successes to close
        breaker.record_success()
        assert breaker.state == CircuitState.HALF_OPEN

        breaker.record_success()
        assert breaker.state == CircuitState.HALF_OPEN

        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED


# ═══════════════════════════════════════════════════════════
#                     Reset Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerReset:
    """اختبارات إعادة التعيين"""

    def test_manual_reset(self):
        """إعادة تعيين يدوية"""
        breaker = CircuitBreaker("test", failure_threshold=1)

        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

        breaker.reset()

        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0

    def test_reset_clears_history(self):
        """إعادة التعيين تمسح السجل"""
        breaker = CircuitBreaker("test", failure_threshold=5)

        for _ in range(3):
            breaker.record_failure()
        for _ in range(3):
            breaker.record_success()

        breaker.reset()

        stats = breaker.get_stats()
        assert stats["total_calls"] == 0


# ═══════════════════════════════════════════════════════════
#                     Concurrency Tests
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerConcurrency:
    """اختبارات التزامن"""

    @pytest.mark.asyncio
    async def test_thread_safe_state_changes(self):
        """تغييرات الحالة آمنة للخيوط"""
        breaker = CircuitBreaker("test", failure_threshold=100)

        async def record_mixed():
            for _ in range(10):
                if _ % 2 == 0:
                    breaker.record_success()
                else:
                    breaker.record_failure()

        # Run concurrently
        await asyncio.gather(*[record_mixed() for _ in range(10)])

        stats = breaker.get_stats()
        assert stats["total_calls"] == 100

    @pytest.mark.asyncio
    async def test_concurrent_protected_calls(self):
        """استدعاءات محمية متزامنة"""
        breaker = CircuitBreaker("test", failure_threshold=50)

        results = []

        @breaker.protect
        async def protected_func(n):
            await asyncio.sleep(0.01)
            results.append(n)
            return n

        await asyncio.gather(*[protected_func(i) for i in range(20)])

        assert len(results) == 20


# ═══════════════════════════════════════════════════════════
#                  Compatibility Edge Cases
# ═══════════════════════════════════════════════════════════


class TestCircuitBreakerCompatibility:
    """اختبارات توافق إضافية"""

    def test_recovery_timeout_alias_sets_open_timeout(self):
        """recovery_timeout القديم يعمل كمرادف"""
        breaker = CircuitBreaker("test", recovery_timeout=0.25)
        assert breaker.recovery_timeout == pytest.approx(0.25)
        assert breaker.config.open_timeout == pytest.approx(0.25)

    def test_protect_sync_rejects_when_open_and_tracks_rejections(self):
        """protect_sync يرفض الطلبات عندما تكون الدائرة مفتوحة"""
        breaker = CircuitBreaker("test", failure_threshold=1, recovery_timeout=60)
        breaker.record_failure()  # Open circuit

        @breaker.protect_sync
        def protected():
            return "ok"

        with pytest.raises(CircuitOpenError):
            protected()

        stats = breaker.get_stats()
        assert stats["rejected_calls"] >= 1
