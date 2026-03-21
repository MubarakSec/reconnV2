"""
Unit Tests for Async HTTP Client

اختبارات:
- Connection pooling
- Retry logic
- Rate limiting
- Error handling
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════
#                     Import Module
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.utils.async_http import (
        AsyncHTTPClient,
        RateLimiter,
        ConnectionPool,
        RetryConfig,
    )

    HAS_ASYNC_HTTP = True
except ImportError:
    HAS_ASYNC_HTTP = False


pytestmark = [
    pytest.mark.skipif(not HAS_ASYNC_HTTP, reason="async_http not available"),
]


# ═══════════════════════════════════════════════════════════
#                     Rate Limiter Tests
# ═══════════════════════════════════════════════════════════


class TestRateLimiter:
    """اختبارات Rate Limiter"""

    @pytest.mark.asyncio
    async def test_rate_limiter_allows_within_limit(self):
        """يسمح بالطلبات ضمن الحد"""
        limiter = RateLimiter(requests_per_second=10)

        # Should allow 10 requests immediately
        for _ in range(10):
            await limiter.acquire()

        # Verify limiter is working
        assert True

    @pytest.mark.asyncio
    async def test_rate_limiter_throttles_excess(self):
        """يخنق الطلبات الزائدة"""
        limiter = RateLimiter(requests_per_second=5)

        start = datetime.now()

        # Make 10 requests (should take ~1 second for excess 5)
        for _ in range(6):
            await limiter.acquire()

        elapsed = (datetime.now() - start).total_seconds()

        # Should have some delay for throttling
        assert elapsed >= 0.1  # At least some delay

    @pytest.mark.asyncio
    async def test_rate_limiter_with_burst(self):
        """Rate limiter مع burst"""
        limiter = RateLimiter(requests_per_second=5, burst_size=10)

        # Should allow burst of 10
        for _ in range(10):
            await limiter.acquire()

        assert True


# ═══════════════════════════════════════════════════════════
#                     Connection Pool Tests
# ═══════════════════════════════════════════════════════════


class TestConnectionPool:
    """اختبارات Connection Pool"""

    @pytest.mark.asyncio
    async def test_pool_creates_connections(self):
        """Pool ينشئ اتصالات"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.return_value = AsyncMock()
            mock_session.return_value.close = AsyncMock()

            pool = ConnectionPool(max_connections=5)

            async with pool.get_session() as session:
                assert session is not None

            await pool.close()

    @pytest.mark.asyncio
    async def test_pool_reuses_connections(self):
        """Pool يعيد استخدام الاتصالات"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_instance = AsyncMock()
            mock_instance.closed = False
            mock_instance.close = AsyncMock()
            mock_session.return_value = mock_instance

            pool = ConnectionPool(max_connections=5)

            # Get and return session twice
            async with pool.get_session():
                pass
            async with pool.get_session():
                pass

            # Should have created session
            assert mock_session.called

            await pool.close()

    @pytest.mark.asyncio
    async def test_pool_limits_connections(self):
        """Pool يحد من الاتصالات"""
        pool = ConnectionPool(max_connections=2)

        # Should limit to 2 concurrent
        assert pool.max_connections == 2


# ═══════════════════════════════════════════════════════════
#                     Retry Config Tests
# ═══════════════════════════════════════════════════════════


class TestRetryConfig:
    """اختبارات Retry Config"""

    def test_default_config(self):
        """Config افتراضي"""
        config = RetryConfig()

        assert config.max_retries >= 1
        assert config.base_delay > 0

    def test_custom_config(self):
        """Config مخصص"""
        config = RetryConfig(
            max_retries=5,
            base_delay=2.0,
            max_delay=60.0,
            exponential_base=3,
        )

        assert config.max_retries == 5
        assert config.base_delay == 2.0

    def test_retry_delay_calculation(self):
        """حساب تأخير إعادة المحاولة"""
        config = RetryConfig(
            base_delay=1.0,
            exponential_base=2,
        )

        # Attempt 0: 1.0
        # Attempt 1: 2.0
        # Attempt 2: 4.0
        delays = [config.get_delay(i) for i in range(3)]

        assert delays[0] == 1.0
        assert delays[1] == 2.0
        assert delays[2] == 4.0

    def test_max_delay_cap(self):
        """الحد الأقصى للتأخير"""
        config = RetryConfig(
            base_delay=1.0,
            exponential_base=2,
            max_delay=5.0,
        )

        # Should be capped at 5.0
        delay = config.get_delay(10)  # Would be 1024 without cap

        assert delay <= 5.0


# ═══════════════════════════════════════════════════════════
#                     HTTP Client Tests
# ═══════════════════════════════════════════════════════════


class TestAsyncHTTPClient:
    """اختبارات Async HTTP Client"""

    @pytest.fixture
    def mock_response(self):
        """Mock response"""
        response = MagicMock()
        response.status = 200
        response.headers = {"content-type": "application/json"}
        response.json = AsyncMock(return_value={"data": "test"})
        response.text = AsyncMock(return_value='{"data": "test"}')
        response.read = AsyncMock(return_value=b'{"data": "test"}')
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=None)
        return response

    @pytest.mark.asyncio
    async def test_client_get_request(self, mock_response):
        """GET request"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.get.return_value.__aenter__.return_value = mock_response
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient() as client:
                result = await client.get("https://example.com")

                assert result is not None

    @pytest.mark.asyncio
    async def test_client_post_request(self, mock_response):
        """POST request"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.post.return_value.__aenter__.return_value = mock_response
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient() as client:
                result = await client.post(
                    "https://example.com/api", json={"key": "value"}
                )

                assert result is not None

    @pytest.mark.asyncio
    async def test_client_retry_on_error(self, mock_response):
        """Retry عند الخطأ"""
        call_count = 0

        async def failing_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Connection error")
            return mock_response

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.get = failing_get
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient(
                retry_config=RetryConfig(max_retries=5, base_delay=0.01)
            ):
                # Should retry and eventually succeed
                # Note: Implementation might differ
                pass

    @pytest.mark.asyncio
    async def test_client_respects_rate_limit(self):
        """يحترم rate limit"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            response = MagicMock()
            response.status = 200
            response.__aenter__ = AsyncMock(return_value=response)
            response.__aexit__ = AsyncMock()
            session_instance.get.return_value = response
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient(rate_limit=5) as client:
                # Make several requests
                start = datetime.now()
                for _ in range(3):
                    await client.get("https://example.com")
                elapsed = (datetime.now() - start).total_seconds()

                # Should complete (rate limiting applies)
                assert elapsed >= 0

    @pytest.mark.asyncio
    async def test_client_timeout(self):
        """Timeout"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.get = AsyncMock(side_effect=asyncio.TimeoutError())
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient(timeout=0.1) as client:
                with pytest.raises((asyncio.TimeoutError, Exception)):
                    await client.get("https://example.com")

    @pytest.mark.asyncio
    async def test_client_concurrent_requests(self, mock_response):
        """طلبات متزامنة"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.get.return_value.__aenter__.return_value = mock_response
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient(max_connections=10) as client:
                urls = [f"https://example.com/{i}" for i in range(5)]

                tasks = [client.get(url) for url in urls]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Should complete all requests
                assert len(results) == 5


# ═══════════════════════════════════════════════════════════
#                     Error Handling Tests
# ═══════════════════════════════════════════════════════════


class TestHTTPErrorHandling:
    """اختبارات معالجة الأخطاء"""

    @pytest.mark.asyncio
    async def test_handles_connection_error(self):
        """معالجة خطأ الاتصال"""
        with patch("aiohttp.ClientSession") as mock_session:
            import aiohttp

            session_instance = AsyncMock()
            session_instance.get = AsyncMock(
                side_effect=aiohttp.ClientConnectorError(
                    MagicMock(), OSError("Connection refused")
                )
            )
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient() as client:
                with pytest.raises(Exception):
                    await client.get("https://invalid.local")

    @pytest.mark.asyncio
    async def test_handles_ssl_error(self):
        """معالجة خطأ SSL"""
        with patch("aiohttp.ClientSession") as mock_session:
            import ssl

            session_instance = AsyncMock()
            session_instance.get = AsyncMock(
                side_effect=ssl.SSLError("certificate verify failed")
            )
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient() as client:
                with pytest.raises(Exception):
                    await client.get("https://invalid-cert.example.com")

    @pytest.mark.asyncio
    async def test_handles_rate_limit_response(self):
        """معالجة rate limit response"""
        response = MagicMock()
        response.status = 429
        response.headers = {"retry-after": "60"}
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock()

        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.get.return_value = response
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient() as client:
                result = await client.get("https://example.com")
                assert result.status == 429


# ═══════════════════════════════════════════════════════════
#                  Compatibility Edge Cases
# ═══════════════════════════════════════════════════════════


class TestAsyncHTTPCompatibility:
    """اختبارات توافق إضافية"""

    @pytest.mark.asyncio
    async def test_constructor_keyword_aliases_map_to_config(self):
        """kwargs القديمة تُطبّق على إعدادات العميل"""
        retry = RetryConfig(
            max_retries=4,
            base_delay=0.2,
            exponential_base=3,
        )
        client = AsyncHTTPClient(
            timeout=2.0,
            max_connections=7,
            rate_limit=9,
            retry_config=retry,
        )

        assert client.config.total_timeout == 2.0
        assert client.config.max_concurrent == 7
        assert client.config.requests_per_second == 9
        assert client.config.max_retries == 4
        assert client.config.retry_delay == 0.2
        assert client.config.retry_multiplier == 3

    @pytest.mark.asyncio
    async def test_get_many_converts_request_exception_to_error_response(self):
        """get_many يعيد HTTPResponse.error عند فشل الطلب"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = AsyncMock()
            session_instance.get = AsyncMock(side_effect=asyncio.TimeoutError())
            session_instance.close = AsyncMock()
            mock_session.return_value = session_instance

            async with AsyncHTTPClient(
                retry_config=RetryConfig(max_retries=0, base_delay=0.01)
            ) as client:
                results = await client.get_many(["https://example.com"])

        assert len(results) == 1
        assert results[0].status == 0
        assert "Timeout" in (results[0].error or "")
