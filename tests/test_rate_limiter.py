"""Tests for rate_limiter.py"""

import time
import pytest
from recon_cli.utils.rate_limiter import (
    TokenBucket,
    RateLimitConfig,
    RateLimiter,
)


class TestTokenBucket:
    """Tests for TokenBucket class."""

    def test_initial_tokens(self):
        """Bucket starts with max tokens."""
        bucket = TokenBucket(rate=10.0, capacity=10)
        assert bucket.tokens == 10

    def test_consume_success(self):
        """Can consume when tokens available."""
        bucket = TokenBucket(rate=10.0, capacity=10)
        assert bucket.consume(5) is True
        assert bucket.tokens == 5

    def test_consume_failure(self):
        """Cannot consume more than available."""
        bucket = TokenBucket(rate=10.0, capacity=10)
        bucket.consume(10)
        assert bucket.consume(1) is False

    def test_refill_over_time(self):
        """Tokens refill based on elapsed time."""
        bucket = TokenBucket(rate=100.0, capacity=10)
        bucket.consume(10)
        assert bucket.tokens == 0
        time.sleep(0.05)  # 50ms = 5 tokens at 100/sec
        bucket.consume(0)  # Trigger refill
        assert bucket.tokens >= 4  # Allow some timing variance

    def test_capacity_limit(self):
        """Tokens cannot exceed capacity."""
        bucket = TokenBucket(rate=1000.0, capacity=10)
        bucket.consume(5)
        time.sleep(0.1)  # Would add 100 tokens at 1000/sec
        bucket.consume(0)  # Trigger refill
        assert bucket.tokens == 10  # Capped at capacity


class TestRateLimitConfig:
    """Tests for RateLimitConfig class."""

    def test_default_config(self):
        """Default configuration values."""
        config = RateLimitConfig()
        assert config.requests_per_second == 10
        assert config.per_host_limit == 5
        assert config.burst_size == 20
        assert config.backoff_factor == 2.0
        assert config.max_backoff == 60.0

    def test_custom_config(self):
        """Custom configuration values."""
        config = RateLimitConfig(
            requests_per_second=50,
            per_host_limit=10,
            burst_size=100,
        )
        assert config.requests_per_second == 50
        assert config.per_host_limit == 10
        assert config.burst_size == 100


class TestRateLimiter:
    """Tests for RateLimiter class."""

    @pytest.mark.asyncio
    async def test_wait_for_slot(self):
        """wait_for_slot respects rate limits."""
        config = RateLimitConfig(requests_per_second=100, per_host_limit=100)
        limiter = RateLimiter(config)

        # Should not block for first request
        start = time.time()
        await limiter.wait_for_slot("https://example.com/page1")
        elapsed = time.time() - start
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_per_host_limiting(self):
        """Different hosts have separate limits."""
        config = RateLimitConfig(requests_per_second=100, per_host_limit=5)
        limiter = RateLimiter(config)

        # Quick requests to different hosts should work
        await limiter.wait_for_slot("https://example.com/")
        await limiter.wait_for_slot("https://test.com/")

        stats = limiter.stats()
        assert stats["total_requests"] == 2

    @pytest.mark.asyncio
    async def test_on_response_429(self):
        """Rate limiter backs off on 429 response."""
        config = RateLimitConfig(requests_per_second=100)
        limiter = RateLimiter(config)

        url = "https://example.com/"
        await limiter.wait_for_slot(url)
        limiter.on_response(url, 429)

        stats = limiter.stats()
        assert stats["total_429s"] == 1

    @pytest.mark.asyncio
    async def test_on_response_success(self):
        """Successful responses are tracked."""
        config = RateLimitConfig(requests_per_second=100)
        limiter = RateLimiter(config)

        url = "https://example.com/"
        await limiter.wait_for_slot(url)
        limiter.on_response(url, 200)

        stats = limiter.stats()
        assert stats["total_requests"] == 1
        assert stats["total_429s"] == 0

    @pytest.mark.asyncio
    async def test_stats(self):
        """Stats returns correct information."""
        config = RateLimitConfig(requests_per_second=100)
        limiter = RateLimiter(config)

        await limiter.wait_for_slot("https://a.com/")
        await limiter.wait_for_slot("https://b.com/")
        await limiter.wait_for_slot("https://c.com/")

        stats = limiter.stats()
        assert stats["total_requests"] == 3
        assert stats["hosts_tracked"] == 3

    def test_extract_host(self):
        """Host extraction from URLs."""
        config = RateLimitConfig()
        limiter = RateLimiter(config)

        # Test various URL formats
        assert limiter._extract_host("https://example.com/path") == "example.com"
        assert limiter._extract_host("http://test.org:8080/") == "test.org"
        assert limiter._extract_host("https://sub.domain.net") == "sub.domain.net"


class TestRateLimiterIntegration:
    """Integration tests for RateLimiter."""

    @pytest.mark.asyncio
    async def test_burst_handling(self):
        """Burst requests are handled correctly."""
        config = RateLimitConfig(
            requests_per_second=10,
            burst_size=5,
        )
        limiter = RateLimiter(config)

        # Burst of 5 requests should go through quickly
        start = time.time()
        for i in range(5):
            await limiter.wait_for_slot(f"https://example.com/page{i}")
        elapsed = time.time() - start

        # Should complete in under 1 second due to burst
        assert elapsed < 1.0

    @pytest.mark.asyncio
    async def test_multiple_hosts_concurrent(self):
        """Multiple hosts can be rate limited independently."""
        config = RateLimitConfig(
            requests_per_second=100,
            per_host_limit=10,
        )
        limiter = RateLimiter(config)

        hosts = ["example.com", "test.org", "demo.net"]
        for host in hosts:
            for i in range(5):
                await limiter.wait_for_slot(f"https://{host}/page{i}")

        stats = limiter.stats()
        assert stats["total_requests"] == 15
        assert stats["hosts_tracked"] == 3
