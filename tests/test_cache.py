"""Tests for cache.py"""

import time
import tempfile
from pathlib import Path
from recon_cli.utils.cache import (
    MemoryCache,
    DiskCache,
    HybridCache,
)


class TestMemoryCache:
    """Tests for MemoryCache class."""

    def test_set_and_get(self):
        """Basic set and get operations."""
        cache = MemoryCache()
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing_key(self):
        """Get returns None for missing keys."""
        cache = MemoryCache()
        assert cache.get("nonexistent") is None

    def test_get_with_default(self):
        """Get returns default for missing keys."""
        cache = MemoryCache()
        assert cache.get("nonexistent", "default") == "default"

    def test_ttl_expiration(self):
        """Items expire after TTL."""
        cache = MemoryCache()
        cache.set("key1", "value1", ttl=0.1)  # 100ms TTL
        assert cache.get("key1") == "value1"
        time.sleep(0.15)
        assert cache.get("key1") is None

    def test_delete(self):
        """Delete removes items."""
        cache = MemoryCache()
        cache.set("key1", "value1")
        cache.delete("key1")
        assert cache.get("key1") is None

    def test_clear(self):
        """Clear removes all items."""
        cache = MemoryCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_max_size(self):
        """Cache respects max size."""
        cache = MemoryCache(max_size=2)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")  # Should evict key1
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"

    def test_stats(self):
        """Stats tracks hits and misses."""
        cache = MemoryCache()
        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("missing")  # Miss

        stats = cache.stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1

    def test_complex_values(self):
        """Cache handles complex values."""
        cache = MemoryCache()
        cache.set("dict", {"a": 1, "b": [2, 3]})
        cache.set("list", [1, 2, 3])

        assert cache.get("dict") == {"a": 1, "b": [2, 3]}
        assert cache.get("list") == [1, 2, 3]


class TestDiskCache:
    """Tests for DiskCache class."""

    def test_set_and_get(self):
        """Basic set and get operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            cache.set("key1", "value1")
            assert cache.get("key1") == "value1"

    def test_get_missing_key(self):
        """Get returns None for missing keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            assert cache.get("nonexistent") is None

    def test_persistence(self):
        """Data persists across cache instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache1 = DiskCache(Path(tmpdir))
            cache1.set("key1", "value1")

            cache2 = DiskCache(Path(tmpdir))
            assert cache2.get("key1") == "value1"

    def test_ttl_expiration(self):
        """Items expire after TTL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            cache.set("key1", "value1", ttl=0.1)
            assert cache.get("key1") == "value1"
            time.sleep(0.15)
            assert cache.get("key1") is None

    def test_delete(self):
        """Delete removes items."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            cache.set("key1", "value1")
            cache.delete("key1")
            assert cache.get("key1") is None

    def test_clear(self):
        """Clear removes all items."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            cache.set("key1", "value1")
            cache.set("key2", "value2")
            cache.clear()
            assert cache.get("key1") is None
            assert cache.get("key2") is None

    def test_complex_values(self):
        """Cache handles complex JSON-serializable values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            cache.set("dict", {"a": 1, "b": [2, 3]})
            assert cache.get("dict") == {"a": 1, "b": [2, 3]}


class TestHybridCache:
    """Tests for HybridCache class."""

    def test_set_and_get(self):
        """Basic set and get operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = HybridCache(Path(tmpdir))
            cache.set("key1", "value1")
            assert cache.get("key1") == "value1"

    def test_memory_first(self):
        """Memory cache is checked first."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = HybridCache(Path(tmpdir))
            cache.set("key1", "value1")

            # Clear disk cache manually
            cache._disk.clear()

            # Should still find in memory
            assert cache.get("key1") == "value1"

    def test_disk_fallback(self):
        """Falls back to disk when not in memory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = HybridCache(Path(tmpdir))
            cache.set("key1", "value1")

            # Clear memory cache
            cache._memory.clear()

            # Should find on disk
            assert cache.get("key1") == "value1"

    def test_stats_combined(self):
        """Stats combines memory and disk stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = HybridCache(Path(tmpdir))
            cache.set("key1", "value1")
            cache.get("key1")  # Memory hit

            stats = cache.stats()
            assert "memory_hits" in stats
            assert "disk_hits" in stats

    def test_clear_both(self):
        """Clear removes from both caches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = HybridCache(Path(tmpdir))
            cache.set("key1", "value1")
            cache.clear()

            assert cache.get("key1") is None


class TestCacheDecorator:
    """Tests for cache decorator functionality."""

    def test_cached_function(self):
        """Decorator caches function results."""
        cache = MemoryCache()
        call_count = 0

        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call
        key = "result_5"
        result = cache.get(key)
        if result is None:
            result = expensive_function(5)
            cache.set(key, result)
        assert result == 10
        assert call_count == 1

        # Second call (cached)
        result = cache.get(key)
        assert result == 10
        assert call_count == 1  # Not called again


class TestCacheEdgeCases:
    """Edge case tests for cache."""

    def test_empty_key(self):
        """Empty key is handled."""
        cache = MemoryCache()
        cache.set("", "empty_key_value")
        assert cache.get("") == "empty_key_value"

    def test_none_value(self):
        """None value is cached correctly."""
        cache = MemoryCache()
        cache.set("key", None)
        # Use sentinel to distinguish None value from missing
        assert cache.get("key", "MISSING") is None

    def test_large_value(self):
        """Large values are handled."""
        cache = MemoryCache()
        large_value = "x" * 1_000_000
        cache.set("large", large_value)
        assert cache.get("large") == large_value

    def test_special_characters_in_key(self):
        """Special characters in keys are handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = DiskCache(Path(tmpdir))
            cache.set("key/with/slashes", "value1")
            cache.set("key:with:colons", "value2")
            cache.set("key?with=query", "value3")

            assert cache.get("key/with/slashes") == "value1"
            assert cache.get("key:with:colons") == "value2"
            assert cache.get("key?with=query") == "value3"
