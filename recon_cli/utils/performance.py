"""
Performance Utilities - أدوات تحسين الأداء
تحسين سرعة النظام وإدارة الموارد
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, TypeVar, Iterator
from contextlib import contextmanager
import time

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class PoolConfig:
    """إعدادات مجمع الاتصالات"""

    pool_connections: int = 10
    pool_maxsize: int = 20
    max_retries: int = 3
    backoff_factor: float = 0.5
    timeout: int = 10


class ConnectionPool:
    """HTTP Connection Pool Manager.

    Provides reusable HTTP connections with:
    - Connection pooling per host
    - Automatic retry with backoff
    - Timeout management
    """

    _instance: Optional["ConnectionPool"] = None
    _sessions: Dict[str, Any] = {}
    _initialized: bool = False

    def __new__(cls, config: Optional[PoolConfig] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config: Optional[PoolConfig] = None):
        if getattr(self, "_initialized", False):
            return

        self.config = config or PoolConfig()
        self._sessions = {}
        self._initialized = True

    def get_session(self, base_url: Optional[str] = None) -> Any:
        """Get or create a session for the given base URL."""
        if not REQUESTS_AVAILABLE:
            return None

        key = base_url or "default"

        if key not in self._sessions:
            session = requests.Session()

            # Configure retry strategy
            retry_strategy = Retry(
                total=self.config.max_retries,
                backoff_factor=self.config.backoff_factor,
                status_forcelist=[429, 500, 502, 503, 504],
            )

            # Configure adapter with connection pooling
            adapter = HTTPAdapter(
                pool_connections=self.config.pool_connections,
                pool_maxsize=self.config.pool_maxsize,
                max_retries=retry_strategy,
            )

            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # Set default timeout
            session.request = self._timeout_wrapper(session.request)  # type: ignore[method-assign]

            self._sessions[key] = session

        return self._sessions[key]

    def _timeout_wrapper(self, request_func):
        """Wrap request function with default timeout."""

        def wrapper(*args, **kwargs):
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.config.timeout
            return request_func(*args, **kwargs)

        return wrapper

    def get(self, url: str, **kwargs) -> Any:
        """Make a GET request using pooled connection."""
        session = self.get_session()
        if session:
            return session.get(url, **kwargs)
        return None

    def post(self, url: str, **kwargs) -> Any:
        """Make a POST request using pooled connection."""
        session = self.get_session()
        if session:
            return session.post(url, **kwargs)
        return None

    def close_all(self):
        """Close all sessions."""
        for session in self._sessions.values():
            try:
                session.close()
            except Exception:
                pass
        self._sessions.clear()

    def stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        return {
            "active_sessions": len(self._sessions),
            "pool_connections": self.config.pool_connections,
            "pool_maxsize": self.config.pool_maxsize,
        }


def chunked_iterator(items: List[T], chunk_size: int = 100) -> Iterator[List[T]]:
    """Iterate over items in chunks to reduce memory usage.

    Args:
        items: List of items to iterate
        chunk_size: Size of each chunk
    """
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


@contextmanager
def execution_timer(name: str):
    """Timer context manager for measuring execution time."""
    start_time = time.perf_counter()
    try:
        yield
    finally:
        end_time = time.perf_counter()
        logger.debug("Execution time [%s]: %.4fs", name, end_time - start_time)


class CacheOptimizer:
    """Optimizes caching strategies based on resource usage."""

    def __init__(self, memory_limit_mb: int = 512):
        self.memory_limit = memory_limit_mb
        self.usage_stats: Dict[str, List[float]] = {}

    def track_access(self, key: str, size_bytes: int):
        """Track cache access pattern."""
        if key not in self.usage_stats:
            self.usage_stats[key] = []
        self.usage_stats[key].append(time.time())

    def should_evict(self, key: str) -> bool:
        """Determine if a key should be evicted based on frequency and recency."""
        # Simple LRU/LFU hybrid logic could go here
        return False


def optimize_memory():
    """Run manual garbage collection if memory is tight."""
    import gc

    gc.collect()


# ─────────────────────────────────────────────────────────
#                     Resource Manager
# ─────────────────────────────────────────────────────────


class ResourceManager:
    """مدير الموارد للنظام"""

    def __init__(self):
        self.pool = ConnectionPool()
        self.optimizer = CacheOptimizer()

    def cleanup(self):
        """تنظيف الموارد"""
        self.pool.close_all()
        optimize_memory()


def get_pool() -> ConnectionPool:
    """الحصول على مجمع الاتصالات العام"""
    return ConnectionPool()
