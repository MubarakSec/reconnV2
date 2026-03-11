"""Performance utilities for ReconnV2.

This module provides:
- HTTP Connection Pooling
- Memory-efficient iterators
- Resource management
"""
from __future__ import annotations

import gc
import weakref
from typing import Any, Dict, Iterator, List, Optional, TypeVar
from dataclasses import dataclass
from contextlib import contextmanager

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None  # type: ignore


T = TypeVar("T")


@dataclass
class PoolConfig:
    """Configuration for connection pooling."""
    pool_connections: int = 10  # Number of connection pools
    pool_maxsize: int = 20  # Max connections per pool
    max_retries: int = 3  # Retry count
    backoff_factor: float = 0.3  # Backoff between retries
    timeout: float = 30.0  # Request timeout
    

class ConnectionPool:
    """HTTP Connection Pool Manager.
    
    Provides reusable HTTP connections with:
    - Connection pooling per host
    - Automatic retry with backoff
    - Timeout management
    """
    
    _instance: Optional["ConnectionPool"] = None
    _sessions: Dict[str, Any] = {}
    
    def __new__(cls, config: Optional[PoolConfig] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config: Optional[PoolConfig] = None):
        if self._initialized:
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
            session.request = self._timeout_wrapper(session.request)
            
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
        
    Yields:
        Chunks of items
    """
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]


def streaming_file_reader(filepath: str, chunk_size: int = 8192) -> Iterator[str]:
    """Read file in streaming mode to reduce memory usage.
    
    Args:
        filepath: Path to file
        chunk_size: Bytes to read per chunk
        
    Yields:
        Lines from file
    """
    with open(filepath, "r", encoding="utf-8") as f:
        buffer = ""
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                if buffer:
                    yield buffer
                break
            buffer += chunk
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                yield line


@contextmanager
def memory_efficient_context():
    """Context manager for memory-efficient operations.
    
    Triggers garbage collection after the block.
    """
    try:
        yield
    finally:
        gc.collect()


class ResourceTracker:
    """Track and manage resources to prevent leaks."""
    
    def __init__(self):
        self._resources: List[weakref.ref] = []
    
    def track(self, resource: Any) -> None:
        """Track a resource for cleanup."""
        self._resources.append(weakref.ref(resource))
    
    def cleanup(self) -> int:
        """Cleanup tracked resources that are still alive."""
        cleaned = 0
        for ref in self._resources:
            obj = ref()
            if obj is not None:
                if hasattr(obj, "close"):
                    try:
                        obj.close()
                        cleaned += 1
                    except Exception:
                        pass
        self._resources.clear()
        gc.collect()
        return cleaned
    
    def stats(self) -> Dict[str, int]:
        """Get tracker statistics."""
        alive = sum(1 for ref in self._resources if ref() is not None)
        return {
            "tracked": len(self._resources),
            "alive": alive,
            "collected": len(self._resources) - alive,
        }


class MemoryMonitor:
    """Monitor memory usage during operations."""
    
    def __init__(self):
        self._snapshots: List[Dict[str, Any]] = []
    
    def snapshot(self, label: str = "") -> Dict[str, Any]:
        """Take a memory snapshot."""
        try:
            import psutil
            process = psutil.Process()
            mem_info = process.memory_info()
            snapshot = {
                "label": label,
                "rss_mb": mem_info.rss / 1024 / 1024,
                "vms_mb": mem_info.vms / 1024 / 1024,
            }
        except ImportError:
            # Fallback without psutil
            snapshot = {
                "label": label,
                "gc_objects": len(gc.get_objects()),
            }
        
        self._snapshots.append(snapshot)
        return snapshot
    
    def report(self) -> List[Dict[str, Any]]:
        """Get all snapshots."""
        return self._snapshots
    
    def clear(self) -> None:
        """Clear snapshots."""
        self._snapshots.clear()


# Singleton instances
_pool: Optional[ConnectionPool] = None
_tracker: Optional[ResourceTracker] = None


def get_pool(config: Optional[PoolConfig] = None) -> ConnectionPool:
    """Get the global connection pool."""
    global _pool
    if _pool is None:
        _pool = ConnectionPool(config)
    return _pool


def get_tracker() -> ResourceTracker:
    """Get the global resource tracker."""
    global _tracker
    if _tracker is None:
        _tracker = ResourceTracker()
    return _tracker


def optimize_memory() -> Dict[str, Any]:
    """Run memory optimization."""
    # Cleanup resources
    tracker = get_tracker()
    cleaned = tracker.cleanup()
    
    # Force garbage collection
    gc.collect()
    
    return {
        "resources_cleaned": cleaned,
        "gc_collected": gc.get_count(),
    }
