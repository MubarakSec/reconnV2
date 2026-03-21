"""
Cache System - نظام تخزين مؤقت للنتائج
يحسن الأداء ويقلل الطلبات المكررة
"""

from __future__ import annotations

import hashlib
import pickle
import sqlite3
from contextlib import contextmanager
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Generic, Iterator, Optional, TypeVar

T = TypeVar("T")


@dataclass
class CacheConfig:
    """إعدادات الـ Cache"""

    default_ttl: int = 3600  # ساعة واحدة
    max_size: int = 10000  # الحد الأقصى للعناصر
    cleanup_interval: int = 300  # تنظيف كل 5 دقائق
    persist_to_disk: bool = True
    cache_dir: Optional[Path] = None


@dataclass
class CacheEntry(Generic[T]):
    """عنصر في الـ Cache"""

    key: str
    value: T
    created_at: float
    expires_at: float
    hits: int = 0

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def touch(self) -> None:
        """تحديث عدد الاستخدامات"""
        self.hits += 1


class MemoryCache(Generic[T]):
    """
    Cache في الذاكرة مع TTL

    الميزات:
    - Thread-safe
    - TTL للعناصر
    - LRU eviction
    - إحصائيات
    """

    def __init__(
        self,
        config: Optional[CacheConfig] = None,
        max_size: Optional[int] = None,
        default_ttl: Optional[int] = None,
        cleanup_interval: Optional[int] = None,
    ):
        self.config = config or CacheConfig()
        if max_size is not None:
            self.config.max_size = int(max_size)
        if default_ttl is not None:
            self.config.default_ttl = int(default_ttl)
        if cleanup_interval is not None:
            self.config.cleanup_interval = int(cleanup_interval)
        self._cache: Dict[str, CacheEntry[T]] = {}
        self._lock = threading.RLock()
        self._stats = {"hits": 0, "misses": 0, "evictions": 0}
        self._last_cleanup = time.time()

    def _make_key(self, key: str) -> str:
        """إنشاء مفتاح موحد"""
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def _cleanup(self) -> None:
        """تنظيف العناصر المنتهية"""
        now = time.time()
        enforce_size = len(self._cache) > self.config.max_size
        if not enforce_size and now - self._last_cleanup < self.config.cleanup_interval:
            return

        expired_keys = [k for k, v in self._cache.items() if v.is_expired]

        for key in expired_keys:
            del self._cache[key]
            self._stats["evictions"] += 1

        # إزالة الأقل استخداماً إذا تجاوز الحد
        if len(self._cache) > self.config.max_size:
            sorted_entries = sorted(
                self._cache.items(), key=lambda x: (x[1].hits, x[1].created_at)
            )
            to_remove = len(self._cache) - self.config.max_size
            for key, _ in sorted_entries[:to_remove]:
                del self._cache[key]
                self._stats["evictions"] += 1

        self._last_cleanup = now

    def get(self, key: str, default: Optional[T] = None) -> Optional[T]:
        """الحصول على قيمة من الـ Cache"""
        hashed_key = self._make_key(key)

        with self._lock:
            self._cleanup()

            entry = self._cache.get(hashed_key)
            if entry is None:
                self._stats["misses"] += 1
                return default

            if entry.is_expired:
                del self._cache[hashed_key]
                self._stats["misses"] += 1
                return default

            entry.touch()
            self._stats["hits"] += 1
            return entry.value

    def set(self, key: str, value: T, ttl: Optional[int] = None) -> None:
        """تخزين قيمة في الـ Cache"""
        hashed_key = self._make_key(key)
        ttl = ttl or self.config.default_ttl
        now = time.time()

        entry = CacheEntry(
            key=hashed_key, value=value, created_at=now, expires_at=now + ttl
        )

        with self._lock:
            self._cache[hashed_key] = entry
            self._cleanup()

    def delete(self, key: str) -> bool:
        """حذف عنصر من الـ Cache"""
        hashed_key = self._make_key(key)

        with self._lock:
            if hashed_key in self._cache:
                del self._cache[hashed_key]
                return True
            return False

    def clear(self) -> None:
        """مسح كل الـ Cache"""
        with self._lock:
            self._cache.clear()

    def stats(self) -> Dict[str, Any]:
        """إحصائيات الـ Cache"""
        with self._lock:
            total = self._stats["hits"] + self._stats["misses"]
            hit_rate = self._stats["hits"] / total if total > 0 else 0

            return {
                "size": len(self._cache),
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "hit_rate": f"{hit_rate:.2%}",
            }


class DiskCache:
    """
    Cache على القرص باستخدام SQLite

    الميزات:
    - يبقى بين الجلسات
    - ضغط البيانات
    - Thread-safe
    """

    def __init__(self, cache_dir: Path, db_name: str = "cache.db"):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / db_name
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """إنشاء قاعدة البيانات"""
        with self._get_connection() as conn:  # type: sqlite3.Connection
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    created_at REAL,
                    expires_at REAL,
                    hits INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires 
                ON cache(expires_at)
            """)

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """الحصول على اتصال بقاعدة البيانات"""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _serialize(self, value: Any) -> bytes:
        """تحويل القيمة إلى bytes"""
        return pickle.dumps(value)

    def _deserialize(self, data: bytes) -> Any:
        """تحويل bytes إلى قيمة"""
        return pickle.loads(data)  # nosec B301

    def get(self, key: str) -> Optional[Any]:
        """الحصول على قيمة"""
        now = time.time()

        with self._lock:
            with self._get_connection() as conn:  # type: sqlite3.Connection
                cursor = conn.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
                )
                row = cursor.fetchone()

                if row is None:
                    return None

                value_bytes, expires_at = row

                if expires_at < now:
                    conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                    return None

                # تحديث hits
                conn.execute("UPDATE cache SET hits = hits + 1 WHERE key = ?", (key,))

                return self._deserialize(value_bytes)

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """تخزين قيمة"""
        now = time.time()
        value_bytes = self._serialize(value)

        with self._lock:
            with self._get_connection() as conn:  # type: sqlite3.Connection
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache 
                    (key, value, created_at, expires_at, hits)
                    VALUES (?, ?, ?, ?, 0)
                """,
                    (key, value_bytes, now, now + ttl),
                )

    def delete(self, key: str) -> bool:
        """حذف عنصر"""
        with self._lock:
            with self._get_connection() as conn:  # type: sqlite3.Connection
                cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return cursor.rowcount > 0

    def clear(self) -> None:
        """مسح كل العناصر"""
        with self._lock:
            with self._get_connection() as conn:  # type: sqlite3.Connection
                conn.execute("DELETE FROM cache")

    def cleanup(self) -> int:
        """تنظيف العناصر المنتهية"""
        now = time.time()

        with self._lock:
            with self._get_connection() as conn:  # type: sqlite3.Connection
                cursor = conn.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
                return cursor.rowcount

    def stats(self) -> Dict[str, Any]:
        """إحصائيات"""
        with self._lock:
            with self._get_connection() as conn:  # type: sqlite3.Connection
                cursor = conn.execute("SELECT COUNT(*), SUM(hits) FROM cache")
                count, total_hits = cursor.fetchone()

                return {
                    "size": count or 0,
                    "total_hits": total_hits or 0,
                    "db_size_mb": self.db_path.stat().st_size / (1024 * 1024)
                    if self.db_path.exists()
                    else 0,
                }


class HybridCache:
    """
    Cache هجين (ذاكرة + قرص)

    - البحث أولاً في الذاكرة (سريع)
    - ثم في القرص (دائم)
    - كتابة في كليهما
    """

    def __init__(self, cache_dir: Path, config: Optional[CacheConfig] = None):
        self.config = config or CacheConfig()
        self._memory: MemoryCache = MemoryCache(config)
        self._disk = DiskCache(cache_dir) if self.config.persist_to_disk else None

    def get(self, key: str) -> Optional[Any]:
        """الحصول على قيمة"""
        # البحث في الذاكرة أولاً
        value = self._memory.get(key)
        if value is not None:
            return value

        # البحث في القرص
        if self._disk:
            value = self._disk.get(key)
            if value is not None:
                # نسخ إلى الذاكرة
                self._memory.set(key, value)
                return value

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """تخزين قيمة"""
        ttl = ttl or self.config.default_ttl

        self._memory.set(key, value, ttl)

        if self._disk:
            self._disk.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """حذف عنصر"""
        memory_deleted = self._memory.delete(key)
        disk_deleted = self._disk.delete(key) if self._disk else False
        return memory_deleted or disk_deleted

    def clear(self) -> None:
        """مسح الذاكرة والقرص"""
        self._memory.clear()
        if self._disk:
            self._disk.clear()

    def stats(self) -> Dict[str, Any]:
        """إحصائيات"""
        memory_stats = self._memory.stats()
        stats: Dict[str, Any] = {
            "memory": memory_stats,
            "memory_hits": memory_stats.get("hits", 0),
            "memory_misses": memory_stats.get("misses", 0),
            "memory_evictions": memory_stats.get("evictions", 0),
        }
        if self._disk:
            disk_stats = self._disk.stats()
            stats["disk"] = disk_stats
            stats["disk_hits"] = disk_stats.get("total_hits", 0)
            stats["disk_misses"] = disk_stats.get("total_misses", 0)
            stats["disk_size"] = disk_stats.get("db_size_mb", 0)
        else:
            stats["disk_hits"] = 0
            stats["disk_misses"] = 0
            stats["disk_size"] = 0
        return stats


# Decorator للتخزين المؤقت
def cached(
    cache: MemoryCache, ttl: Optional[int] = None, key_func: Optional[Callable] = None
):
    """
    Decorator لتخزين نتائج الدوال

    مثال:
        cache = MemoryCache()

        @cached(cache, ttl=300)
        def expensive_function(url):
            return requests.get(url).text
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            # إنشاء المفتاح
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{args}:{kwargs}"

            # البحث في الـ Cache
            result = cache.get(cache_key)
            if result is not None:
                return result

            # تنفيذ الدالة
            result = func(*args, **kwargs)

            # تخزين النتيجة
            cache.set(cache_key, result, ttl)

            return result

        return wrapper

    return decorator
