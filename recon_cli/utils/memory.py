"""
Memory Optimization Utilities - أدوات تحسين الذاكرة

توفر أدوات لـ:
- تتبع استخدام الذاكرة
- تحسين البيانات الكبيرة
- التنظيف التلقائي
- معالجة التسربات

Example:
    >>> with MemoryTracker() as tracker:
    ...     process_large_data()
    ...     print(tracker.peak_mb)
"""

from __future__ import annotations

import gc
import logging
import sys
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    TypeVar,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════
#                     Memory Tracking
# ═══════════════════════════════════════════════════════════


@dataclass
class MemorySnapshot:
    """لقطة من حالة الذاكرة"""

    timestamp: float
    rss_bytes: int
    heap_bytes: int
    objects_count: int
    gc_counts: tuple

    @property
    def rss_mb(self) -> float:
        return self.rss_bytes / (1024 * 1024)

    @property
    def heap_mb(self) -> float:
        return self.heap_bytes / (1024 * 1024)


@dataclass
class MemoryStats:
    """إحصائيات الذاكرة"""

    current_mb: float
    peak_mb: float
    allocated_mb: float
    freed_mb: float
    gc_collections: int
    large_objects: int


class MemoryTracker:
    """
    تتبع استخدام الذاكرة.

    Example:
        >>> tracker = MemoryTracker()
        >>> tracker.start()
        >>> # ... process data ...
        >>> stats = tracker.stop()
        >>> print(f"Peak: {stats.peak_mb:.1f} MB")
    """

    def __init__(self, label: str = "default"):
        self.label = label
        self._snapshots: List[MemorySnapshot] = []
        self._start_snapshot: Optional[MemorySnapshot] = None
        self._peak_bytes = 0
        self._tracking = False

    def _take_snapshot(self) -> MemorySnapshot:
        """أخذ لقطة من الذاكرة"""
        import time

        try:
            import psutil

            process = psutil.Process()
            rss = process.memory_info().rss
        except ImportError:
            rss = 0

        # Get heap info
        gc.collect()
        heap = sum(sys.getsizeof(obj) for obj in gc.get_objects()[:1000])

        return MemorySnapshot(
            timestamp=time.time(),
            rss_bytes=rss,
            heap_bytes=heap,
            objects_count=len(gc.get_objects()),
            gc_counts=gc.get_count(),
        )

    def start(self) -> "MemoryTracker":
        """بدء التتبع"""
        gc.collect()
        self._start_snapshot = self._take_snapshot()
        self._peak_bytes = self._start_snapshot.rss_bytes
        self._snapshots = [self._start_snapshot]
        self._tracking = True
        logger.debug("Memory tracking started: %s", self.label)
        return self

    def checkpoint(self, name: str = "") -> MemorySnapshot:
        """نقطة فحص"""
        snapshot = self._take_snapshot()
        self._snapshots.append(snapshot)

        if snapshot.rss_bytes > self._peak_bytes:
            self._peak_bytes = snapshot.rss_bytes

        logger.debug(
            "Memory checkpoint [%s]: %.1f MB",
            name or len(self._snapshots),
            snapshot.rss_mb,
        )
        return snapshot

    def stop(self) -> MemoryStats:
        """إيقاف التتبع وإرجاع الإحصائيات"""
        if not self._tracking:
            return MemoryStats(0, 0, 0, 0, 0, 0)

        final = self._take_snapshot()
        self._snapshots.append(final)
        self._tracking = False

        start = self._start_snapshot
        gc_collections = sum(final.gc_counts) - sum(start.gc_counts)

        return MemoryStats(
            current_mb=final.rss_mb,
            peak_mb=self._peak_bytes / (1024 * 1024),
            allocated_mb=(self._peak_bytes - start.rss_bytes) / (1024 * 1024),
            freed_mb=(self._peak_bytes - final.rss_bytes) / (1024 * 1024),
            gc_collections=gc_collections,
            large_objects=final.objects_count - start.objects_count,
        )

    def __enter__(self) -> "MemoryTracker":
        return self.start()

    def __exit__(self, *args) -> None:
        stats = self.stop()
        logger.info(
            "Memory [%s]: current=%.1f MB, peak=%.1f MB, allocated=%.1f MB",
            self.label,
            stats.current_mb,
            stats.peak_mb,
            stats.allocated_mb,
        )


# ═══════════════════════════════════════════════════════════
#                     Memory-Efficient Data Structures
# ═══════════════════════════════════════════════════════════


class ChunkedList:
    """
    قائمة مقسمة لتوفير الذاكرة.

    بدلاً من تخزين كل العناصر في الذاكرة، تخزن chunks
    ويمكن تفريغ القديمة.

    Example:
        >>> cl = ChunkedList(chunk_size=1000)
        >>> for item in large_data:
        ...     cl.append(item)
        >>> for chunk in cl.iter_chunks():
        ...     process(chunk)
    """

    def __init__(self, chunk_size: int = 10000):
        self.chunk_size = chunk_size
        self._chunks: List[List[Any]] = [[]]
        self._total_items = 0

    def append(self, item: Any) -> None:
        if len(self._chunks[-1]) >= self.chunk_size:
            self._chunks.append([])
        self._chunks[-1].append(item)
        self._total_items += 1

    def extend(self, items: Iterable[Any]) -> None:
        for item in items:
            self.append(item)

    def __len__(self) -> int:
        return self._total_items

    def iter_chunks(self) -> Iterator[List[Any]]:
        """تكرار على الـ chunks"""
        for chunk in self._chunks:
            if chunk:
                yield chunk

    def clear_processed(self, keep_last: int = 1) -> int:
        """مسح الـ chunks المعالجة"""
        if len(self._chunks) <= keep_last:
            return 0

        to_clear = len(self._chunks) - keep_last
        cleared_items = sum(len(c) for c in self._chunks[:to_clear])

        self._chunks = self._chunks[-keep_last:]
        self._total_items -= cleared_items

        gc.collect()
        return cleared_items


def chunked_iterator(
    iterable: Iterable[T],
    chunk_size: int = 1000,
) -> Generator[List[T], None, None]:
    """
    تقسيم iterator إلى chunks.

    Example:
        >>> for chunk in chunked_iterator(range(10000), 100):
        ...     process_batch(chunk)
    """
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# ═══════════════════════════════════════════════════════════
#                     Memory Optimization
# ═══════════════════════════════════════════════════════════


class ObjectPool:
    """
    Object Pool لإعادة استخدام الكائنات.

    يقلل من عمليات allocation/deallocation.

    Example:
        >>> pool = ObjectPool(dict, max_size=100)
        >>> obj = pool.acquire()
        >>> obj["key"] = "value"
        >>> pool.release(obj)  # Returns to pool
    """

    def __init__(
        self,
        factory: Callable[[], T],
        max_size: int = 100,
        reset_func: Optional[Callable[[T], None]] = None,
    ):
        self.factory = factory
        self.max_size = max_size
        self.reset_func = reset_func or self._default_reset
        self._pool: List[T] = []
        self._created = 0
        self._reused = 0

    def _default_reset(self, obj: Any) -> None:
        """إعادة تعيين افتراضية"""
        if hasattr(obj, "clear"):
            obj.clear()

    def acquire(self) -> T:
        """الحصول على كائن"""
        if self._pool:
            self._reused += 1
            return self._pool.pop()
        self._created += 1
        return self.factory()

    def release(self, obj: T) -> None:
        """إرجاع كائن للـ pool"""
        if len(self._pool) < self.max_size:
            self.reset_func(obj)
            self._pool.append(obj)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "pool_size": len(self._pool),
            "created": self._created,
            "reused": self._reused,
        }


class WeakCache:
    """
    Cache يستخدم weak references.

    يسمح لـ GC بمسح العناصر غير المستخدمة.

    Example:
        >>> cache = WeakCache()
        >>> cache["key"] = large_object
        >>> # إذا لم يُستخدم large_object، سيُمسح تلقائياً
    """

    def __init__(self):
        self._cache: Dict[str, weakref.ref] = {}

    def __setitem__(self, key: str, value: Any) -> None:
        try:
            self._cache[key] = weakref.ref(value)
        except TypeError:
            # Some objects can't be weakref'd
            pass

    def __getitem__(self, key: str) -> Optional[Any]:
        ref = self._cache.get(key)
        if ref is None:
            return None
        value = ref()
        if value is None:
            del self._cache[key]
        return value

    def get(self, key: str, default: Any = None) -> Any:
        value = self[key]
        return value if value is not None else default

    def cleanup(self) -> int:
        """مسح المراجع الميتة"""
        dead = [k for k, v in self._cache.items() if v() is None]
        for k in dead:
            del self._cache[k]
        return len(dead)


# ═══════════════════════════════════════════════════════════
#                     Decorators & Helpers
# ═══════════════════════════════════════════════════════════


def track_memory(label: str = ""):
    """
    Decorator لتتبع الذاكرة.

    Example:
        >>> @track_memory("process_data")
        ... def process_data(data):
        ...     return [x * 2 for x in data]
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracker = MemoryTracker(label or func.__name__)
            tracker.start()
            try:
                return func(*args, **kwargs)
            finally:
                stats = tracker.stop()
                logger.info(
                    "Memory [%s]: peak=%.1f MB, gc=%d",
                    label or func.__name__,
                    stats.peak_mb,
                    stats.gc_collections,
                )

        return wrapper

    return decorator


def gc_after(func: Callable) -> Callable:
    """
    تشغيل GC بعد الـ function.

    Example:
        >>> @gc_after
        ... def process_large_file(path):
        ...     with open(path) as f:
        ...         return process(f.read())
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        finally:
            gc.collect()

    return wrapper


@contextmanager
def memory_limit_context(warn_mb: float = 500, label: str = ""):
    """
    Context manager للتحذير عند تجاوز حد الذاكرة.

    Example:
        >>> with memory_limit_context(warn_mb=1000, label="import"):
        ...     import_large_data()
    """
    tracker = MemoryTracker(label)
    tracker.start()
    try:
        yield tracker
    finally:
        stats = tracker.stop()
        if stats.peak_mb > warn_mb:
            logger.warning(
                "Memory warning [%s]: %.1f MB exceeded limit of %.1f MB",
                label,
                stats.peak_mb,
                warn_mb,
            )


def optimize_dict(d: dict) -> dict:
    """
    تحسين dict لتوفير الذاكرة.

    يحول إلى أنواع أصغر حيث ممكن.
    """
    optimized = {}
    for k, v in d.items():
        # Intern string keys
        if isinstance(k, str):
            k = sys.intern(k)

        # Optimize values
        if isinstance(v, dict):
            v = optimize_dict(v)
        elif isinstance(v, list) and len(v) > 0:
            # Convert list to tuple if not modified
            v = tuple(v)

        optimized[k] = v

    return optimized


def sizeof_deep(obj: Any, seen: Optional[set] = None) -> int:
    """
    حساب الحجم الحقيقي للكائن (بما في ذلك المتداخل).

    Example:
        >>> sizeof_deep({"a": [1, 2, 3], "b": {"c": "d"}})
        456
    """
    if seen is None:
        seen = set()

    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)

    size = sys.getsizeof(obj)

    if isinstance(obj, dict):
        size += sum(sizeof_deep(k, seen) + sizeof_deep(v, seen) for k, v in obj.items())
    elif isinstance(obj, (list, tuple, set, frozenset)):
        size += sum(sizeof_deep(item, seen) for item in obj)
    elif hasattr(obj, "__dict__"):
        size += sizeof_deep(obj.__dict__, seen)

    return size


def format_bytes(num_bytes: int) -> str:
    """تنسيق البايتات بشكل مقروء"""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"
