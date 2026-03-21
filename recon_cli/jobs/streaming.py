"""
Result Streaming - بث النتائج

توفر streaming للنتائج بدلاً من تحميلها كلها في الذاكرة.
مفيد للـ jobs الكبيرة مع ملايين النتائج.

Example:
    >>> async for result in stream_results(job_id):
    ...     process(result)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import (
    AsyncIterator,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Union,
)

logger = logging.getLogger(__name__)


@dataclass
class StreamingConfig:
    """إعدادات البث"""

    batch_size: int = 100
    buffer_size: int = 1000
    flush_interval: float = 1.0
    compression: bool = False


class ResultStream:
    """
    Stream للنتائج من ملف JSONL.

    يقرأ سطر بسطر لتوفير الذاكرة.

    Example:
        >>> stream = ResultStream("results.jsonl")
        >>> for result in stream:
        ...     process(result)
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        filter_func: Optional[Callable[[dict], bool]] = None,
    ):
        self.file_path = Path(file_path)
        self.filter_func = filter_func
        self._count = 0
        self._filtered = 0

    def __iter__(self) -> Iterator[dict]:
        if not self.file_path.exists():
            return

        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    result = json.loads(line)
                    self._count += 1

                    if self.filter_func and not self.filter_func(result):
                        self._filtered += 1
                        continue

                    yield result

                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON line: {e}")

    def count(self) -> int:
        """عدد النتائج الكلي"""
        if not self.file_path.exists():
            return 0

        with open(self.file_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    def batched(self, batch_size: int = 100) -> Iterator[List[dict]]:
        """إرجاع batches من النتائج"""
        batch = []
        for result in self:
            batch.append(result)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "total": self._count,
            "filtered": self._filtered,
            "yielded": self._count - self._filtered,
        }


class AsyncResultStream:
    """
    Async stream للنتائج.

    Example:
        >>> async with AsyncResultStream("results.jsonl") as stream:
        ...     async for result in stream:
        ...         await process(result)
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        filter_func: Optional[Callable[[dict], bool]] = None,
        buffer_size: int = 100,
    ):
        self.file_path = Path(file_path)
        self.filter_func = filter_func
        self.buffer_size = buffer_size
        self._file = None
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=buffer_size)
        self._reader_task: Optional[asyncio.Task] = None
        self._done = False

    async def __aenter__(self) -> "AsyncResultStream":
        await self.start()
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def start(self) -> None:
        """بدء القراءة"""
        if not self.file_path.exists():
            self._done = True
            return

        self._reader_task = asyncio.create_task(self._read_file())

    async def close(self) -> None:
        """إغلاق الـ stream"""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

    async def _read_file(self) -> None:
        """قراءة الملف في الخلفية"""
        try:
            loop = asyncio.get_event_loop()

            def read_sync():
                results = []
                with open(self.file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            result = json.loads(line)
                            if self.filter_func and not self.filter_func(result):
                                continue
                            results.append(result)
                        except json.JSONDecodeError:
                            pass
                return results

            results = await loop.run_in_executor(None, read_sync)

            for result in results:
                await self._queue.put(result)

        finally:
            self._done = True

    async def __aiter__(self) -> AsyncIterator[dict]:
        while True:
            if self._done and self._queue.empty():
                break

            try:
                result = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                yield result
            except asyncio.TimeoutError:
                if self._done:
                    break


class ResultWriter:
    """
    كاتب نتائج مع buffering.

    يكتب بـ batches لتحسين الأداء.

    Example:
        >>> writer = ResultWriter("results.jsonl")
        >>> for result in results:
        ...     writer.write(result)
        >>> writer.flush()
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        buffer_size: int = 100,
        auto_flush: bool = True,
    ):
        self.file_path = Path(file_path)
        self.buffer_size = buffer_size
        self.auto_flush = auto_flush
        self._buffer: List[dict] = []
        self._total_written = 0
        self._file = None

    def __enter__(self) -> "ResultWriter":
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.file_path, "a", encoding="utf-8")  # type: ignore[assignment]
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def write(self, result: dict) -> None:
        """كتابة نتيجة"""
        self._buffer.append(result)

        if self.auto_flush and len(self._buffer) >= self.buffer_size:
            self.flush()

    def write_many(self, results: List[dict]) -> None:
        """كتابة نتائج متعددة"""
        for result in results:
            self.write(result)

    def flush(self) -> int:
        """كتابة الـ buffer للملف"""
        if not self._buffer:
            return 0

        if not self._file:
            self._file = open(self.file_path, "a", encoding="utf-8")  # type: ignore[assignment]

        count = 0
        for result in self._buffer:
            try:
                line = json.dumps(result, ensure_ascii=False)
                self._file.write(line + "\n")  # type: ignore[attr-defined]
                count += 1
            except (TypeError, ValueError) as e:
                logger.warning(f"Failed to serialize result: {e}")

        self._file.flush()  # type: ignore[attr-defined]
        self._total_written += count
        self._buffer.clear()

        return count

    def close(self) -> None:
        """إغلاق الملف"""
        self.flush()
        if self._file:
            self._file.close()
            self._file = None

    @property
    def total_written(self) -> int:
        return self._total_written


class AsyncResultWriter:
    """
    Async كاتب نتائج.

    Example:
        >>> async with AsyncResultWriter("results.jsonl") as writer:
        ...     await writer.write(result)
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        buffer_size: int = 100,
        flush_interval: float = 1.0,
    ):
        self.file_path = Path(file_path)
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self._queue: asyncio.Queue = asyncio.Queue()
        self._writer_task: Optional[asyncio.Task] = None
        self._total_written = 0
        self._running = False

    async def __aenter__(self) -> "AsyncResultWriter":
        await self.start()
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def start(self) -> None:
        """بدء الكتابة"""
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._running = True
        self._writer_task = asyncio.create_task(self._write_loop())

    async def _write_loop(self) -> None:
        """حلقة الكتابة"""
        buffer = []
        last_flush = asyncio.get_event_loop().time()

        while self._running or not self._queue.empty():
            try:
                result = await asyncio.wait_for(
                    self._queue.get(), timeout=self.flush_interval
                )
                buffer.append(result)
            except asyncio.TimeoutError:
                pass

            current_time = asyncio.get_event_loop().time()
            should_flush = (
                len(buffer) >= self.buffer_size
                or (current_time - last_flush) >= self.flush_interval
            )

            if buffer and should_flush:
                await self._flush_buffer(buffer)
                buffer.clear()
                last_flush = current_time

        if buffer:
            await self._flush_buffer(buffer)

    async def _flush_buffer(self, buffer: List[dict]) -> None:
        """كتابة الـ buffer"""
        loop = asyncio.get_event_loop()

        def write_sync():
            with open(self.file_path, "a", encoding="utf-8") as f:
                for result in buffer:
                    try:
                        line = json.dumps(result, ensure_ascii=False)
                        f.write(line + "\n")
                    except (TypeError, ValueError):
                        pass
            return len(buffer)

        count = await loop.run_in_executor(None, write_sync)
        self._total_written += count

    async def write(self, result: dict) -> None:
        """كتابة نتيجة"""
        await self._queue.put(result)

    async def write_many(self, results: List[dict]) -> None:
        """كتابة نتائج متعددة"""
        for result in results:
            await self._queue.put(result)

    async def close(self) -> None:
        """إغلاق"""
        self._running = False
        if self._writer_task:
            await self._writer_task

    @property
    def total_written(self) -> int:
        return self._total_written


# ═══════════════════════════════════════════════════════════
#                     Aggregation Helpers
# ═══════════════════════════════════════════════════════════


def stream_aggregate(
    file_path: Union[str, Path],
    key_func: Callable[[dict], str],
    agg_func: Callable[[dict, dict], dict],
    initial_value: Optional[dict] = None,
) -> Dict[str, dict]:
    """
    تجميع النتائج بشكل streaming.

    Example:
        >>> results = stream_aggregate(
        ...     "results.jsonl",
        ...     key_func=lambda r: r["type"],
        ...     agg_func=lambda acc, r: {"count": acc.get("count", 0) + 1},
        ... )
    """
    aggregates: Dict[str, dict] = {}

    for result in ResultStream(file_path):
        key = key_func(result)
        current = aggregates.get(key, initial_value or {})
        aggregates[key] = agg_func(current, result)

    return aggregates


def stream_filter_write(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    filter_func: Callable[[dict], bool],
) -> int:
    """
    تصفية وكتابة النتائج.

    Example:
        >>> count = stream_filter_write(
        ...     "all_results.jsonl",
        ...     "high_severity.jsonl",
        ...     lambda r: r.get("severity") == "high"
        ... )
    """
    with ResultWriter(output_path) as writer:
        for result in ResultStream(input_path, filter_func):
            writer.write(result)

    return writer.total_written


def merge_result_files(
    input_paths: List[Union[str, Path]],
    output_path: Union[str, Path],
    dedup_key: Optional[Callable[[dict], str]] = None,
) -> int:
    """
    دمج ملفات نتائج متعددة.

    Example:
        >>> count = merge_result_files(
        ...     ["results1.jsonl", "results2.jsonl"],
        ...     "merged.jsonl",
        ...     dedup_key=lambda r: r["url"]
        ... )
    """
    seen = set()

    with ResultWriter(output_path) as writer:
        for path in input_paths:
            for result in ResultStream(path):
                if dedup_key:
                    key = dedup_key(result)
                    if key in seen:
                        continue
                    seen.add(key)

                writer.write(result)

    return writer.total_written
