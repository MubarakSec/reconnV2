"""
Unified tracing utilities for recon-cli.

This module intentionally exposes a small tracing API that is compatible with
the existing tests while avoiding the previous duplicated Span/Trace/Tracer
implementations.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import random
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Sequence, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class SpanStatus(Enum):
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


class SpanKind(Enum):
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class SpanEvent:
    name: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "timestamp": self.timestamp,
            "attributes": self.attributes,
        }


@dataclass
class SpanContext:
    trace_id: str
    span_id: str

    def to_dict(self) -> Dict[str, str]:
        return {"trace_id": self.trace_id, "span_id": self.span_id}

    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> "SpanContext":
        lowered = {str(k).lower(): str(v) for k, v in headers.items()}
        return cls(
            trace_id=lowered.get(
                "x-trace-id", lowered.get("traceparent", uuid.uuid4().hex)
            ),
            span_id=lowered.get("x-span-id", uuid.uuid4().hex[:16]),
        )


class Span:
    def __init__(
        self,
        name: str,
        trace_id: str,
        parent_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
    ):
        self.name = name
        self.trace_id = trace_id
        self.span_id = span_id or uuid.uuid4().hex[:16]
        self.parent_id = parent_id or parent_span_id
        self.kind = kind
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.tags: Dict[str, Any] = {}
        self.logs: List[Dict[str, Any]] = []
        self.error: Optional[Exception] = None
        self.has_error: bool = False
        self.finished: bool = False
        self.status: SpanStatus = SpanStatus.UNSET
        self._started: bool = False

    @property
    def parent_span_id(self) -> Optional[str]:
        return self.parent_id

    @property
    def attributes(self) -> Dict[str, Any]:
        return self.tags

    @property
    def events(self) -> List[Dict[str, Any]]:
        return self.logs

    @property
    def error_message(self) -> Optional[str]:
        return str(self.error) if self.error else None

    @property
    def error_type(self) -> Optional[str]:
        if self.error is None:
            return None
        return type(self.error).__name__

    def start(self) -> None:
        if self._started and not self.finished:
            return
        self.start_time = time.time()
        self.end_time = None
        self.finished = False
        self._started = True
        if not self.has_error:
            self.status = SpanStatus.UNSET

    def finish(self) -> None:
        if self.finished:
            return
        self.end_time = time.time()
        self.finished = True
        if self.status == SpanStatus.UNSET:
            self.status = SpanStatus.ERROR if self.has_error else SpanStatus.OK

    def end(self) -> None:
        self.finish()

    def set_tag(self, key: str, value: Any) -> "Span":
        self.tags[str(key)] = value
        return self

    def set_attribute(self, key: str, value: Any) -> "Span":
        return self.set_tag(key, value)

    def set_attributes(self, attributes: Dict[str, Any]) -> "Span":
        self.tags.update(attributes)
        return self

    def log(self, message: str, fields: Optional[Dict[str, Any]] = None) -> "Span":
        self.logs.append(
            {
                "timestamp": datetime.now().isoformat(),
                "message": message,
                "fields": fields or {},
            }
        )
        return self

    def add_event(
        self, name: str, attributes: Optional[Dict[str, Any]] = None
    ) -> "Span":
        return self.log(name, attributes)

    def set_status(self, status: SpanStatus, message: str = "") -> "Span":
        self.status = status
        if status == SpanStatus.ERROR and message:
            self.error = RuntimeError(message)
            self.has_error = True
        return self

    def set_error(self, exc: Exception) -> "Span":
        self.error = Exception(f"{type(exc).__name__}: {exc}")
        self.has_error = True
        self.status = SpanStatus.ERROR
        return self

    def record_exception(self, exc: Exception) -> "Span":
        return self.set_error(exc)

    @property
    def duration_ms(self) -> float:
        end = self.end_time if self.end_time is not None else time.time()
        return (end - self.start_time) * 1000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "parent_span_id": self.parent_id,
            "kind": self.kind.value,
            "duration_ms": self.duration_ms,
            "tags": self.tags,
            "attributes": self.tags,
            "logs": self.logs,
            "events": self.logs,
            "status": self.status.value,
            "has_error": self.has_error,
            "error": str(self.error) if self.error else None,
            "error_message": self.error_message,
            "error_type": self.error_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }

    def __enter__(self) -> "Span":
        self.start()
        return self

    def __exit__(self, exc_type, exc, _tb) -> None:
        if exc is not None:
            self.set_error(exc)
        self.finish()


class Trace:
    def __init__(
        self,
        name: str = "",
        trace_id: Optional[str] = None,
        sampled: bool = True,
        parent_id: Optional[str] = None,
        baggage: Optional[Dict[str, str]] = None,
    ):
        self.name = name
        self.trace_id = trace_id or uuid.uuid4().hex
        self.sampled = sampled
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self.finished = False
        self.spans: List[Span] = []
        self.baggage: Dict[str, str] = dict(baggage or {})
        self._stack: List[Span] = []
        self.root_span: Optional[Span] = None
        if name:
            self.root_span = self.create_span(name, parent_id=parent_id)
            self.root_span.start()
            self._stack.append(self.root_span)

    def create_span(
        self,
        name: str,
        parent_id: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Span:
        resolved_parent = parent_id
        if resolved_parent is None and self._stack:
            resolved_parent = self._stack[-1].span_id
        span = Span(
            name=name, trace_id=self.trace_id, parent_id=resolved_parent, kind=kind
        )
        self.spans.append(span)
        return span

    @contextmanager
    def span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Generator[Span, None, None]:
        span = self.create_span(name, kind=kind)
        span.start()
        self._stack.append(span)
        try:
            yield span
        except Exception as exc:
            span.set_error(exc)
            raise
        finally:
            span.finish()
            if self._stack and self._stack[-1] is span:
                self._stack.pop()

    def current_span(self) -> Optional[Span]:
        return self._stack[-1] if self._stack else None

    def set_baggage(self, key: str, value: str) -> None:
        self.baggage[str(key)] = str(value)

    def get_baggage(self, key: str) -> Optional[str]:
        return self.baggage.get(key)

    def finish(self) -> None:
        if self.finished:
            return
        self.ended_at = time.time()
        self.finished = True
        for span in self.spans:
            if not span.finished:
                span.finish()
        self._stack.clear()

    def end(self) -> None:
        self.finish()

    @property
    def duration_ms(self) -> float:
        end = self.ended_at if self.ended_at is not None else time.time()
        return (end - self.started_at) * 1000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "name": self.name,
            "sampled": self.sampled,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "spans": [span.to_dict() for span in self.spans],
            "baggage": self.baggage,
        }

    def __enter__(self) -> "Trace":
        return self

    def __exit__(self, exc_type, exc, _tb) -> None:
        if exc is not None and self.root_span is not None:
            self.root_span.set_error(exc)
        self.finish()


@dataclass(frozen=True)
class _TraceScope:
    owner_id: int
    trace: Trace
    span_stack: Sequence[Span]


_TRACE_SCOPE: contextvars.ContextVar[Optional[_TraceScope]] = contextvars.ContextVar(
    "recon_cli_trace_scope",
    default=None,
)


class TraceContext:
    TRACE_HEADER = "X-Trace-ID"
    SPAN_HEADER = "X-Span-ID"
    BAGGAGE_PREFIX = "X-Baggage-"

    @classmethod
    def inject(cls, trace: Trace) -> Dict[str, str]:
        headers = {cls.TRACE_HEADER: trace.trace_id}
        current = trace.current_span()
        if current is not None:
            headers[cls.SPAN_HEADER] = current.span_id
        for key, value in trace.baggage.items():
            headers[f"{cls.BAGGAGE_PREFIX}{key}"] = value
        return headers

    @classmethod
    def extract(cls, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        lowered = {str(k).lower(): str(v) for k, v in headers.items()}
        trace_id = lowered.get(cls.TRACE_HEADER.lower())
        if not trace_id:
            return None
        baggage: Dict[str, str] = {}
        prefix = cls.BAGGAGE_PREFIX.lower()
        for key, value in lowered.items():
            if key.startswith(prefix):
                baggage[key[len(prefix) :]] = value
        return {
            "trace_id": trace_id,
            "parent_span_id": lowered.get(cls.SPAN_HEADER.lower()),
            "baggage": baggage,
        }


class TraceExporter:
    def export(self, traces: List[Trace]) -> bool:
        raise NotImplementedError


class ConsoleExporter(TraceExporter):
    def export(self, traces: List[Trace]) -> bool:
        for trace in traces:
            print(f"\n{'=' * 60}")
            print(f"Trace: {trace.name} ({trace.trace_id})")
            print(f"Duration: {trace.duration_ms:.2f}ms")
            print(f"Spans: {len(trace.spans)}")
            for span in trace.spans:
                indent = "  " if span.parent_id else ""
                status = "x" if span.has_error else "o"
                print(f"{indent}{status} {span.name}: {span.duration_ms:.2f}ms")
                if span.error_message:
                    print(f"{indent}  Error: {span.error_message}")
            print(f"{'=' * 60}\n")
        return True


class JSONFileExporter(TraceExporter):
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, traces: List[Trace]) -> bool:
        try:
            for trace in traces:
                filepath = self.output_dir / f"{trace.trace_id}.json"
                with filepath.open("w", encoding="utf-8") as handle:
                    json.dump(trace.to_dict(), handle, indent=2)
            return True
        except Exception as exc:  # pragma: no cover - defensive exporter path
            logger.error("Failed to export traces: %s", exc)
            return False


class JaegerExporter(TraceExporter):
    def __init__(
        self,
        endpoint: str = "http://localhost:14268/api/traces",
        service_name: str = "recon-cli",
    ):
        self.endpoint = endpoint
        self.service_name = service_name

    def export(self, traces: List[Trace]) -> bool:
        try:
            import aiohttp
        except ImportError:  # pragma: no cover - optional dependency
            logger.warning("aiohttp required for Jaeger export")
            return False

        async def _export() -> None:
            async with aiohttp.ClientSession() as session:
                for trace in traces:
                    payload = self._to_jaeger_format(trace)
                    async with session.post(self.endpoint, json=payload) as resp:
                        if resp.status >= 300:
                            logger.warning("Jaeger export failed: %d", resp.status)

        try:
            asyncio.run(_export())
        except Exception as exc:  # pragma: no cover - network/export failure
            logger.error("Jaeger export error: %s", exc)
            return False
        return True

    def _to_jaeger_format(self, trace: Trace) -> Dict[str, Any]:
        trace_id = trace.trace_id.rjust(32, "0")
        spans: List[Dict[str, Any]] = []
        for span in trace.spans:
            item = {
                "traceIdLow": int(trace_id[-16:], 16),
                "traceIdHigh": int(trace_id[:-16], 16),
                "spanId": int(span.span_id, 16),
                "operationName": span.name,
                "startTime": int(span.start_time * 1_000_000),
                "duration": int(span.duration_ms * 1000),
                "tags": [
                    {"key": key, "type": "string", "value": str(value)}
                    for key, value in span.attributes.items()
                ],
            }
            if span.parent_id:
                item["references"] = [
                    {"refType": "CHILD_OF", "spanId": int(span.parent_id, 16)}
                ]
            spans.append(item)
        return {
            "batch": {
                "process": {"serviceName": self.service_name},
                "spans": spans,
            }
        }


@dataclass
class TracingConfig:
    enabled: bool = True
    sample_rate: float = 1.0
    export_endpoint: str = ""
    service_name: str = "recon-cli"


class Tracer:
    def __init__(
        self,
        service_name: str = "recon-cli",
        config: Optional[TracingConfig] = None,
        exporters: Optional[List[TraceExporter]] = None,
        auto_flush: bool = False,
        max_traces: int = 1000,
    ):
        self.config = config or TracingConfig(service_name=service_name)
        self.service_name = self.config.service_name or service_name
        self.exporters = list(exporters or [])
        self.auto_flush = auto_flush
        self.max_traces = max(1, int(max_traces))
        self._pending_traces: List[Trace] = []
        self._lock = threading.Lock()

    def _should_sample(self) -> bool:
        if not self.config.enabled:
            return False
        rate = max(0.0, min(1.0, float(self.config.sample_rate)))
        return random.random() < rate

    def _scope(self) -> Optional[_TraceScope]:
        scope = _TRACE_SCOPE.get()
        if scope is None or scope.owner_id != id(self):
            return None
        return scope

    def _set_scope(self, trace: Trace, span_stack: Sequence[Span]) -> None:
        _TRACE_SCOPE.set(
            _TraceScope(owner_id=id(self), trace=trace, span_stack=tuple(span_stack))
        )

    def _clear_scope(self) -> None:
        scope = self._scope()
        if scope is not None:
            _TRACE_SCOPE.set(None)

    def _enqueue_trace(self, trace: Trace) -> None:
        if not trace.sampled:
            return
        should_flush = False
        with self._lock:
            self._pending_traces.append(trace)
            should_flush = (
                self.auto_flush and len(self._pending_traces) >= self.max_traces
            )
        if not should_flush:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.flush())
            return
        loop.create_task(self.flush())

    def start_trace(
        self, name: str, parent_context: Optional[Dict[str, Any]] = None
    ) -> Trace:
        trace_id = None
        parent_id = None
        baggage: Dict[str, str] = {}
        if parent_context:
            trace_id = parent_context.get("trace_id")
            parent_id = parent_context.get("span_id") or parent_context.get(
                "parent_span_id"
            )
            baggage = dict(parent_context.get("baggage") or {})
        trace = Trace(
            name=name,
            trace_id=trace_id,
            sampled=self._should_sample(),
            parent_id=parent_id,
            baggage=baggage,
        )
        self._set_scope(trace, trace._stack)
        self._enqueue_trace(trace)
        return trace

    def get_current_trace(self) -> Optional[Trace]:
        scope = self._scope()
        if scope is None:
            return None
        return scope.trace

    @property
    def active_span(self) -> Optional[Span]:
        scope = self._scope()
        if scope is None or not scope.span_stack:
            return None
        return scope.span_stack[-1]

    def start_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL) -> Span:
        trace = self.get_current_trace()
        if trace is None or trace.finished:
            orphan = Span(name=name, trace_id=uuid.uuid4().hex, kind=kind)
            orphan.start()
            return orphan
        span = trace.create_span(name, kind=kind)
        span.start()
        trace._stack.append(span)
        self._set_scope(trace, trace._stack)
        return span

    def _pop_span(self, span: Span) -> None:
        scope = self._scope()
        if scope is None or scope.trace.finished:
            return
        if scope.trace._stack and scope.trace._stack[-1] is span:
            scope.trace._stack.pop()
        else:
            try:
                scope.trace._stack.remove(span)
            except ValueError:
                pass
        self._set_scope(scope.trace, scope.trace._stack)

    @contextmanager
    def trace(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Generator[Span, None, None]:
        current = self.get_current_trace()
        if (
            current is not None
            and not current.finished
            and self.active_span is not None
        ):
            span = self.start_span(name, kind=kind)
            try:
                yield span
            except Exception as exc:
                span.set_error(exc)
                raise
            finally:
                span.finish()
                self._pop_span(span)
            return

        trace = self.start_trace(name)
        root = trace.root_span
        if root is None:
            root = self.start_span(name, kind=kind)
        try:
            yield root
        except Exception as exc:
            root.set_error(exc)
            raise
        finally:
            trace.finish()
            self._clear_scope()

    def inject(self, headers: Dict[str, str]) -> None:
        trace = self.get_current_trace()
        if trace is not None:
            headers["x-trace-id"] = trace.trace_id
        active = self.active_span
        if active is not None:
            headers["x-span-id"] = active.span_id

    def extract(self, headers: Dict[str, str]) -> SpanContext:
        return SpanContext.from_headers(headers)

    async def flush(self) -> None:
        with self._lock:
            traces = list(self._pending_traces)
            self._pending_traces.clear()
        if not traces:
            return
        for exporter in self.exporters:
            try:
                exporter.export(traces)
            except Exception as exc:  # pragma: no cover - defensive exporter path
                logger.error("Exporter %s failed: %s", type(exporter).__name__, exc)
        if not self.config.export_endpoint:
            return
        try:
            import aiohttp
        except ImportError:  # pragma: no cover - optional dependency
            return
        async with aiohttp.ClientSession() as session:
            for trace in traces:
                try:
                    async with session.post(
                        self.config.export_endpoint, json=trace.to_dict()
                    ) as _resp:
                        pass
                except Exception:  # pragma: no cover - export failures are non-fatal
                    continue

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "pending_traces": len(self._pending_traces),
                "pending_spans": sum(
                    len(trace.spans) for trace in self._pending_traces
                ),
                "exporters": [type(exporter).__name__ for exporter in self.exporters],
            }


def traced(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
) -> Callable:
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        op_name = name or func.__name__

        if asyncio.iscoroutinefunction(func):

            async def async_wrapper(*args, **kwargs) -> T:
                tracer_obj = get_tracer()
                with tracer_obj.trace(op_name, kind=kind) as span:
                    if attributes:
                        span.set_attributes(attributes)
                    return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        def sync_wrapper(*args, **kwargs) -> T:
            tracer_obj = get_tracer()
            with tracer_obj.trace(op_name, kind=kind) as span:
                if attributes:
                    span.set_attributes(attributes)
                return func(*args, **kwargs)

        return sync_wrapper

    return decorator


def trace_async(name: Optional[str] = None) -> Callable:
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        op_name = name or func.__name__

        async def wrapper(*args, **kwargs) -> T:
            tracer_obj = get_tracer()
            with tracer_obj.trace(op_name) as _span:
                return await func(*args, **kwargs)  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator


def trace_sync(name: Optional[str] = None) -> Callable:
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        op_name = name or func.__name__

        def wrapper(*args, **kwargs) -> T:
            tracer_obj = get_tracer()
            with tracer_obj.trace(op_name) as _span:
                return func(*args, **kwargs)

        return wrapper

    return decorator


_GLOBAL_TRACER: Tracer = Tracer()
tracer: Tracer = _GLOBAL_TRACER


def get_tracer(config: Optional[TracingConfig] = None) -> Tracer:
    global _GLOBAL_TRACER, tracer
    if config is not None:
        service = config.service_name or _GLOBAL_TRACER.service_name
        _GLOBAL_TRACER = Tracer(service_name=service, config=config)
        tracer = _GLOBAL_TRACER
    return _GLOBAL_TRACER


def configure_tracer(
    service_name: str = "recon-cli",
    exporters: Optional[List[TraceExporter]] = None,
    auto_flush: bool = False,
) -> Tracer:
    global _GLOBAL_TRACER, tracer
    _GLOBAL_TRACER = Tracer(
        service_name=service_name,
        exporters=exporters,
        auto_flush=auto_flush,
    )
    tracer = _GLOBAL_TRACER
    return _GLOBAL_TRACER


__all__ = [
    "ConsoleExporter",
    "JSONFileExporter",
    "JaegerExporter",
    "Span",
    "SpanContext",
    "SpanEvent",
    "SpanKind",
    "SpanStatus",
    "Trace",
    "TraceContext",
    "TraceExporter",
    "Tracer",
    "TracingConfig",
    "configure_tracer",
    "get_tracer",
    "trace_async",
    "trace_sync",
    "traced",
    "tracer",
]
