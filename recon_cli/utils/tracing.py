"""
Distributed Tracing - التتبع الموزع

نظام تتبع للطلبات والعمليات.

Features:
- Trace ID لكل فحص
- Spans للعمليات الفرعية
- Context Propagation
- تصدير للأنظمة الخارجية

Example:
    >>> with tracer.start_trace("scan-job") as trace:
    ...     with trace.span("subdomain-enum"):
    ...         enumerate_subdomains()
    ...     with trace.span("port-scan"):
    ...         scan_ports()
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════
#                     Span Types
# ═══════════════════════════════════════════════════════════

class SpanStatus(Enum):
    """حالة الـ Span"""
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


class SpanKind(Enum):
    """نوع الـ Span"""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class SpanEvent:
    """حدث داخل Span"""
    
    name: str
    timestamp: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "timestamp": self.timestamp,
            "attributes": self.attributes,
        }


@dataclass
class Span:
    """
    وحدة العمل.
    
    يمثل عملية واحدة ضمن trace.
    """
    
    trace_id: str
    span_id: str
    name: str
    parent_span_id: Optional[str] = None
    
    kind: SpanKind = SpanKind.INTERNAL
    status: SpanStatus = SpanStatus.UNSET
    
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[SpanEvent] = field(default_factory=list)
    
    # Error info
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    
    def set_attribute(self, key: str, value: Any) -> "Span":
        """إضافة attribute"""
        self.attributes[key] = value
        return self
    
    def set_attributes(self, attributes: Dict[str, Any]) -> "Span":
        """إضافة attributes متعددة"""
        self.attributes.update(attributes)
        return self
    
    def add_event(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> "Span":
        """إضافة حدث"""
        self.events.append(SpanEvent(
            name=name,
            attributes=attributes or {},
        ))
        return self
    
    def set_status(self, status: SpanStatus, message: str = "") -> "Span":
        """تعيين الحالة"""
        self.status = status
        if status == SpanStatus.ERROR and message:
            self.error_message = message
        return self
    
    def record_exception(self, exception: Exception) -> "Span":
        """تسجيل استثناء"""
        self.status = SpanStatus.ERROR
        self.error_type = type(exception).__name__
        self.error_message = str(exception)
        
        self.add_event("exception", {
            "type": self.error_type,
            "message": self.error_message,
        })
        
        return self
    
    def end(self) -> None:
        """إنهاء الـ Span"""
        if self.end_time is None:
            self.end_time = time.time()
            
            if self.status == SpanStatus.UNSET:
                self.status = SpanStatus.OK
    
    @property
    def duration_ms(self) -> float:
        """المدة بالميلي ثانية"""
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل لـ dictionary"""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind.value,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "events": [e.to_dict() for e in self.events],
            "error_message": self.error_message,
            "error_type": self.error_type,
        }


# ═══════════════════════════════════════════════════════════
#                     Trace
# ═══════════════════════════════════════════════════════════

@dataclass
class Trace:
    """
    تتبع كامل.
    
    يحتوي على عدة Spans.
    
    Example:
        >>> trace = Trace("my-trace")
        >>> with trace.span("operation1"):
        ...     do_something()
        >>> trace.end()
    """
    
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = ""
    
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    
    spans: List[Span] = field(default_factory=list)
    
    # Baggage - data propagated across services
    baggage: Dict[str, str] = field(default_factory=dict)
    
    # Root span
    root_span: Optional[Span] = None
    
    # Current span stack
    _span_stack: List[Span] = field(default_factory=list)
    
    def __post_init__(self):
        if self.name:
            self.root_span = self._create_span(self.name)
            self._span_stack.append(self.root_span)
    
    def _generate_span_id(self) -> str:
        """توليد Span ID"""
        return uuid.uuid4().hex[:16]
    
    def _create_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Span:
        """إنشاء Span"""
        parent_id = None
        if self._span_stack:
            parent_id = self._span_stack[-1].span_id
        
        span = Span(
            trace_id=self.trace_id,
            span_id=self._generate_span_id(),
            name=name,
            parent_span_id=parent_id,
            kind=kind,
        )
        
        self.spans.append(span)
        return span
    
    @contextmanager
    def span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Generator[Span, None, None]:
        """
        بدء Span جديد.
        
        Example:
            >>> with trace.span("process-data") as s:
            ...     s.set_attribute("items", 100)
            ...     process_data()
        """
        span = self._create_span(name, kind)
        self._span_stack.append(span)
        
        try:
            yield span
        except Exception as e:
            span.record_exception(e)
            raise
        finally:
            span.end()
            self._span_stack.pop()
    
    def current_span(self) -> Optional[Span]:
        """الـ Span الحالي"""
        return self._span_stack[-1] if self._span_stack else None
    
    def set_baggage(self, key: str, value: str) -> None:
        """إضافة baggage"""
        self.baggage[key] = value
    
    def get_baggage(self, key: str) -> Optional[str]:
        """الحصول على baggage"""
        return self.baggage.get(key)
    
    def end(self) -> None:
        """إنهاء التتبع"""
        self.end_time = time.time()
        
        if self.root_span:
            self.root_span.end()
    
    @property
    def duration_ms(self) -> float:
        """المدة الكلية"""
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل لـ dictionary"""
        return {
            "trace_id": self.trace_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "spans": [s.to_dict() for s in self.spans],
            "baggage": self.baggage,
        }


# ═══════════════════════════════════════════════════════════
#                     Context
# ═══════════════════════════════════════════════════════════

# Context variable for current trace
_current_trace: contextvars.ContextVar[Optional[Trace]] = contextvars.ContextVar(
    "current_trace", default=None
)

# Context variable for current span
_current_span: contextvars.ContextVar[Optional[Span]] = contextvars.ContextVar(
    "current_span", default=None
)


class TraceContext:
    """
    سياق التتبع.
    
    للتمرير بين الخدمات.
    """
    
    TRACE_HEADER = "X-Trace-ID"
    SPAN_HEADER = "X-Span-ID"
    BAGGAGE_PREFIX = "X-Baggage-"
    
    @classmethod
    def inject(cls, trace: Trace) -> Dict[str, str]:
        """حقن السياق في headers"""
        headers = {
            cls.TRACE_HEADER: trace.trace_id,
        }
        
        current = trace.current_span()
        if current:
            headers[cls.SPAN_HEADER] = current.span_id
        
        for key, value in trace.baggage.items():
            headers[f"{cls.BAGGAGE_PREFIX}{key}"] = value
        
        return headers
    
    @classmethod
    def extract(cls, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """استخراج السياق من headers"""
        trace_id = headers.get(cls.TRACE_HEADER)
        
        if not trace_id:
            return None
        
        context = {
            "trace_id": trace_id,
            "parent_span_id": headers.get(cls.SPAN_HEADER),
            "baggage": {},
        }
        
        for key, value in headers.items():
            if key.startswith(cls.BAGGAGE_PREFIX):
                baggage_key = key[len(cls.BAGGAGE_PREFIX):]
                context["baggage"][baggage_key] = value
        
        return context


# ═══════════════════════════════════════════════════════════
#                     Trace Exporter
# ═══════════════════════════════════════════════════════════

class TraceExporter:
    """
    مُصدِّر التتبعات.
    
    Base class للتصدير لأنظمة مختلفة.
    """
    
    def export(self, traces: List[Trace]) -> bool:
        """تصدير التتبعات"""
        raise NotImplementedError


class ConsoleExporter(TraceExporter):
    """تصدير للكونسول"""
    
    def export(self, traces: List[Trace]) -> bool:
        for trace in traces:
            print(f"\n{'='*60}")
            print(f"Trace: {trace.name} ({trace.trace_id})")
            print(f"Duration: {trace.duration_ms:.2f}ms")
            print(f"Spans: {len(trace.spans)}")
            
            for span in trace.spans:
                indent = "  " if span.parent_span_id else ""
                status = "✓" if span.status == SpanStatus.OK else "✗"
                print(f"{indent}{status} {span.name}: {span.duration_ms:.2f}ms")
                
                if span.error_message:
                    print(f"{indent}  Error: {span.error_message}")
            
            print(f"{'='*60}\n")
        
        return True


class JSONFileExporter(TraceExporter):
    """تصدير لملف JSON"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export(self, traces: List[Trace]) -> bool:
        try:
            for trace in traces:
                filename = f"{trace.trace_id}.json"
                filepath = self.output_dir / filename
                
                with open(filepath, "w") as f:
                    json.dump(trace.to_dict(), f, indent=2)
            
            return True
        except Exception as e:
            logger.error("Failed to export traces: %s", e)
            return False


class JaegerExporter(TraceExporter):
    """
    تصدير لـ Jaeger.
    
    يتطلب تشغيل Jaeger collector.
    """
    
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
            
            async def _export():
                async with aiohttp.ClientSession() as session:
                    for trace in traces:
                        payload = self._to_jaeger_format(trace)
                        async with session.post(
                            self.endpoint,
                            json=payload,
                        ) as resp:
                            if resp.status != 202:
                                logger.warning(
                                    "Jaeger export failed: %d", resp.status
                                )
            
            asyncio.run(_export())
            return True
            
        except ImportError:
            logger.warning("aiohttp required for Jaeger export")
            return False
        except Exception as e:
            logger.error("Jaeger export error: %s", e)
            return False
    
    def _to_jaeger_format(self, trace: Trace) -> Dict[str, Any]:
        """تحويل لتنسيق Jaeger"""
        spans = []
        
        for span in trace.spans:
            jaeger_span = {
                "traceIdLow": int(trace.trace_id[:16], 16),
                "traceIdHigh": int(trace.trace_id[16:], 16) if len(trace.trace_id) > 16 else 0,
                "spanId": int(span.span_id, 16),
                "operationName": span.name,
                "startTime": int(span.start_time * 1_000_000),  # microseconds
                "duration": int(span.duration_ms * 1000),  # microseconds
                "tags": [
                    {"key": k, "type": "string", "value": str(v)}
                    for k, v in span.attributes.items()
                ],
            }
            
            if span.parent_span_id:
                jaeger_span["references"] = [{
                    "refType": "CHILD_OF",
                    "spanId": int(span.parent_span_id, 16),
                }]
            
            spans.append(jaeger_span)
        
        return {
            "batch": {
                "process": {
                    "serviceName": self.service_name,
                },
                "spans": spans,
            }
        }


# ═══════════════════════════════════════════════════════════
#                     Tracer
# ═══════════════════════════════════════════════════════════

class Tracer:
    """
    المتتبع الرئيسي.
    
    Example:
        >>> tracer = Tracer(service_name="recon-cli")
        >>> 
        >>> with tracer.start_trace("scan-job") as trace:
        ...     with trace.span("subdomain-enum") as span:
        ...         span.set_attribute("target", "example.com")
        ...         enumerate_subdomains()
        ...     with trace.span("port-scan"):
        ...         scan_ports()
        >>> 
        >>> tracer.flush()
    """
    
    def __init__(
        self,
        service_name: str = "recon-cli",
        exporters: Optional[List[TraceExporter]] = None,
        auto_flush: bool = True,
        max_traces: int = 1000,
    ):
        self.service_name = service_name
        self.exporters = exporters or [ConsoleExporter()]
        self.auto_flush = auto_flush
        self.max_traces = max_traces
        
        self._traces: List[Trace] = []
        self._lock = threading.Lock()
    
    @contextmanager
    def start_trace(
        self,
        name: str,
        parent_context: Optional[Dict[str, Any]] = None,
    ) -> Generator[Trace, None, None]:
        """
        بدء trace جديد.
        
        Args:
            name: اسم التتبع
            parent_context: سياق من trace آخر
        """
        # Create trace
        if parent_context:
            trace = Trace(
                trace_id=parent_context.get("trace_id", uuid.uuid4().hex),
                name=name,
            )
            trace.baggage = parent_context.get("baggage", {})
        else:
            trace = Trace(name=name)
        
        # Set in context
        token = _current_trace.set(trace)
        
        try:
            yield trace
        finally:
            trace.end()
            _current_trace.reset(token)
            
            # Store trace
            with self._lock:
                self._traces.append(trace)
                
                # Auto flush if needed
                if self.auto_flush and len(self._traces) >= self.max_traces:
                    self._flush_internal()
    
    def get_current_trace(self) -> Optional[Trace]:
        """الـ trace الحالي"""
        return _current_trace.get()
    
    @contextmanager
    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Generator[Span, None, None]:
        """
        بدء span في الـ trace الحالي.
        
        Example:
            >>> with tracer.start_span("db-query") as span:
            ...     span.set_attribute("query", "SELECT * FROM ...")
            ...     execute_query()
        """
        trace = self.get_current_trace()
        
        if trace:
            with trace.span(name, kind) as span:
                yield span
        else:
            # No active trace, create orphan span
            span = Span(
                trace_id="orphan",
                span_id=uuid.uuid4().hex[:16],
                name=name,
                kind=kind,
            )
            try:
                yield span
            finally:
                span.end()
    
    def flush(self) -> None:
        """تصدير التتبعات المُخزنة"""
        with self._lock:
            self._flush_internal()
    
    def _flush_internal(self) -> None:
        """تصدير داخلي"""
        if not self._traces:
            return
        
        for exporter in self.exporters:
            try:
                exporter.export(self._traces)
            except Exception as e:
                logger.error("Exporter %s failed: %s", type(exporter).__name__, e)
        
        self._traces.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """إحصائيات"""
        with self._lock:
            total_spans = sum(len(t.spans) for t in self._traces)
            
            return {
                "pending_traces": len(self._traces),
                "pending_spans": total_spans,
                "exporters": [type(e).__name__ for e in self.exporters],
            }


# ═══════════════════════════════════════════════════════════
#                     Decorators
# ═══════════════════════════════════════════════════════════

def traced(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
) -> Callable:
    """
    مُزخرف لتتبع دالة.
    
    Example:
        >>> @traced("fetch-data")
        ... def fetch_data():
        ...     return get_data()
        >>> 
        >>> @traced(attributes={"component": "db"})
        ... async def query_db():
        ...     return await db.query()
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        span_name = name or func.__name__
        
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs) -> T:
                trace = _current_trace.get()
                
                if trace:
                    with trace.span(span_name, kind) as span:
                        if attributes:
                            span.set_attributes(attributes)
                        return await func(*args, **kwargs)
                else:
                    return await func(*args, **kwargs)
            
            return async_wrapper
        else:
            def sync_wrapper(*args, **kwargs) -> T:
                trace = _current_trace.get()
                
                if trace:
                    with trace.span(span_name, kind) as span:
                        if attributes:
                            span.set_attributes(attributes)
                        return func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            
            return sync_wrapper
    
    return decorator


# ═══════════════════════════════════════════════════════════
#                     Global Tracer
# ═══════════════════════════════════════════════════════════

# Default tracer
tracer = Tracer(service_name="recon-cli")


def get_tracer() -> Tracer:
    """الحصول على المتتبع"""
    return tracer


def configure_tracer(
    service_name: str = "recon-cli",
    exporters: Optional[List[TraceExporter]] = None,
    auto_flush: bool = True,
) -> Tracer:
    """تكوين المتتبع"""
    global tracer
    tracer = Tracer(
        service_name=service_name,
        exporters=exporters,
        auto_flush=auto_flush,
    )
    return tracer
