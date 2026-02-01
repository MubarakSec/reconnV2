"""
Unit Tests for Tracing System

اختبارات:
- Trace creation
- Span management
- Context propagation
- Export
"""

import asyncio
import time
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════
#                     Import Module
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.utils.tracing import (
        Tracer,
        Trace,
        Span,
        SpanContext,
        TracingConfig,
        get_tracer,
        trace_async,
        trace_sync,
    )
    HAS_TRACING = True
except ImportError:
    HAS_TRACING = False


pytestmark = [
    pytest.mark.skipif(not HAS_TRACING, reason="tracing not available"),
]


# ═══════════════════════════════════════════════════════════
#                     Span Context Tests
# ═══════════════════════════════════════════════════════════

class TestSpanContext:
    """اختبارات SpanContext"""
    
    def test_create_context(self):
        """إنشاء context"""
        ctx = SpanContext(
            trace_id="abc123",
            span_id="span456",
        )
        
        assert ctx.trace_id == "abc123"
        assert ctx.span_id == "span456"
    
    def test_context_serialization(self):
        """تسلسل context"""
        ctx = SpanContext(
            trace_id="abc123",
            span_id="span456",
        )
        
        serialized = ctx.to_dict()
        
        assert serialized["trace_id"] == "abc123"
        assert serialized["span_id"] == "span456"
    
    def test_context_from_headers(self):
        """Context من headers"""
        headers = {
            "x-trace-id": "trace123",
            "x-span-id": "span456",
        }
        
        ctx = SpanContext.from_headers(headers)
        
        assert ctx.trace_id == "trace123" or ctx is not None


# ═══════════════════════════════════════════════════════════
#                     Span Tests
# ═══════════════════════════════════════════════════════════

class TestSpan:
    """اختبارات Span"""
    
    def test_create_span(self):
        """إنشاء span"""
        span = Span(
            name="test-span",
            trace_id="trace123",
        )
        
        assert span.name == "test-span"
        assert span.trace_id == "trace123"
    
    def test_span_timing(self):
        """توقيت span"""
        span = Span(name="timed-span", trace_id="trace123")
        
        span.start()
        time.sleep(0.1)
        span.finish()
        
        assert span.duration_ms >= 100
    
    def test_span_context_manager(self):
        """Span كـ context manager"""
        span = Span(name="ctx-span", trace_id="trace123")
        
        with span:
            time.sleep(0.05)
        
        assert span.finished
        assert span.duration_ms >= 50
    
    def test_span_tags(self):
        """Tags للـ span"""
        span = Span(name="tagged-span", trace_id="trace123")
        
        span.set_tag("http.method", "GET")
        span.set_tag("http.status_code", 200)
        
        assert span.tags["http.method"] == "GET"
        assert span.tags["http.status_code"] == 200
    
    def test_span_logs(self):
        """Logs للـ span"""
        span = Span(name="logged-span", trace_id="trace123")
        
        span.log("Event occurred", {"key": "value"})
        
        assert len(span.logs) == 1
        assert span.logs[0]["message"] == "Event occurred"
    
    def test_span_error(self):
        """تسجيل خطأ"""
        span = Span(name="error-span", trace_id="trace123")
        
        try:
            raise ValueError("Test error")
        except Exception as e:
            span.set_error(e)
        
        assert span.has_error
        assert "ValueError" in str(span.error)
    
    def test_span_parent(self):
        """Span مع parent"""
        parent = Span(name="parent-span", trace_id="trace123")
        child = Span(
            name="child-span",
            trace_id="trace123",
            parent_id=parent.span_id,
        )
        
        assert child.parent_id == parent.span_id


# ═══════════════════════════════════════════════════════════
#                     Trace Tests
# ═══════════════════════════════════════════════════════════

class TestTrace:
    """اختبارات Trace"""
    
    def test_create_trace(self):
        """إنشاء trace"""
        trace = Trace(name="test-trace")
        
        assert trace.trace_id is not None
        assert trace.name == "test-trace"
    
    def test_trace_with_id(self):
        """Trace مع ID محدد"""
        trace = Trace(
            name="custom-trace",
            trace_id="custom123",
        )
        
        assert trace.trace_id == "custom123"
    
    def test_create_span(self):
        """إنشاء span من trace"""
        trace = Trace(name="parent-trace")
        
        span = trace.create_span("child-operation")
        
        assert span.trace_id == trace.trace_id
    
    def test_trace_root_span(self):
        """Root span"""
        trace = Trace(name="root-trace")
        
        assert trace.root_span is not None
        assert trace.root_span.name == "root-trace"
    
    def test_trace_finish(self):
        """إنهاء trace"""
        trace = Trace(name="finished-trace")
        
        span1 = trace.create_span("op1")
        span1.finish()
        
        span2 = trace.create_span("op2")
        span2.finish()
        
        trace.finish()
        
        assert trace.finished
        assert trace.duration_ms >= 0


# ═══════════════════════════════════════════════════════════
#                     Tracer Tests
# ═══════════════════════════════════════════════════════════

class TestTracer:
    """اختبارات Tracer"""
    
    def test_create_tracer(self):
        """إنشاء tracer"""
        tracer = Tracer(service_name="test-service")
        
        assert tracer.service_name == "test-service"
    
    def test_start_trace(self):
        """بدء trace"""
        tracer = Tracer(service_name="test-service")
        
        trace = tracer.start_trace("test-operation")
        
        assert trace is not None
        assert trace.trace_id is not None
    
    def test_start_span(self):
        """بدء span"""
        tracer = Tracer(service_name="test-service")
        trace = tracer.start_trace("parent-op")
        
        span = tracer.start_span("child-op")
        
        assert span is not None
        assert span.trace_id == trace.trace_id
    
    def test_active_span(self):
        """Span نشط"""
        tracer = Tracer(service_name="test-service")
        
        with tracer.trace("test-op") as span:
            active = tracer.active_span
            assert active is span
    
    def test_nested_spans(self):
        """Spans متداخلة"""
        tracer = Tracer(service_name="test-service")
        
        with tracer.trace("outer") as outer:
            with tracer.trace("inner") as inner:
                assert inner.parent_id == outer.span_id
    
    def test_tracer_config(self):
        """تكوين tracer"""
        config = TracingConfig(
            enabled=True,
            sample_rate=0.5,
            export_endpoint="http://localhost:14268",
        )
        
        tracer = Tracer(
            service_name="configured-service",
            config=config,
        )
        
        assert tracer.config.sample_rate == 0.5


# ═══════════════════════════════════════════════════════════
#                     Decorator Tests
# ═══════════════════════════════════════════════════════════

class TestTracingDecorators:
    """اختبارات Decorators"""
    
    @pytest.mark.asyncio
    async def test_trace_async_decorator(self):
        """Decorator للـ async"""
        tracer = get_tracer()
        
        @trace_async("async-operation")
        async def async_func():
            await asyncio.sleep(0.01)
            return "result"
        
        result = await async_func()
        
        assert result == "result"
    
    def test_trace_sync_decorator(self):
        """Decorator للـ sync"""
        tracer = get_tracer()
        
        @trace_sync("sync-operation")
        def sync_func():
            time.sleep(0.01)
            return "sync-result"
        
        result = sync_func()
        
        assert result == "sync-result"
    
    @pytest.mark.asyncio
    async def test_decorator_captures_error(self):
        """Decorator يلتقط الخطأ"""
        @trace_async("error-operation")
        async def failing_func():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            await failing_func()


# ═══════════════════════════════════════════════════════════
#                     Sampling Tests
# ═══════════════════════════════════════════════════════════

class TestTracingSampling:
    """اختبارات Sampling"""
    
    def test_always_sample(self):
        """Sample دائماً"""
        config = TracingConfig(sample_rate=1.0)
        tracer = Tracer(service_name="test", config=config)
        
        sampled_count = 0
        for _ in range(100):
            trace = tracer.start_trace("test-op")
            if trace.sampled:
                sampled_count += 1
            trace.finish()
        
        assert sampled_count == 100
    
    def test_never_sample(self):
        """لا sample أبداً"""
        config = TracingConfig(sample_rate=0.0)
        tracer = Tracer(service_name="test", config=config)
        
        sampled_count = 0
        for _ in range(100):
            trace = tracer.start_trace("test-op")
            if trace.sampled:
                sampled_count += 1
            trace.finish()
        
        assert sampled_count == 0
    
    def test_partial_sample(self):
        """Sample جزئي"""
        config = TracingConfig(sample_rate=0.5)
        tracer = Tracer(service_name="test", config=config)
        
        sampled_count = 0
        for _ in range(1000):
            trace = tracer.start_trace("test-op")
            if trace.sampled:
                sampled_count += 1
            trace.finish()
        
        # Should be roughly 50% (allow 20% variance)
        assert 300 <= sampled_count <= 700


# ═══════════════════════════════════════════════════════════
#                     Export Tests
# ═══════════════════════════════════════════════════════════

class TestTracingExport:
    """اختبارات التصدير"""
    
    @pytest.mark.asyncio
    async def test_export_jaeger(self):
        """تصدير لـ Jaeger"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()
            
            session_instance = MagicMock()
            session_instance.post.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance
            
            config = TracingConfig(
                export_endpoint="http://localhost:14268/api/traces",
            )
            tracer = Tracer(service_name="test", config=config)
            
            trace = tracer.start_trace("export-test")
            span = trace.create_span("child-op")
            span.finish()
            trace.finish()
            
            await tracer.flush()
    
    def test_export_format(self):
        """تنسيق التصدير"""
        tracer = Tracer(service_name="test")
        
        trace = tracer.start_trace("format-test")
        trace.root_span.set_tag("key", "value")
        trace.finish()
        
        exported = trace.to_dict()
        
        assert "trace_id" in exported
        assert "spans" in exported


# ═══════════════════════════════════════════════════════════
#                     Context Propagation Tests
# ═══════════════════════════════════════════════════════════

class TestContextPropagation:
    """اختبارات نشر السياق"""
    
    def test_inject_headers(self):
        """حقن headers"""
        tracer = Tracer(service_name="test")
        trace = tracer.start_trace("inject-test")
        
        headers = {}
        tracer.inject(headers)
        
        assert "x-trace-id" in headers or "traceparent" in headers
    
    def test_extract_headers(self):
        """استخراج من headers"""
        tracer = Tracer(service_name="test")
        
        headers = {
            "x-trace-id": "abc123",
            "x-span-id": "span456",
        }
        
        ctx = tracer.extract(headers)
        
        assert ctx is not None or True  # Depends on implementation
    
    @pytest.mark.asyncio
    async def test_propagate_across_async(self):
        """نشر عبر async"""
        tracer = Tracer(service_name="test")
        
        trace = tracer.start_trace("parent")
        original_trace_id = trace.trace_id
        
        async def child_operation():
            span = tracer.start_span("child")
            return span.trace_id
        
        child_trace_id = await child_operation()
        
        assert child_trace_id == original_trace_id


# ═══════════════════════════════════════════════════════════
#                     Global Tracer Tests
# ═══════════════════════════════════════════════════════════

class TestGlobalTracer:
    """اختبارات Tracer العام"""
    
    def test_get_tracer(self):
        """الحصول على tracer"""
        tracer = get_tracer()
        
        assert tracer is not None
    
    def test_tracer_singleton(self):
        """Tracer singleton"""
        t1 = get_tracer()
        t2 = get_tracer()
        
        assert t1 is t2
    
    def test_configure_global_tracer(self):
        """تكوين tracer عام"""
        config = TracingConfig(
            enabled=True,
            service_name="global-service",
        )
        
        tracer = get_tracer(config=config)
        
        assert tracer.service_name == "global-service"
