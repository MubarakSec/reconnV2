"""
Unit Tests for Metrics System

اختبارات:
- Counter, Gauge, Histogram, Summary
- Labels
- Export formats
"""

import time

import pytest


# ═══════════════════════════════════════════════════════════
#                     Import Module
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.utils.metrics import (
        Counter,
        Gauge,
        Histogram,
        Summary,
        MetricsRegistry,
        get_metrics,
        export_prometheus,
    )

    HAS_METRICS = True
except ImportError:
    HAS_METRICS = False


pytestmark = [
    pytest.mark.skipif(not HAS_METRICS, reason="metrics not available"),
]


# ═══════════════════════════════════════════════════════════
#                     Counter Tests
# ═══════════════════════════════════════════════════════════


class TestCounter:
    """اختبارات Counter"""

    def test_counter_increment(self):
        """زيادة العداد"""
        counter = Counter("test_counter", "Test counter")

        counter.inc()

        assert counter.get() == 1

    def test_counter_increment_by_value(self):
        """زيادة بقيمة محددة"""
        counter = Counter("test_counter_2", "Test counter")

        counter.inc(5)

        assert counter.get() == 5

    def test_counter_with_labels(self):
        """عداد مع labels"""
        counter = Counter(
            "test_labeled_counter",
            "Test labeled counter",
            labels=["method", "status"],
        )

        counter.labels(method="GET", status="200").inc()
        counter.labels(method="POST", status="201").inc(2)

        assert counter.labels(method="GET", status="200").get() == 1
        assert counter.labels(method="POST", status="201").get() == 2

    def test_counter_cannot_decrease(self):
        """العداد لا يمكن أن ينخفض"""
        counter = Counter("test_counter_3", "Test counter")

        counter.inc(5)

        with pytest.raises((ValueError, Exception)):
            counter.inc(-1)


# ═══════════════════════════════════════════════════════════
#                     Gauge Tests
# ═══════════════════════════════════════════════════════════


class TestGauge:
    """اختبارات Gauge"""

    def test_gauge_set(self):
        """تعيين قيمة"""
        gauge = Gauge("test_gauge", "Test gauge")

        gauge.set(42)

        assert gauge.get() == 42

    def test_gauge_inc(self):
        """زيادة"""
        gauge = Gauge("test_gauge_2", "Test gauge")

        gauge.set(10)
        gauge.inc(5)

        assert gauge.get() == 15

    def test_gauge_dec(self):
        """نقصان"""
        gauge = Gauge("test_gauge_3", "Test gauge")

        gauge.set(10)
        gauge.dec(3)

        assert gauge.get() == 7

    def test_gauge_with_labels(self):
        """gauge مع labels"""
        gauge = Gauge(
            "test_labeled_gauge",
            "Test labeled gauge",
            labels=["host"],
        )

        gauge.labels(host="server1").set(100)
        gauge.labels(host="server2").set(200)

        assert gauge.labels(host="server1").get() == 100
        assert gauge.labels(host="server2").get() == 200

    def test_gauge_set_to_current_time(self):
        """تعيين للوقت الحالي"""
        gauge = Gauge("test_time_gauge", "Test time gauge")

        before = time.time()
        gauge.set_to_current_time()
        after = time.time()

        assert before <= gauge.get() <= after


# ═══════════════════════════════════════════════════════════
#                     Histogram Tests
# ═══════════════════════════════════════════════════════════


class TestHistogram:
    """اختبارات Histogram"""

    def test_histogram_observe(self):
        """ملاحظة قيمة"""
        histogram = Histogram(
            "test_histogram",
            "Test histogram",
            buckets=[0.1, 0.5, 1.0, 5.0],
        )

        histogram.observe(0.3)
        histogram.observe(0.7)
        histogram.observe(2.0)

        stats = histogram.get_stats()

        assert stats["count"] == 3
        assert stats["sum"] == pytest.approx(3.0)

    def test_histogram_buckets(self):
        """buckets"""
        histogram = Histogram(
            "test_histogram_2",
            "Test histogram",
            buckets=[0.1, 0.5, 1.0],
        )

        histogram.observe(0.05)  # <= 0.1
        histogram.observe(0.3)  # <= 0.5
        histogram.observe(0.8)  # <= 1.0
        histogram.observe(2.0)  # > 1.0

        buckets = histogram.get_buckets()

        assert buckets["0.1"] >= 1
        assert buckets["0.5"] >= 2
        assert buckets["1.0"] >= 3

    def test_histogram_with_labels(self):
        """histogram مع labels"""
        histogram = Histogram(
            "test_labeled_histogram",
            "Test labeled histogram",
            labels=["endpoint"],
            buckets=[0.1, 0.5, 1.0],
        )

        histogram.labels(endpoint="/api/users").observe(0.2)
        histogram.labels(endpoint="/api/jobs").observe(0.8)

        stats1 = histogram.labels(endpoint="/api/users").get_stats()
        stats2 = histogram.labels(endpoint="/api/jobs").get_stats()

        assert stats1["count"] == 1
        assert stats2["count"] == 1

    def test_histogram_timer(self):
        """مؤقت"""
        histogram = Histogram(
            "test_timer_histogram",
            "Test timer histogram",
            buckets=[0.01, 0.1, 1.0],
        )

        with histogram.time():
            time.sleep(0.05)

        stats = histogram.get_stats()

        assert stats["count"] == 1
        assert stats["sum"] >= 0.05


# ═══════════════════════════════════════════════════════════
#                     Summary Tests
# ═══════════════════════════════════════════════════════════


class TestSummary:
    """اختبارات Summary"""

    def test_summary_observe(self):
        """ملاحظة قيمة"""
        summary = Summary(
            "test_summary",
            "Test summary",
        )

        for i in range(100):
            summary.observe(i)

        stats = summary.get_stats()

        assert stats["count"] == 100
        assert stats["sum"] == sum(range(100))

    def test_summary_quantiles(self):
        """quantiles"""
        summary = Summary(
            "test_summary_2",
            "Test summary",
            quantiles=[0.5, 0.9, 0.99],
        )

        for i in range(1, 101):
            summary.observe(i)

        quantiles = summary.get_quantiles()

        # Median should be around 50
        assert 45 <= quantiles["0.5"] <= 55
        # 90th percentile should be around 90
        assert 85 <= quantiles["0.9"] <= 95

    def test_summary_with_labels(self):
        """summary مع labels"""
        summary = Summary(
            "test_labeled_summary",
            "Test labeled summary",
            labels=["method"],
        )

        summary.labels(method="GET").observe(0.1)
        summary.labels(method="POST").observe(0.2)

        stats_get = summary.labels(method="GET").get_stats()
        stats_post = summary.labels(method="POST").get_stats()

        assert stats_get["count"] == 1
        assert stats_post["count"] == 1


# ═══════════════════════════════════════════════════════════
#                     Registry Tests
# ═══════════════════════════════════════════════════════════


class TestMetricsRegistry:
    """اختبارات Registry"""

    def test_register_metric(self):
        """تسجيل metric"""
        registry = MetricsRegistry()

        counter = Counter("reg_test_counter", "Test counter")
        registry.register(counter)

        assert "reg_test_counter" in registry.get_all()

    def test_get_metric(self):
        """الحصول على metric"""
        registry = MetricsRegistry()

        counter = Counter("reg_test_counter_2", "Test counter")
        registry.register(counter)

        retrieved = registry.get("reg_test_counter_2")

        assert retrieved is counter

    def test_unregister_metric(self):
        """إلغاء تسجيل metric"""
        registry = MetricsRegistry()

        counter = Counter("reg_test_counter_3", "Test counter")
        registry.register(counter)
        registry.unregister("reg_test_counter_3")

        assert "reg_test_counter_3" not in registry.get_all()

    def test_clear_registry(self):
        """مسح السجل"""
        registry = MetricsRegistry()

        counter1 = Counter("clear_test_1", "Test 1")
        counter2 = Counter("clear_test_2", "Test 2")
        registry.register(counter1)
        registry.register(counter2)

        registry.clear()

        assert len(registry.get_all()) == 0


# ═══════════════════════════════════════════════════════════
#                     Export Tests
# ═══════════════════════════════════════════════════════════


class TestMetricsExport:
    """اختبارات التصدير"""

    def test_prometheus_format(self):
        """تنسيق Prometheus"""
        registry = MetricsRegistry()

        counter = Counter("export_counter", "Export test counter")
        counter.inc(5)
        registry.register(counter)

        output = export_prometheus(registry)

        assert "export_counter" in output
        assert "5" in output

    def test_prometheus_with_labels(self):
        """Prometheus مع labels"""
        registry = MetricsRegistry()

        counter = Counter(
            "labeled_export_counter",
            "Labeled export test",
            labels=["method"],
        )
        counter.labels(method="GET").inc(10)
        registry.register(counter)

        output = export_prometheus(registry)

        assert 'method="GET"' in output
        assert "10" in output

    def test_prometheus_histogram(self):
        """Prometheus histogram"""
        registry = MetricsRegistry()

        histogram = Histogram(
            "export_histogram",
            "Export test histogram",
            buckets=[0.1, 1.0, 10.0],
        )
        histogram.observe(0.5)
        histogram.observe(5.0)
        registry.register(histogram)

        output = export_prometheus(registry)

        assert "export_histogram_bucket" in output
        assert "export_histogram_count" in output
        assert "export_histogram_sum" in output


# ═══════════════════════════════════════════════════════════
#                     Global Metrics Tests
# ═══════════════════════════════════════════════════════════


class TestGlobalMetrics:
    """اختبارات المقاييس العامة"""

    def test_get_metrics(self):
        """الحصول على المقاييس"""
        metrics = get_metrics()

        assert metrics is not None

    def test_metrics_singleton(self):
        """المقاييس singleton"""
        m1 = get_metrics()
        m2 = get_metrics()

        assert m1 is m2


# ═══════════════════════════════════════════════════════════
#                     Thread Safety Tests
# ═══════════════════════════════════════════════════════════


class TestMetricsThreadSafety:
    """اختبارات سلامة الخيوط"""

    def test_concurrent_counter_increment(self):
        """زيادة متزامنة للعداد"""
        import threading

        counter = Counter("thread_test_counter", "Thread test")

        def increment():
            for _ in range(100):
                counter.inc()

        threads = [threading.Thread(target=increment) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter.get() == 1000

    def test_concurrent_gauge_updates(self):
        """تحديثات متزامنة للـ gauge"""
        import threading

        gauge = Gauge("thread_test_gauge", "Thread test")
        gauge.set(0)

        def update(value):
            for _ in range(100):
                gauge.inc(value)

        threads = [threading.Thread(target=update, args=(1,)) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert gauge.get() == 1000
