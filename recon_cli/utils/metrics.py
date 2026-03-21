"""
Prometheus Metrics - مقاييس المراقبة

نظام مقاييس متوافق مع Prometheus.

Features:
- Counters, Gauges, Histograms
- تصدير بتنسيق Prometheus
- مقاييس Pipeline و Jobs
- تكامل مع API

Example:
    >>> from recon_cli.utils.metrics import metrics
    >>> metrics.scans_total.inc()
    >>> metrics.scan_duration.observe(15.5)
    >>> print(metrics.export())
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════
#                     Metric Types
# ═══════════════════════════════════════════════════════════


class MetricType(Enum):
    """أنواع المقاييس"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class MetricLabel:
    """تسمية المقياس"""

    name: str
    value: str


# ═══════════════════════════════════════════════════════════
#                     Counter
# ═══════════════════════════════════════════════════════════


class Counter:
    """
    عداد تصاعدي.

    يُستخدم لعد الأحداث التي تزيد فقط.

    Example:
        >>> requests = Counter("http_requests_total", "Total HTTP requests")
        >>> requests.inc()
        >>> requests.inc(5)
        >>> requests.labels(method="GET", status="200").inc()
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
    ):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._type = MetricType.COUNTER

        self._value = 0.0
        self._labeled_values: Dict[Tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0) -> None:
        """زيادة العداد"""
        if amount < 0:
            raise ValueError("Counter can only increase")

        with self._lock:
            self._value += amount

    def labels(self, **kwargs) -> "_LabeledCounter":
        """مع تسميات"""
        label_values = tuple(kwargs.get(name, "") for name in self.label_names)
        return _LabeledCounter(self, label_values)

    def get(self) -> float:
        """القيمة الحالية"""
        with self._lock:
            return self._value

    def get_labeled(self, label_values: Tuple) -> float:
        """القيمة مع تسميات"""
        with self._lock:
            return self._labeled_values.get(label_values, 0.0)

    def _inc_labeled(self, label_values: Tuple, amount: float = 1.0) -> None:
        """زيادة مع تسميات"""
        with self._lock:
            self._labeled_values[label_values] += amount

    def reset(self) -> None:
        """إعادة تعيين (للاختبار فقط)"""
        with self._lock:
            self._value = 0.0
            self._labeled_values.clear()


class _LabeledCounter:
    """عداد مع تسميات"""

    def __init__(self, counter: Counter, label_values: Tuple):
        self._counter = counter
        self._label_values = label_values

    def inc(self, amount: float = 1.0) -> None:
        self._counter._inc_labeled(self._label_values, amount)

    def get(self) -> float:
        return self._counter.get_labeled(self._label_values)


# ═══════════════════════════════════════════════════════════
#                     Gauge
# ═══════════════════════════════════════════════════════════


class Gauge:
    """
    مقياس قابل للزيادة والنقصان.

    يُستخدم للقيم التي ترتفع وتنخفض.

    Example:
        >>> temperature = Gauge("temperature_celsius", "Current temperature")
        >>> temperature.set(25.5)
        >>> temperature.inc(2)
        >>> temperature.dec(1)
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
    ):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._type = MetricType.GAUGE

        self._value = 0.0
        self._labeled_values: Dict[Tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        """تعيين القيمة"""
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0) -> None:
        """زيادة"""
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        """نقصان"""
        with self._lock:
            self._value -= amount

    def labels(self, **kwargs) -> "_LabeledGauge":
        """مع تسميات"""
        label_values = tuple(kwargs.get(name, "") for name in self.label_names)
        return _LabeledGauge(self, label_values)

    def get(self) -> float:
        """القيمة الحالية"""
        with self._lock:
            return self._value

    def set_to_current_time(self) -> None:
        """تعيين للوقت الحالي (Unix timestamp)"""
        self.set(time.time())

    def track_inprogress(self) -> "_InProgressTracker":
        """تتبع العمليات الجارية"""
        return _InProgressTracker(self)

    def _set_labeled(self, label_values: Tuple, value: float) -> None:
        with self._lock:
            self._labeled_values[label_values] = value

    def _inc_labeled(self, label_values: Tuple, amount: float = 1.0) -> None:
        with self._lock:
            self._labeled_values[label_values] += amount

    def _dec_labeled(self, label_values: Tuple, amount: float = 1.0) -> None:
        with self._lock:
            self._labeled_values[label_values] -= amount

    def get_labeled(self, label_values: Tuple) -> float:
        with self._lock:
            return self._labeled_values.get(label_values, 0.0)


class _LabeledGauge:
    """مقياس مع تسميات"""

    def __init__(self, gauge: Gauge, label_values: Tuple):
        self._gauge = gauge
        self._label_values = label_values

    def set(self, value: float) -> None:
        self._gauge._set_labeled(self._label_values, value)

    def inc(self, amount: float = 1.0) -> None:
        self._gauge._inc_labeled(self._label_values, amount)

    def dec(self, amount: float = 1.0) -> None:
        self._gauge._dec_labeled(self._label_values, amount)

    def get(self) -> float:
        return self._gauge.get_labeled(self._label_values)


class _InProgressTracker:
    """تتبع context manager"""

    def __init__(self, gauge: Gauge):
        self._gauge = gauge

    def __enter__(self):
        self._gauge.inc()
        return self

    def __exit__(self, *args):
        self._gauge.dec()


# ═══════════════════════════════════════════════════════════
#                     Histogram
# ═══════════════════════════════════════════════════════════


class Histogram:
    """
    توزيع القيم.

    يُستخدم لقياس توزيع القيم (مثل مدة الطلبات).

    Example:
        >>> duration = Histogram(
        ...     "request_duration_seconds",
        ...     "Request duration",
        ...     buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
        ... )
        >>> duration.observe(0.25)
        >>> with duration.time():
        ...     do_something()
    """

    DEFAULT_BUCKETS = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.075,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        7.5,
        10.0,
        float("inf"),
    )

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Optional[Sequence[float]] = None,
        labels: Optional[List[str]] = None,
    ):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._type = MetricType.HISTOGRAM

        self._buckets = tuple(sorted(buckets or self.DEFAULT_BUCKETS))
        if self._buckets[-1] != float("inf"):
            self._buckets = self._buckets + (float("inf"),)

        self._bucket_counts: Dict[float, int] = {b: 0 for b in self._buckets}
        self._sum = 0.0
        self._count = 0

        self._labeled_data: Dict[Tuple, Dict] = defaultdict(
            lambda: {
                "buckets": {b: 0 for b in self._buckets},
                "sum": 0.0,
                "count": 0,
            }
        )
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        """تسجيل قيمة"""
        with self._lock:
            self._sum += value
            self._count += 1

            for bucket in self._buckets:
                if value <= bucket:
                    self._bucket_counts[bucket] += 1

    def labels(self, **kwargs) -> "_LabeledHistogram":
        """مع تسميات"""
        label_values = tuple(kwargs.get(name, "") for name in self.label_names)
        return _LabeledHistogram(self, label_values)

    def time(self) -> "_HistogramTimer":
        """قياس الوقت"""
        return _HistogramTimer(self)

    def get_sample_count(self) -> int:
        """عدد العينات"""
        with self._lock:
            return self._count

    def get_sample_sum(self) -> float:
        """مجموع القيم"""
        with self._lock:
            return self._sum

    def _get_buckets_internal(self) -> Dict[float, int]:
        with self._lock:
            return dict(self._bucket_counts)

    def get_buckets(self) -> Dict[str, int]:
        """البيانات بالـ buckets"""
        with self._lock:
            formatted: Dict[str, int] = {}
            for bucket, value in self._bucket_counts.items():
                key = "+Inf" if bucket == float("inf") else str(bucket)
                formatted[key] = value
            return formatted

    def get_stats(self) -> Dict[str, float]:
        with self._lock:
            return {"count": float(self._count), "sum": self._sum}

    def _observe_labeled(self, label_values: Tuple, value: float) -> None:
        with self._lock:
            data = self._labeled_data[label_values]
            data["sum"] += value
            data["count"] += 1

            for bucket in self._buckets:
                if value <= bucket:
                    data["buckets"][bucket] += 1


class _LabeledHistogram:
    """توزيع مع تسميات"""

    def __init__(self, histogram: Histogram, label_values: Tuple):
        self._histogram = histogram
        self._label_values = label_values

    def observe(self, value: float) -> None:
        self._histogram._observe_labeled(self._label_values, value)

    def time(self) -> "_HistogramTimer":
        return _HistogramTimer(self)

    def get_stats(self) -> Dict[str, float]:
        with self._histogram._lock:
            data = self._histogram._labeled_data[self._label_values]
            return {"count": float(data["count"]), "sum": float(data["sum"])}


class _HistogramTimer:
    """مؤقت للـ Histogram"""

    def __init__(self, histogram: Union[Histogram, _LabeledHistogram]):
        self._histogram = histogram
        self._start = None

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        duration = time.perf_counter() - self._start
        self._histogram.observe(duration)


# ═══════════════════════════════════════════════════════════
#                     Summary
# ═══════════════════════════════════════════════════════════


class Summary:
    """
    ملخص إحصائي.

    يحسب النسب المئوية (quantiles).

    Example:
        >>> latency = Summary("request_latency", "Request latency")
        >>> latency.observe(0.5)
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        quantiles: Optional[List[float]] = None,
        labels: Optional[List[str]] = None,
    ):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._type = MetricType.SUMMARY

        self._quantiles = quantiles or [0.5, 0.9, 0.99]
        self._values: List[float] = []
        self._sum = 0.0
        self._count = 0
        self._max_samples = 10000
        self._labeled_data: Dict[Tuple, Dict[str, Any]] = defaultdict(
            lambda: {"values": [], "sum": 0.0, "count": 0}
        )
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        """تسجيل قيمة"""
        with self._lock:
            self._sum += value
            self._count += 1

            self._values.append(value)
            if len(self._values) > self._max_samples:
                self._values = self._values[-self._max_samples :]

    def get_quantile(self, quantile: float) -> float:
        """الحصول على quantile"""
        with self._lock:
            if not self._values:
                return 0.0

            sorted_values = sorted(self._values)
            idx = int(quantile * len(sorted_values))
            return sorted_values[min(idx, len(sorted_values) - 1)]

    def get_sample_count(self) -> int:
        with self._lock:
            return self._count

    def get_sample_sum(self) -> float:
        with self._lock:
            return self._sum

    def labels(self, **kwargs) -> "_LabeledSummary":
        label_values = tuple(kwargs.get(name, "") for name in self.label_names)
        return _LabeledSummary(self, label_values)

    def _observe_labeled(self, label_values: Tuple, value: float) -> None:
        with self._lock:
            data = self._labeled_data[label_values]
            data["sum"] += value
            data["count"] += 1
            values = data["values"]
            values.append(value)
            if len(values) > self._max_samples:
                data["values"] = values[-self._max_samples :]

    def _get_stats_labeled(self, label_values: Tuple) -> Dict[str, float]:
        with self._lock:
            data = self._labeled_data[label_values]
            return {"count": float(data["count"]), "sum": float(data["sum"])}

    def _get_quantile_labeled(self, label_values: Tuple, quantile: float) -> float:
        with self._lock:
            values = self._labeled_data[label_values]["values"]
            if not values:
                return 0.0
            sorted_values = sorted(values)
            idx = int(quantile * len(sorted_values))
            return sorted_values[min(idx, len(sorted_values) - 1)]

    def get_stats(self) -> Dict[str, float]:
        with self._lock:
            return {"count": float(self._count), "sum": self._sum}

    def get_quantiles(self) -> Dict[str, float]:
        return {str(q): self.get_quantile(q) for q in self._quantiles}


class _LabeledSummary:
    def __init__(self, summary: Summary, label_values: Tuple):
        self._summary = summary
        self._label_values = label_values

    def observe(self, value: float) -> None:
        self._summary._observe_labeled(self._label_values, value)

    def get_stats(self) -> Dict[str, float]:
        return self._summary._get_stats_labeled(self._label_values)

    def get_quantiles(self) -> Dict[str, float]:
        return {
            str(q): self._summary._get_quantile_labeled(self._label_values, q)
            for q in self._summary._quantiles
        }


# ═══════════════════════════════════════════════════════════
#                     Metrics Registry
# ═══════════════════════════════════════════════════════════


class MetricsRegistry:
    """
    سجل المقاييس.

    يجمع كل المقاييس ويصدرها بتنسيق Prometheus.

    Example:
        >>> registry = MetricsRegistry()
        >>> counter = registry.counter("requests_total", "Total requests")
        >>> gauge = registry.gauge("active_connections", "Active connections")
        >>> print(registry.export())
    """

    def __init__(self):
        self._metrics: Dict[str, Union[Counter, Gauge, Histogram, Summary]] = {}
        self._lock = threading.Lock()

    def counter(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
    ) -> Counter:
        """إنشاء Counter"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Counter(name, description, labels)
            return self._metrics[name]  # type: ignore[return-value]

    def gauge(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
    ) -> Gauge:
        """إنشاء Gauge"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Gauge(name, description, labels)
            return self._metrics[name]  # type: ignore[return-value]

    def histogram(
        self,
        name: str,
        description: str = "",
        buckets: Optional[Sequence[float]] = None,
        labels: Optional[List[str]] = None,
    ) -> Histogram:
        """إنشاء Histogram"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Histogram(name, description, buckets, labels)
            return self._metrics[name]  # type: ignore[return-value]

    def summary(
        self,
        name: str,
        description: str = "",
        quantiles: Optional[List[float]] = None,
        labels: Optional[List[str]] = None,
    ) -> Summary:
        """إنشاء Summary"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Summary(name, description, quantiles, labels)
            return self._metrics[name]  # type: ignore[return-value]

    def register(self, metric: Union[Counter, Gauge, Histogram, Summary]) -> None:
        with self._lock:
            self._metrics[metric.name] = metric

    def get(self, name: str) -> Optional[Union[Counter, Gauge, Histogram, Summary]]:
        with self._lock:
            return self._metrics.get(name)

    def unregister(self, name: str) -> bool:
        with self._lock:
            if name in self._metrics:
                del self._metrics[name]
                return True
            return False

    def get_all(self) -> Dict[str, Union[Counter, Gauge, Histogram, Summary]]:
        with self._lock:
            return dict(self._metrics)

    def clear(self) -> None:
        with self._lock:
            self._metrics.clear()

    def export(self) -> str:
        """تصدير بتنسيق Prometheus"""
        lines = []

        with self._lock:
            for name, metric in sorted(self._metrics.items()):
                # HELP line
                if metric.description:
                    lines.append(f"# HELP {name} {metric.description}")

                # TYPE line
                lines.append(f"# TYPE {name} {metric._type.value}")

                # Values
                if isinstance(metric, Counter):
                    lines.append(f"{name} {metric.get()}")

                    for label_values, value in metric._labeled_values.items():
                        labels_str = self._format_labels(
                            metric.label_names, label_values
                        )
                        lines.append(f"{name}{{{labels_str}}} {value}")

                elif isinstance(metric, Gauge):
                    lines.append(f"{name} {metric.get()}")

                    for label_values, value in metric._labeled_values.items():
                        labels_str = self._format_labels(
                            metric.label_names, label_values
                        )
                        lines.append(f"{name}{{{labels_str}}} {value}")

                elif isinstance(metric, Histogram):
                    buckets = metric._get_buckets_internal()
                    cumulative = 0

                    for bucket, count in sorted(buckets.items()):
                        cumulative += count
                        le = "+Inf" if bucket == float("inf") else bucket
                        lines.append(f'{name}_bucket{{le="{le}"}} {cumulative}')

                    lines.append(f"{name}_sum {metric.get_sample_sum()}")
                    lines.append(f"{name}_count {metric.get_sample_count()}")

                elif isinstance(metric, Summary):
                    for q in metric._quantiles:
                        value = metric.get_quantile(q)
                        lines.append(f'{name}{{quantile="{q}"}} {value}')

                    lines.append(f"{name}_sum {metric.get_sample_sum()}")
                    lines.append(f"{name}_count {metric.get_sample_count()}")

                lines.append("")

        return "\n".join(lines)

    def export_json(self) -> Dict[str, Any]:
        """تصدير كـ JSON"""
        data = {}

        with self._lock:
            for name, metric in self._metrics.items():
                if isinstance(metric, Counter):
                    data[name] = {
                        "type": "counter",
                        "value": metric.get(),
                        "labeled": dict(metric._labeled_values),
                    }

                elif isinstance(metric, Gauge):
                    data[name] = {
                        "type": "gauge",
                        "value": metric.get(),
                        "labeled": dict(metric._labeled_values),
                    }

                elif isinstance(metric, Histogram):
                    data[name] = {
                        "type": "histogram",
                        "buckets": metric._get_buckets_internal(),
                        "sum": metric.get_sample_sum(),
                        "count": metric.get_sample_count(),
                    }

                elif isinstance(metric, Summary):
                    data[name] = {
                        "type": "summary",
                        "quantiles": {
                            q: metric.get_quantile(q) for q in metric._quantiles
                        },
                        "sum": metric.get_sample_sum(),
                        "count": metric.get_sample_count(),
                    }

        return data

    def _format_labels(self, names: List[str], values: Tuple) -> str:
        """تنسيق التسميات"""
        pairs = [f'{n}="{v}"' for n, v in zip(names, values) if v]
        return ",".join(pairs)

    def reset(self) -> None:
        """إعادة تعيين (للاختبار)"""
        with self._lock:
            for metric in self._metrics.values():
                if hasattr(metric, "reset"):
                    metric.reset()


# ═══════════════════════════════════════════════════════════
#                     Default Metrics
# ═══════════════════════════════════════════════════════════

# Global registry
registry = MetricsRegistry()


class ReconMetrics:
    """
    مقاييس ReconnV2 المُعرَّفة مسبقاً.

    Example:
        >>> from recon_cli.utils.metrics import metrics
        >>> metrics.scans_total.inc()
        >>> metrics.active_jobs.set(5)
        >>> with metrics.scan_duration.time():
        ...     run_scan()
    """

    def __init__(self, reg: MetricsRegistry):
        self._registry = reg

        # ─────────────────────────────────────────────────────
        #                     Job Metrics
        # ─────────────────────────────────────────────────────

        self.jobs_total = reg.counter(
            "recon_jobs_total",
            "Total number of jobs created",
            labels=["status"],
        )

        self.jobs_active = reg.gauge(
            "recon_jobs_active",
            "Currently running jobs",
        )

        self.job_duration_seconds = reg.histogram(
            "recon_job_duration_seconds",
            "Job execution duration in seconds",
            buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
        )

        # ─────────────────────────────────────────────────────
        #                     Scan Metrics
        # ─────────────────────────────────────────────────────

        self.scans_total = reg.counter(
            "recon_scans_total",
            "Total number of scans performed",
            labels=["type", "status"],
        )

        self.scan_duration_seconds = reg.histogram(
            "recon_scan_duration_seconds",
            "Scan duration in seconds",
            labels=["type"],
        )

        self.targets_scanned = reg.counter(
            "recon_targets_scanned_total",
            "Total targets scanned",
        )

        # ─────────────────────────────────────────────────────
        #                     Pipeline Metrics
        # ─────────────────────────────────────────────────────

        self.stage_duration_seconds = reg.histogram(
            "recon_stage_duration_seconds",
            "Pipeline stage duration",
            labels=["stage"],
            buckets=(0.1, 0.5, 1, 5, 10, 30, 60, 120, 300),
        )

        self.stage_items_processed = reg.counter(
            "recon_stage_items_processed_total",
            "Items processed by stage",
            labels=["stage"],
        )

        self.stage_errors = reg.counter(
            "recon_stage_errors_total",
            "Errors by stage",
            labels=["stage", "error_type"],
        )

        # ─────────────────────────────────────────────────────
        #                     Results Metrics
        # ─────────────────────────────────────────────────────

        self.findings_total = reg.counter(
            "recon_findings_total",
            "Total findings discovered",
            labels=["type", "severity"],
        )

        self.subdomains_discovered = reg.counter(
            "recon_subdomains_discovered_total",
            "Subdomains discovered",
        )

        self.vulnerabilities_found = reg.counter(
            "recon_vulnerabilities_found_total",
            "Vulnerabilities found",
            labels=["severity"],
        )

        # ─────────────────────────────────────────────────────
        #                     Tool Metrics
        # ─────────────────────────────────────────────────────

        self.tool_executions = reg.counter(
            "recon_tool_executions_total",
            "Tool execution count",
            labels=["tool", "status"],
        )

        self.tool_duration_seconds = reg.histogram(
            "recon_tool_duration_seconds",
            "Tool execution duration",
            labels=["tool"],
        )

        # ─────────────────────────────────────────────────────
        #                     HTTP Metrics
        # ─────────────────────────────────────────────────────

        self.http_requests_total = reg.counter(
            "recon_http_requests_total",
            "HTTP requests made",
            labels=["method", "status"],
        )

        self.http_request_duration_seconds = reg.histogram(
            "recon_http_request_duration_seconds",
            "HTTP request duration",
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
        )

        # ─────────────────────────────────────────────────────
        #                     System Metrics
        # ─────────────────────────────────────────────────────

        self.memory_bytes = reg.gauge(
            "recon_memory_bytes",
            "Memory usage in bytes",
        )

        self.cpu_percent = reg.gauge(
            "recon_cpu_percent",
            "CPU usage percentage",
        )

        self.queue_size = reg.gauge(
            "recon_queue_size",
            "Job queue size",
            labels=["queue"],
        )

    def export(self) -> str:
        """تصدير Prometheus"""
        return self._registry.export()

    def export_json(self) -> Dict[str, Any]:
        """تصدير JSON"""
        return self._registry.export_json()

    def record_job_start(self) -> None:
        """تسجيل بدء مهمة"""
        self.jobs_total.labels(status="started").inc()
        self.jobs_active.inc()

    def record_job_end(self, status: str, duration: float) -> None:
        """تسجيل انتهاء مهمة"""
        self.jobs_total.labels(status=status).inc()
        self.jobs_active.dec()
        self.job_duration_seconds.observe(duration)

    def record_stage(self, stage: str, duration: float, items: int) -> None:
        """تسجيل مرحلة"""
        self.stage_duration_seconds.labels(stage=stage).observe(duration)
        self.stage_items_processed.labels(stage=stage).inc(items)

    def record_finding(self, finding_type: str, severity: str = "info") -> None:
        """تسجيل اكتشاف"""
        self.findings_total.labels(type=finding_type, severity=severity).inc()

    def record_tool_execution(
        self,
        tool: str,
        status: str,
        duration: float,
    ) -> None:
        """تسجيل تنفيذ أداة"""
        self.tool_executions.labels(tool=tool, status=status).inc()
        self.tool_duration_seconds.labels(tool=tool).observe(duration)


# Default metrics instance
metrics = ReconMetrics(registry)


# ═══════════════════════════════════════════════════════════
#                     Decorators
# ═══════════════════════════════════════════════════════════


def count_calls(counter: Counter) -> Callable:
    """
    مُزخرف لعد الاستدعاءات.

    Example:
        >>> @count_calls(metrics.http_requests_total)
        ... def make_request():
        ...     pass
    """

    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        def wrapper(*args, **kwargs) -> T:
            counter.inc()
            return func(*args, **kwargs)

        return wrapper

    return decorator


def time_function(histogram: Histogram) -> Callable:
    """
    مُزخرف لقياس وقت التنفيذ.

    Example:
        >>> @time_function(metrics.scan_duration_seconds)
        ... def run_scan():
        ...     pass
    """

    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        def wrapper(*args, **kwargs) -> T:
            with histogram.time():
                return func(*args, **kwargs)

        return wrapper

    return decorator


def track_inprogress(gauge: Gauge) -> Callable:
    """
    مُزخرف لتتبع العمليات الجارية.

    Example:
        >>> @track_inprogress(metrics.jobs_active)
        ... def run_job():
        ...     pass
    """

    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        def wrapper(*args, **kwargs) -> T:
            with gauge.track_inprogress():
                return func(*args, **kwargs)

        return wrapper

    return decorator


def get_metrics() -> ReconMetrics:
    return metrics


def export_prometheus(reg: Optional[MetricsRegistry] = None) -> str:
    target = reg or registry
    return target.export()
