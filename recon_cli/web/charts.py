"""
Chart Generation for ReconnV2 Dashboard.

Provides chart generation for:
- Vulnerability trends
- Host statistics
- Scan coverage
- Finding distribution

Example:
    >>> from recon_cli.web.charts import ChartGenerator
    >>> generator = ChartGenerator()
    >>> chart = generator.vulnerability_trend(data)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from collections import defaultdict

from recon_cli.utils.reporting import resolve_severity

__all__ = [
    "ChartType",
    "ChartConfig",
    "DataPoint",
    "Series",
    "ChartData",
    "TimeSeriesChart",
    "PieChart",
    "BarChart",
    "HeatmapChart",
    "ChartGenerator",
    "DashboardCharts",
]


class ChartType(Enum):
    """Types of charts."""
    
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    DOUGHNUT = "doughnut"
    AREA = "area"
    SCATTER = "scatter"
    RADAR = "radar"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    GAUGE = "gauge"


@dataclass
class ChartConfig:
    """Chart configuration options."""
    
    title: str = ""
    subtitle: str = ""
    width: int = 800
    height: int = 400
    responsive: bool = True
    legend_position: str = "top"
    show_grid: bool = True
    animate: bool = True
    theme: str = "default"
    colors: List[str] = field(default_factory=lambda: [
        "#3b82f6", "#10b981", "#f59e0b", "#ef4444",
        "#8b5cf6", "#06b6d4", "#ec4899", "#84cc16",
    ])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DataPoint:
    """Single data point."""
    
    label: str
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    color: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "label": self.label,
            "value": self.value,
            "metadata": self.metadata,
            "color": self.color,
        }


@dataclass
class Series:
    """Data series for charts."""
    
    name: str
    data: List[Union[float, DataPoint]] = field(default_factory=list)
    color: Optional[str] = None
    type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data_list = [
            d.to_dict() if isinstance(d, DataPoint) else d
            for d in self.data
        ]
        return {
            "name": self.name,
            "data": data_list,
            "color": self.color,
            "type": self.type,
        }


@dataclass
class ChartData:
    """Complete chart data structure."""
    
    chart_type: ChartType
    labels: List[str] = field(default_factory=list)
    series: List[Series] = field(default_factory=list)
    config: ChartConfig = field(default_factory=ChartConfig)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.chart_type.value,
            "labels": self.labels,
            "series": [s.to_dict() for s in self.series],
            "config": self.config.to_dict(),
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_chartjs(self) -> Dict[str, Any]:
        """Convert to Chart.js format."""
        datasets = []
        for i, series in enumerate(self.series):
            color = series.color or self.config.colors[i % len(self.config.colors)]
            dataset = {
                "label": series.name,
                "data": [
                    d.value if isinstance(d, DataPoint) else d
                    for d in series.data
                ],
                "backgroundColor": color,
                "borderColor": color,
            }
            if self.chart_type in (ChartType.LINE, ChartType.AREA):
                dataset["fill"] = self.chart_type == ChartType.AREA
            datasets.append(dataset)
        
        return {
            "type": self.chart_type.value,
            "data": {
                "labels": self.labels,
                "datasets": datasets,
            },
            "options": {
                "responsive": self.config.responsive,
                "plugins": {
                    "title": {
                        "display": bool(self.config.title),
                        "text": self.config.title,
                    },
                    "legend": {
                        "position": self.config.legend_position,
                    },
                },
            },
        }
    
    def to_apexcharts(self) -> Dict[str, Any]:
        """Convert to ApexCharts format."""
        series_data = []
        for series in self.series:
            series_data.append({
                "name": series.name,
                "data": [
                    d.value if isinstance(d, DataPoint) else d
                    for d in series.data
                ],
            })
        
        return {
            "chart": {
                "type": self.chart_type.value,
                "height": self.config.height,
                "animations": {"enabled": self.config.animate},
            },
            "series": series_data,
            "xaxis": {"categories": self.labels},
            "title": {"text": self.config.title},
            "colors": self.config.colors,
        }


class TimeSeriesChart:
    """Time series chart builder."""
    
    def __init__(
        self,
        title: str = "",
        chart_type: ChartType = ChartType.LINE,
    ):
        self.title = title
        self.chart_type = chart_type
        self._series: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
    
    def add_point(self, series_name: str, timestamp: datetime, value: float) -> None:
        """Add a data point."""
        self._series[series_name].append((timestamp, value))
    
    def add_points(
        self,
        series_name: str,
        points: List[Tuple[datetime, float]],
    ) -> None:
        """Add multiple data points."""
        self._series[series_name].extend(points)
    
    def build(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        interval: timedelta = timedelta(hours=1),
    ) -> ChartData:
        """Build the chart data."""
        # Determine time range
        all_times = [t for points in self._series.values() for t, _ in points]
        if not all_times:
            return ChartData(chart_type=self.chart_type)
        
        start = start_time or min(all_times)
        end = end_time or max(all_times)
        
        # Generate time labels
        labels = []
        current = start
        while current <= end:
            labels.append(current.strftime("%Y-%m-%d %H:%M"))
            current += interval
        
        # Aggregate data into intervals
        series_list = []
        for name, points in self._series.items():
            # Bucket points by interval
            buckets: Dict[str, float] = {label: 0 for label in labels}
            for timestamp, value in points:
                label = timestamp.strftime("%Y-%m-%d %H:%M")
                # Find closest bucket
                for l in labels:
                    if l >= label:
                        buckets[l] += value
                        break
            
            series_list.append(Series(
                name=name,
                data=list(buckets.values()),
            ))
        
        return ChartData(
            chart_type=self.chart_type,
            labels=labels,
            series=series_list,
            config=ChartConfig(title=self.title),
        )


class PieChart:
    """Pie/Doughnut chart builder."""
    
    def __init__(
        self,
        title: str = "",
        doughnut: bool = False,
    ):
        self.title = title
        self.chart_type = ChartType.DOUGHNUT if doughnut else ChartType.PIE
        self._data: List[DataPoint] = []
    
    def add_slice(
        self,
        label: str,
        value: float,
        color: Optional[str] = None,
    ) -> None:
        """Add a pie slice."""
        self._data.append(DataPoint(label=label, value=value, color=color))
    
    def from_dict(self, data: Dict[str, float]) -> "PieChart":
        """Build from dictionary."""
        for label, value in data.items():
            self.add_slice(label, value)
        return self
    
    def build(self) -> ChartData:
        """Build the chart data."""
        labels = [d.label for d in self._data]
        values = [d.value for d in self._data]
        colors = [d.color for d in self._data if d.color]
        
        config = ChartConfig(title=self.title)
        if colors:
            config.colors = colors
        
        return ChartData(
            chart_type=self.chart_type,
            labels=labels,
            series=[Series(name="data", data=values)],
            config=config,
        )


class BarChart:
    """Bar chart builder."""
    
    def __init__(
        self,
        title: str = "",
        horizontal: bool = False,
        stacked: bool = False,
    ):
        self.title = title
        self.horizontal = horizontal
        self.stacked = stacked
        self._labels: List[str] = []
        self._series: Dict[str, List[float]] = {}
    
    def set_labels(self, labels: List[str]) -> "BarChart":
        """Set category labels."""
        self._labels = labels
        return self
    
    def add_series(self, name: str, values: List[float]) -> "BarChart":
        """Add a data series."""
        self._series[name] = values
        return self
    
    def build(self) -> ChartData:
        """Build the chart data."""
        series_list = [
            Series(name=name, data=values)
            for name, values in self._series.items()
        ]
        
        return ChartData(
            chart_type=ChartType.BAR,
            labels=self._labels,
            series=series_list,
            config=ChartConfig(title=self.title),
        )


class HeatmapChart:
    """Heatmap chart builder."""
    
    def __init__(
        self,
        title: str = "",
        x_labels: Optional[List[str]] = None,
        y_labels: Optional[List[str]] = None,
    ):
        self.title = title
        self.x_labels = x_labels or []
        self.y_labels = y_labels or []
        self._data: List[List[float]] = []
    
    def set_data(self, data: List[List[float]]) -> "HeatmapChart":
        """Set the heatmap data matrix."""
        self._data = data
        return self
    
    def add_row(self, row: List[float]) -> "HeatmapChart":
        """Add a row of data."""
        self._data.append(row)
        return self
    
    def build(self) -> ChartData:
        """Build the chart data."""
        series_list = []
        for i, row in enumerate(self._data):
            label = self.y_labels[i] if i < len(self.y_labels) else f"Row {i}"
            series_list.append(Series(name=label, data=row))
        
        return ChartData(
            chart_type=ChartType.HEATMAP,
            labels=self.x_labels,
            series=series_list,
            config=ChartConfig(title=self.title),
        )


class ChartGenerator:
    """High-level chart generator for common use cases."""
    
    def __init__(self, colors: Optional[List[str]] = None):
        self.colors = colors or ChartConfig().colors
    
    def vulnerability_trend(
        self,
        data: List[Dict[str, Any]],
        group_by: str = "day",
    ) -> ChartData:
        """Generate vulnerability trend chart.
        
        Args:
            data: List of findings with 'timestamp' and 'severity' fields
            group_by: Time grouping ('hour', 'day', 'week', 'month')
        """
        chart = TimeSeriesChart(
            title="Vulnerability Trend",
            chart_type=ChartType.AREA,
        )
        
        # Group by severity
        severity_data: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        
        for item in data:
            timestamp = item.get("timestamp")
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            severity = resolve_severity(item)
            severity_data[severity].append((timestamp, 1))
        
        for severity, points in severity_data.items():
            chart.add_points(severity, points)
        
        interval = {
            "hour": timedelta(hours=1),
            "day": timedelta(days=1),
            "week": timedelta(weeks=1),
            "month": timedelta(days=30),
        }.get(group_by, timedelta(days=1))
        
        return chart.build(interval=interval)
    
    def severity_distribution(
        self,
        findings: List[Dict[str, Any]],
    ) -> ChartData:
        """Generate severity distribution pie chart."""
        counts: Dict[str, int] = defaultdict(int)
        
        for finding in findings:
            severity = resolve_severity(finding)
            counts[severity] += 1
        
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#eab308",
            "low": "#3b82f6",
            "info": "#6b7280",
        }
        
        chart = PieChart(title="Severity Distribution", doughnut=True)
        for severity, count in counts.items():
            chart.add_slice(
                label=severity.title(),
                value=count,
                color=severity_colors.get(severity),
            )
        
        return chart.build()
    
    def host_stats(
        self,
        hosts: List[Dict[str, Any]],
    ) -> ChartData:
        """Generate host statistics bar chart."""
        # Group by some attribute (e.g., status, type)
        status_counts: Dict[str, int] = defaultdict(int)
        
        for host in hosts:
            status = host.get("status", "unknown")
            status_counts[status] += 1
        
        chart = BarChart(title="Host Status Distribution")
        chart.set_labels(list(status_counts.keys()))
        chart.add_series("Hosts", list(status_counts.values()))
        
        return chart.build()
    
    def scan_coverage(
        self,
        stages: Dict[str, Dict[str, Any]],
    ) -> ChartData:
        """Generate scan coverage radar chart."""
        labels = []
        values = []
        
        for stage_name, stage_data in stages.items():
            labels.append(stage_name)
            # Calculate coverage as percentage of completed items
            total = stage_data.get("total", 1)
            completed = stage_data.get("completed", 0)
            coverage = (completed / total * 100) if total > 0 else 0
            values.append(coverage)
        
        return ChartData(
            chart_type=ChartType.RADAR,
            labels=labels,
            series=[Series(name="Coverage", data=values)],
            config=ChartConfig(title="Scan Coverage"),
        )
    
    def finding_by_type(
        self,
        findings: List[Dict[str, Any]],
    ) -> ChartData:
        """Generate findings by type bar chart."""
        type_counts: Dict[str, int] = defaultdict(int)
        
        for finding in findings:
            finding_type = finding.get("finding_type") or finding.get("type", "unknown")
            type_counts[finding_type] += 1
        
        # Sort by count
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        chart = BarChart(title="Findings by Type", horizontal=True)
        chart.set_labels([t[0] for t in sorted_types[:10]])
        chart.add_series("Count", [t[1] for t in sorted_types[:10]])
        
        return chart.build()
    
    def port_heatmap(
        self,
        hosts: List[Dict[str, Any]],
        common_ports: Optional[List[int]] = None,
    ) -> ChartData:
        """Generate port/host heatmap."""
        ports = common_ports or [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]
        
        heatmap = HeatmapChart(
            title="Port Status Heatmap",
            x_labels=[str(p) for p in ports],
        )
        
        for host in hosts:
            hostname = host.get("hostname", host.get("ip", "unknown"))
            open_ports = set(host.get("open_ports", []))
            row = [1.0 if p in open_ports else 0.0 for p in ports]
            heatmap.y_labels.append(hostname)
            heatmap.add_row(row)
        
        return heatmap.build()


class DashboardCharts:
    """Pre-built dashboard chart collection."""
    
    def __init__(self):
        self.generator = ChartGenerator()
    
    def overview_charts(
        self,
        findings: List[Dict[str, Any]],
        hosts: List[Dict[str, Any]],
    ) -> Dict[str, ChartData]:
        """Generate all overview dashboard charts."""
        return {
            "vulnerability_trend": self.generator.vulnerability_trend(findings),
            "severity_distribution": self.generator.severity_distribution(findings),
            "finding_by_type": self.generator.finding_by_type(findings),
            "host_stats": self.generator.host_stats(hosts),
        }
    
    def job_charts(
        self,
        job_data: Dict[str, Any],
    ) -> Dict[str, ChartData]:
        """Generate job-specific charts."""
        findings = job_data.get("findings", [])
        stages = job_data.get("stages", {})
        
        return {
            "severity": self.generator.severity_distribution(findings),
            "coverage": self.generator.scan_coverage(stages),
            "findings": self.generator.finding_by_type(findings),
        }
    
    def to_html(self, chart: ChartData) -> str:
        """Convert chart to embeddable HTML."""
        chart_id = f"chart_{id(chart)}"
        chart_config = json.dumps(chart.to_chartjs())
        
        return f"""
<div class="chart-container" style="position: relative; height:{chart.config.height}px; width:100%;">
    <canvas id="{chart_id}"></canvas>
</div>
<script>
    new Chart(document.getElementById('{chart_id}'), {chart_config});
</script>
"""
