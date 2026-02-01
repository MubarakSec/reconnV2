"""
Web Dashboard for ReconnV2.

Provides:
- WebSocket for real-time updates
- Charts and visualizations
- Search functionality
"""
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

from recon_cli.web.websocket import (
    WebSocketManager,
    ConnectionManager,
    Message,
    MessageType,
    broadcast_update,
)
from recon_cli.web.charts import (
    ChartGenerator,
    ChartType,
    ChartData,
    TimeSeriesChart,
    PieChart,
    BarChart,
    HeatmapChart,
    DashboardCharts,
)
from recon_cli.web.search import (
    SearchEngine,
    SearchQuery,
    SearchResult,
    SearchIndex,
    SearchType,
)

__all__ = [
    "TEMPLATES_DIR",
    "STATIC_DIR",
    # WebSocket
    "WebSocketManager",
    "ConnectionManager",
    "Message",
    "MessageType",
    "broadcast_update",
    # Charts
    "ChartGenerator",
    "ChartType",
    "ChartData",
    "TimeSeriesChart",
    "PieChart",
    "BarChart",
    "HeatmapChart",
    "DashboardCharts",
    # Search
    "SearchEngine",
    "SearchQuery",
    "SearchResult",
    "SearchIndex",
    "SearchType",
]
