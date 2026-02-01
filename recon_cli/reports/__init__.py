"""
ReconnV2 Reports Module.

Provides:
- Report generation in multiple formats
- Executive summary generator
- Custom report templates
"""

from recon_cli.reports.generator import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportSection,
)
from recon_cli.reports.templates import (
    TemplateEngine,
    ReportTemplate,
    load_template,
)
from recon_cli.reports.executive import (
    ExecutiveSummary,
    ExecutiveSummaryGenerator,
)

__all__ = [
    # Generator
    "ReportGenerator",
    "ReportConfig",
    "ReportFormat",
    "ReportSection",
    # Templates
    "TemplateEngine",
    "ReportTemplate",
    "load_template",
    # Executive
    "ExecutiveSummary",
    "ExecutiveSummaryGenerator",
]
