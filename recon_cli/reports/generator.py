"""
Report Generator for ReconnV2.

Generates reports in multiple formats:
- HTML
- PDF
- JSON
- CSV
- Markdown
- XML

Example:
    >>> from recon_cli.reports.generator import ReportGenerator
    >>> generator = ReportGenerator()
    >>> report = await generator.generate(job_data, format=ReportFormat.HTML)
"""

from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from collections import defaultdict

from recon_cli.utils.last_run import update_last_report_pointer
from recon_cli.utils.reporting import resolve_severity, resolve_finding_type
from recon_cli.utils.sanitizer import escape_html_text, sanitize_text

__all__ = [
    "ReportFormat",
    "ReportConfig",
    "ReportSection",
    "ReportData",
    "ReportGenerator",
    "HTMLReportGenerator",
    "PDFReportGenerator",
    "CSVExporter",
    "XMLExporter",
]


class ReportFormat(Enum):
    """Supported report formats."""

    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    MARKDOWN = "markdown"
    XML = "xml"
    EXCEL = "excel"


@dataclass
class ReportConfig:
    """Report configuration options."""

    title: str = "Reconnaissance Report"
    subtitle: str = ""
    author: str = "ReconnV2"
    company: str = ""
    logo_path: Optional[Path] = None
    include_summary: bool = True
    include_findings: bool = True
    include_hosts: bool = True
    include_charts: bool = True
    include_timeline: bool = True
    include_raw_data: bool = False
    severity_filter: Optional[List[str]] = None  # Filter findings by severity
    max_findings: Optional[int] = None  # Limit number of findings
    group_by: str = "severity"  # severity, type, host
    theme: str = "default"  # default, dark, corporate
    custom_css: Optional[str] = None
    page_size: str = "A4"  # For PDF
    verified_only: bool = False
    proof_required: bool = False
    strict_mode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ReportSection:
    """A section of the report."""

    id: str
    title: str
    content: str = ""
    order: int = 0
    visible: bool = True
    subsections: List["ReportSection"] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "order": self.order,
            "visible": self.visible,
            "subsections": [s.to_dict() for s in self.subsections],
            "data": self.data,
        }


@dataclass
class ReportData:
    """Collected data for report generation."""

    job_id: str
    job_name: str = ""
    targets: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    stages: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_job(cls, job_data: Dict[str, Any]) -> "ReportData":
        """Create from job data."""

        def _parse_dt(value: Optional[str]) -> Optional[datetime]:
            if not value:
                return None
            if isinstance(value, str) and value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(value) if isinstance(value, str) else None
            except ValueError:
                return None

        return cls(
            job_id=job_data.get("id") or job_data.get("job_id", ""),
            job_name=job_data.get("name") or job_data.get("job_name", ""),
            targets=job_data.get("targets", []),
            start_time=_parse_dt(job_data.get("start_time")),
            end_time=_parse_dt(job_data.get("end_time")),
            findings=job_data.get("findings", []),
            hosts=job_data.get("hosts", []),
            stages=job_data.get("stages", {}),
            metadata=job_data.get("metadata", {}),
        )

    @property
    def duration(self) -> Optional[str]:
        """Get formatted duration."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return str(delta)
        return None

    @property
    def finding_counts(self) -> Dict[str, int]:
        """Get finding counts by severity."""
        counts: Dict[str, int] = defaultdict(int)
        for finding in self.findings:
            severity = resolve_severity(finding)
            counts[severity] += 1
        return dict(counts)

    @property
    def total_findings(self) -> int:
        """Get total finding count."""
        return len(self.findings)


class ReportGenerator:
    """Main report generator."""

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self._generators = {
            ReportFormat.HTML: HTMLReportGenerator,
            ReportFormat.JSON: JSONReportGenerator,
            ReportFormat.CSV: CSVExporter,
            ReportFormat.MARKDOWN: MarkdownReportGenerator,
            ReportFormat.XML: XMLExporter,
        }

    async def generate(
        self,
        data: Union[Dict[str, Any], ReportData],
        format: ReportFormat = ReportFormat.HTML,
        output_path: Optional[Path] = None,
    ) -> str:
        """Generate a report."""
        if isinstance(data, dict):
            data = ReportData.from_job(data)

        # Filter findings if configured
        if self.config.strict_mode:
            self.config.verified_only = True
            self.config.proof_required = True

        if self.config.severity_filter:
            data.findings = [
                f
                for f in data.findings
                if resolve_severity(f) in self.config.severity_filter
            ]

        if self.config.verified_only:
            data.findings = [
                f for f in data.findings
                if f.get("confidence_label") == "verified" or "confirmed" in f.get("tags", [])
            ]

        if self.config.proof_required:
            data.findings = [
                f for f in data.findings
                if f.get("proof") or f.get("poc") or f.get("details", {}).get("proof")
            ]

        if self.config.max_findings:
            data.findings = data.findings[: self.config.max_findings]

        # Get generator
        generator_class = self._generators.get(format)
        if generator_class is None:
            raise ValueError(f"Unsupported format: {format}")

        generator = generator_class(self.config)
        content = generator.generate(data)  # type: ignore[attr-defined]

        # Write to file if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if format in (
                ReportFormat.JSON,
                ReportFormat.HTML,
                ReportFormat.MARKDOWN,
                ReportFormat.XML,
                ReportFormat.CSV,
            ):
                output_path.write_text(content)
            else:
                output_path.write_bytes(
                    content.encode() if isinstance(content, str) else content
                )
            update_last_report_pointer(output_path)

        return content

    def build_sections(self, data: ReportData) -> List[ReportSection]:
        """Build report sections."""
        sections = []

        # Summary section
        if self.config.include_summary:
            sections.append(
                ReportSection(
                    id="summary",
                    title="Executive Summary",
                    order=1,
                    data={
                        "total_targets": len(data.targets),
                        "total_findings": data.total_findings,
                        "finding_counts": data.finding_counts,
                        "duration": data.duration,
                    },
                )
            )

        # Findings section
        if self.config.include_findings:
            # Group findings
            grouped = self._group_findings(data.findings, self.config.group_by)

            findings_section = ReportSection(
                id="findings",
                title="Findings",
                order=2,
            )

            for group_name, findings in grouped.items():
                findings_section.subsections.append(
                    ReportSection(
                        id=f"findings-{group_name}",
                        title=group_name.title(),
                        data={"findings": findings},
                    )
                )

            sections.append(findings_section)

        # Hosts section
        if self.config.include_hosts and data.hosts:
            sections.append(
                ReportSection(
                    id="hosts",
                    title="Discovered Hosts",
                    order=3,
                    data={"hosts": data.hosts},
                )
            )

        return sections

    def _group_findings(
        self,
        findings: List[Dict[str, Any]],
        group_by: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by specified field."""
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            if group_by == "severity":
                key = resolve_severity(finding)
            elif group_by == "type":
                key = resolve_finding_type(finding)
            else:
                key = finding.get(group_by, "other")
            if isinstance(key, list):
                key = key[0] if key else "other"
            grouped[str(key)].append(finding)

        # Sort by severity order if grouping by severity
        if group_by == "severity":
            severity_order = ["critical", "high", "medium", "low", "info"]
            return {k: grouped[k] for k in severity_order if k in grouped}

        return dict(grouped)


class HTMLReportGenerator:
    """Generate HTML reports."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, data: ReportData) -> str:
        """Generate HTML report."""
        sections = self._build_sections_html(data)
        charts_html = (
            self._build_charts_html(data) if self.config.include_charts else ""
        )

        # Build findings section
        findings_html = self._build_findings_section(data.findings)

        # Build hosts table
        hosts_html = self._build_hosts_table(data.hosts) if data.hosts else ""

        custom_css = sanitize_text(self.config.custom_css or "")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape_html_text(self.config.title)}</title>
    <style>
        :root {{
            --primary: #3b82f6;
            --danger: #dc2626;
            --warning: #eab308;
            --success: #10b981;
            --bg: #f9fafb;
            --bg-card: #ffffff;
            --text: #1f2937;
            --text-light: #6b7280;
            --border: #e5e7eb;
            --font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: var(--font-family);
            line-height: 1.6;
            color: var(--text);
            background: var(--bg);
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }}
        
        h1 {{ font-size: 2.5rem; margin-bottom: 0.5rem; }}
        h2 {{ font-size: 1.75rem; margin: 2rem 0 1rem; color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
        h3 {{ font-size: 1.25rem; margin: 1.5rem 0 0.75rem; }}
        
        .subtitle {{ color: var(--text-light); font-size: 1.1rem; }}
        .meta {{ color: #9ca3af; font-size: 0.9rem; margin-top: 1rem; }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}
        
        .summary-card {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
        }}
        
        .summary-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary);
        }}
        
        .summary-card .label {{
            color: var(--text-light);
            font-size: 0.9rem;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: #fef2f2; color: #dc2626; border: 1px solid #dc2626; }}
        .severity-high {{ background: #fff7ed; color: #ea580c; border: 1px solid #ea580c; }}
        .severity-medium {{ background: #fefce8; color: #ca8a04; border: 1px solid #ca8a04; }}
        .severity-low {{ background: #eff6ff; color: #3b82f6; border: 1px solid #3b82f6; }}
        .severity-info {{ background: #f3f4f6; color: #6b7280; border: 1px solid #6b7280; }}

        .finding-filters {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s ease;
        }}

        .filter-btn.active, .filter-btn:hover {{
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }}
        
        .finding {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin: 1rem 0;
            overflow: hidden;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            cursor: pointer;
            transition: background 0.2s ease;
        }}

        .finding-header:hover {{
            background: #f3f4f6;
        }}
        
        .finding-title {{
            font-weight: 600;
            font-size: 1.1rem;
        }}
        
        .finding-body {{
            padding: 0 1.5rem 1.5rem;
            display: none;
        }}

        .finding-body h4 {{
            font-size: 1rem;
            color: var(--primary);
            margin: 1rem 0 0.5rem;
        }}

        .finding-body pre {{
            background: #f3f4f6;
            padding: 1rem;
            border-radius: 4px;
            white-space: pre-wrap;
            word-break: break-all;
            font-family: 'SF Mono', 'Menlo', 'Consolas', monospace;
            font-size: 0.9rem;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        th {{
            background: #f9fafb;
            font-weight: 600;
        }}
        
        tr:hover {{ background: #f3f4f6; }}
        
        footer {{
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            text-align: center;
            color: #9ca3af;
            font-size: 0.9rem;
        }}
        
        @media print {{
            body {{ padding: 0; }}
            .no-print {{ display: none; }}
        }}
        
        {custom_css}
    </style>
</head>
<body>
    <header>
        <h1>{escape_html_text(self.config.title)}</h1>
        {f'<p class="subtitle">{escape_html_text(self.config.subtitle)}</p>' if self.config.subtitle else ""}
        <p class="meta">
            Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
            Job: {escape_html_text(data.job_id)} |
            By: {escape_html_text(self.config.author)}
        </p>
    </header>
    
    <main>
        {self._build_summary_section(data)}
        
        {charts_html}
        
        <section id="findings">
            <h2>📋 Findings ({data.total_findings})</h2>
            {findings_html}
        </section>
        
        {f'<h2>🖥️ Discovered Hosts ({len(data.hosts)})</h2>{hosts_html}' if data.hosts else ""}
        
        {sections}
    </main>
    
    <footer>
        <p>Generated by {escape_html_text(self.config.author)}</p>
        <p>Report ID: {escape_html_text(data.job_id)}</p>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', function () {{
            const findingHeaders = document.querySelectorAll('.finding-header');
            findingHeaders.forEach(header => {{
                header.addEventListener('click', () => {{
                    const body = header.nextElementSibling;
                    body.style.display = body.style.display === 'block' ? 'none' : 'block';
                }});
            }});

            const filterButtons = document.querySelectorAll('.filter-btn');
            const findings = document.querySelectorAll('.finding');
            
            filterButtons.forEach(button => {{
                button.addEventListener('click', () => {{
                    const severity = button.getAttribute('data-severity');
                    
                    button.classList.toggle('active');
                    
                    const activeSeverities = Array.from(document.querySelectorAll('.filter-btn.active'))
                                                 .map(btn => btn.getAttribute('data-severity'));

                    findings.forEach(finding => {{
                        if (activeSeverities.length === 0) {{
                            finding.style.display = 'block';
                        }} else {{
                            const findingSeverity = finding.getAttribute('data-severity');
                            if (activeSeverities.includes(findingSeverity)) {{
                                finding.style.display = 'block';
                            }} else {{
                                finding.style.display = 'none';
                            }}
                        }}
                    }});
                }});
            }});
        }});
    </script>
</body>
</html>"""

        return html

    def _build_summary_section(self, data: ReportData) -> str:
        """Build summary section HTML."""
        counts = data.finding_counts

        return f"""
        <section id="summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="value">{len(data.targets)}</div>
                    <div class="label">Targets Scanned</div>
                </div>
                <div class="summary-card">
                    <div class="value">{data.total_findings}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid var(--danger);">
                    <div class="value" style="color: var(--danger);">{counts.get("critical", 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid #ea580c;">
                    <div class="value" style="color: #ea580c;">{counts.get("high", 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid var(--warning);">
                    <div class="value" style="color: var(--warning);">{counts.get("medium", 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid var(--primary);">
                    <div class="value" style="color: var(--primary);">{counts.get("low", 0)}</div>
                    <div class="label">Low</div>
                </div>
            </div>
            <p><strong>Duration:</strong> {escape_html_text(data.duration or "N/A")}</p>
        </section>
"""

    def _build_findings_section(self, findings: List[Dict[str, Any]]) -> str:
        """Build interactive findings section HTML."""
        if not findings:
            return "<p>No findings to display.</p>"

        # Sort findings by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        findings.sort(key=lambda f: severity_order.index(resolve_severity(f)))

        finding_html_parts = []
        for finding in findings:
            severity = resolve_severity(finding)
            title = escape_html_text(finding.get("title") or finding.get("description") or resolve_finding_type(finding))
            host = escape_html_text(finding.get("host") or finding.get("hostname") or finding.get("target") or finding.get("url") or "N/A")
            description = escape_html_text(finding.get("description", "No description provided."))
            proof = escape_html_text(finding.get("proof") or finding.get("poc") or finding.get("details", {}).get("proof", ""))

            finding_html_parts.append(f"""
            <div class="finding" data-severity="{severity}">
                <div class="finding-header">
                    <div class="finding-title-container">
                        <span class="severity-badge severity-{severity}">{severity}</span>
                        <span class="finding-title">{title}</span>
                    </div>
                    <div class="finding-host">{host}</div>
                </div>
                <div class="finding-body">
                    <h4>Description</h4>
                    <p>{description}</p>
                    {f"<h4>Proof</h4><pre>{proof}</pre>" if proof else ""}
                </div>
            </div>
            """)

        severities_present = sorted(set(resolve_severity(f) for f in findings), key=lambda s: severity_order.index(s))
        
        filter_buttons = "".join(
            f'<button class="filter-btn" data-severity="{s}">{s.title()}</button>' for s in severities_present
        )

        return f"""
        <div class="finding-filters">
            {filter_buttons}
        </div>
        <div id="findings-list">
            {"".join(finding_html_parts)}
        </div>
        """

    def _build_hosts_table(self, hosts: List[Dict[str, Any]]) -> str:
        """Build hosts table HTML."""
        if not hosts:
            return ""

        rows = []
        for host in hosts:
            ip = host.get("ip", "N/A")
            hostname = host.get("hostname", "N/A")
            ports = ", ".join(str(p) for p in host.get("open_ports", [])[:10])
            if len(host.get("open_ports", [])) > 10:
                ports += "..."

            rows.append(f"""
            <tr>
                <td>{escape_html_text(ip)}</td>
                <td>{escape_html_text(hostname)}</td>
                <td>{escape_html_text(ports or "N/A")}</td>
                <td>{escape_html_text(host.get("status", "unknown"))}</td>
            </tr>
""")

        return f"""
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Open Ports</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
"""

    def _build_charts_html(self, data: ReportData) -> str:
        """Build charts section HTML."""
        counts = data.finding_counts
        if not counts:
            return ""

        return f"""
        <section id="charts" class="charts-container no-print">
            <div class="chart">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
        </section>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps([sanitize_text(label, collapse_ws=True) for label in counts.keys()])},
                    datasets: [{{
                        data: {json.dumps(list(counts.values()))},
                        backgroundColor: ['#dc2626', '#ea580c', '#eab308', '#3b82f6', '#6b7280']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'top',
                        }}
                    }}
                }}
            }});
        </script>
"""

    def _build_sections_html(self, data: ReportData) -> str:
        """Build custom sections HTML."""
        return ""


class JSONReportGenerator:
    """Generate JSON reports."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, data: ReportData) -> str:
        """Generate JSON report."""
        report = {
            "meta": {
                "title": self.config.title,
                "author": self.config.author,
                "generated_at": datetime.now().isoformat(),
            },
            "job": {
                "id": data.job_id,
                "name": data.job_name,
                "targets": data.targets,
                "start_time": data.start_time.isoformat() if data.start_time else None,
                "end_time": data.end_time.isoformat() if data.end_time else None,
                "duration": data.duration,
            },
            "summary": {
                "total_findings": data.total_findings,
                "finding_counts": data.finding_counts,
                "total_hosts": len(data.hosts),
            },
            "findings": data.findings,
            "hosts": data.hosts,
        }

        return json.dumps(report, indent=2, default=str)


class MarkdownReportGenerator:
    """Generate Markdown reports."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, data: ReportData) -> str:
        """Generate Markdown report."""
        counts = data.finding_counts

        md = f"""# {self.config.title}

{self.config.subtitle}

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Job ID:** {data.job_id}  
**Author:** {self.config.author}

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Targets Scanned | {len(data.targets)} |
| Total Findings | {data.total_findings} |
| Critical | {counts.get("critical", 0)} |
| High | {counts.get("high", 0)} |
| Medium | {counts.get("medium", 0)} |
| Low | {counts.get("low", 0)} |
| Duration | {data.duration or "N/A"} |

---

## 📋 Findings

"""

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: Dict[str, List[Dict]] = defaultdict(list)

        for finding in data.findings:
            severity = resolve_severity(finding)
            grouped[severity].append(finding)

        for severity in severity_order:
            if severity not in grouped:
                continue

            md += f"\n### {severity.upper()} ({len(grouped[severity])})\n\n"

            for finding in grouped[severity]:
                title = (
                    finding.get("title")
                    or finding.get("description")
                    or resolve_finding_type(finding)
                )
                host = (
                    finding.get("host")
                    or finding.get("hostname")
                    or finding.get("target")
                    or finding.get("url")
                    or "N/A"
                )
                desc = finding.get("description", "No description")

                md += f"""#### {title}

- **Host:** {host}
- **Description:** {desc}

"""

        # Hosts section
        if data.hosts:
            md += "\n---\n\n## 🖥️ Discovered Hosts\n\n"
            md += "| IP | Hostname | Open Ports | Status |\n"
            md += "|----|---------|-----------|---------|\n"

            for host in data.hosts:
                ip = host.get("ip", "N/A")
                hostname = host.get("hostname", "N/A")
                ports = ", ".join(str(p) for p in host.get("open_ports", [])[:5])
                status = host.get("status", "unknown")
                md += f"| {ip} | {hostname} | {ports} | {status} |\n"

        md += f"""

---

*Generated by {self.config.author}*
"""

        return md


class CSVExporter:
    """Export findings to CSV."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, data: ReportData) -> str:
        """Generate CSV export."""
        output = io.StringIO()

        if not data.findings:
            return ""

        # Determine columns
        columns = ["severity", "title", "type", "host", "target", "description"]

        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        for finding in data.findings:
            row = dict(finding)
            row["severity"] = resolve_severity(finding)
            row["type"] = resolve_finding_type(finding)
            row.setdefault("title", finding.get("description") or row["type"])
            row.setdefault(
                "host",
                finding.get("hostname") or finding.get("url") or finding.get("target"),
            )
            writer.writerow(row)

        return output.getvalue()


class XMLExporter:
    """Export to XML format."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, data: ReportData) -> str:
        """Generate XML export."""
        root = ET.Element("report")

        # Metadata
        meta = ET.SubElement(root, "metadata")
        ET.SubElement(meta, "title").text = self.config.title
        ET.SubElement(meta, "author").text = self.config.author
        ET.SubElement(meta, "generated").text = datetime.now().isoformat()
        ET.SubElement(meta, "job_id").text = data.job_id

        # Summary
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "total_targets").text = str(len(data.targets))
        ET.SubElement(summary, "total_findings").text = str(data.total_findings)

        counts = ET.SubElement(summary, "severity_counts")
        for sev, count in data.finding_counts.items():
            ET.SubElement(counts, sev).text = str(count)

        # Findings
        findings_elem = ET.SubElement(root, "findings")
        for finding in data.findings:
            finding_elem = ET.SubElement(findings_elem, "finding")
            for key, value in finding.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value)
                elem = ET.SubElement(finding_elem, key)
                elem.text = str(value) if value else ""

        # Hosts
        hosts_elem = ET.SubElement(root, "hosts")
        for host in data.hosts:
            host_elem = ET.SubElement(hosts_elem, "host")
            for key, value in host.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value)
                elem = ET.SubElement(host_elem, key)
                elem.text = str(value) if value else ""

        return ET.tostring(root, encoding="unicode", method="xml")


class PDFReportGenerator:
    """Generate PDF reports (requires additional dependencies)."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, data: ReportData) -> bytes:
        """Generate PDF report."""
        # First generate HTML
        html_gen = HTMLReportGenerator(self.config)
        html = html_gen.generate(data)

        # Try to convert to PDF
        try:
            import weasyprint

            pdf = weasyprint.HTML(string=html).write_pdf()
            return pdf
        except ImportError:
            # Fallback: return HTML with message
            return f"<!-- PDF generation requires weasyprint -->\n{html}".encode()
