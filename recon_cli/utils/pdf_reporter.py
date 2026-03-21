"""
PDF Report Generator for ReconnV2
Professional security reports with Arabic support
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import json

from recon_cli.utils.last_run import update_last_report_pointer
from recon_cli.utils.reporting import is_finding, resolve_confidence_label
from recon_cli.utils.sanitizer import escape_html_text, sanitize_text


@dataclass
class PDFReportConfig:
    """PDF Report configuration"""

    title: str = "تقرير الاستطلاع الأمني"
    company_name: str = "ReconnV2"
    logo_path: Optional[str] = None
    include_toc: bool = True
    include_executive_summary: bool = True
    include_charts: bool = True
    page_size: str = "A4"  # A4, Letter
    font_family: str = "Arial"
    primary_color: str = "#2563eb"
    secondary_color: str = "#64748b"


@dataclass
class ReportSection:
    """Report section data"""

    title: str
    content: Any
    section_type: str  # summary, table, chart, text
    order: int = 0


class PDFReporter:
    """
    Professional PDF Report Generator

    Uses reportlab or weasyprint for PDF generation
    Supports Arabic text with proper RTL rendering
    """

    def __init__(self, config: Optional[PDFReportConfig] = None):
        self.config = config or PDFReportConfig()
        self._check_dependencies()

    def _check_dependencies(self) -> bool:
        """Check if PDF libraries are available"""
        self.use_weasyprint = False
        self.use_reportlab = False

        try:
            from weasyprint import HTML, CSS  # noqa: F401

            self.use_weasyprint = True
            return True
        except ImportError:
            pass

        try:
            from reportlab.lib.pagesizes import A4, letter  # noqa: F401
            from reportlab.pdfgen import canvas  # noqa: F401

            self.use_reportlab = True
            return True
        except ImportError:
            pass

        return False

    def generate_report(
        self,
        job_data: Dict[str, Any],
        output_path: Path,
        results: Optional[List[Dict]] = None,
    ) -> Path:
        """
        Generate PDF report for a job

        Args:
            job_data: Job metadata
            output_path: Output file path
            results: Optional list of results

        Returns:
            Path to generated PDF
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if self.use_weasyprint:
            generated_path = self._generate_with_weasyprint(
                job_data, output_path, results
            )
        elif self.use_reportlab:
            generated_path = self._generate_with_reportlab(
                job_data, output_path, results
            )
        else:
            raise RuntimeError(
                "No PDF library available. Install with: "
                "pip install weasyprint or pip install reportlab"
            )
        update_last_report_pointer(generated_path)
        return generated_path

    def _generate_with_weasyprint(
        self,
        job_data: Dict[str, Any],
        output_path: Path,
        results: Optional[List[Dict]] = None,
    ) -> Path:
        """Generate PDF using WeasyPrint"""
        from weasyprint import HTML, CSS

        # Generate HTML content
        html_content = self._generate_html_content(job_data, results)

        # Generate CSS
        css_content = self._generate_pdf_css()

        # Create PDF
        html = HTML(string=html_content)
        css = CSS(string=css_content)

        html.write_pdf(str(output_path), stylesheets=[css])

        return output_path

    def _generate_with_reportlab(
        self,
        job_data: Dict[str, Any],
        output_path: Path,
        results: Optional[List[Dict]] = None,
    ) -> Path:
        """Generate PDF using ReportLab"""
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
        )

        # Page size
        page_size = A4 if self.config.page_size == "A4" else letter

        # Create document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=page_size,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        # Build story (content)
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            spaceAfter=30,
            alignment=1,  # Center
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
        )

        normal_style = ParagraphStyle(
            "CustomNormal",
            parent=styles["Normal"],
            fontSize=10,
            spaceBefore=5,
            spaceAfter=5,
        )

        # Title
        story.append(Paragraph(escape_html_text(self.config.title), title_style))
        story.append(Spacer(1, 20))

        # Report Info
        target = job_data.get("target", "Unknown")
        created = job_data.get("created_at", datetime.now().isoformat())
        profile = job_data.get("profile", "default")

        info_data = [
            ["Target:", sanitize_text(target)],
            ["Date:", sanitize_text(created[:10] if len(created) > 10 else created)],
            ["Profile:", sanitize_text(profile)],
            ["Generated By:", sanitize_text(self.config.company_name)],
        ]

        info_table = Table(info_data, colWidths=[3 * cm, 10 * cm])
        info_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(info_table)
        story.append(Spacer(1, 30))

        # Executive Summary
        if self.config.include_executive_summary:
            story.append(Paragraph("Executive Summary", heading_style))
            summary = self._generate_executive_summary(job_data, results)
            story.append(Paragraph(escape_html_text(summary), normal_style))
            story.append(Spacer(1, 20))

        # Statistics
        if results:
            stats = self._calculate_statistics(results)
            quality = self._calculate_quality_stats(job_data, results)
            story.append(Paragraph("Statistics", heading_style))

            stats_data = [
                ["Metric", "Value"],
                ["Total Hosts", str(stats.get("hosts", 0))],
                ["Total URLs", str(stats.get("urls", 0))],
                ["Vulnerabilities", str(stats.get("vulnerabilities", 0))],
                ["Secrets Found", str(stats.get("secrets", 0))],
            ]
            if quality:
                stats_data.extend(
                    [
                        ["Noise ratio", self._format_ratio(quality.get("noise_ratio"))],
                        [
                            "Verified ratio",
                            self._format_ratio(quality.get("verified_ratio")),
                        ],
                    ]
                )
                if quality.get("duplicate_ratio") is not None:
                    stats_data.append(
                        [
                            "Duplicate ratio",
                            self._format_ratio(quality.get("duplicate_ratio")),
                        ]
                    )

            stats_table = Table(stats_data, colWidths=[8 * cm, 5 * cm])
            stats_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                        ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ]
                )
            )
            story.append(stats_table)
            story.append(Spacer(1, 30))

        # Hosts Section
        if results:
            hosts = [r for r in results if r.get("type") == "host"]
            if hosts:
                story.append(PageBreak())
                story.append(Paragraph("Discovered Hosts", heading_style))

                hosts_data = [["Hostname", "IP", "Status", "Source"]]
                for host in hosts[:50]:  # Limit to 50
                    hosts_data.append(
                        [
                            sanitize_text(host.get("host", "N/A"))[:40],
                            sanitize_text(host.get("ip", "N/A")),
                            sanitize_text(host.get("status_code", "-")),
                            sanitize_text(host.get("source", "N/A")),
                        ]
                    )

                hosts_table = Table(
                    hosts_data, colWidths=[6 * cm, 3 * cm, 2 * cm, 3 * cm]
                )
                hosts_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                            (
                                "ROWBACKGROUNDS",
                                (0, 1),
                                (-1, -1),
                                [colors.white, colors.HexColor("#f8fafc")],
                            ),
                        ]
                    )
                )
                story.append(hosts_table)

        # Vulnerabilities Section
        if results:
            vulns = [r for r in results if r.get("type") == "vulnerability"]
            if vulns:
                story.append(PageBreak())
                story.append(Paragraph("Vulnerabilities", heading_style))

                # Sort by severity
                severity_order = {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 3,
                    "info": 4,
                }
                vulns.sort(
                    key=lambda x: severity_order.get(
                        x.get("severity", "info").lower(), 5
                    )
                )

                vulns_data = [["Severity", "Name", "Host", "Template"]]
                for vuln in vulns[:100]:  # Limit to 100
                    vulns_data.append(
                        [
                            sanitize_text(vuln.get("severity", "info")).upper(),
                            sanitize_text(vuln.get("name", "N/A"))[:30],
                            sanitize_text(vuln.get("host", "N/A"))[:25],
                            sanitize_text(vuln.get("template_id", "N/A"))[:20],
                        ]
                    )

                vulns_table = Table(
                    vulns_data, colWidths=[2.5 * cm, 5 * cm, 4 * cm, 3 * cm]
                )

                # Severity colors
                severity_colors = {
                    "CRITICAL": colors.HexColor("#7f1d1d"),
                    "HIGH": colors.HexColor("#ef4444"),
                    "MEDIUM": colors.HexColor("#f59e0b"),
                    "LOW": colors.HexColor("#0ea5e9"),
                    "INFO": colors.HexColor("#64748b"),
                }

                table_style = [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ]

                # Color severity cells
                for i, vuln in enumerate(vulns[:100], start=1):
                    sev = vuln.get("severity", "info").upper()
                    if sev in severity_colors:
                        table_style.append(
                            ("BACKGROUND", (0, i), (0, i), severity_colors[sev])
                        )
                        table_style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))

                vulns_table.setStyle(TableStyle(table_style))
                story.append(vulns_table)

        # Secrets Section
        if results:
            secrets = [r for r in results if r.get("type") == "secret"]
            if secrets:
                story.append(PageBreak())
                story.append(Paragraph("Secrets Found", heading_style))
                story.append(
                    Paragraph(
                        "⚠️ Warning: The following secrets were found exposed. "
                        "Take immediate action to rotate these credentials.",
                        normal_style,
                    )
                )
                story.append(Spacer(1, 10))

                secrets_data = [["Type", "Location", "Severity"]]
                for secret in secrets[:50]:  # Limit to 50
                    secrets_data.append(
                        [
                            sanitize_text(secret.get("secret_type", "Unknown"))[:25],
                            sanitize_text(secret.get("location", "N/A"))[:35],
                            sanitize_text(secret.get("severity", "high")).upper(),
                        ]
                    )

                secrets_table = Table(
                    secrets_data, colWidths=[4 * cm, 7 * cm, 2.5 * cm]
                )
                secrets_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                        ]
                    )
                )
                story.append(secrets_table)

        # Footer
        story.append(Spacer(1, 40))
        story.append(
            Paragraph(
                escape_html_text(
                    f"Generated by {self.config.company_name} on {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                ),
                ParagraphStyle(
                    "Footer", parent=styles["Normal"], fontSize=8, alignment=1
                ),
            )
        )

        # Build PDF
        doc.build(story)

        return output_path

    def _generate_html_content(
        self, job_data: Dict[str, Any], results: Optional[List[Dict]] = None
    ) -> str:
        """Generate HTML content for WeasyPrint"""
        target = job_data.get("target", "Unknown")
        created = job_data.get("created_at", datetime.now().isoformat())
        profile = job_data.get("profile", "default")

        stats = self._calculate_statistics(results) if results else {}
        quality = self._calculate_quality_stats(job_data, results) if results else {}

        # Categorize results
        hosts = [r for r in (results or []) if r.get("type") == "host"]
        vulns = [r for r in (results or []) if r.get("type") == "vulnerability"]

        secrets = [r for r in (results or []) if r.get("type") == "secret"]

        html = f"""
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <title>{escape_html_text(self.config.title)}</title>
</head>
<body>
    <header>
        <h1>{escape_html_text(self.config.title)}</h1>
        <div class="subtitle">{escape_html_text(self.config.company_name)}</div>
    </header>
    
    <section class="info-section">
        <h2>معلومات الفحص</h2>
        <table class="info-table">
            <tr><td class="label">الهدف:</td><td>{escape_html_text(target)}</td></tr>
            <tr><td class="label">التاريخ:</td><td>{escape_html_text(created[:10] if len(created) > 10 else created)}</td></tr>
            <tr><td class="label">الملف الشخصي:</td><td>{escape_html_text(profile)}</td></tr>
        </table>
    </section>
    
    <section class="summary-section">
        <h2>ملخص تنفيذي</h2>
        <p>{escape_html_text(self._generate_executive_summary(job_data, results))}</p>
    </section>
    
    <section class="stats-section">
        <h2>الإحصائيات</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{stats.get("hosts", 0)}</div>
                <div class="label">المضيفين</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get("urls", 0)}</div>
                <div class="label">الروابط</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get("vulnerabilities", 0)}</div>
                <div class="label">الثغرات</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get("secrets", 0)}</div>
                <div class="label">الأسرار</div>
            </div>
            {self._quality_cards(quality) if quality else ""}
        </div>
    </section>
"""

        # Hosts section
        if hosts:
            html += """
    <section class="hosts-section">
        <h2>المضيفين المكتشفين</h2>
        <table class="data-table">
            <thead>
                <tr>
                    <th>المضيف</th>
                    <th>IP</th>
                    <th>الحالة</th>
                    <th>المصدر</th>
                </tr>
            </thead>
            <tbody>
"""
            for host in hosts[:50]:
                html += f"""
                <tr>
                    <td>{escape_html_text(host.get("host", "N/A"))}</td>
                    <td>{escape_html_text(host.get("ip", "N/A"))}</td>
                    <td>{escape_html_text(host.get("status_code", "-"))}</td>
                    <td>{escape_html_text(host.get("source", "N/A"))}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
    </section>
"""

        # Vulnerabilities section
        if vulns:
            # Sort by severity
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            vulns.sort(
                key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5)
            )

            html += """
    <section class="vulns-section">
        <h2>الثغرات الأمنية</h2>
        <table class="data-table">
            <thead>
                <tr>
                    <th>الخطورة</th>
                    <th>الاسم</th>
                    <th>المضيف</th>
                    <th>القالب</th>
                </tr>
            </thead>
            <tbody>
"""
            for vuln in vulns[:100]:
                sev = vuln.get("severity", "info").lower()
                html += f"""
                <tr>
                    <td><span class="severity-badge {sev}">{sev.upper()}</span></td>
                    <td>{escape_html_text(vuln.get("name", "N/A"))}</td>
                    <td>{escape_html_text(vuln.get("host", "N/A"))}</td>
                    <td>{escape_html_text(vuln.get("template_id", "N/A"))}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
    </section>
"""

        # Secrets section
        if secrets:
            html += """
    <section class="secrets-section">
        <h2>⚠️ الأسرار المكتشفة</h2>
        <p class="warning">تحذير: تم اكتشاف الأسرار التالية. اتخذ إجراءات فورية لتدوير هذه البيانات.</p>
        <table class="data-table">
            <thead>
                <tr>
                    <th>النوع</th>
                    <th>الموقع</th>
                    <th>الخطورة</th>
                </tr>
            </thead>
            <tbody>
"""
            for secret in secrets[:50]:
                html += f"""
                <tr>
                    <td>{escape_html_text(secret.get("secret_type", "Unknown"))}</td>
                    <td>{escape_html_text(secret.get("location", "N/A"))}</td>
                    <td>{escape_html_text(str(secret.get("severity", "HIGH")).upper())}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
    </section>
"""

        # Footer
        html += f"""
    <footer>
        <p>تم إنشاء هذا التقرير بواسطة {escape_html_text(self.config.company_name)} في {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
    </footer>
</body>
</html>
"""
        return html

    def _generate_pdf_css(self) -> str:
        """Generate CSS for PDF"""
        return f"""
@page {{
    size: {self.config.page_size};
    margin: 2cm;
    @bottom-center {{
        content: "صفحة " counter(page) " من " counter(pages);
        font-size: 9pt;
        color: #64748b;
    }}
}}

body {{
    font-family: 'Arial', 'Segoe UI', sans-serif;
    font-size: 10pt;
    line-height: 1.6;
    color: #1e293b;
    direction: rtl;
}}

header {{
    text-align: center;
    margin-bottom: 30pt;
    padding-bottom: 20pt;
    border-bottom: 2pt solid {self.config.primary_color};
}}

h1 {{
    font-size: 24pt;
    color: {self.config.primary_color};
    margin-bottom: 5pt;
}}

.subtitle {{
    font-size: 12pt;
    color: {self.config.secondary_color};
}}

h2 {{
    font-size: 14pt;
    color: #1e293b;
    margin-top: 25pt;
    margin-bottom: 10pt;
    padding-bottom: 5pt;
    border-bottom: 1pt solid #e2e8f0;
}}

section {{
    margin-bottom: 20pt;
}}

.info-table {{
    width: 100%;
}}

.info-table td {{
    padding: 5pt;
}}

.info-table .label {{
    font-weight: bold;
    width: 100pt;
}}

.stats-grid {{
    display: flex;
    justify-content: space-around;
    margin: 20pt 0;
}}

.stat-card {{
    text-align: center;
    padding: 15pt;
    background: #f8fafc;
    border-radius: 8pt;
    min-width: 80pt;
}}

.stat-card .value {{
    font-size: 24pt;
    font-weight: bold;
    color: {self.config.primary_color};
}}

.stat-card .label {{
    font-size: 9pt;
    color: {self.config.secondary_color};
    margin-top: 5pt;
}}

.data-table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0;
}}

.data-table th {{
    background: #1e293b;
    color: white;
    padding: 8pt;
    text-align: right;
    font-size: 9pt;
}}

.data-table td {{
    padding: 6pt 8pt;
    border-bottom: 0.5pt solid #e2e8f0;
    font-size: 9pt;
}}

.data-table tbody tr:nth-child(even) {{
    background: #f8fafc;
}}

.severity-badge {{
    display: inline-block;
    padding: 2pt 8pt;
    border-radius: 4pt;
    font-size: 8pt;
    font-weight: bold;
    color: white;
}}

.severity-badge.critical {{
    background: #7f1d1d;
}}

.severity-badge.high {{
    background: #ef4444;
}}

.severity-badge.medium {{
    background: #f59e0b;
    color: #1e293b;
}}

.severity-badge.low {{
    background: #0ea5e9;
}}

.severity-badge.info {{
    background: #64748b;
}}

.warning {{
    background: #fef3c7;
    border: 1pt solid #f59e0b;
    padding: 10pt;
    border-radius: 4pt;
    color: #92400e;
}}

footer {{
    margin-top: 40pt;
    padding-top: 20pt;
    border-top: 1pt solid #e2e8f0;
    text-align: center;
    font-size: 8pt;
    color: {self.config.secondary_color};
}}
"""

    def _generate_executive_summary(
        self, job_data: Dict[str, Any], results: Optional[List[Dict]] = None
    ) -> str:
        """Generate executive summary text"""
        target = job_data.get("target", "Unknown")
        stats = self._calculate_statistics(results) if results else {}

        hosts = stats.get("hosts", 0)
        vulns = stats.get("vulnerabilities", 0)
        secrets = stats.get("secrets", 0)
        critical = stats.get("critical_vulns", 0)
        high = stats.get("high_vulns", 0)

        summary_parts = [f"تم إجراء فحص أمني شامل على الهدف {target}."]

        if hosts > 0:
            summary_parts.append(f"تم اكتشاف {hosts} مضيف.")

        if vulns > 0:
            vuln_text = f"تم العثور على {vulns} ثغرة أمنية"
            if critical > 0 or high > 0:
                vuln_text += f" ({critical} حرجة، {high} عالية الخطورة)"
            vuln_text += "."
            summary_parts.append(vuln_text)

        if secrets > 0:
            summary_parts.append(
                f"تحذير: تم اكتشاف {secrets} من الأسرار المكشوفة التي تتطلب إجراءً فورياً."
            )

        if vulns == 0 and secrets == 0:
            summary_parts.append("لم يتم اكتشاف ثغرات أمنية كبيرة.")

        return " ".join(summary_parts)

    def _calculate_statistics(
        self, results: Optional[List[Dict]] = None
    ) -> Dict[str, int]:
        """Calculate statistics from results"""
        if not results:
            return {}

        stats = {
            "hosts": 0,
            "urls": 0,
            "vulnerabilities": 0,
            "secrets": 0,
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "low_vulns": 0,
            "info_vulns": 0,
        }

        for result in results:
            result_type = result.get("type", "")

            if result_type == "host":
                stats["hosts"] += 1
            elif result_type == "url":
                stats["urls"] += 1
            elif result_type == "vulnerability":
                stats["vulnerabilities"] += 1
                severity = result.get("severity", "info").lower()
                if severity == "critical":
                    stats["critical_vulns"] += 1
                elif severity == "high":
                    stats["high_vulns"] += 1
                elif severity == "medium":
                    stats["medium_vulns"] += 1
                elif severity == "low":
                    stats["low_vulns"] += 1
                else:
                    stats["info_vulns"] += 1
            elif result_type == "secret":
                stats["secrets"] += 1

        return stats

    def _calculate_quality_stats(
        self,
        job_data: Dict[str, Any],
        results: Optional[List[Dict]] = None,
    ) -> Dict[str, object]:
        stats = job_data.get("stats", {}) if isinstance(job_data, dict) else {}
        quality = (
            stats.get("quality") if isinstance(stats.get("quality"), dict) else None
        )
        if quality:
            return quality
        if not results:
            return {}
        total_urls = 0
        noise_count = 0
        findings_total = 0
        verified_count = 0
        for entry in results:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "url":
                total_urls += 1
                tags = entry.get("tags", [])
                if isinstance(tags, list) and "noise" in tags:
                    noise_count += 1
            if is_finding(entry):
                findings_total += 1
                if resolve_confidence_label(entry) == "verified":
                    verified_count += 1
        return {
            "noise_ratio": (noise_count / total_urls) if total_urls else 0.0,
            "verified_ratio": (verified_count / findings_total)
            if findings_total
            else 0.0,
            "duplicate_ratio": None,
            "noise": noise_count,
            "urls": total_urls,
            "verified_findings": verified_count,
            "findings": findings_total,
        }

    @staticmethod
    def _format_ratio(value: object) -> str:
        try:
            return f"{float(value) * 100:.2f}%"  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return "n/a"

    def _quality_cards(self, quality: Dict[str, object]) -> str:
        if not quality:
            return ""
        return f"""
            <div class="stat-card">
                <div class="value">{self._format_ratio(quality.get("noise_ratio"))}</div>
                <div class="label">نسبة الضوضاء</div>
            </div>
            <div class="stat-card">
                <div class="value">{self._format_ratio(quality.get("verified_ratio"))}</div>
                <div class="label">نسبة التحقق</div>
            </div>
            <div class="stat-card">
                <div class="value">{self._format_ratio(quality.get("duplicate_ratio"))}</div>
                <div class="label">نسبة التكرار</div>
            </div>
        """


def generate_pdf_report(
    job_path: Path,
    output_path: Optional[Path] = None,
    config: Optional[PDFReportConfig] = None,
) -> Path:
    """
    Convenience function to generate PDF report

    Args:
        job_path: Path to job directory
        output_path: Optional output path (defaults to job_path/report.pdf)
        config: Optional report configuration

    Returns:
        Path to generated PDF
    """
    job_path = Path(job_path)

    # Load job metadata
    metadata_path = job_path / "metadata.json"
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            job_data = json.load(f)
    else:
        job_data = {"target": job_path.name}

    # Load results
    results = []
    results_path = job_path / "results.jsonl"
    if results_path.exists():
        with open(results_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    # Output path
    if output_path is None:
        output_path = job_path / "report.pdf"

    # Generate report
    reporter = PDFReporter(config)
    return reporter.generate_report(job_data, output_path, results)


# CLI integration helper
def add_pdf_command_to_cli():
    """Example of how to add PDF command to CLI"""
    code = '''
# Add to cli.py

@app.command()
def pdf(
    job_id: str = typer.Argument(..., help="Job ID to generate report for"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output path"),
):
    """Generate PDF report for a job"""
    from recon_cli.utils.pdf_reporter import generate_pdf_report, PDFReportConfig
    
    job_path = find_job_path(job_id)
    if not job_path:
        console.print(f"[red]Job not found: {job_id}[/red]")
        raise typer.Exit(1)
    
    config = PDFReportConfig(
        title="تقرير الاستطلاع الأمني",
        company_name="ReconnV2"
    )
    
    try:
        pdf_path = generate_pdf_report(job_path, output, config)
        console.print(f"[green]✓ PDF report generated: {pdf_path}[/green]")
    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[yellow]Install dependencies with: pip install weasyprint[/yellow]")
        raise typer.Exit(1)
'''
    return code
