from __future__ import annotations

import asyncio
import json
from pathlib import Path

from recon_cli.reports.executive import ExecutiveSummaryGenerator
from recon_cli.reports.generator import ReportFormat, ReportGenerator
from recon_cli.utils.pdf_reporter import PDFReporter
from recon_cli.utils.reporter import generate_html_report


def test_html_report_escapes_untrusted_scan_values(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "metadata.json").write_text(
        json.dumps({"job_id": "job-xss", "status": "finished", "stats": {}}),
        encoding="utf-8",
    )
    results = [
        {
            "type": "finding",
            "title": "<script>alert(1)</script>",
            "description": "<img src=x onerror=alert(1)>",
            "severity": "high",
        }
    ]
    with (job_dir / "results.jsonl").open("w", encoding="utf-8") as handle:
        for item in results:
            handle.write(json.dumps(item))
            handle.write("\n")

    output_path = tmp_path / "report.html"
    generate_html_report(job_dir, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_report_generator_html_escapes_untrusted_values() -> None:
    generator = ReportGenerator()
    html = asyncio.run(
        generator.generate(
            {
                "job_id": "job-generator",
                "targets": ["example.com"],
                "findings": [
                    {
                        "type": "finding",
                        "severity": "high",
                        "title": "<script>alert(2)</script>",
                        "description": "<img src=x onerror=alert(2)>",
                    }
                ],
                "hosts": [
                    {"hostname": 'bad"><script>alert(3)</script>', "open_ports": [80]}
                ],
            },
            format=ReportFormat.HTML,
        )
    )

    assert "<script>alert(2)</script>" not in html
    assert "<img src=x onerror=alert(2)>" not in html
    assert 'bad"><script>alert(3)</script>' not in html
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html
    assert "bad&quot;&gt;&lt;script&gt;alert(3)&lt;/script&gt;" in html


def test_executive_summary_html_escapes_untrusted_values() -> None:
    summary = ExecutiveSummaryGenerator(author="<b>ops</b>").generate(
        {
            "targets": ["<script>alert(4)</script>"],
            "findings": [
                {
                    "type": "finding",
                    "severity": "critical",
                    "title": "<img src=x onerror=alert(4)>",
                    "description": "<svg/onload=alert(4)>",
                }
            ],
            "hosts": [{"hostname": "example.com"}],
        }
    )

    html = summary.to_html()
    assert "<script>alert(4)</script>" not in html
    assert "<img src=x onerror=alert(4)>" not in html
    assert "<b>ops</b>" not in html
    assert "&lt;script&gt;alert(4)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(4)&gt;" in html
    assert "&lt;b&gt;ops&lt;/b&gt;" in html


def test_pdf_reporter_html_content_escapes_untrusted_values() -> None:
    reporter = PDFReporter()
    html = reporter._generate_html_content(
        {
            "target": "<script>alert(5)</script>",
            "created_at": "2026-03-10T00:00:00",
            "profile": "<img src=x onerror=alert(5)>",
        },
        [
            {
                "type": "host",
                "host": 'bad"><script>alert(6)</script>',
                "ip": "1.2.3.4",
                "source": "<svg/onload=alert(6)>",
            }
        ],
    )

    assert "<script>alert(5)</script>" not in html
    assert "<img src=x onerror=alert(5)>" not in html
    assert 'bad"><script>alert(6)</script>' not in html
    assert "&lt;script&gt;alert(5)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(5)&gt;" in html
    assert "bad&quot;&gt;&lt;script&gt;alert(6)&lt;/script&gt;" in html
