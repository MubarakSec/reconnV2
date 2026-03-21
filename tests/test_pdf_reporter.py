"""
Tests for PDF Reporter
"""

import json
import pytest
from unittest.mock import patch


class TestPDFReportConfig:
    """Tests for PDFReportConfig"""

    def test_default_config(self):
        """Test default configuration"""
        from recon_cli.utils.pdf_reporter import PDFReportConfig

        config = PDFReportConfig()
        assert config.title == "تقرير الاستطلاع الأمني"
        assert config.company_name == "ReconnV2"
        assert config.include_toc is True
        assert config.page_size == "A4"

    def test_custom_config(self):
        """Test custom configuration"""
        from recon_cli.utils.pdf_reporter import PDFReportConfig

        config = PDFReportConfig(
            title="Custom Report", company_name="MyCompany", page_size="Letter"
        )
        assert config.title == "Custom Report"
        assert config.company_name == "MyCompany"
        assert config.page_size == "Letter"


class TestPDFReporter:
    """Tests for PDFReporter class"""

    def test_initialization(self):
        """Test reporter initialization"""
        from recon_cli.utils.pdf_reporter import PDFReporter, PDFReportConfig

        config = PDFReportConfig(title="Test Report")
        reporter = PDFReporter(config)

        assert reporter.config.title == "Test Report"

    def test_calculate_statistics(self):
        """Test statistics calculation"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()

        results = [
            {"type": "host", "host": "example.com"},
            {"type": "host", "host": "test.com"},
            {"type": "url", "url": "http://example.com/page"},
            {"type": "vulnerability", "severity": "critical"},
            {"type": "vulnerability", "severity": "high"},
            {"type": "vulnerability", "severity": "medium"},
            {"type": "secret", "secret_type": "api_key"},
        ]

        stats = reporter._calculate_statistics(results)

        assert stats["hosts"] == 2
        assert stats["urls"] == 1
        assert stats["vulnerabilities"] == 3
        assert stats["secrets"] == 1
        assert stats["critical_vulns"] == 1
        assert stats["high_vulns"] == 1

    def test_calculate_statistics_empty(self):
        """Test statistics with empty results"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()
        stats = reporter._calculate_statistics([])

        assert stats == {}

    def test_executive_summary(self):
        """Test executive summary generation"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()

        job_data = {"target": "example.com"}
        results = [
            {"type": "host", "host": "sub.example.com"},
            {"type": "vulnerability", "severity": "critical"},
        ]

        summary = reporter._generate_executive_summary(job_data, results)

        assert "example.com" in summary
        assert "1" in summary  # 1 host

    def test_html_content_generation(self):
        """Test HTML content generation"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()

        job_data = {
            "target": "example.com",
            "created_at": "2024-01-15T10:30:00",
            "profile": "full",
        }

        results = [
            {"type": "host", "host": "sub.example.com", "ip": "1.2.3.4"},
        ]

        html = reporter._generate_html_content(job_data, results)

        assert "<!DOCTYPE html>" in html
        assert "example.com" in html
        assert "sub.example.com" in html
        assert 'dir="rtl"' in html

    def test_css_generation(self):
        """Test CSS generation"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()
        css = reporter._generate_pdf_css()

        assert "@page" in css
        assert "direction: rtl" in css
        assert reporter.config.primary_color in css


class TestReportGeneration:
    """Tests for report generation"""

    def test_generate_report_no_dependencies(self, tmp_path):
        """Test report generation when no PDF libraries available"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()
        reporter.use_weasyprint = False
        reporter.use_reportlab = False

        job_data = {"target": "example.com"}
        output_path = tmp_path / "report.pdf"

        with pytest.raises(RuntimeError, match="No PDF library available"):
            reporter.generate_report(job_data, output_path)

    @patch("recon_cli.utils.pdf_reporter.PDFReporter._generate_with_reportlab")
    def test_generate_report_with_reportlab(self, mock_reportlab, tmp_path):
        """Test report uses reportlab when available"""
        from recon_cli.utils.pdf_reporter import PDFReporter

        reporter = PDFReporter()
        reporter.use_weasyprint = False
        reporter.use_reportlab = True

        job_data = {"target": "example.com"}
        output_path = tmp_path / "report.pdf"
        mock_reportlab.return_value = output_path

        reporter.generate_report(job_data, output_path)

        mock_reportlab.assert_called_once()


class TestConvenienceFunction:
    """Tests for convenience functions"""

    def test_generate_pdf_report_no_metadata(self, tmp_path):
        """Test generate_pdf_report without metadata file"""
        from recon_cli.utils.pdf_reporter import generate_pdf_report, PDFReporter

        job_path = tmp_path / "test_job"
        job_path.mkdir()

        # Create empty results file
        (job_path / "results.jsonl").write_text("")

        # Mock the reporter
        with patch.object(PDFReporter, "generate_report") as mock_gen:
            mock_gen.return_value = job_path / "report.pdf"

            generate_pdf_report(job_path)

            assert mock_gen.called

    def test_generate_pdf_report_with_metadata(self, tmp_path):
        """Test generate_pdf_report with metadata file"""
        from recon_cli.utils.pdf_reporter import generate_pdf_report, PDFReporter

        job_path = tmp_path / "test_job"
        job_path.mkdir()

        # Create metadata
        metadata = {"target": "example.com", "profile": "full"}
        (job_path / "metadata.json").write_text(json.dumps(metadata))

        # Create results
        results = [
            {"type": "host", "host": "sub.example.com"},
        ]
        (job_path / "results.jsonl").write_text(
            "\n".join(json.dumps(r) for r in results)
        )

        # Mock the reporter
        with patch.object(PDFReporter, "generate_report") as mock_gen:
            mock_gen.return_value = job_path / "report.pdf"

            generate_pdf_report(job_path)

            # Check that job_data was loaded correctly
            call_args = mock_gen.call_args
            assert call_args[0][0]["target"] == "example.com"
            assert len(call_args[0][2]) == 1  # 1 result
