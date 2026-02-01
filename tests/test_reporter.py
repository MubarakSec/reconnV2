"""Tests for reporter.py"""
import json
import tempfile
import pytest
from pathlib import Path
from recon_cli.utils.reporter import (
    generate_html_report,
    ReportData,
)


class TestReportData:
    """Tests for ReportData class."""

    def test_from_job_dir_missing(self):
        """Returns None for missing job directory."""
        result = ReportData.from_job_dir(Path("/nonexistent/path"))
        assert result is None

    def test_from_job_dir_valid(self):
        """Parses valid job directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir)
            
            # Create metadata.json
            metadata = {
                "job_id": "test_job_123",
                "status": "finished",
                "started_at": "2026-01-15T10:00:00Z",
                "finished_at": "2026-01-15T10:30:00Z",
                "stats": {
                    "hosts_discovered": 50,
                    "http_urls": 100,
                    "vulnerabilities": 5,
                }
            }
            (job_dir / "metadata.json").write_text(json.dumps(metadata))
            
            # Create results.jsonl
            results = [
                {"type": "host", "hostname": "example.com"},
                {"type": "url", "url": "https://example.com/"},
                {"type": "vulnerability", "severity": "high"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")
            
            # Parse
            data = ReportData.from_job_dir(job_dir)
            assert data is not None
            assert data.job_id == "test_job_123"
            assert data.status == "finished"
            assert len(data.results) == 3

    def test_severity_counts(self):
        """Counts severities correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir)
            
            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test",
                "status": "finished",
            }))
            
            results = [
                {"type": "vulnerability", "severity": "critical"},
                {"type": "vulnerability", "severity": "high"},
                {"type": "vulnerability", "severity": "high"},
                {"type": "vulnerability", "severity": "medium"},
                {"type": "vulnerability", "severity": "low"},
                {"type": "vulnerability", "severity": "info"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")
            
            data = ReportData.from_job_dir(job_dir)
            counts = data.get_severity_counts()
            
            assert counts["critical"] == 1
            assert counts["high"] == 2
            assert counts["medium"] == 1
            assert counts["low"] == 1
            assert counts["info"] == 1


class TestGenerateHtmlReport:
    """Tests for generate_html_report function."""

    def test_generates_html_file(self):
        """Generates HTML report file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()
            
            # Create minimal job data
            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "started_at": "2026-01-15T10:00:00Z",
                "finished_at": "2026-01-15T10:30:00Z",
                "stats": {}
            }))
            (job_dir / "results.jsonl").write_text("")
            
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(job_dir, output_path)
            
            assert output_path.exists()
            content = output_path.read_text()
            assert "<!DOCTYPE html>" in content
            assert "test_job" in content

    def test_html_contains_results(self):
        """HTML contains result data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()
            
            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {"hosts_discovered": 10}
            }))
            
            results = [
                {"type": "host", "hostname": "vulnerable.example.com"},
                {"type": "url", "url": "https://api.example.com/v1"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")
            
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(job_dir, output_path)
            
            content = output_path.read_text()
            assert "vulnerable.example.com" in content
            assert "api.example.com" in content

    def test_handles_arabic_content(self):
        """Handles Arabic text in results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()
            
            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_arabic",
                "status": "منتهي",
                "stats": {}
            }), encoding="utf-8")
            (job_dir / "results.jsonl").write_text("")
            
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(job_dir, output_path)
            
            content = output_path.read_text(encoding="utf-8")
            assert "منتهي" in content

    def test_missing_job_dir(self):
        """Handles missing job directory gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            
            # Should not raise, just return without creating file
            try:
                generate_html_report(Path("/nonexistent"), output_path)
            except Exception:
                pass  # Expected
            
            assert not output_path.exists()


class TestHtmlReportContent:
    """Tests for HTML report content structure."""

    def test_has_required_sections(self):
        """Report has all required sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()
            
            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {}
            }))
            (job_dir / "results.jsonl").write_text("")
            
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(job_dir, output_path)
            
            content = output_path.read_text()
            
            # Check for essential HTML elements
            assert "<head>" in content
            assert "<body>" in content
            assert "</html>" in content
            
            # Check for CSS styling
            assert "<style>" in content or "style=" in content

    def test_vulnerability_highlighting(self):
        """Critical vulnerabilities are highlighted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()
            
            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {}
            }))
            
            results = [
                {"type": "vulnerability", "severity": "critical", "name": "SQL Injection"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")
            
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(job_dir, output_path)
            
            content = output_path.read_text()
            assert "critical" in content.lower()
            assert "SQL Injection" in content
