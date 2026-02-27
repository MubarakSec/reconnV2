"""Tests for reporter.py"""
import json
import tempfile
import pytest
from pathlib import Path
from recon_cli.utils.reporter import (
    generate_html_report,
    ReportData,
    ReportConfig,
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

    def test_html_redacts_sensitive_tokens(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()

            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {},
            }))
            results = [
                {"type": "url", "url": "https://example.com/profile?token=abc123"},
                {"type": "finding", "title": "auth leak", "severity": "high", "proof": "Authorization: Bearer xyz987"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for item in results:
                    f.write(json.dumps(item) + "\n")

            output_path = Path(tmpdir) / "report.html"
            generate_html_report(job_dir, output_path)

            content = output_path.read_text()
            assert "abc123" not in content
            assert "xyz987" not in content
            assert "***" in content

    def test_html_includes_quality_metrics(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()

            metadata = {
                "job_id": "test_job",
                "status": "finished",
                "stats": {
                    "quality": {
                        "noise_ratio": 0.25,
                        "verified_ratio": 0.5,
                        "duplicate_ratio": 0.1,
                    }
                },
            }
            (job_dir / "metadata.json").write_text(json.dumps(metadata))
            (job_dir / "results.jsonl").write_text("")

            output_path = Path(tmpdir) / "report.html"
            config = ReportConfig(language="en", include_quality=True)
            generate_html_report(job_dir, output_path, config)

            content = output_path.read_text()
            assert "Verified ratio" in content
            assert "Noise ratio" in content
            assert "Duplicate ratio" in content

    def test_html_verified_only_filters_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()

            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {}
            }))

            results = [
                {"type": "finding", "title": "confirmed-issue", "tags": ["ssrf:confirmed"], "severity": "high"},
                {"type": "finding", "title": "unconfirmed-issue", "severity": "high"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")

            output_path = Path(tmpdir) / "report.html"
            config = ReportConfig(language="en", verified_only=True)
            generate_html_report(job_dir, output_path, config)

            content = output_path.read_text()
            assert "confirmed-issue" in content
            assert "unconfirmed-issue" not in content

    def test_html_hunter_mode_top_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()

            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {}
            }))

            results = [
                {
                    "type": "finding",
                    "title": "confirmed-issue",
                    "tags": ["ssrf:confirmed"],
                    "severity": "high",
                    "source": "dalfox",
                    "repro_cmd": "curl https://example.com?x=1",
                },
                {"type": "finding", "title": "unconfirmed-issue", "severity": "high"},
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")

            output_path = Path(tmpdir) / "report.html"
            config = ReportConfig(language="en", hunter_mode=True)
            generate_html_report(job_dir, output_path, config)

            content = output_path.read_text()
            assert "Top Actionable Findings" in content
            assert "confirmed-issue" in content
            assert "unconfirmed-issue" not in content
            assert "curl https://example.com" in content
            assert "Submission Summary" in content
            assert "confidence=verified" in content
            assert "recon-cli rerun test_job --stages vuln_scan --keep-results" in content

    def test_html_hunter_mode_includes_triage_hints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job"
            job_dir.mkdir()

            (job_dir / "metadata.json").write_text(json.dumps({
                "job_id": "test_job",
                "status": "finished",
                "stats": {}
            }))
            (job_dir / "spec.json").write_text(json.dumps({
                "job_id": "test_job",
                "target": "example.com",
                "profile": "passive"
            }))

            results = [
                {
                    "type": "finding",
                    "title": "dup-issue",
                    "tags": ["ssrf:confirmed", "duplicate"],
                    "source": "extended-validation",
                    "severity": "high",
                    "proof": "seen before",
                    "url": "https://example.com/path",
                },
                {
                    "type": "finding",
                    "title": "oos-issue",
                    "tags": ["ssrf:confirmed"],
                    "source": "extended-validation",
                    "severity": "high",
                    "proof": "confirmed",
                    "url": "https://cdn.other.net/asset",
                },
            ]
            with (job_dir / "results.jsonl").open("w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")

            output_path = Path(tmpdir) / "report.html"
            config = ReportConfig(language="en", hunter_mode=True)
            generate_html_report(job_dir, output_path, config)

            content = output_path.read_text()
            assert "Triage Hints" in content
            assert "Likely Duplicates" in content
            assert "Likely Out of Scope" in content
            assert "host_mismatch:cdn.other.net" in content

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
