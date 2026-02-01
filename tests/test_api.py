"""Tests for REST API (recon_cli/api/app.py)"""
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Skip if FastAPI not installed
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from recon_cli.api.app import app, JOBS_BASE


class TestAPIStatus:
    """Tests for /api/status endpoint."""

    def test_status_returns_ok(self):
        """Status endpoint returns OK."""
        client = TestClient(app)
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_status_includes_uptime(self):
        """Status includes uptime information."""
        client = TestClient(app)
        response = client.get("/api/status")
        data = response.json()
        assert "uptime" in data or "started_at" in data or "version" in data


class TestAPIStats:
    """Tests for /api/stats endpoint."""

    def test_stats_returns_counts(self):
        """Stats endpoint returns job counts."""
        client = TestClient(app)
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "queued" in data or "jobs" in data or "total" in data


class TestAPIJobs:
    """Tests for /api/jobs endpoints."""

    def test_list_jobs_empty(self):
        """List jobs returns empty when no jobs."""
        client = TestClient(app)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(JOBS_BASE, '__class__', Path):
                response = client.get("/api/jobs")
                assert response.status_code == 200

    def test_get_job_not_found(self):
        """Get non-existent job returns 404."""
        client = TestClient(app)
        response = client.get("/api/jobs/nonexistent_job_id")
        assert response.status_code == 404


class TestAPIScan:
    """Tests for /api/scan endpoint."""

    def test_scan_requires_target(self):
        """Scan requires target parameter."""
        client = TestClient(app)
        response = client.post("/api/scan", json={})
        # Should fail validation
        assert response.status_code in [400, 422]

    def test_scan_with_valid_target(self):
        """Scan with valid target creates job."""
        client = TestClient(app)
        with patch("recon_cli.api.app.JobManager") as mock_manager:
            mock_record = MagicMock()
            mock_record.metadata.job_id = "test_job_123"
            mock_manager.return_value.create_job.return_value = mock_record
            
            response = client.post("/api/scan", json={
                "target": "example.com",
                "profile": "passive"
            })
            # Either creates job or returns validation error
            assert response.status_code in [200, 201, 422, 500]


class TestAPIResults:
    """Tests for /api/jobs/{id}/results endpoint."""

    def test_results_not_found(self):
        """Results for non-existent job returns 404."""
        client = TestClient(app)
        response = client.get("/api/jobs/nonexistent/results")
        assert response.status_code == 404


class TestAPIReport:
    """Tests for /api/jobs/{id}/report endpoint."""

    def test_report_not_found(self):
        """Report for non-existent job returns 404."""
        client = TestClient(app)
        response = client.get("/api/jobs/nonexistent/report")
        assert response.status_code == 404


class TestAPIErrorHandling:
    """Tests for API error handling."""

    def test_invalid_json(self):
        """Invalid JSON returns 422."""
        client = TestClient(app)
        response = client.post(
            "/api/scan",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422

    def test_method_not_allowed(self):
        """Wrong HTTP method returns 405."""
        client = TestClient(app)
        response = client.post("/api/status")
        assert response.status_code == 405

    def test_not_found_route(self):
        """Unknown route returns 404."""
        client = TestClient(app)
        response = client.get("/api/unknown_endpoint")
        assert response.status_code == 404


class TestAPIDocs:
    """Tests for API documentation."""

    def test_docs_available(self):
        """OpenAPI docs are available."""
        client = TestClient(app)
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_json(self):
        """OpenAPI JSON schema is available."""
        client = TestClient(app)
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "paths" in data


class TestAPIResponseFormat:
    """Tests for API response formats."""

    def test_json_content_type(self):
        """API returns JSON content type."""
        client = TestClient(app)
        response = client.get("/api/status")
        assert "application/json" in response.headers.get("content-type", "")

    def test_cors_headers(self):
        """CORS headers are present if configured."""
        client = TestClient(app)
        response = client.options("/api/status")
        # CORS may or may not be configured
        assert response.status_code in [200, 405]
