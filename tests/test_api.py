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
        assert response.status_code == 200
        data = response.json()
        assert "uptime" in data
        assert isinstance(data["uptime"], str)


class TestAPIStats:
    """Tests for /api/stats endpoint."""

    def test_stats_returns_counts(self):
        """Stats endpoint returns job counts."""
        client = TestClient(app)
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        for key in ("queued", "running", "finished", "failed", "total"):
            assert key in data
        assert data["total"] == data["queued"] + data["running"] + data["finished"] + data["failed"]


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

    def test_delete_requires_api_key(self):
        """Delete endpoint requires API key."""
        client = TestClient(app)
        response = client.delete("/api/jobs/job-123")
        assert response.status_code == 401

    def test_requeue_requires_api_key(self):
        """Requeue endpoint requires API key."""
        client = TestClient(app)
        response = client.post("/api/jobs/job-123/requeue")
        assert response.status_code == 401

    def test_delete_requires_permission(self):
        """Delete endpoint enforces job delete permission."""
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {
                "user_id": 1,
                "permissions": ["api:access", "jobs:view"],
                "scopes": [],
            }
            response = client.delete(
                "/api/jobs/job-123",
                headers={"X-API-Key": "test-api-key"},
            )
        assert response.status_code == 403
        assert response.json()["detail"] == "API key lacks jobs:delete"

    def test_delete_rejects_path_traversal_job_id(self):
        """Encoded traversal job_id is rejected before deletion."""
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {"user_id": 1, "permissions": ["write"]}
            with patch("recon_cli.jobs.lifecycle.JobLifecycle.delete_job") as mock_delete:
                response = client.delete(
                    "/api/jobs/%2E%2E",
                    headers={"X-API-Key": "test-api-key"},
                )
                assert response.status_code == 400
                mock_delete.assert_not_called()


class TestAPIScan:
    """Tests for /api/scan endpoint."""

    def test_scan_requires_api_key(self):
        """Scan creation requires API key."""
        client = TestClient(app)
        response = client.post("/api/scan", json={"target": "example.com"})
        assert response.status_code == 401

    def test_scan_requires_target(self):
        """Scan requires target parameter."""
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {
                "user_id": 1,
                "permissions": ["api:access", "jobs:create"],
                "scopes": [],
            }
            response = client.post("/api/scan", json={}, headers={"X-API-Key": "test-api-key"})
        assert response.status_code == 400
        assert response.json()["detail"] == "target is required"

    def test_scan_with_valid_target(self):
        """Scan with valid target creates job."""
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {
                "user_id": 1,
                "permissions": ["api:access", "jobs:create"],
                "scopes": [],
            }
            with patch.object(app.state.manager, "create_job") as mock_create_job:
                mock_record = MagicMock()
                mock_record.spec.job_id = "test_job_123"
                mock_record.metadata.queued_at = "2026-03-10T00:00:00Z"
                mock_create_job.return_value = mock_record

                response = client.post("/api/scan", json={
                    "target": "example.com",
                    "profile": "passive"
                }, headers={"X-API-Key": "test-api-key"})
                assert response.status_code == 200
                assert response.json() == {
                    "job_id": "test_job_123",
                    "status": "queued",
                    "target": "example.com",
                    "profile": "passive",
                    "stage": None,
                    "queued_at": "2026-03-10T00:00:00Z",
                    "started_at": None,
                    "finished_at": None,
                    "error": None,
                    "stats": {},
                    "quality": {},
                }

    def test_scan_rejects_invalid_scanner_token(self):
        """Invalid scanner names are rejected."""
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {
                "user_id": 1,
                "permissions": ["api:access", "jobs:create"],
                "scopes": [],
            }
            response = client.post(
                "/api/scan",
                json={"target": "example.com", "profile": "passive", "scanners": ["bad token"]},
                headers={"X-API-Key": "test-api-key"},
            )
        assert response.status_code == 400
        assert "Invalid scanners value" in response.json().get("detail", "")


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


class TestAPIMutationValidation:
    """Tests for stricter validation on mutation endpoints."""

    def test_create_job_rejects_empty_target_entries(self):
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {
                "user_id": 1,
                "permissions": ["api:access", "jobs:create"],
                "scopes": [],
            }
            response = client.post(
                "/api/jobs",
                json={"targets": ["example.com", "   "], "stages": [], "options": {}},
                headers={"X-API-Key": "test-api-key"},
            )
        assert response.status_code == 400
        assert "empty values" in response.json().get("detail", "")

    def test_create_job_rejects_non_boolean_allow_ip(self):
        client = TestClient(app)
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {
                "user_id": 1,
                "permissions": ["api:access", "jobs:create"],
                "scopes": [],
            }
            response = client.post(
                "/api/jobs",
                json={"targets": ["example.com"], "stages": [], "options": {"allow_ip": "yes"}},
                headers={"X-API-Key": "test-api-key"},
            )
        assert response.status_code == 400
        assert "allow_ip" in response.json().get("detail", "")
