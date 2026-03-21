"""Tests for REST API (recon_cli/api/app.py)"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Skip if FastAPI not installed
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from recon_cli.api.app import app, create_app, JOBS_BASE
@pytest.fixture
def api_client(tmp_path):
    with patch("recon_cli.users.UserManager.validate_api_key") as mock_val:
        # Mock a valid user with all permissions
        mock_val.return_value = {
            "id": "admin",
            "username": "admin",
            "permissions": ["api:admin", "api:access", "jobs:create", "jobs:run", "jobs:delete"],
            "scopes": ["*"]
        }
        from recon_cli.jobs.manager import JobManager
        # Now truly isolated via refactored constructor
        isolated_manager = JobManager(home=tmp_path)

        # Create a fresh app instance for each test
        fresh_app = create_app(manager=isolated_manager)
        client = TestClient(fresh_app)
        client.headers["X-API-Key"] = "test-key"
        yield client
class TestAPIStatus:
    """Tests for /api/status endpoint."""

    def test_status_returns_ok(self, api_client):
        """Status endpoint returns OK."""
        response = api_client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_status_includes_uptime(self, api_client):
        """Status includes uptime information."""
        response = api_client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "uptime" in data
        assert isinstance(data["uptime"], str)


class TestAPIStats:
    """Tests for /api/stats endpoint."""

    def test_stats_returns_counts(self, api_client):
        """Stats endpoint returns job counts."""
        response = api_client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        for key in ("queued", "running", "finished", "failed", "total"):
            assert key in data
        assert data["total"] == data["queued"] + data["running"] + data["finished"] + data["failed"]


class TestAPIJobs:
    """Tests for /api/jobs endpoints."""

    def test_list_jobs_empty(self, api_client):
        """Jobs list is empty initially."""
        response = api_client.get("/api/jobs")
        assert response.status_code == 200
        data = response.json()
        assert "jobs" in data
        assert data["total"] == 0

    def test_get_job_not_found(self, api_client):
        """Requesting non-existent job returns 404."""
        response = api_client.get("/api/jobs/nonexistent-job")
        assert response.status_code == 404

    def test_delete_requires_api_key(self, api_client):
        """Deleting job requires API key."""
        api_client.headers.pop("X-API-Key", None)
        response = api_client.delete("/api/jobs/job-123")
        assert response.status_code == 401

    def test_requeue_requires_api_key(self, api_client):
        """Requeue job requires API key."""
        api_client.headers.pop("X-API-Key", None)
        response = api_client.post("/api/jobs/job-123/requeue")
        assert response.status_code == 401

    def test_delete_requires_permission(self, api_client):
        """Deleting job requires permission."""
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_val:
            mock_val.return_value = {"id": "user", "permissions": ["api:access"], "scopes": []}
            response = api_client.delete("/api/jobs/job-123")
            assert response.status_code == 403

    def test_delete_rejects_path_traversal_job_id(self, api_client):
        """Job ID cannot contain path traversal."""
        response = api_client.delete("/api/jobs/../../etc/passwd")
        assert response.status_code in {400, 404}


class TestAPIScan:
    """Tests for /api/scan endpoint."""

    def test_scan_requires_api_key(self, api_client):
        """Starting scan requires API key."""
        api_client.headers.pop("X-API-Key", None)
        response = api_client.post("/api/scan", json={"target": "example.com"})
        assert response.status_code == 401

    def test_scan_requires_target(self, api_client):
        """Starting scan requires target."""
        response = api_client.post("/api/scan", json={})
        assert response.status_code == 422  # Pydantic validation error

    def test_scan_with_valid_target(self, api_client):
        """Starting scan with valid target works."""
        with patch("recon_cli.jobs.manager.JobManager.create_job") as mock_create:
            mock_job = MagicMock()
            mock_job.spec.job_id = "job-123"
            mock_job.spec.target = "example.com"
            mock_job.spec.profile = "passive"
            mock_job.metadata.status = "queued"
            mock_job.metadata.stage = "queued"
            mock_job.metadata.queued_at = "2026-01-01T00:00:00Z"
            mock_job.metadata.stats = {}
            mock_create.return_value = mock_job
            
            response = api_client.post("/api/scan", json={
                "target": "example.com",
                "profile": "passive",
                "inline": False
            })
            if response.status_code != 200:
                print(f"DEBUG: Response body: {response.json()}")
            assert response.status_code == 200
            assert response.json()["job_id"] == "job-123"

    def test_scan_rejects_invalid_scanner_token(self, api_client):
        """Invalid scanner tokens are rejected."""
        response = api_client.post("/api/scan", json={"target": "ex.com", "scanners": ["../bad"]})
        assert response.status_code == 422


class TestAPIResults:
    """Tests for job results endpoints."""

    def test_results_not_found(self, api_client):
        """Requesting results for non-existent job returns 404."""
        response = api_client.get("/api/jobs/nonexistent-job/results")
        assert response.status_code == 404


class TestAPIReport:
    """Tests for job report endpoint."""

    def test_report_not_found(self, api_client):
        """Requesting report for non-existent job returns 404."""
        response = api_client.get("/api/jobs/nonexistent-job/report")
        assert response.status_code == 404


class TestAPIErrorHandling:
    """Tests for API error handling."""

    def test_invalid_json(self, api_client):
        """Invalid JSON payload returns 422."""
        response = api_client.post("/api/scan", data="not-json")
        assert response.status_code == 422

    def test_method_not_allowed(self, api_client):
        """Invalid method for route returns 405."""
        response = api_client.put("/api/status")
        assert response.status_code == 405

    def test_not_found_route(self, api_client):
        """Requesting non-existent route returns 404."""
        response = api_client.get("/api/invalid")
        assert response.status_code == 404


class TestAPIDocs:
    """Tests for API documentation."""

    def test_docs_available(self, api_client):
        """Swagger documentation is available."""
        response = api_client.get("/docs")
        assert response.status_code == 200

    def test_openapi_json(self, api_client):
        """OpenAPI schema is available."""
        response = api_client.get("/openapi.json")
        assert response.status_code == 200


class TestAPIResponseFormat:
    """Tests for API response formatting."""

    def test_json_content_type(self, api_client):
        """API responses are JSON."""
        response = api_client.get("/api/status")
        assert response.headers["content-type"] == "application/json"

    def test_cors_headers(self, api_client):
        """Responses include CORS headers."""
        response = api_client.options("/api/status", headers={
            "Origin": "http://localhost:8080", 
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key"
        })
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:8080"


class TestAPIMutationValidation:
    """Tests for complex input validation."""

    def test_create_job_rejects_empty_target_entries(self, api_client):
        """Empty target strings are rejected."""
        response = api_client.post("/api/jobs", json={"targets": [""]})
        assert response.status_code == 422

    def test_create_job_rejects_non_boolean_allow_ip(self, api_client):
        """Non-boolean allow_ip is rejected."""
        response = api_client.post("/api/jobs", json={"targets": ["ex.com"], "options": {"allow_ip": "yes"}})
        assert response.status_code == 422 # Pydantic type error
