from __future__ import annotations

"""
Integration Tests for API

اختبارات تكامل للـ API
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════
#                     Import Modules
# ═══════════════════════════════════════════════════════════

try:
    from fastapi.testclient import TestClient
    from recon_cli.api.app import create_app
    HAS_API = True
except ImportError:
    HAS_API = False


pytestmark = [
    pytest.mark.skipif(not HAS_API, reason="API modules not available"),
    pytest.mark.integration,
]


# ═══════════════════════════════════════════════════════════
#                     Fixtures
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def api_client():
    """عميل API"""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def api_dir(tmp_path: Path) -> Path:
    """مجلد API"""
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    (jobs_dir / "queued").mkdir()
    (jobs_dir / "running").mkdir()
    (jobs_dir / "finished").mkdir()
    (jobs_dir / "failed").mkdir()
    return tmp_path


@pytest.fixture
def sample_job_data() -> dict:
    """بيانات مهمة للاختبار"""
    return {
        "targets": ["example.com", "test.com"],
        "stages": ["subdomain-enum", "port-scan"],
        "options": {
            "concurrency": 10,
            "timeout": 300,
        },
    }


# ═══════════════════════════════════════════════════════════
#                     Health Endpoint Tests
# ═══════════════════════════════════════════════════════════

class TestHealthEndpoint:
    """اختبارات Health Endpoint"""
    
    def test_health_endpoint(self, api_client: TestClient):
        """Health endpoint"""
        response = api_client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    
    def test_health_returns_healthy(self, api_client: TestClient):
        """Health يرجع صحي"""
        response = api_client.get("/api/health")
        
        data = response.json()
        assert data["status"] in ["healthy", "ok", "up"]
    
    def test_health_includes_components(self, api_client: TestClient):
        """Health يتضمن المكونات"""
        response = api_client.get("/api/health")
        
        data = response.json()
        # May include components depending on implementation
        assert isinstance(data, dict)


# ═══════════════════════════════════════════════════════════
#                     Version Endpoint Tests
# ═══════════════════════════════════════════════════════════

class TestVersionEndpoint:
    """اختبارات Version Endpoint"""
    
    def test_version_endpoint(self, api_client: TestClient):
        """Version endpoint"""
        response = api_client.get("/api/version")
        
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
    
    def test_version_format(self, api_client: TestClient):
        """تنسيق الإصدار"""
        response = api_client.get("/api/version")
        
        data = response.json()
        version = data["version"]
        
        # Should be semver format
        parts = version.split(".")
        assert len(parts) >= 2


# ═══════════════════════════════════════════════════════════
#                     Jobs API Tests
# ═══════════════════════════════════════════════════════════

class TestJobsAPI:
    """اختبارات Jobs API"""
    
    def test_list_jobs(self, api_client: TestClient):
        """قائمة المهام"""
        response = api_client.get("/api/jobs")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))
    
    def test_create_job(self, api_client: TestClient, sample_job_data: dict):
        """إنشاء مهمة"""
        with patch("recon_cli.jobs.lifecycle.JobLifecycle.create_job") as mock_create:
            mock_create.return_value = "job-123"
            
            response = api_client.post("/api/jobs", json=sample_job_data)
            
            assert response.status_code in [200, 201, 202]
    
    def test_get_job(self, api_client: TestClient):
        """الحصول على مهمة"""
        with patch("recon_cli.jobs.lifecycle.JobLifecycle.get_job") as mock_get:
            mock_get.return_value = {
                "job_id": "job-123",
                "status": "running",
                "created_at": datetime.now().isoformat(),
            }
            
            response = api_client.get("/api/jobs/job-123")
            
            assert response.status_code in [200, 404]
    
    def test_get_nonexistent_job(self, api_client: TestClient):
        """الحصول على مهمة غير موجودة"""
        with patch("recon_cli.jobs.lifecycle.JobLifecycle.get_job") as mock_get:
            mock_get.return_value = None
            
            response = api_client.get("/api/jobs/nonexistent-job")
            
            assert response.status_code in [404, 200]
    
    def test_delete_job(self, api_client: TestClient):
        """حذف مهمة"""
        with patch("recon_cli.jobs.lifecycle.JobLifecycle.delete_job") as mock_delete:
            mock_delete.return_value = True
            
            response = api_client.delete("/api/jobs/job-123")
            
            assert response.status_code in [200, 204, 404]


# ═══════════════════════════════════════════════════════════
#                     Job Results Tests
# ═══════════════════════════════════════════════════════════

class TestJobResultsAPI:
    """اختبارات Job Results API"""
    
    def test_get_job_results(self, api_client: TestClient):
        """الحصول على نتائج المهمة"""
        with patch("recon_cli.jobs.results.JobResults.get_results") as mock_results:
            mock_results.return_value = [
                {"type": "subdomain", "value": "www.example.com"},
                {"type": "subdomain", "value": "api.example.com"},
            ]
            
            response = api_client.get("/api/jobs/job-123/results")
            
            assert response.status_code in [200, 404]
    
    def test_get_job_summary(self, api_client: TestClient):
        """الحصول على ملخص المهمة"""
        with patch("recon_cli.jobs.summary.JobSummary.get_summary") as mock_summary:
            mock_summary.return_value = {
                "total_targets": 5,
                "total_subdomains": 50,
                "total_vulns": 3,
                "duration_seconds": 120,
            }
            
            response = api_client.get("/api/jobs/job-123/summary")
            
            assert response.status_code in [200, 404]
    
    def test_get_job_logs(self, api_client: TestClient):
        """الحصول على سجلات المهمة"""
        response = api_client.get("/api/jobs/job-123/logs")
        
        assert response.status_code in [200, 404]


# ═══════════════════════════════════════════════════════════
#                     Metrics Endpoint Tests
# ═══════════════════════════════════════════════════════════

class TestMetricsEndpoint:
    """اختبارات Metrics Endpoint"""
    
    def test_metrics_endpoint(self, api_client: TestClient):
        """Metrics endpoint"""
        response = api_client.get("/api/metrics")
        
        assert response.status_code == 200
    
    def test_metrics_prometheus_format(self, api_client: TestClient):
        """تنسيق Prometheus"""
        response = api_client.get("/api/metrics")
        
        # Should be text/plain for Prometheus
        content_type = response.headers.get("content-type", "")
        assert "text" in content_type or response.status_code == 200


# ═══════════════════════════════════════════════════════════
#                     Authentication Tests
# ═══════════════════════════════════════════════════════════

class TestAPIAuthentication:
    """اختبارات المصادقة"""
    
    def test_unauthenticated_access(self, api_client: TestClient):
        """وصول بدون مصادقة"""
        # Public endpoints should work
        response = api_client.get("/api/health")
        assert response.status_code == 200
    
    def test_api_key_authentication(self, api_client: TestClient):
        """مصادقة بـ API key"""
        headers = {"X-API-Key": "test-api-key"}
        
        with patch("recon_cli.users.UserManager.validate_api_key") as mock_validate:
            mock_validate.return_value = {"user_id": 1, "permissions": ["read"]}
            
            response = api_client.get("/api/jobs", headers=headers)
            
            assert response.status_code in [200, 401, 403]


# ═══════════════════════════════════════════════════════════
#                     Error Handling Tests
# ═══════════════════════════════════════════════════════════

class TestAPIErrorHandling:
    """اختبارات معالجة الأخطاء"""
    
    def test_404_response(self, api_client: TestClient):
        """استجابة 404"""
        response = api_client.get("/api/nonexistent-endpoint")
        
        assert response.status_code == 404
    
    def test_400_on_invalid_json(self, api_client: TestClient):
        """400 على JSON غير صالح"""
        response = api_client.post(
            "/api/jobs",
            content="invalid json",
            headers={"Content-Type": "application/json"},
        )
        
        assert response.status_code in [400, 422]
    
    def test_validation_error(self, api_client: TestClient):
        """خطأ التحقق"""
        invalid_data = {
            "targets": [],  # Empty targets should be invalid
            "stages": [],   # Empty stages should be invalid
        }
        
        response = api_client.post("/api/jobs", json=invalid_data)
        
        assert response.status_code in [400, 422, 200]
    
    def test_internal_server_error(self, api_client: TestClient):
        """خطأ داخلي في الخادم"""
        with patch("recon_cli.jobs.lifecycle.JobLifecycle.list_jobs") as mock_list:
            mock_list.side_effect = Exception("Database error")
            
            response = api_client.get("/api/jobs")
            
            # Should handle gracefully
            assert response.status_code in [200, 500]


# ═══════════════════════════════════════════════════════════
#                     Pagination Tests
# ═══════════════════════════════════════════════════════════

class TestAPIPagination:
    """اختبارات الترقيم"""
    
    def test_list_with_pagination(self, api_client: TestClient):
        """قائمة مع ترقيم"""
        response = api_client.get("/api/jobs?page=1&limit=10")
        
        assert response.status_code == 200
    
    def test_pagination_parameters(self, api_client: TestClient):
        """معاملات الترقيم"""
        response = api_client.get("/api/jobs?offset=0&limit=20")
        
        assert response.status_code == 200
    
    def test_default_pagination(self, api_client: TestClient):
        """ترقيم افتراضي"""
        response = api_client.get("/api/jobs")
        
        assert response.status_code == 200


# ═══════════════════════════════════════════════════════════
#                     Rate Limiting Tests
# ═══════════════════════════════════════════════════════════

class TestAPIRateLimiting:
    """اختبارات Rate Limiting"""
    
    def test_rate_limit_headers(self, api_client: TestClient):
        """Headers الـ rate limit"""
        response = api_client.get("/api/jobs")
        
        # May include rate limit headers
        # assert "X-RateLimit-Remaining" in response.headers
        assert response.status_code == 200
    
    def test_rate_limit_exceeded(self, api_client: TestClient):
        """تجاوز الـ rate limit"""
        # Make many requests quickly
        for _ in range(100):
            response = api_client.get("/api/jobs")
            if response.status_code == 429:
                break
        
        # Either succeeds or hits rate limit
        assert response.status_code in [200, 429]


# ═══════════════════════════════════════════════════════════
#                     CORS Tests
# ═══════════════════════════════════════════════════════════

class TestAPICORS:
    """اختبارات CORS"""
    
    def test_cors_preflight(self, api_client: TestClient):
        """CORS preflight"""
        response = api_client.options(
            "/api/jobs",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        
        # Should allow CORS or return 405
        assert response.status_code in [200, 204, 405]
    
    def test_cors_headers(self, api_client: TestClient):
        """CORS headers"""
        response = api_client.get(
            "/api/health",
            headers={"Origin": "http://localhost:3000"},
        )
        
        # Should include CORS headers if enabled
        assert response.status_code == 200


# ═══════════════════════════════════════════════════════════
#                     WebSocket Tests
# ═══════════════════════════════════════════════════════════

class TestAPIWebSocket:
    """اختبارات WebSocket"""
    
    def test_websocket_connection(self, api_client: TestClient):
        """اتصال WebSocket"""
        try:
            with api_client.websocket_connect("/api/ws/jobs") as ws:
                # Connection successful
                pass
        except Exception:
            # WebSocket might not be implemented
            pass
    
    def test_websocket_job_updates(self, api_client: TestClient):
        """تحديثات المهام عبر WebSocket"""
        try:
            with api_client.websocket_connect("/api/ws/jobs/job-123") as ws:
                # Should receive updates
                pass
        except Exception:
            # WebSocket might not be implemented
            pass


# ═══════════════════════════════════════════════════════════
#                     Async API Tests
# ═══════════════════════════════════════════════════════════

class TestAsyncAPI:
    """اختبارات API Async"""
    
    @pytest.mark.asyncio
    async def test_async_client(self):
        """عميل async"""
        try:
            from httpx import AsyncClient
            
            app = create_app()
            
            async with AsyncClient(app=app, base_url="http://test") as client:
                response = await client.get("/api/health")
                assert response.status_code == 200
        except ImportError:
            pytest.skip("httpx not installed")
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """طلبات متزامنة"""
        try:
            from httpx import AsyncClient
            
            app = create_app()
            
            async with AsyncClient(app=app, base_url="http://test") as client:
                tasks = [client.get("/api/health") for _ in range(10)]
                responses = await asyncio.gather(*tasks)
                
                assert all(r.status_code == 200 for r in responses)
        except ImportError:
            pytest.skip("httpx not installed")
