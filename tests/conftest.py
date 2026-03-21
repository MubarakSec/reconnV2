"""
Test Fixtures & Configuration - إعدادات الاختبار

ملف conftest.py الرئيسي مع:
- Fixtures مشتركة
- مولدات البيانات
- إعدادات pytest
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Disable joblib multiprocessing in restricted test environments to avoid
# semaphore permission warnings; tests do not rely on process-based backends.
os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")

# Ensure local package imports work when running pytest without PYTHONPATH.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_testclient_compat() -> None:
    """
    Provide a stable TestClient implementation backed by httpx ASGI transport.

    In this execution environment, anyio's blocking portal can stall, which
    causes fastapi/starlette TestClient requests to hang indefinitely.
    """
    try:
        import httpx
        import fastapi.testclient as fastapi_testclient
    except Exception:
        return

    class _CompatTestClient:
        __test__ = False

        def __init__(
            self,
            app: Any,
            base_url: str = "http://testserver",
            headers: Optional[Dict[str, str]] = None,
            follow_redirects: bool = True,
            **_: Any,
        ) -> None:
            self.app = app
            self.base_url = base_url
            self.headers = dict(headers or {})
            self.follow_redirects = follow_redirects

        async def _request_async(self, method: str, url: str, **kwargs: Any) -> Any:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url=self.base_url,
                follow_redirects=self.follow_redirects,
            ) as client:
                return await client.request(method, url, **kwargs)

        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            req_headers = kwargs.pop("headers", None) or {}
            merged_headers = dict(self.headers)
            merged_headers.update(req_headers)
            kwargs["headers"] = merged_headers
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(
                    self._request_async(method, url, **kwargs)
                )
            finally:
                loop.close()

        def get(self, url: str, **kwargs: Any) -> Any:
            return self.request("GET", url, **kwargs)

        def post(self, url: str, **kwargs: Any) -> Any:
            return self.request("POST", url, **kwargs)

        def put(self, url: str, **kwargs: Any) -> Any:
            return self.request("PUT", url, **kwargs)

        def patch(self, url: str, **kwargs: Any) -> Any:
            return self.request("PATCH", url, **kwargs)

        def delete(self, url: str, **kwargs: Any) -> Any:
            return self.request("DELETE", url, **kwargs)

        def options(self, url: str, **kwargs: Any) -> Any:
            return self.request("OPTIONS", url, **kwargs)

        def websocket_connect(self, *_: Any, **__: Any) -> Any:
            raise RuntimeError("WebSocket test client is not available in compat mode")

        def close(self) -> None:
            return None

        def __enter__(self) -> "_CompatTestClient":
            return self

        def __exit__(self, *_: Any) -> None:
            self.close()

    fastapi_testclient.TestClient = _CompatTestClient


_install_testclient_compat()


# ═══════════════════════════════════════════════════════════
#                     Pytest Configuration
# ═══════════════════════════════════════════════════════════


def pytest_configure(config):
    """تكوين pytest"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "asyncio: marks tests as async")


# ═══════════════════════════════════════════════════════════
#                     Temp Directories
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """مجلد مؤقت"""
    path = Path(tempfile.mkdtemp(prefix="recon_test_"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def jobs_dir(temp_dir: Path) -> Path:
    """مجلد المهام"""
    path = temp_dir / "jobs"
    path.mkdir()
    (path / "queued").mkdir()
    (path / "running").mkdir()
    (path / "finished").mkdir()
    (path / "failed").mkdir()
    return path


@pytest.fixture
def config_dir(temp_dir: Path) -> Path:
    """مجلد الإعدادات"""
    path = temp_dir / "config"
    path.mkdir()
    return path


# ═══════════════════════════════════════════════════════════
#                     Data Factories
# ═══════════════════════════════════════════════════════════


@dataclass
class TestDataFactory:
    """مصنع بيانات الاختبار"""

    base_dir: Path = field(default_factory=lambda: Path(tempfile.gettempdir()))

    # ─────────────────────────────────────────────────────────
    #                     Targets
    # ─────────────────────────────────────────────────────────

    def create_targets(self, count: int = 5) -> List[str]:
        """إنشاء أهداف"""
        return [f"test{i}.example.com" for i in range(1, count + 1)]

    def create_targets_file(self, count: int = 5) -> Path:
        """إنشاء ملف أهداف"""
        path = self.base_dir / "targets.txt"
        targets = self.create_targets(count)
        path.write_text("\n".join(targets))
        return path

    # ─────────────────────────────────────────────────────────
    #                     Subdomains
    # ─────────────────────────────────────────────────────────

    def create_subdomains(
        self,
        domain: str = "example.com",
        count: int = 10,
    ) -> List[Dict[str, Any]]:
        """إنشاء نتائج subdomain"""
        prefixes = [
            "www",
            "api",
            "admin",
            "mail",
            "blog",
            "dev",
            "test",
            "staging",
            "app",
            "cdn",
        ]
        return [
            {
                "host": f"{prefixes[i % len(prefixes)]}{i // len(prefixes) or ''}.{domain}",
                "source": "test",
                "timestamp": datetime.now().isoformat(),
            }
            for i in range(count)
        ]

    def create_subdomains_file(
        self,
        domain: str = "example.com",
        count: int = 10,
    ) -> Path:
        """إنشاء ملف subdomains"""
        path = self.base_dir / "subdomains.json"
        subs = self.create_subdomains(domain, count)
        with open(path, "w") as f:
            for sub in subs:
                f.write(json.dumps(sub) + "\n")
        return path

    # ─────────────────────────────────────────────────────────
    #                     HTTP Responses
    # ─────────────────────────────────────────────────────────

    def create_http_responses(self, count: int = 10) -> List[Dict[str, Any]]:
        """إنشاء استجابات HTTP"""
        return [
            {
                "url": f"https://test{i}.example.com/",
                "status_code": 200 if i % 3 != 0 else 404,
                "content_length": 1000 + i * 100,
                "title": f"Test Page {i}",
                "technologies": ["nginx", "react"] if i % 2 == 0 else ["apache", "php"],
            }
            for i in range(count)
        ]

    # ─────────────────────────────────────────────────────────
    #                     Vulnerabilities
    # ─────────────────────────────────────────────────────────

    def create_vulnerabilities(self, count: int = 5) -> List[Dict[str, Any]]:
        """إنشاء ثغرات"""
        severities = ["critical", "high", "medium", "low", "info"]
        templates = [
            "CVE-2021-44228",
            "CVE-2023-1234",
            "xss-reflected",
            "sqli-error-based",
            "open-redirect",
        ]

        return [
            {
                "template_id": templates[i % len(templates)],
                "host": f"https://vuln{i}.example.com",
                "severity": severities[i % len(severities)],
                "name": f"Test Vulnerability {i}",
                "description": f"Test vulnerability description {i}",
                "matched_at": f"https://vuln{i}.example.com/path",
                "extracted_results": ["test_result"],
            }
            for i in range(count)
        ]

    # ─────────────────────────────────────────────────────────
    #                     Secrets
    # ─────────────────────────────────────────────────────────

    def create_secrets(self, count: int = 3) -> List[Dict[str, Any]]:
        """إنشاء أسرار"""
        types = ["aws_access_key", "github_token", "api_key"]

        return [
            {
                "type": types[i % len(types)],
                "file": f"/path/to/file{i}.js",
                "line": 10 + i,
                "secret": "REDACTED",
                "entropy": 4.5 + i * 0.1,
            }
            for i in range(count)
        ]

    # ─────────────────────────────────────────────────────────
    #                     Job Specs
    # ─────────────────────────────────────────────────────────

    def create_job_spec(
        self,
        targets: Optional[List[str]] = None,
        stages: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """إنشاء مواصفات مهمة"""
        return {
            "targets": targets or self.create_targets(3),
            "stages": stages or ["subdomain-enum", "port-scan", "vuln-scan"],
            "options": {
                "concurrency": 10,
                "timeout": 300,
                "rate_limit": 50,
            },
            "notify": {
                "on_complete": True,
                "on_error": True,
            },
        }

    def create_job_dir(self, job_id: str = "test_job") -> Path:
        """إنشاء مجلد مهمة"""
        path = self.base_dir / "jobs" / job_id
        path.mkdir(parents=True, exist_ok=True)

        # Create spec
        spec = self.create_job_spec()
        (path / "spec.json").write_text(json.dumps(spec))

        # Create metadata
        metadata = {
            "job_id": job_id,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
        }
        (path / "metadata.json").write_text(json.dumps(metadata))

        return path

    # ─────────────────────────────────────────────────────────
    #                     Results
    # ─────────────────────────────────────────────────────────

    def create_scan_results(self) -> Dict[str, Any]:
        """إنشاء نتائج فحص كاملة"""
        return {
            "subdomains": self.create_subdomains(),
            "http_responses": self.create_http_responses(),
            "vulnerabilities": self.create_vulnerabilities(),
            "secrets": self.create_secrets(),
            "stats": {
                "total_targets": 5,
                "total_subdomains": 10,
                "total_vulns": 5,
                "duration_seconds": 120.5,
            },
        }

    def create_results_file(self) -> Path:
        """إنشاء ملف نتائج JSONL"""
        path = self.base_dir / "results.jsonl"

        results = []
        results.extend(self.create_subdomains(count=5))
        results.extend(self.create_http_responses(count=5))
        results.extend(self.create_vulnerabilities(count=3))

        with open(path, "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")

        return path


@pytest.fixture
def data_factory(temp_dir: Path) -> TestDataFactory:
    """مصنع البيانات"""
    factory = TestDataFactory(base_dir=temp_dir)
    return factory


# ═══════════════════════════════════════════════════════════
#                     Mock Factories
# ═══════════════════════════════════════════════════════════


@dataclass
class MockFactory:
    """مصنع الـ Mocks"""

    def create_http_response(
        self,
        status: int = 200,
        text: str = "OK",
        json_data: Optional[Dict] = None,
    ) -> MagicMock:
        """إنشاء response mock"""
        response = MagicMock()
        response.status = status
        response.status_code = status
        response.text = AsyncMock(return_value=text)
        response.json = AsyncMock(return_value=json_data or {})
        response.read = AsyncMock(return_value=text.encode())
        response.headers = {"content-type": "application/json"}
        return response

    def create_subprocess_result(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> MagicMock:
        """إنشاء subprocess result"""
        result = MagicMock()
        result.returncode = returncode
        result.stdout = stdout.encode()
        result.stderr = stderr.encode()
        return result

    def create_async_subprocess(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> MagicMock:
        """إنشاء async subprocess"""
        process = MagicMock()
        process.returncode = returncode
        process.communicate = AsyncMock(return_value=(stdout.encode(), stderr.encode()))
        process.wait = AsyncMock(return_value=returncode)
        return process

    def create_tool_executor(self) -> MagicMock:
        """إنشاء tool executor mock"""
        executor = MagicMock()
        executor.run = AsyncMock(
            return_value={
                "success": True,
                "output": "test output",
                "results": [],
            }
        )
        return executor

    def create_http_client(self) -> MagicMock:
        """إنشاء HTTP client mock"""
        client = MagicMock()
        client.get = AsyncMock(return_value=self.create_http_response())
        client.post = AsyncMock(return_value=self.create_http_response())
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        return client


@pytest.fixture
def mock_factory() -> MockFactory:
    """مصنع الـ Mocks"""
    return MockFactory()


# ═══════════════════════════════════════════════════════════
#                     Tool Mocks
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def mock_subfinder(data_factory: TestDataFactory):
    """Mock subfinder"""
    subs = data_factory.create_subdomains()
    output = "\n".join(s["host"] for s in subs)

    with patch("asyncio.create_subprocess_exec") as mock:
        process = MagicMock()
        process.returncode = 0
        process.communicate = AsyncMock(return_value=(output.encode(), b""))
        mock.return_value = process
        yield mock


@pytest.fixture
def mock_httpx(data_factory: TestDataFactory):
    """Mock httpx-toolkit"""
    responses = data_factory.create_http_responses()
    output = "\n".join(json.dumps(r) for r in responses)

    with patch("asyncio.create_subprocess_exec") as mock:
        process = MagicMock()
        process.returncode = 0
        process.communicate = AsyncMock(return_value=(output.encode(), b""))
        mock.return_value = process
        yield mock


@pytest.fixture
def mock_nuclei(data_factory: TestDataFactory):
    """Mock nuclei"""
    vulns = data_factory.create_vulnerabilities()
    output = "\n".join(json.dumps(v) for v in vulns)

    with patch("asyncio.create_subprocess_exec") as mock:
        process = MagicMock()
        process.returncode = 0
        process.communicate = AsyncMock(return_value=(output.encode(), b""))
        mock.return_value = process
        yield mock


# ═══════════════════════════════════════════════════════════
#                     Environment
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def clean_env():
    """بيئة نظيفة"""
    original = os.environ.copy()

    # Remove RECON_ prefixed vars
    for key in list(os.environ.keys()):
        if key.startswith("RECON_"):
            del os.environ[key]

    yield

    # Restore
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def test_env(temp_dir: Path):
    """بيئة اختبار"""
    original = os.environ.copy()

    os.environ["RECON_JOBS_DIR"] = str(temp_dir / "jobs")
    os.environ["RECON_CONFIG_DIR"] = str(temp_dir / "config")
    os.environ["RECON_LOG_LEVEL"] = "DEBUG"
    os.environ["RECON_CONCURRENCY"] = "5"

    yield

    os.environ.clear()
    os.environ.update(original)


# ═══════════════════════════════════════════════════════════
#                     Async Helpers
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def async_timeout():
    """Timeout للاختبارات الـ async"""
    return 10.0


async def run_with_timeout(coro, timeout: float = 10.0):
    """تشغيل coroutine مع timeout"""
    return await asyncio.wait_for(coro, timeout=timeout)


# ═══════════════════════════════════════════════════════════
#                     Database
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def temp_db(temp_dir: Path) -> Path:
    """قاعدة بيانات مؤقتة"""
    db_path = temp_dir / "test.db"
    return db_path


@pytest.fixture
def memory_db() -> str:
    """قاعدة بيانات في الذاكرة"""
    return ":memory:"


# ═══════════════════════════════════════════════════════════
#                     API Testing
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def api_client():
    """عميل API للاختبار"""
    try:
        from fastapi.testclient import TestClient
        from recon_cli.api.app import create_app

        app = create_app()
        return TestClient(app)
    except ImportError:
        pytest.skip("FastAPI not installed")


@pytest.fixture
def async_api_client():
    """عميل API async"""
    try:
        from httpx import AsyncClient
        from recon_cli.api.app import create_app

        app = create_app()
        return AsyncClient(app=app, base_url="http://test")
    except ImportError:
        pytest.skip("httpx not installed")


# ═══════════════════════════════════════════════════════════
#                     Assertions
# ═══════════════════════════════════════════════════════════


class Assertions:
    """تأكيدات مخصصة"""

    @staticmethod
    def assert_valid_subdomain(data: Dict[str, Any]) -> None:
        """تأكيد صحة subdomain"""
        assert "host" in data
        assert "." in data["host"]

    @staticmethod
    def assert_valid_vulnerability(data: Dict[str, Any]) -> None:
        """تأكيد صحة vulnerability"""
        assert "severity" in data
        assert data["severity"] in ["critical", "high", "medium", "low", "info"]

    @staticmethod
    def assert_valid_job(data: Dict[str, Any]) -> None:
        """تأكيد صحة job"""
        assert "job_id" in data or "id" in data
        assert "status" in data

    @staticmethod
    def assert_file_contains(path: Path, text: str) -> None:
        """تأكيد احتواء ملف على نص"""
        content = path.read_text()
        assert text in content, f"'{text}' not found in {path}"

    @staticmethod
    def assert_json_file(path: Path) -> Dict:
        """تأكيد صحة ملف JSON"""
        content = path.read_text()
        data = json.loads(content)
        return data


@pytest.fixture
def assertions() -> Assertions:
    """التأكيدات"""
    return Assertions()


# ═══════════════════════════════════════════════════════════
#                     Performance
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def performance_threshold():
    """عتبات الأداء"""
    return {
        "max_response_time_ms": 1000,
        "max_memory_mb": 500,
        "min_throughput_rps": 10,
    }


class PerformanceTimer:
    """مؤقت الأداء"""

    def __init__(self):
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        import time

        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args):
        import time

        self.end_time = time.perf_counter()

    @property
    def elapsed_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0


@pytest.fixture
def timer() -> PerformanceTimer:
    """مؤقت الأداء"""
    return PerformanceTimer()
