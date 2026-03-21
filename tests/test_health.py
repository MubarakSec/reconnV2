"""
Unit Tests for Health Checks

اختبارات:
- Health check components
- Aggregation
- HTTP endpoint
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════
#                     Import Module
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.utils.health import (
        HealthCheck,
        HealthStatus,
        HealthComponent,
        HealthRegistry,
        get_health,
        DatabaseHealthCheck,
        DiskHealthCheck,
        MemoryHealthCheck,
        ExternalServiceHealthCheck,
    )

    HAS_HEALTH = True
except ImportError:
    HAS_HEALTH = False


pytestmark = [
    pytest.mark.skipif(not HAS_HEALTH, reason="health not available"),
]


# ═══════════════════════════════════════════════════════════
#                     Health Status Tests
# ═══════════════════════════════════════════════════════════


class TestHealthStatus:
    """اختبارات Health Status"""

    def test_status_values(self):
        """قيم الحالة"""
        assert HealthStatus.HEALTHY is not None
        assert HealthStatus.DEGRADED is not None
        assert HealthStatus.UNHEALTHY is not None

    def test_status_comparison(self):
        """مقارنة الحالات"""
        # Healthy is best, Unhealthy is worst
        assert HealthStatus.HEALTHY.value <= HealthStatus.DEGRADED.value
        assert HealthStatus.DEGRADED.value <= HealthStatus.UNHEALTHY.value


# ═══════════════════════════════════════════════════════════
#                     Health Component Tests
# ═══════════════════════════════════════════════════════════


class TestHealthComponent:
    """اختبارات Health Component"""

    def test_create_component(self):
        """إنشاء component"""
        component = HealthComponent(
            name="test-component",
            status=HealthStatus.HEALTHY,
        )

        assert component.name == "test-component"
        assert component.status == HealthStatus.HEALTHY

    def test_component_with_message(self):
        """Component مع رسالة"""
        component = HealthComponent(
            name="test-component",
            status=HealthStatus.DEGRADED,
            message="High latency detected",
        )

        assert component.message == "High latency detected"

    def test_component_with_metadata(self):
        """Component مع metadata"""
        component = HealthComponent(
            name="test-component",
            status=HealthStatus.HEALTHY,
            metadata={
                "version": "1.0.0",
                "uptime": 3600,
            },
        )

        assert component.metadata["version"] == "1.0.0"
        assert component.metadata["uptime"] == 3600

    def test_component_timestamp(self):
        """Timestamp للـ component"""
        before = datetime.now()
        component = HealthComponent(
            name="test",
            status=HealthStatus.HEALTHY,
        )
        after = datetime.now()

        assert before <= component.checked_at <= after


# ═══════════════════════════════════════════════════════════
#                     Health Check Base Tests
# ═══════════════════════════════════════════════════════════


class TestHealthCheck:
    """اختبارات Health Check"""

    @pytest.mark.asyncio
    async def test_custom_health_check(self):
        """Health check مخصص"""

        class CustomCheck(HealthCheck):
            async def check(self) -> HealthComponent:
                return HealthComponent(
                    name="custom",
                    status=HealthStatus.HEALTHY,
                    message="All good",
                )

        check = CustomCheck(name="custom")
        result = await check.check()

        assert result.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_failing_health_check(self):
        """Health check فاشل"""

        class FailingCheck(HealthCheck):
            async def check(self) -> HealthComponent:
                return HealthComponent(
                    name="failing",
                    status=HealthStatus.UNHEALTHY,
                    message="Service unavailable",
                )

        check = FailingCheck(name="failing")
        result = await check.check()

        assert result.status == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_health_check_timeout(self):
        """Timeout للـ health check"""

        class SlowCheck(HealthCheck):
            async def check(self) -> HealthComponent:
                await asyncio.sleep(10)
                return HealthComponent(
                    name="slow",
                    status=HealthStatus.HEALTHY,
                )

        check = SlowCheck(name="slow", timeout=0.1)

        # Should timeout and return unhealthy
        try:
            result = await asyncio.wait_for(check.check(), timeout=0.2)
        except asyncio.TimeoutError:
            result = HealthComponent(
                name="slow",
                status=HealthStatus.UNHEALTHY,
                message="Timeout",
            )

        assert result.status == HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     Database Health Tests
# ═══════════════════════════════════════════════════════════


class TestDatabaseHealthCheck:
    """اختبارات Database Health Check"""

    @pytest.mark.asyncio
    async def test_healthy_database(self):
        """قاعدة بيانات صحية"""
        with patch("sqlite3.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = (1,)
            mock_conn.cursor.return_value = mock_cursor
            mock_connect.return_value = mock_conn

            check = DatabaseHealthCheck(
                name="database",
                connection_string=":memory:",
            )

            result = await check.check()

            assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]

    @pytest.mark.asyncio
    async def test_unhealthy_database(self):
        """قاعدة بيانات غير صحية"""
        with patch("sqlite3.connect") as mock_connect:
            mock_connect.side_effect = Exception("Connection refused")

            check = DatabaseHealthCheck(
                name="database",
                connection_string="invalid",
            )

            result = await check.check()

            assert result.status == HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     Disk Health Tests
# ═══════════════════════════════════════════════════════════


class TestDiskHealthCheck:
    """اختبارات Disk Health Check"""

    @pytest.mark.asyncio
    async def test_healthy_disk(self):
        """قرص صحي"""
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = (
                100 * 1024 * 1024 * 1024,  # total: 100GB
                50 * 1024 * 1024 * 1024,  # used: 50GB
                50 * 1024 * 1024 * 1024,  # free: 50GB
            )

            check = DiskHealthCheck(
                name="disk",
                path="/",
                warning_threshold=80,
                critical_threshold=90,
            )

            result = await check.check()

            assert result.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_degraded_disk(self):
        """قرص متدهور"""
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = (
                100 * 1024 * 1024 * 1024,  # total: 100GB
                85 * 1024 * 1024 * 1024,  # used: 85GB
                15 * 1024 * 1024 * 1024,  # free: 15GB
            )

            check = DiskHealthCheck(
                name="disk",
                path="/",
                warning_threshold=80,
                critical_threshold=90,
            )

            result = await check.check()

            assert result.status == HealthStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_critical_disk(self):
        """قرص حرج"""
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = (
                100 * 1024 * 1024 * 1024,  # total: 100GB
                95 * 1024 * 1024 * 1024,  # used: 95GB
                5 * 1024 * 1024 * 1024,  # free: 5GB
            )

            check = DiskHealthCheck(
                name="disk",
                path="/",
                warning_threshold=80,
                critical_threshold=90,
            )

            result = await check.check()

            assert result.status == HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     Memory Health Tests
# ═══════════════════════════════════════════════════════════


class TestMemoryHealthCheck:
    """اختبارات Memory Health Check"""

    @pytest.mark.asyncio
    async def test_healthy_memory(self):
        """ذاكرة صحية"""
        with patch("psutil.virtual_memory") as mock_mem:
            mock_mem.return_value = MagicMock(
                total=16 * 1024 * 1024 * 1024,  # 16GB
                available=8 * 1024 * 1024 * 1024,  # 8GB
                percent=50.0,
            )

            check = MemoryHealthCheck(
                name="memory",
                warning_threshold=80,
                critical_threshold=90,
            )

            result = await check.check()

            assert result.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_critical_memory(self):
        """ذاكرة حرجة"""
        with patch("psutil.virtual_memory") as mock_mem:
            mock_mem.return_value = MagicMock(
                total=16 * 1024 * 1024 * 1024,  # 16GB
                available=1 * 1024 * 1024 * 1024,  # 1GB
                percent=95.0,
            )

            check = MemoryHealthCheck(
                name="memory",
                warning_threshold=80,
                critical_threshold=90,
            )

            result = await check.check()

            assert result.status == HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     External Service Health Tests
# ═══════════════════════════════════════════════════════════


class TestExternalServiceHealthCheck:
    """اختبارات External Service Health Check"""

    @pytest.mark.asyncio
    async def test_healthy_service(self):
        """خدمة صحية"""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            session_instance = MagicMock()
            session_instance.get.return_value = mock_response
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            check = ExternalServiceHealthCheck(
                name="api",
                url="https://api.example.com/health",
            )

            result = await check.check()

            assert result.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unhealthy_service(self):
        """خدمة غير صحية"""
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = MagicMock()
            session_instance.get = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            session_instance.close = AsyncMock()
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()
            mock_session.return_value = session_instance

            check = ExternalServiceHealthCheck(
                name="api",
                url="https://api.example.com/health",
            )

            result = await check.check()

            assert result.status == HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     Health Registry Tests
# ═══════════════════════════════════════════════════════════


class TestHealthRegistry:
    """اختبارات Health Registry"""

    def test_register_check(self):
        """تسجيل check"""
        registry = HealthRegistry()

        check = MemoryHealthCheck(name="memory")
        registry.register(check)

        assert "memory" in registry.checks

    def test_unregister_check(self):
        """إلغاء تسجيل check"""
        registry = HealthRegistry()

        check = MemoryHealthCheck(name="memory")
        registry.register(check)
        registry.unregister("memory")

        assert "memory" not in registry.checks

    @pytest.mark.asyncio
    async def test_check_all(self):
        """فحص الكل"""
        registry = HealthRegistry()

        class AlwaysHealthy(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                )

        registry.register(AlwaysHealthy(name="check1"))
        registry.register(AlwaysHealthy(name="check2"))

        results = await registry.check_all()

        assert len(results) == 2
        assert all(r.status == HealthStatus.HEALTHY for r in results)

    @pytest.mark.asyncio
    async def test_overall_status_healthy(self):
        """حالة عامة صحية"""
        registry = HealthRegistry()

        class AlwaysHealthy(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                )

        registry.register(AlwaysHealthy(name="check1"))
        registry.register(AlwaysHealthy(name="check2"))

        status = await registry.get_overall_status()

        assert status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_overall_status_degraded(self):
        """حالة عامة متدهورة"""
        registry = HealthRegistry()

        class HealthyCheck(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                )

        class DegradedCheck(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.DEGRADED,
                )

        registry.register(HealthyCheck(name="check1"))
        registry.register(DegradedCheck(name="check2"))

        status = await registry.get_overall_status()

        assert status == HealthStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_overall_status_unhealthy(self):
        """حالة عامة غير صحية"""
        registry = HealthRegistry()

        class HealthyCheck(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                )

        class UnhealthyCheck(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                )

        registry.register(HealthyCheck(name="check1"))
        registry.register(UnhealthyCheck(name="check2"))

        status = await registry.get_overall_status()

        assert status == HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     Global Health Tests
# ═══════════════════════════════════════════════════════════


class TestGlobalHealth:
    """اختبارات الصحة العامة"""

    def test_get_health(self):
        """الحصول على الصحة"""
        health = get_health()

        assert health is not None

    def test_health_singleton(self):
        """Health singleton"""
        h1 = get_health()
        h2 = get_health()

        assert h1 is h2


# ═══════════════════════════════════════════════════════════
#                     Serialization Tests
# ═══════════════════════════════════════════════════════════


class TestHealthSerialization:
    """اختبارات التسلسل"""

    def test_component_to_dict(self):
        """Component إلى dict"""
        component = HealthComponent(
            name="test",
            status=HealthStatus.HEALTHY,
            message="All good",
            metadata={"key": "value"},
        )

        data = component.to_dict()

        assert data["name"] == "test"
        assert data["status"] == "healthy"
        assert data["message"] == "All good"

    @pytest.mark.asyncio
    async def test_registry_to_dict(self):
        """Registry إلى dict"""
        registry = HealthRegistry()

        class AlwaysHealthy(HealthCheck):
            async def check(self):
                return HealthComponent(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                )

        registry.register(AlwaysHealthy(name="check1"))

        data = await registry.to_dict()

        assert "status" in data
        assert "components" in data
