"""
Health & Status API - واجهة الصحة والحالة

Endpoints للمراقبة والمقاييس.

Example:
    >>> from fastapi import FastAPI
    >>> from recon_cli.utils.health import create_health_router
    >>>
    >>> app = FastAPI()
    >>> app.include_router(create_health_router())
"""

from __future__ import annotations

import asyncio
import inspect
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

try:
    from fastapi import APIRouter, Response
    from fastapi.responses import PlainTextResponse

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


# ═══════════════════════════════════════════════════════════
#                     Health Check Types
# ═══════════════════════════════════════════════════════════


class HealthStatus(IntEnum):
    """حالة الصحة"""

    HEALTHY = 0
    DEGRADED = 1
    UNHEALTHY = 2


def _status_name(status: "HealthStatus") -> str:
    return status.name.lower()


@dataclass
class HealthCheck:
    """فحص صحة"""

    name: str
    status: HealthStatus = HealthStatus.HEALTHY
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=datetime.now)
    timeout: float = 5.0
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.metadata and not self.details:
            self.details = dict(self.metadata)
        elif self.details and not self.metadata:
            self.metadata = dict(self.details)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": _status_name(self.status),
            "message": self.message,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "details": self.details,
            "checked_at": self.checked_at.isoformat(),
        }

    async def check(self) -> "HealthCheck":
        return self


@dataclass
class HealthReport:
    """تقرير الصحة"""

    status: HealthStatus = HealthStatus.HEALTHY
    checks: List[HealthCheck] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    version: str = ""
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": _status_name(self.status),
            "checks": [c.to_dict() for c in self.checks],
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
        }


# ═══════════════════════════════════════════════════════════
#                     Health Checker
# ═══════════════════════════════════════════════════════════


class HealthChecker:
    """
    مُفحص الصحة.

    Example:
        >>> checker = HealthChecker()
        >>> checker.add_check("database", check_database)
        >>> checker.add_check("redis", check_redis)
        >>> report = await checker.check()
    """

    def __init__(self, version: str = "1.0.0"):
        self.version = version
        self._start_time = time.time()
        self._checks: Dict[str, Callable] = {}

    def add_check(
        self,
        name: str,
        check_func: Callable[[], HealthCheck],
    ) -> None:
        """إضافة فحص"""
        self._checks[name] = check_func

    def remove_check(self, name: str) -> bool:
        """إزالة فحص"""
        if name in self._checks:
            del self._checks[name]
            return True
        return False

    async def check(self) -> HealthReport:
        """تشغيل جميع الفحوصات"""
        checks = []
        overall_status = HealthStatus.HEALTHY

        for name, check_func in self._checks.items():
            start = time.perf_counter()

            try:
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()

                if not isinstance(result, HealthCheck):
                    result = HealthCheck(
                        name=name,
                        status=HealthStatus.HEALTHY
                        if result
                        else HealthStatus.UNHEALTHY,
                    )

                result.duration_ms = (time.perf_counter() - start) * 1000

            except Exception as e:
                result = HealthCheck(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=str(e),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            checks.append(result)

            # Update overall status
            if result.status == HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.UNHEALTHY
            elif (
                result.status == HealthStatus.DEGRADED
                and overall_status == HealthStatus.HEALTHY
            ):
                overall_status = HealthStatus.DEGRADED

        return HealthReport(
            status=overall_status,
            checks=checks,
            version=self.version,
            uptime_seconds=time.time() - self._start_time,
        )

    async def check_liveness(self) -> bool:
        """فحص الحياة البسيط"""
        return True

    async def check_readiness(self) -> bool:
        """فحص الجاهزية"""
        report = await self.check()
        return report.status != HealthStatus.UNHEALTHY


# ═══════════════════════════════════════════════════════════
#                     Default Checks
# ═══════════════════════════════════════════════════════════


def check_disk_space(
    path: str = "/",
    warning_threshold: float = 0.8,
    critical_threshold: float = 0.95,
) -> HealthCheck:
    """فحص مساحة القرص"""
    try:
        import shutil

        total, used, free = shutil.disk_usage(path)
        usage_ratio = used / total

        if usage_ratio >= critical_threshold:
            status = HealthStatus.UNHEALTHY
            message = f"Disk usage critical: {usage_ratio * 100:.1f}%"
        elif usage_ratio >= warning_threshold:
            status = HealthStatus.DEGRADED
            message = f"Disk usage warning: {usage_ratio * 100:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"Disk usage: {usage_ratio * 100:.1f}%"

        return HealthCheck(
            name="disk_space",
            status=status,
            message=message,
            details={
                "total_gb": total / (1024**3),
                "used_gb": used / (1024**3),
                "free_gb": free / (1024**3),
                "usage_percent": usage_ratio * 100,
            },
        )

    except Exception as e:
        return HealthCheck(
            name="disk_space",
            status=HealthStatus.UNHEALTHY,
            message=str(e),
        )


def check_memory(
    warning_threshold: float = 0.8,
    critical_threshold: float = 0.95,
) -> HealthCheck:
    """فحص الذاكرة"""
    try:
        import psutil

        memory = psutil.virtual_memory()
        usage_ratio = memory.percent / 100

        if usage_ratio >= critical_threshold:
            status = HealthStatus.UNHEALTHY
            message = f"Memory usage critical: {usage_ratio * 100:.1f}%"
        elif usage_ratio >= warning_threshold:
            status = HealthStatus.DEGRADED
            message = f"Memory usage warning: {usage_ratio * 100:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"Memory usage: {usage_ratio * 100:.1f}%"

        return HealthCheck(
            name="memory",
            status=status,
            message=message,
            details={
                "total_gb": memory.total / (1024**3),
                "available_gb": memory.available / (1024**3),
                "usage_percent": memory.percent,
            },
        )

    except ImportError:
        return HealthCheck(
            name="memory",
            status=HealthStatus.DEGRADED,
            message="psutil not installed",
        )
    except Exception as e:
        return HealthCheck(
            name="memory",
            status=HealthStatus.UNHEALTHY,
            message=str(e),
        )


def check_cpu(
    warning_threshold: float = 0.8,
    critical_threshold: float = 0.95,
) -> HealthCheck:
    """فحص CPU"""
    try:
        import psutil

        cpu_percent = psutil.cpu_percent(interval=0.1) / 100

        if cpu_percent >= critical_threshold:
            status = HealthStatus.UNHEALTHY
            message = f"CPU usage critical: {cpu_percent * 100:.1f}%"
        elif cpu_percent >= warning_threshold:
            status = HealthStatus.DEGRADED
            message = f"CPU usage warning: {cpu_percent * 100:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"CPU usage: {cpu_percent * 100:.1f}%"

        return HealthCheck(
            name="cpu",
            status=status,
            message=message,
            details={
                "usage_percent": cpu_percent * 100,
                "cpu_count": psutil.cpu_count(),
                "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
            },
        )

    except ImportError:
        return HealthCheck(
            name="cpu",
            status=HealthStatus.DEGRADED,
            message="psutil not installed",
        )
    except Exception as e:
        return HealthCheck(
            name="cpu",
            status=HealthStatus.UNHEALTHY,
            message=str(e),
        )


# ═══════════════════════════════════════════════════════════
#                     FastAPI Router
# ═══════════════════════════════════════════════════════════


def create_health_router(
    checker: Optional[HealthChecker] = None,
    prefix: str = "",
) -> "APIRouter":
    """
    إنشاء router للصحة.

    Args:
        checker: مُفحص الصحة
        prefix: بادئة المسار

    Returns:
        FastAPI APIRouter
    """
    if not HAS_FASTAPI:
        raise ImportError("FastAPI is required for health router")

    router = APIRouter(prefix=prefix, tags=["Health"])

    if checker is None:
        checker = HealthChecker()
        checker.add_check("disk", check_disk_space)
        checker.add_check("memory", check_memory)
        checker.add_check("cpu", check_cpu)

    @router.get("/health")
    async def health():
        """Full health check"""
        report = await checker.check()
        return report.to_dict()

    @router.get("/health/live")
    async def liveness():
        """Kubernetes liveness probe"""
        alive = await checker.check_liveness()
        if alive:
            return {"status": "alive"}
        return Response(status_code=503, content='{"status": "dead"}')

    @router.get("/health/ready")
    async def readiness():
        """Kubernetes readiness probe"""
        ready = await checker.check_readiness()
        if ready:
            return {"status": "ready"}
        return Response(status_code=503, content='{"status": "not ready"}')

    @router.get("/version")
    async def version():
        """Version information"""
        return {
            "version": checker.version,
            "python": sys.version,
            "platform": platform.platform(),
        }

    return router


# ═══════════════════════════════════════════════════════════
#                     Metrics Router
# ═══════════════════════════════════════════════════════════


def create_metrics_router(prefix: str = "") -> "APIRouter":
    """
    إنشاء router للمقاييس.

    Returns:
        FastAPI APIRouter
    """
    if not HAS_FASTAPI:
        raise ImportError("FastAPI is required for metrics router")

    router = APIRouter(prefix=prefix, tags=["Metrics"])

    @router.get("/metrics", response_class=PlainTextResponse)
    async def metrics():
        """Prometheus metrics endpoint"""
        try:
            from recon_cli.utils.metrics import metrics as m

            return m.export()
        except ImportError:
            return "# Metrics not available\n"

    @router.get("/metrics/json")
    async def metrics_json():
        """JSON metrics endpoint"""
        try:
            from recon_cli.utils.metrics import metrics as m

            return m.export_json()
        except ImportError:
            return {"error": "Metrics not available"}

    @router.get("/stats")
    async def stats():
        """Application statistics"""
        try:
            from recon_cli.utils.metrics import metrics as m

            return {
                "jobs": {
                    "total": m.jobs_total.get(),
                    "active": m.jobs_active.get(),
                },
                "scans": {
                    "total": m.scans_total.get(),
                    "targets": m.targets_scanned.get(),
                },
                "findings": {
                    "total": m.findings_total.get(),
                    "subdomains": m.subdomains_discovered.get(),
                },
            }
        except ImportError:
            return {"error": "Metrics not available"}

    return router


# ═══════════════════════════════════════════════════════════
#                     Status Dashboard Data
# ═══════════════════════════════════════════════════════════


@dataclass
class SystemStatus:
    """حالة النظام"""

    health: HealthStatus = HealthStatus.HEALTHY
    uptime_seconds: float = 0.0

    # Jobs
    active_jobs: int = 0
    queued_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0

    # Scans
    scans_today: int = 0
    findings_today: int = 0

    # Resources
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0

    # Errors
    recent_errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "health": self.health.value,
            "uptime_seconds": self.uptime_seconds,
            "jobs": {
                "active": self.active_jobs,
                "queued": self.queued_jobs,
                "completed": self.completed_jobs,
                "failed": self.failed_jobs,
            },
            "scans": {
                "today": self.scans_today,
                "findings_today": self.findings_today,
            },
            "resources": {
                "cpu_percent": self.cpu_percent,
                "memory_percent": self.memory_percent,
                "disk_percent": self.disk_percent,
            },
            "errors": {
                "recent": self.recent_errors,
            },
        }


async def get_system_status(checker: HealthChecker) -> SystemStatus:
    """الحصول على حالة النظام"""
    report = await checker.check()

    status = SystemStatus(
        health=report.status,
        uptime_seconds=report.uptime_seconds,
    )

    # Extract from checks
    for check in report.checks:
        if check.name == "cpu":
            status.cpu_percent = check.details.get("usage_percent", 0)
        elif check.name == "memory":
            status.memory_percent = check.details.get("usage_percent", 0)
        elif check.name == "disk":
            status.disk_percent = check.details.get("usage_percent", 0)

    # Get metrics if available
    try:
        from recon_cli.utils.metrics import metrics as m

        status.active_jobs = int(m.jobs_active.get())
        status.completed_jobs = int(m.jobs_total.labels(status="completed").get())
        status.failed_jobs = int(m.jobs_total.labels(status="failed").get())
        status.scans_today = int(m.scans_total.get())
        status.findings_today = int(m.findings_total.get())
    except ImportError:
        pass

    return status


# Backward-compatible API used by unit tests.
HealthComponent = HealthCheck


class DatabaseHealthCheck(HealthCheck):
    def __init__(
        self, name: str, connection_string: str = ":memory:", timeout: float = 1.0
    ):
        super().__init__(name=name)
        self.connection_string = connection_string
        self.timeout = timeout

    async def check(self) -> HealthComponent:
        start = time.perf_counter()
        try:
            import sqlite3

            conn = sqlite3.connect(self.connection_string)
            try:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            finally:
                conn.close()
            status = HealthStatus.HEALTHY
            message = "Database reachable"
        except Exception as exc:
            status = HealthStatus.UNHEALTHY
            message = str(exc)
        return HealthComponent(
            name=self.name,
            status=status,
            message=message,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


class DiskHealthCheck(HealthCheck):
    def __init__(
        self,
        name: str,
        path: str = "/",
        warning_threshold: float = 80.0,
        critical_threshold: float = 90.0,
    ):
        super().__init__(name=name)
        self.path = path
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold

    async def check(self) -> HealthComponent:
        start = time.perf_counter()
        try:
            import shutil

            total, used, free = shutil.disk_usage(self.path)
            usage_percent = (used / total) * 100 if total else 0.0
            if usage_percent >= self.critical_threshold:
                status = HealthStatus.UNHEALTHY
            elif usage_percent >= self.warning_threshold:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
            message = f"Disk usage: {usage_percent:.1f}%"
            metadata = {
                "total": total,
                "used": used,
                "free": free,
                "usage_percent": usage_percent,
            }
        except Exception as exc:
            status = HealthStatus.UNHEALTHY
            message = str(exc)
            metadata = {}
        return HealthComponent(
            name=self.name,
            status=status,
            message=message,
            metadata=metadata,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


class MemoryHealthCheck(HealthCheck):
    def __init__(
        self,
        name: str,
        warning_threshold: float = 80.0,
        critical_threshold: float = 90.0,
    ):
        super().__init__(name=name)
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold

    async def check(self) -> HealthComponent:
        start = time.perf_counter()
        try:
            import psutil

            memory = psutil.virtual_memory()
            usage_percent = float(getattr(memory, "percent", 0.0))
            if usage_percent >= self.critical_threshold:
                status = HealthStatus.UNHEALTHY
            elif usage_percent >= self.warning_threshold:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
            message = f"Memory usage: {usage_percent:.1f}%"
            metadata = {
                "total": getattr(memory, "total", 0),
                "available": getattr(memory, "available", 0),
                "usage_percent": usage_percent,
            }
        except ImportError:
            status = HealthStatus.DEGRADED
            message = "psutil not installed"
            metadata = {}
        except Exception as exc:
            status = HealthStatus.UNHEALTHY
            message = str(exc)
            metadata = {}
        return HealthComponent(
            name=self.name,
            status=status,
            message=message,
            metadata=metadata,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


class ExternalServiceHealthCheck(HealthCheck):
    def __init__(self, name: str, url: str, timeout: float = 5.0):
        super().__init__(name=name)
        self.url = url
        self.timeout = timeout

    async def check(self) -> HealthComponent:
        start = time.perf_counter()
        status = HealthStatus.UNHEALTHY
        message = "Service check failed"
        metadata = {"url": self.url}
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                req = session.get(self.url, timeout=self.timeout)
                if inspect.isawaitable(req):
                    req = await req
                async with req as resp:
                    status = (
                        HealthStatus.HEALTHY
                        if resp.status < 400
                        else HealthStatus.UNHEALTHY
                    )
                    message = f"HTTP {resp.status}"
        except ImportError:
            status = HealthStatus.DEGRADED
            message = "aiohttp not installed"
        except Exception as exc:
            status = HealthStatus.UNHEALTHY
            message = str(exc)
        return HealthComponent(
            name=self.name,
            status=status,
            message=message,
            metadata=metadata,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


class HealthRegistry:
    def __init__(self):
        self.checks: Dict[str, HealthCheck] = {}

    def register(self, check: HealthCheck) -> None:
        self.checks[check.name] = check

    def unregister(self, name: str) -> bool:
        return self.checks.pop(name, None) is not None

    async def check_all(self) -> List[HealthComponent]:
        results: List[HealthComponent] = []
        for check in self.checks.values():
            results.append(await check.check())
        return results

    async def get_overall_status(self) -> HealthStatus:
        results = await self.check_all()
        if any(item.status == HealthStatus.UNHEALTHY for item in results):
            return HealthStatus.UNHEALTHY
        if any(item.status == HealthStatus.DEGRADED for item in results):
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY

    async def to_dict(self) -> Dict[str, Any]:
        results = await self.check_all()
        status = await self.get_overall_status()
        return {
            "status": _status_name(status),
            "components": [item.to_dict() for item in results],
        }


_HEALTH_REGISTRY: Optional[HealthRegistry] = None


def get_health() -> HealthRegistry:
    global _HEALTH_REGISTRY
    if _HEALTH_REGISTRY is None:
        _HEALTH_REGISTRY = HealthRegistry()
    return _HEALTH_REGISTRY
