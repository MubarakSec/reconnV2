"""
ReconnV2 REST API - FastAPI Application
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Header
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse, Response
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None
    BaseModel = object

from recon_cli import config
from recon_cli.jobs.manager import JobManager
from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.jobs.results import JobResults
from recon_cli.jobs.summary import JobSummary
from recon_cli.utils.metrics import metrics as metrics_registry
from recon_cli.utils import validation
from recon_cli.utils.jsonl import read_jsonl


class _JobsBaseProxy:
    def __init__(self, path: Path) -> None:
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_mocked_class", None)

    def __getattr__(self, name: str):
        return getattr(self._path, name)

    def __fspath__(self) -> str:
        return str(self._path)

    def __str__(self) -> str:
        return str(self._path)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._path!s})"

    def __truediv__(self, other: object) -> Path:
        return self._path / other  # type: ignore[operator]

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"_path", "_mocked_class"}:
            object.__setattr__(self, name, value)
            return
        if name == "__class__":
            object.__setattr__(self, "_mocked_class", value)
            return
        setattr(self._path, name, value)

    def __delattr__(self, name: str) -> None:
        if name == "__class__":
            object.__setattr__(self, "_mocked_class", None)
            return
        delattr(self._path, name)


JOBS_BASE = _JobsBaseProxy(config.JOBS_ROOT)


def _patch_httpx_asyncclient() -> None:
    try:
        import inspect
        import httpx
    except Exception:
        return
    try:
        sig = inspect.signature(httpx.AsyncClient.__init__)
    except (TypeError, ValueError):
        return
    if "app" in sig.parameters:
        return
    original_init = httpx.AsyncClient.__init__

    def _init(self, *args, app=None, base_url=None, **kwargs):
        if app is not None and "transport" not in kwargs:
            try:
                from httpx import ASGITransport
                kwargs["transport"] = ASGITransport(app=app)
            except Exception:
                pass
        if base_url is not None and "base_url" not in kwargs:
            kwargs["base_url"] = base_url
        return original_init(self, *args, **kwargs)

    httpx.AsyncClient.__init__ = _init


_patch_httpx_asyncclient()


# ═══════════════════════════════════════════════════════════
#                     Pydantic Models
# ═══════════════════════════════════════════════════════════

if FASTAPI_AVAILABLE:
    class ScanRequest(BaseModel):
        """طلب فحص جديد"""
        target: str = Field("", description="الهدف (domain أو IP)")
        profile: str = Field("passive", description="الملف الشخصي")
        inline: bool = Field(False, description="تشغيل فوري")
        scanners: List[str] = Field(default_factory=list, description="الماسحات")
        active_modules: List[str] = Field(default_factory=list, description="الوحدات النشطة")
        force: bool = Field(False, description="إعادة تشغيل كل المراحل")
        allow_ip: bool = Field(False, description="السماح بـ IP")

    class JobCreateRequest(BaseModel):
        """طلب إنشاء مهمة"""
        targets: List[str] = Field(default_factory=list, description="الأهداف")
        stages: List[str] = Field(default_factory=list, description="المراحل")
        options: Dict[str, Any] = Field(default_factory=dict, description="خيارات")

    class JobResponse(BaseModel):
        """استجابة معلومات المهمة"""
        job_id: str
        status: str
        target: Optional[str] = None
        profile: Optional[str] = None
        stage: Optional[str] = None
        queued_at: Optional[str] = None
        started_at: Optional[str] = None
        finished_at: Optional[str] = None
        error: Optional[str] = None
        stats: Dict[str, Any] = Field(default_factory=dict)

    class JobListResponse(BaseModel):
        """قائمة المهام"""
        jobs: List[JobResponse]
        total: int

    class ResultItem(BaseModel):
        """عنصر نتيجة"""
        type: str
        data: Dict[str, Any]

    class StatsResponse(BaseModel):
        """إحصائيات النظام"""
        queued: int
        running: int
        finished: int
        failed: int
        total: int
        queued_jobs: int
        running_jobs: int
        finished_jobs: int
        failed_jobs: int
        total_jobs: int

    class APIStatus(BaseModel):
        """حالة الـ API"""
        status: str
        version: str
        uptime: str


# ═══════════════════════════════════════════════════════════
#                     API Application
# ═══════════════════════════════════════════════════════════

def create_app() -> "FastAPI":
    """إنشاء تطبيق FastAPI"""
    
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not installed. Run: pip install fastapi uvicorn")
    
    app = FastAPI(
        title="ReconnV2 API",
        description="واجهة برمجة تطبيقات للتحكم في أداة الاستطلاع الأمني",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    
    # CORS - Restricted to localhost for security
    # For production, add your domain to allow_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # حالة التطبيق
    app.state.start_time = datetime.now()
    app.state.manager = JobManager()

    async def _maybe_authenticate(x_api_key: Optional[str]) -> Optional[Dict[str, Any]]:
        if not x_api_key:
            return None
        try:
            from recon_cli.users import UserManager
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Authentication unavailable") from exc
        user_manager = UserManager(str(config.RECON_HOME / "users.db"))
        validated = user_manager.validate_api_key(x_api_key)
        if not validated:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return validated
    
    # ───────────────────────────────────────────────────────
    #                      Endpoints
    # ───────────────────────────────────────────────────────
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """الصفحة الرئيسية"""
        return """
        <html>
            <head>
                <title>ReconnV2 API</title>
                <style>
                    body { 
                        font-family: Arial; 
                        background: #1a1a2e; 
                        color: #eee; 
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container { text-align: center; }
                    h1 { color: #e94560; }
                    a { color: #0f3460; background: #eee; padding: 10px 20px; 
                        border-radius: 5px; text-decoration: none; margin: 5px; }
                    a:hover { background: #e94560; color: white; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔍 ReconnV2 API</h1>
                    <p>Advanced Reconnaissance Pipeline</p>
                    <br>
                    <a href="/docs">📚 Documentation</a>
                    <a href="/api/status">📊 Status</a>
                    <a href="/api/jobs">📋 Jobs</a>
                </div>
            </body>
        </html>
        """
    
    @app.get("/api/status", response_model=APIStatus)
    async def get_status():
        """حالة الـ API"""
        uptime = datetime.now() - app.state.start_time
        return APIStatus(
            status="ok",
            version="0.1.0",
            uptime=str(uptime).split('.')[0]
        )
    
    @app.get("/api/health")
    async def health_check():
        """
        Health check endpoint للتحقق من صحة الخدمة.
        
        يُستخدم من قبل:
        - Load balancers
        - Kubernetes probes
        - Monitoring systems
        
        Returns:
            dict: حالة الخدمة وتفاصيلها
        """
        import sys
        import platform
        
        # Check critical components
        checks = {
            "api": "healthy",
            "jobs_dir": "healthy" if config.RECON_HOME.exists() else "unhealthy",
            "queued_dir": "healthy" if config.QUEUED_JOBS.exists() else "unhealthy",
        }
        
        overall = "healthy" if all(v == "healthy" for v in checks.values()) else "unhealthy"
        
        return {
            "status": overall,
            "checks": checks,
            "timestamp": datetime.now().isoformat(),
            "python_version": sys.version.split()[0],
            "platform": platform.system(),
        }
    
    @app.get("/api/version")
    async def get_version():
        """
        معلومات الإصدار.
        
        Returns:
            dict: رقم الإصدار ومعلومات البناء
        """
        return {
            "version": "0.1.0",
            "api_version": "v1",
            "name": "ReconnV2",
            "description": "Advanced Security Reconnaissance Pipeline",
            "build_date": "2026-02-01",
            "python_required": ">=3.10",
            "docs_url": "/docs",
        }

    @app.get("/api/stats", response_model=StatsResponse)
    async def get_stats():
        """إحصائيات النظام"""
        queued = len(list(config.QUEUED_JOBS.glob("*"))) if config.QUEUED_JOBS.exists() else 0
        running = len(list(config.RUNNING_JOBS.glob("*"))) if config.RUNNING_JOBS.exists() else 0
        finished = len(list(config.FINISHED_JOBS.glob("*"))) if config.FINISHED_JOBS.exists() else 0
        failed = len(list(config.FAILED_JOBS.glob("*"))) if config.FAILED_JOBS.exists() else 0
        
        return StatsResponse(
            queued=queued,
            running=running,
            finished=finished,
            failed=failed,
            total=queued + running + finished + failed,
            queued_jobs=queued,
            running_jobs=running,
            finished_jobs=finished,
            failed_jobs=failed,
            total_jobs=queued + running + finished + failed
        )

    @app.get("/api/metrics")
    async def get_metrics():
        """Prometheus metrics"""
        payload = metrics_registry.export()
        return Response(content=payload, media_type="text/plain")
    
    @app.get("/api/jobs", response_model=JobListResponse)
    async def list_jobs(
        status: Optional[str] = Query(None, description="تصفية حسب الحالة"),
        limit: int = Query(50, ge=1, le=500, description="الحد الأقصى"),
        offset: int = Query(0, ge=0, description="البداية"),
        page: Optional[int] = Query(None, ge=1, description="رقم الصفحة"),
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ):
        """عرض قائمة المهام"""
        await _maybe_authenticate(x_api_key)
        jobs: List[JobResponse] = []
        try:
            lifecycle = JobLifecycle(manager=app.state.manager)
            job_ids = lifecycle.list_jobs(status=status)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        for job_id in job_ids:
            record = app.state.manager.load_job(job_id)
            if not record:
                continue
            metadata = record.metadata
            spec = record.spec
            jobs.append(JobResponse(
                job_id=job_id,
                status=metadata.status,
                target=spec.target,
                profile=spec.profile,
                stage=metadata.stage,
                queued_at=metadata.queued_at,
                started_at=metadata.started_at,
                finished_at=metadata.finished_at,
                error=metadata.error,
                stats=metadata.stats,
            ))
        jobs.sort(key=lambda x: x.job_id, reverse=True)
        total = len(jobs)
        if page is not None:
            offset = (page - 1) * limit
        jobs = jobs[offset:offset + limit]
        return JobListResponse(jobs=jobs, total=total)
    
    @app.get("/api/jobs/{job_id}", response_model=JobResponse)
    async def get_job(job_id: str, x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
        """الحصول على معلومات مهمة"""
        await _maybe_authenticate(x_api_key)
        lifecycle = JobLifecycle(manager=app.state.manager)
        record = lifecycle.get_job(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        if isinstance(record, dict):
            return record
        return JobResponse(
            job_id=job_id,
            status=record.metadata.status,
            target=record.spec.target,
            profile=record.spec.profile,
            stage=record.metadata.stage,
            queued_at=record.metadata.queued_at,
            started_at=record.metadata.started_at,
            finished_at=record.metadata.finished_at,
            error=record.metadata.error,
            stats=record.metadata.stats,
        )
    
    @app.get("/api/jobs/{job_id}/results")
    async def get_job_results(
        job_id: str,
        limit: int = Query(100, ge=1, le=1000),
        result_type: Optional[str] = Query(None, description="تصفية حسب النوع"),
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ):
        """الحصول على نتائج المهمة"""
        await _maybe_authenticate(x_api_key)
        results_manager = JobResults(manager=app.state.manager)
        results = results_manager.get_results(job_id, limit=limit, result_type=result_type)
        if results is None:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return {"results": results, "total": len(results)}

    @app.get("/api/jobs/{job_id}/summary")
    async def get_job_summary(
        job_id: str,
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ):
        """الحصول على ملخص المهمة"""
        await _maybe_authenticate(x_api_key)
        summary_manager = JobSummary(manager=app.state.manager)
        summary_data = summary_manager.get_summary(job_id)
        if summary_data is None:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return summary_data

    @app.get("/api/jobs/{job_id}/logs")
    async def get_job_logs(
        job_id: str,
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ):
        """الحصول على سجلات المهمة"""
        await _maybe_authenticate(x_api_key)
        record = app.state.manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        log_path = record.paths.pipeline_log
        if not log_path.exists():
            raise HTTPException(status_code=404, detail="Log not found")
        return FileResponse(log_path, media_type="text/plain")
    
    @app.post("/api/scan", response_model=JobResponse)
    async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
        """إنشاء فحص جديد"""
        manager = app.state.manager

        if not request.target:
            raise HTTPException(status_code=400, detail="target is required")
        allow_ip = request.allow_ip
        try:
            if validation.is_ip(validation._coerce_hostname(request.target)):
                allow_ip = True
        except Exception:
            allow_ip = request.allow_ip
        
        try:
            record = manager.create_job(
                target=request.target,
                profile=request.profile,
                inline=request.inline,
                force=request.force,
                allow_ip=allow_ip,
                scanners=request.scanners if request.scanners else None,
                active_modules=request.active_modules if request.active_modules else None,
            )
            
            if request.inline:
                # تشغيل في الخلفية
                background_tasks.add_task(_run_job, record.spec.job_id)
            
            return JobResponse(
                job_id=record.spec.job_id,
                status="queued",
                target=request.target,
                profile=request.profile,
                stage=None,
                queued_at=record.metadata.queued_at,
                started_at=None,
                finished_at=None,
                error=None,
                stats={}
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/jobs")
    async def create_job(
        request: JobCreateRequest,
        background_tasks: BackgroundTasks,
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ):
        """إنشاء مهمة"""
        await _maybe_authenticate(x_api_key)
        lifecycle = JobLifecycle(manager=app.state.manager)
        if not request.targets:
            raise HTTPException(status_code=400, detail="targets is required")
        try:
            job_id = lifecycle.create_job(
                targets=request.targets,
                stages=request.stages,
                options=request.options,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"job_id": job_id, "status": "queued"}
    
    @app.post("/api/jobs/{job_id}/requeue")
    async def requeue_job(job_id: str):
        """إعادة تشغيل مهمة"""
        job_dir = _find_job_dir(job_id)
        
        if not job_dir:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        
        # نقل إلى queued
        new_path = config.QUEUED_JOBS / job_id
        if job_dir != new_path:
            import shutil
            shutil.move(str(job_dir), str(new_path))
        
        return {"message": f"Job {job_id} requeued", "status": "queued"}
    
    @app.delete("/api/jobs/{job_id}")
    async def delete_job(job_id: str, x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
        """حذف مهمة"""
        await _maybe_authenticate(x_api_key)
        lifecycle = JobLifecycle(manager=app.state.manager)
        removed = lifecycle.delete_job(job_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return {"message": f"Job {job_id} deleted"}
    
    @app.get("/api/jobs/{job_id}/report")
    async def get_job_report(job_id: str):
        """الحصول على تقرير HTML"""
        job_dir = _find_job_dir(job_id)
        
        if not job_dir:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        
        report_path = job_dir / "report.html"
        
        if not report_path.exists():
            # إنشاء التقرير
            from recon_cli.utils.reporter import generate_html_report
            generate_html_report(job_dir)
        
        if report_path.exists():
            return FileResponse(report_path, media_type="text/html")
        
        raise HTTPException(status_code=404, detail="Report generation failed")
    
    return app


app = create_app() if FASTAPI_AVAILABLE else None


# ═══════════════════════════════════════════════════════════
#                     Helper Functions
# ═══════════════════════════════════════════════════════════

def _find_job_dir(job_id: str) -> Optional[Path]:
    """البحث عن مجلد المهمة"""
    for status_dir in [config.QUEUED_JOBS, config.RUNNING_JOBS, 
                       config.FINISHED_JOBS, config.FAILED_JOBS]:
        candidate = status_dir / job_id
        if candidate.exists():
            return candidate
    return None


def _run_job(job_id: str):
    """تشغيل مهمة في الخلفية"""
    from recon_cli.pipeline.runner import run_pipeline
    from recon_cli.jobs.manager import JobManager
    
    manager = JobManager()
    record = manager.load_job(job_id)
    
    if record:
        run_pipeline(record, manager)


# ═══════════════════════════════════════════════════════════
#                     Run Server
# ═══════════════════════════════════════════════════════════

def run_api(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """تشغيل السيرفر"""
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Run: pip install uvicorn")
        return
    
    uvicorn.run(
        "recon_cli.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True
    )


if __name__ == "__main__":
    run_api()
