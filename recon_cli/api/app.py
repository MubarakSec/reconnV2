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
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None
    BaseModel = object

from recon_cli import config
from recon_cli.jobs.manager import JobManager
from recon_cli.utils.jsonl import read_jsonl


# ═══════════════════════════════════════════════════════════
#                     Pydantic Models
# ═══════════════════════════════════════════════════════════

if FASTAPI_AVAILABLE:
    class ScanRequest(BaseModel):
        """طلب فحص جديد"""
        target: str = Field(..., description="الهدف (domain أو IP)")
        profile: str = Field("passive", description="الملف الشخصي")
        inline: bool = Field(False, description="تشغيل فوري")
        scanners: List[str] = Field(default_factory=list, description="الماسحات")
        active_modules: List[str] = Field(default_factory=list, description="الوحدات النشطة")
        force: bool = Field(False, description="إعادة تشغيل كل المراحل")
        allow_ip: bool = Field(False, description="السماح بـ IP")

    class JobResponse(BaseModel):
        """استجابة معلومات المهمة"""
        job_id: str
        status: str
        target: Optional[str]
        profile: Optional[str]
        stage: Optional[str]
        queued_at: Optional[str]
        started_at: Optional[str]
        finished_at: Optional[str]
        error: Optional[str]
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
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # حالة التطبيق
    app.state.start_time = datetime.now()
    app.state.manager = JobManager()
    
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
            status="running",
            version="0.1.0",
            uptime=str(uptime).split('.')[0]
        )
    
    @app.get("/api/stats", response_model=StatsResponse)
    async def get_stats():
        """إحصائيات النظام"""
        queued = len(list(config.QUEUED_JOBS.glob("*"))) if config.QUEUED_JOBS.exists() else 0
        running = len(list(config.RUNNING_JOBS.glob("*"))) if config.RUNNING_JOBS.exists() else 0
        finished = len(list(config.FINISHED_JOBS.glob("*"))) if config.FINISHED_JOBS.exists() else 0
        failed = len(list(config.FAILED_JOBS.glob("*"))) if config.FAILED_JOBS.exists() else 0
        
        return StatsResponse(
            queued_jobs=queued,
            running_jobs=running,
            finished_jobs=finished,
            failed_jobs=failed,
            total_jobs=queued + running + finished + failed
        )
    
    @app.get("/api/jobs", response_model=JobListResponse)
    async def list_jobs(
        status: Optional[str] = Query(None, description="تصفية حسب الحالة"),
        limit: int = Query(50, ge=1, le=500, description="الحد الأقصى"),
        offset: int = Query(0, ge=0, description="البداية")
    ):
        """عرض قائمة المهام"""
        jobs = []
        
        status_dirs = {
            "queued": config.QUEUED_JOBS,
            "running": config.RUNNING_JOBS,
            "finished": config.FINISHED_JOBS,
            "failed": config.FAILED_JOBS,
        }
        
        if status and status in status_dirs:
            dirs_to_check = {status: status_dirs[status]}
        else:
            dirs_to_check = status_dirs
        
        for job_status, status_dir in dirs_to_check.items():
            if not status_dir.exists():
                continue
            
            for job_dir in status_dir.iterdir():
                if not job_dir.is_dir():
                    continue
                
                metadata_path = job_dir / "metadata.json"
                spec_path = job_dir / "spec.json"
                
                try:
                    metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
                    spec = json.loads(spec_path.read_text()) if spec_path.exists() else {}
                    
                    jobs.append(JobResponse(
                        job_id=job_dir.name,
                        status=metadata.get("status", job_status),
                        target=spec.get("target"),
                        profile=spec.get("profile"),
                        stage=metadata.get("stage"),
                        queued_at=metadata.get("queued_at"),
                        started_at=metadata.get("started_at"),
                        finished_at=metadata.get("finished_at"),
                        error=metadata.get("error"),
                        stats=metadata.get("stats", {})
                    ))
                except Exception:
                    continue
        
        # ترتيب حسب التاريخ
        jobs.sort(key=lambda x: x.job_id, reverse=True)
        
        total = len(jobs)
        jobs = jobs[offset:offset + limit]
        
        return JobListResponse(jobs=jobs, total=total)
    
    @app.get("/api/jobs/{job_id}", response_model=JobResponse)
    async def get_job(job_id: str):
        """الحصول على معلومات مهمة"""
        job_dir = _find_job_dir(job_id)
        
        if not job_dir:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        
        metadata_path = job_dir / "metadata.json"
        spec_path = job_dir / "spec.json"
        
        metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
        spec = json.loads(spec_path.read_text()) if spec_path.exists() else {}
        
        return JobResponse(
            job_id=job_id,
            status=metadata.get("status", "unknown"),
            target=spec.get("target"),
            profile=spec.get("profile"),
            stage=metadata.get("stage"),
            queued_at=metadata.get("queued_at"),
            started_at=metadata.get("started_at"),
            finished_at=metadata.get("finished_at"),
            error=metadata.get("error"),
            stats=metadata.get("stats", {})
        )
    
    @app.get("/api/jobs/{job_id}/results")
    async def get_job_results(
        job_id: str,
        limit: int = Query(100, ge=1, le=1000),
        result_type: Optional[str] = Query(None, description="تصفية حسب النوع")
    ):
        """الحصول على نتائج المهمة"""
        job_dir = _find_job_dir(job_id)
        
        if not job_dir:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        
        results_path = job_dir / "results.jsonl"
        
        if not results_path.exists():
            return {"results": [], "total": 0}
        
        results = []
        for item in read_jsonl(results_path):
            if result_type and item.get("type") != result_type:
                continue
            results.append(item)
            if len(results) >= limit:
                break
        
        return {"results": results, "total": len(results)}
    
    @app.post("/api/scan", response_model=JobResponse)
    async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
        """إنشاء فحص جديد"""
        manager = app.state.manager
        
        try:
            record = manager.create_job(
                target=request.target,
                profile=request.profile,
                inline=request.inline,
                force=request.force,
                allow_ip=request.allow_ip,
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
    async def delete_job(job_id: str):
        """حذف مهمة"""
        job_dir = _find_job_dir(job_id)
        
        if not job_dir:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        
        import shutil
        shutil.rmtree(job_dir)
        
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
