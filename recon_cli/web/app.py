"""Web Dashboard Application for ReconnV2."""
from pathlib import Path
from typing import List, Dict, Any, Optional
import json

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import HTMLResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    import uvicorn
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False

from recon_cli import config
from recon_cli.jobs.manager import JobManager
from recon_cli.utils.jsonl import read_jsonl

# Paths
WEB_DIR = Path(__file__).parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

if WEB_AVAILABLE:
    app = FastAPI(title="ReconnV2 Dashboard", docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    
    # Mount static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def get_job_stats() -> Dict[str, int]:
    """Get job counts by status."""
    stats = {"queued": 0, "running": 0, "finished": 0, "failed": 0}
    
    for status, dir_path in [
        ("queued", config.QUEUED_JOBS),
        ("running", config.RUNNING_JOBS),
        ("finished", config.FINISHED_JOBS),
        ("failed", config.FAILED_JOBS),
    ]:
        if dir_path.exists():
            stats[status] = len([d for d in dir_path.iterdir() if d.is_dir()])
    
    return stats


def get_recent_jobs(limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent jobs from all statuses."""
    jobs = []
    manager = JobManager()
    
    for status in ["running", "queued", "finished", "failed"]:
        job_ids = manager.list_jobs(status)
        for job_id in job_ids[:limit]:
            record = manager.load_job(job_id)
            if record:
                jobs.append({
                    "id": job_id,
                    "status": status,
                    "target": record.spec.target if hasattr(record.spec, 'target') else None,
                    "profile": record.spec.profile if hasattr(record.spec, 'profile') else None,
                    "started_at": record.metadata.started_at,
                    "finished_at": record.metadata.finished_at,
                    "stage": record.metadata.stage,
                    "stats": record.metadata.stats,
                })
    
    # Sort by started_at descending
    jobs.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    return jobs[:limit]


def get_job_results(job_id: str) -> Dict[str, List[Dict]]:
    """Get categorized results for a job."""
    results = {
        "hosts": [],
        "urls": [],
        "vulnerabilities": [],
        "secrets": [],
        "other": [],
    }
    
    manager = JobManager()
    record = manager.load_job(job_id)
    if not record:
        return results
    
    results_file = record.paths.results_jsonl
    if not results_file.exists():
        return results
    
    for item in read_jsonl(results_file):
        item_type = item.get("type", "other")
        if item_type == "host":
            results["hosts"].append(item)
        elif item_type == "url":
            results["urls"].append(item)
        elif item_type in ["vulnerability", "finding", "nuclei"]:
            results["vulnerabilities"].append(item)
        elif item_type in ["secret", "credential"]:
            results["secrets"].append(item)
        else:
            results["other"].append(item)
    
    return results


if WEB_AVAILABLE:
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        """Main dashboard page."""
        stats = get_job_stats()
        jobs = get_recent_jobs(10)
        return templates.TemplateResponse("index.html", {
            "request": request,
            "stats": stats,
            "jobs": jobs,
        })
    
    @app.get("/jobs", response_class=HTMLResponse)
    async def jobs_list(request: Request, status: Optional[str] = None):
        """List all jobs."""
        stats = get_job_stats()
        manager = JobManager()
        jobs = []
        
        statuses = [status] if status else ["running", "queued", "finished", "failed"]
        for s in statuses:
            job_ids = manager.list_jobs(s)
            for job_id in job_ids:
                record = manager.load_job(job_id)
                if record:
                    jobs.append({
                        "id": job_id,
                        "status": s,
                        "target": record.spec.target if hasattr(record.spec, 'target') else None,
                        "started_at": record.metadata.started_at,
                        "finished_at": record.metadata.finished_at,
                        "stage": record.metadata.stage,
                    })
        
        return templates.TemplateResponse("index.html", {
            "request": request,
            "stats": stats,
            "jobs": jobs,
        })
    
    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_detail(request: Request, job_id: str):
        """Job detail page."""
        manager = JobManager()
        record = manager.load_job(job_id)
        
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")
        
        job = {
            "id": job_id,
            "status": record.metadata.status,
            "target": record.spec.target if hasattr(record.spec, 'target') else None,
            "profile": record.spec.profile if hasattr(record.spec, 'profile') else None,
            "started_at": record.metadata.started_at,
            "finished_at": record.metadata.finished_at,
            "stage": record.metadata.stage,
            "stats": record.metadata.stats,
            "error": record.metadata.error,
        }
        
        results = get_job_results(job_id)
        
        return templates.TemplateResponse("job_detail.html", {
            "request": request,
            "job": job,
            "results": results,
        })
    
    @app.get("/jobs/{job_id}/report", response_class=HTMLResponse)
    async def job_report(request: Request, job_id: str):
        """Generate and return HTML report."""
        from recon_cli.utils.reporter import generate_html_report
        
        manager = JobManager()
        record = manager.load_job(job_id)
        
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")
        
        report_path = record.paths.root / "report.html"
        generate_html_report(record.paths.root, report_path)
        
        if report_path.exists():
            return HTMLResponse(content=report_path.read_text(encoding="utf-8"))
        
        raise HTTPException(status_code=500, detail="Failed to generate report")
    
    @app.get("/scan", response_class=HTMLResponse)
    async def scan_page(request: Request):
        """New scan page."""
        stats = get_job_stats()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "stats": stats,
            "jobs": [],
        })


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Run the web dashboard."""
    if not WEB_AVAILABLE:
        print("❌ FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn jinja2")
        return
    
    print(f"🚀 Starting ReconnV2 Dashboard at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
