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
        """New scan page with form to start scans."""
        jobs = get_recent_jobs(5)
        return templates.TemplateResponse("scan.html", {
            "request": request,
            "jobs": jobs,
        })
    
    # ========================================================================
    # SEARCH API
    # ========================================================================
    
    @app.get("/api/search")
    async def search_api(
        q: str,
        type: Optional[str] = None,
        limit: int = 50,
    ):
        """Search across all job results."""
        try:
            from recon_cli.web.search import SearchEngine, SearchQuery, SearchType
            
            engine = SearchEngine()
            
            # Build index from all jobs
            manager = JobManager()
            for status in ["finished", "running"]:
                for job_id in manager.list_jobs(status):
                    record = manager.load_job(job_id)
                    if record and record.paths.results_jsonl.exists():
                        for item in read_jsonl(record.paths.results_jsonl):
                            engine.index.add_document(
                                doc_id=f"{job_id}:{item.get('id', hash(str(item)))}",
                                content=json.dumps(item),
                                doc_type=item.get("type", "other"),
                                metadata={"job_id": job_id, **item},
                            )
            
            # Parse and execute query
            query = SearchQuery.parse(q)
            if type:
                query.types = [SearchType(type)]
            
            results = engine.search(query, limit=limit)
            
            return {
                "query": q,
                "total": results.total,
                "results": [
                    {
                        "id": r.doc_id,
                        "score": r.score,
                        "type": r.doc_type,
                        "data": r.metadata,
                        "highlights": r.highlights,
                    }
                    for r in results.results
                ],
                "aggregations": results.aggregations,
            }
        except ImportError:
            return {"error": "Search module not available", "results": []}
    
    # ========================================================================
    # CHARTS API
    # ========================================================================
    
    @app.get("/api/charts/{chart_type}")
    async def chart_api(chart_type: str, job_id: Optional[str] = None):
        """Get chart data for dashboard."""
        try:
            from recon_cli.web.charts import ChartGenerator
            
            # Collect findings
            findings = []
            manager = JobManager()
            
            job_ids = [job_id] if job_id else manager.list_jobs("finished")[:20]
            
            for jid in job_ids:
                record = manager.load_job(jid)
                if record and record.paths.results_jsonl.exists():
                    for item in read_jsonl(record.paths.results_jsonl):
                        item["job_id"] = jid
                        findings.append(item)
            
            generator = ChartGenerator()
            
            if chart_type == "severity":
                chart = generator.severity_distribution(findings)
            elif chart_type == "type":
                chart = generator.finding_types(findings)
            elif chart_type == "timeline":
                chart = generator.vulnerability_trend(findings)
            elif chart_type == "top_hosts":
                chart = generator.top_affected_hosts(findings)
            else:
                return {"error": f"Unknown chart type: {chart_type}"}
            
            return chart.to_chartjs()
            
        except ImportError:
            return {"error": "Charts module not available"}
    
    # ========================================================================
    # WEBSOCKET FOR REAL-TIME UPDATES
    # ========================================================================
    
    try:
        from recon_cli.web.websocket import create_websocket_router
        
        ws_router = create_websocket_router()
        app.include_router(ws_router, prefix="/ws")
    except ImportError:
        pass  # WebSocket module not available
    
    # ========================================================================
    # REPORTS API
    # ========================================================================
    
    @app.get("/api/jobs/{job_id}/report")
    async def report_api(
        job_id: str,
        format: str = "json",
        executive: bool = False,
    ):
        """Generate report in specified format."""
        try:
            from recon_cli.reports import ReportGenerator, ReportConfig, ReportFormat
            from recon_cli.reports.executive import ExecutiveSummaryGenerator
            
            manager = JobManager()
            record = manager.load_job(job_id)
            
            if not record:
                raise HTTPException(status_code=404, detail="Job not found")
            
            # Build job data
            job_data = {
                "job_id": job_id,
                "targets": [record.spec.target] if hasattr(record.spec, 'target') else [],
                "findings": [],
                "hosts": [],
                "start_time": record.metadata.started_at,
                "end_time": record.metadata.finished_at,
            }
            
            if record.paths.results_jsonl.exists():
                for item in read_jsonl(record.paths.results_jsonl):
                    item_type = item.get("type", "other")
                    if item_type == "host":
                        job_data["hosts"].append(item)
                    else:
                        job_data["findings"].append(item)
            
            if executive:
                gen = ExecutiveSummaryGenerator()
                summary = gen.generate(job_data)
                return summary.to_dict()
            else:
                report_format = ReportFormat(format.lower())
                config = ReportConfig(format=report_format)
                generator = ReportGenerator(config)
                content = generator.generate(job_data)
                
                if format == "json":
                    return json.loads(content)
                else:
                    return {"content": content, "format": format}
                    
        except ImportError as e:
            return {"error": f"Reports module not available: {e}"}

    # ========================================================================
    # SCAN API - Start scans from web
    # ========================================================================
    
    @app.post("/api/scan")
    async def start_scan_api(request: Request):
        """Start a new scan from web interface."""
        try:
            data = await request.json()
            target = data.get("target")
            profile = data.get("profile", "passive")
            notify = data.get("notify", False)
            
            if not target:
                raise HTTPException(status_code=400, detail="Target is required")
            
            from recon_cli.jobs.manager import JobManager
            
            manager = JobManager()
            record = manager.create_job(
                target=target,
                profile=profile,
            )
            
            return {
                "success": True,
                "job_id": record.spec.job_id,
                "message": f"Scan started for {target}",
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # ========================================================================
    # SETTINGS PAGE
    # ========================================================================
    
    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        """Settings page."""
        # Load current settings
        settings_data = {
            "notifications": {
                "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
                "slack": {"enabled": False, "webhook_url": ""},
                "discord": {"enabled": False, "webhook_url": ""},
                "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "to": ""},
            },
            "profiles": [],
        }
        
        # Load from config if exists
        config_file = Path(config.CONFIG_DIR) / "settings.json"
        if config_file.exists():
            try:
                settings_data = json.loads(config_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass  # Settings file corrupted or unreadable, use defaults
        
        # Load available profiles
        profiles = list(config.available_profiles().keys())
        
        return templates.TemplateResponse("settings.html", {
            "request": request,
            "settings": settings_data,
            "profiles": profiles,
        })
    
    @app.post("/api/settings")
    async def save_settings_api(request: Request):
        """Save settings."""
        try:
            data = await request.json()
            config_file = Path(config.CONFIG_DIR) / "settings.json"
            config_file.parent.mkdir(parents=True, exist_ok=True)
            config_file.write_text(json.dumps(data, indent=2))
            return {"success": True, "message": "Settings saved"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/test-notification")
    async def test_notification_api(request: Request):
        """Test notification channel."""
        try:
            data = await request.json()
            channel = data.get("channel")
            
            # Import alerting module
            from recon_cli.utils.alerting import AlertManager
            
            manager = AlertManager()
            success = await manager.send_test(channel, data)
            
            if success:
                return {"success": True, "message": f"Test notification sent to {channel}"}
            else:
                return {"success": False, "message": "Failed to send notification"}
        except ImportError:
            return {"success": False, "message": "Alerting module not available"}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    # ========================================================================
    # JOB ACTIONS - Cancel, Retry, Delete from web
    # ========================================================================
    
    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job_api(job_id: str):
        """Cancel a running job."""
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")
        
        # Move to failed
        try:
            from recon_cli.jobs.lifecycle import JobLifecycle
            lifecycle = JobLifecycle(manager)
            lifecycle.move_to_failed(job_id)
            return {"success": True, "message": f"Job {job_id} cancelled"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/jobs/{job_id}/retry")
    async def retry_job_api(job_id: str):
        """Retry a failed job."""
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")
        
        try:
            from recon_cli.jobs.lifecycle import JobLifecycle
            lifecycle = JobLifecycle(manager)
            lifecycle.requeue(job_id)
            return {"success": True, "job_id": job_id, "message": f"Job {job_id} requeued"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.delete("/api/jobs/{job_id}")
    async def delete_job_api(job_id: str):
        """Delete a job."""
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")
        
        try:
            import shutil
            shutil.rmtree(record.paths.root)
            return {"success": True, "message": f"Job {job_id} deleted"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Run the web dashboard."""
    if not WEB_AVAILABLE:
        print("❌ FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn jinja2")
        return
    
    print(f"🚀 Starting ReconnV2 Dashboard at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
