"""Web Dashboard Application for ReconnV2."""
from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import uuid

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import HTMLResponse, Response
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    import uvicorn
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False

from recon_cli import config
from recon_cli.jobs.manager import JobManager
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.reporting import categorize_results, is_finding

MAX_WEB_TARGETS = 1000
MAX_TARGET_LENGTH = 2048
MAX_SETTINGS_BYTES = 262_144
MAX_OUTPUT_DOWNLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_SCAN_MODES = {"queued", "immediate"}
ALLOWED_NOTIFICATION_CHANNELS = {"telegram", "slack", "discord", "email"}

# Paths
WEB_DIR = Path(__file__).parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

if WEB_AVAILABLE:
    app = FastAPI(title="ReconnV2 Dashboard", docs_url=None, redoc_url=None)

    class _TemplateStub:
        def TemplateResponse(self, *_args, **_kwargs):  # pragma: no cover - fallback
            raise HTTPException(status_code=503, detail="Templates not available (install jinja2)")

    try:
        templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    except Exception:
        templates = _TemplateStub()

    # Mount static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _validate_job_id_or_400(job_id: str) -> None:
        if not JobManager.is_safe_job_id(job_id):
            raise HTTPException(status_code=400, detail="Invalid job_id")


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
    results = {"hosts": [], "urls": [], "vulnerabilities": [], "confirmed": [], "secrets": [], "other": []}
    
    manager = JobManager()
    record = manager.load_job(job_id)
    if not record:
        return results
    
    results_file = record.paths.results_jsonl
    if not results_file.exists():
        return results
    
    categorized = categorize_results(read_jsonl(results_file), include_secret_in_findings=False)
    results["hosts"] = categorized["hosts"]
    results["urls"] = categorized["urls"]
    results["secrets"] = categorized["secrets"]
    results["vulnerabilities"] = categorized["findings"]
    results["other"] = categorized["other"]
    results["confirmed"] = [finding for finding in categorized["findings"] if _is_confirmed_finding(finding)]
    
    return results


def _is_confirmed_finding(entry: Dict[str, Any]) -> bool:
    tags = entry.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            tag_value = str(tag)
            if tag_value == "confirmed" or tag_value.endswith(":confirmed"):
                return True
    source = entry.get("source")
    if isinstance(source, str) and source in {"extended-validation", "exploit-validation"}:
        return True
    return False


def _normalize_targets(data: Dict[str, Any]) -> List[str]:
    targets: List[str] = []
    raw_targets = data.get("targets")
    if isinstance(raw_targets, list):
        targets.extend([str(item).strip() for item in raw_targets if str(item).strip()])
    elif isinstance(raw_targets, str):
        targets.extend([line.strip() for line in raw_targets.splitlines() if line.strip()])
    target = data.get("target")
    if isinstance(target, str) and target.strip():
        targets.append(target.strip())
    deduped = []
    seen = set()
    for item in targets:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _stage_overrides(selected: List[str]) -> Dict[str, Any]:
    selected_set = {str(item).lower() for item in selected}
    overrides: Dict[str, Any] = {}
    if not selected_set:
        return overrides

    def disable(keys: List[str]) -> None:
        for key in keys:
            overrides[key] = False

    if "dns" not in selected_set:
        disable(["enable_ct_pivot", "enable_asn_pivot"])
    if "subdomains" not in selected_set:
        disable(["enable_subdomain_permute", "enable_vhost", "enable_takeover", "enable_cloud_discovery"])
    if "ports" not in selected_set:
        disable(["enable_nmap"])
    if "web" not in selected_set:
        disable([
            "enable_waf_probe",
            "enable_security_headers",
            "enable_tls_hygiene",
            "enable_runtime_crawl",
            "enable_js_intel",
            "enable_api_recon",
            "enable_api_schema_probe",
            "enable_graphql_recon",
            "enable_graphql_exploit",
            "enable_oauth_discovery",
            "enable_ws_grpc_discovery",
            "enable_upload_probe",
            "enable_cms_scan",
        ])
    if "vulnerabilities" not in selected_set:
        disable([
            "enable_fuzz",
            "enable_param_fuzz",
            "enable_param_mining",
            "enable_dalfox",
            "enable_sqlmap",
            "auto_scanners",
            "enable_verification",
            "enable_extended_validation",
            "enable_exploit_validation",
        ])
    if "secrets" not in selected_set:
        disable(["enable_secrets"])
    return overrides


def record_id_safe() -> str:
    return uuid.uuid4().hex[:10]


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
        _validate_job_id_or_400(job_id)
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

        _validate_job_id_or_400(job_id)
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
        if job_id is not None:
            _validate_job_id_or_400(job_id)
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
                        if not is_finding(item):
                            continue
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
        _validate_job_id_or_400(job_id)
        try:
            from recon_cli.reports import ReportGenerator, ReportConfig, ReportFormat
            from recon_cli.reports.executive import ExecutiveSummaryGenerator
            
            manager = JobManager()
            record = manager.load_job(job_id)
            
            if not record:
                raise HTTPException(status_code=404, detail="Job not found")
            
            # Build job data
            job_data = {
                "id": job_id,
                "job_id": job_id,
                "targets": [record.spec.target] if hasattr(record.spec, 'target') else [],
                "findings": [],
                "hosts": [],
                "start_time": record.metadata.started_at,
                "end_time": record.metadata.finished_at,
            }
            
            if record.paths.results_jsonl.exists():
                categorized = categorize_results(read_jsonl(record.paths.results_jsonl), include_secret_in_findings=True)
                job_data["hosts"].extend(categorized["hosts"])
                job_data["findings"].extend(categorized["findings"])
            
            if executive:
                gen = ExecutiveSummaryGenerator()
                summary = gen.generate(job_data)
                return summary.to_dict()
            else:
                try:
                    report_format = ReportFormat(format.lower())
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=f"Unsupported report format: {format}") from exc
                config = ReportConfig()
                generator = ReportGenerator(config)
                content = await generator.generate(job_data, format=report_format)
                
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
            if not isinstance(data, dict):
                raise HTTPException(status_code=400, detail="Invalid request payload")
            targets = _normalize_targets(data)
            profile = data.get("profile", "passive")
            scan_mode = data.get("scanMode", "queued")
            stages = data.get("stages") if isinstance(data.get("stages"), list) else []
            passive_only = bool(data.get("passive", False))

            if not targets:
                raise HTTPException(status_code=400, detail="Target is required")
            if len(targets) > MAX_WEB_TARGETS:
                raise HTTPException(status_code=400, detail=f"Too many targets (max {MAX_WEB_TARGETS})")
            if any(len(target) > MAX_TARGET_LENGTH for target in targets):
                raise HTTPException(status_code=400, detail=f"Target too long (max {MAX_TARGET_LENGTH} chars)")
            if scan_mode not in ALLOWED_SCAN_MODES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid scanMode '{scan_mode}'. Allowed: {', '.join(sorted(ALLOWED_SCAN_MODES))}",
                )

            if passive_only:
                profile = "passive"

            runtime_overrides: Dict[str, Any] = {}
            threads = data.get("threads")
            if isinstance(threads, int) and threads > 0:
                runtime_overrides["httpx_threads"] = threads
                runtime_overrides["ffuf_threads"] = max(5, int(threads // 2))
            timeout = data.get("timeout")
            if isinstance(timeout, int) and timeout > 0:
                runtime_overrides["timeout_http"] = timeout
            rate_limit = data.get("rate_limit")
            if isinstance(rate_limit, int) and rate_limit > 0:
                runtime_overrides["requests_per_second"] = rate_limit
                runtime_overrides["per_host_limit"] = max(1, int(rate_limit // 4))

            resolvers = data.get("resolvers")
            if resolvers in {"cloudflare", "google"}:
                resolver_lines = [
                    "1.1.1.1" if resolvers == "cloudflare" else "8.8.8.8",
                    "1.0.0.1" if resolvers == "cloudflare" else "8.8.4.4",
                ]
                resolver_dir = config.RECON_HOME / "tmp"
                resolver_dir.mkdir(parents=True, exist_ok=True)
                resolver_path = resolver_dir / f"web_resolvers_{record_id_safe()}.txt"
                resolver_path.write_text("\n".join(resolver_lines) + "\n", encoding="utf-8")
                runtime_overrides["resolvers_file"] = str(resolver_path)

            runtime_overrides.update(_stage_overrides(stages))

            from recon_cli.jobs.manager import JobManager
            from recon_cli.pipeline.runner import run_pipeline

            manager = JobManager()
            targets_file = None
            if len(targets) > 1:
                targets_dir = config.RECON_HOME / "tmp"
                targets_dir.mkdir(parents=True, exist_ok=True)
                targets_path = targets_dir / f"web_targets_{record_id_safe()}.txt"
                targets_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
                targets_file = str(targets_path)

            record = manager.create_job(
                target=targets[0],
                profile=profile,
                targets_file=targets_file,
                runtime_overrides=runtime_overrides,
            )

            if stages:
                record.spec.stages = [str(stage) for stage in stages]
                manager.update_spec(record)

            # If scanMode is 'immediate', run the pipeline right away
            if scan_mode == "immediate":
                try:
                    run_pipeline(record, manager)
                except Exception:
                    return {
                        "success": False,
                        "job_id": record.spec.job_id,
                        "message": "Failed to start scan immediately",
                    }
                return {
                    "success": True,
                    "job_id": record.spec.job_id,
                    "message": f"Scan started immediately for {targets[0]}",
                }
            else:
                return {
                    "success": True,
                    "job_id": record.spec.job_id,
                    "message": f"Scan queued for {targets[0]}",
                }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to create scan job") from exc

    # ========================================================================
    # OUTPUTS API - Download job outputs
    # ========================================================================

    @app.get("/api/jobs/{job_id}/outputs/{output_name}")
    async def outputs_api(job_id: str, output_name: str):
        """Download job output files (results, confirmed, bigger, jsonl)."""
        _validate_job_id_or_400(job_id)
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")

        output_map = {
            "results": ("results.txt", "text/plain"),
            "results_bigger": ("results_bigger.txt", "text/plain"),
            "results_confirmed": ("results_confirmed.txt", "text/plain"),
            "results_jsonl": ("results.jsonl", "application/x-ndjson"),
            "results_trimmed": ("results_trimmed.jsonl", "application/x-ndjson"),
        }
        file_info = output_map.get(output_name)
        if not file_info:
            raise HTTPException(status_code=404, detail="Output not found")
        filename, mime = file_info
        path = record.paths.root / filename
        if not path.exists():
            raise HTTPException(status_code=404, detail="Output file missing")
        if path.stat().st_size > MAX_OUTPUT_DOWNLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Output too large for web download (max {MAX_OUTPUT_DOWNLOAD_BYTES} bytes)",
            )
        content = path.read_bytes()
        return Response(
            content=content,
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    
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
            if not isinstance(data, dict):
                raise HTTPException(status_code=400, detail="Settings payload must be a JSON object")
            serialized = json.dumps(data, indent=2)
            if len(serialized.encode("utf-8")) > MAX_SETTINGS_BYTES:
                raise HTTPException(status_code=413, detail=f"Settings payload too large (max {MAX_SETTINGS_BYTES} bytes)")
            config_file = Path(config.CONFIG_DIR) / "settings.json"
            config_file.parent.mkdir(parents=True, exist_ok=True)
            config_file.write_text(serialized, encoding="utf-8")
            return {"success": True, "message": "Settings saved"}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to save settings") from exc
    
    @app.post("/api/test-notification")
    async def test_notification_api(request: Request):
        """Test notification channel."""
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise HTTPException(status_code=400, detail="Invalid request payload")
            channel = data.get("channel")
            if channel not in ALLOWED_NOTIFICATION_CHANNELS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid channel '{channel}'. Allowed: {', '.join(sorted(ALLOWED_NOTIFICATION_CHANNELS))}",
                )
            
            # Import alerting module
            from recon_cli.utils.alerting import AlertManager
            
            manager = AlertManager()
            success = await manager.send_test(channel, data)
            
            if success:
                return {"success": True, "message": f"Test notification sent to {channel}"}
            else:
                return {"success": False, "message": "Failed to send notification"}
        except HTTPException:
            raise
        except ImportError:
            return {"success": False, "message": "Alerting module not available"}
        except Exception:
            return {"success": False, "message": "Notification test failed"}
    
    # ========================================================================
    # JOB ACTIONS - Cancel, Retry, Delete from web
    # ========================================================================
    
    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job_api(job_id: str):
        """Cancel a running job."""
        _validate_job_id_or_400(job_id)
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")

        if record.metadata.status not in {"queued", "running"}:
            raise HTTPException(status_code=409, detail=f"Cannot cancel job in status '{record.metadata.status}'")

        # Move to failed
        try:
            from recon_cli.jobs.lifecycle import JobLifecycle
            lifecycle = JobLifecycle(manager)
            moved = lifecycle.move_to_failed(job_id)
            if not moved:
                raise HTTPException(status_code=409, detail="Unable to cancel job")
            return {"success": True, "message": f"Job {job_id} cancelled"}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to cancel job") from exc
    
    @app.post("/api/jobs/{job_id}/retry")
    async def retry_job_api(job_id: str):
        """Retry a failed job."""
        _validate_job_id_or_400(job_id)
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")

        if record.metadata.status not in {"failed", "finished"}:
            raise HTTPException(status_code=409, detail=f"Cannot retry job in status '{record.metadata.status}'")

        try:
            from recon_cli.jobs.lifecycle import JobLifecycle
            lifecycle = JobLifecycle(manager)
            moved = lifecycle.requeue(job_id)
            if not moved:
                raise HTTPException(status_code=409, detail="Unable to requeue job")
            return {"success": True, "job_id": job_id, "message": f"Job {job_id} requeued"}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to retry job") from exc
    
    @app.delete("/api/jobs/{job_id}")
    async def delete_job_api(job_id: str):
        """Delete a job."""
        _validate_job_id_or_400(job_id)
        manager = JobManager()
        record = manager.load_job(job_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")

        try:
            removed = manager.remove_job(job_id)
            if not removed:
                raise HTTPException(status_code=409, detail="Unable to delete job")
            return {"success": True, "message": f"Job {job_id} deleted"}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to delete job") from exc


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Run the web dashboard."""
    if not WEB_AVAILABLE:
        print("❌ FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn jinja2")
        return
    
    print(f"🚀 Starting ReconnV2 Dashboard at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
