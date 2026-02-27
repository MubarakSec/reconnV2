"""Web Dashboard Application for ReconnV2."""
from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import re
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
from recon_cli.utils import validation

MAX_WEB_TARGETS = 1000
MAX_TARGET_LENGTH = 2048
MAX_SETTINGS_BYTES = 262_144
MAX_OUTPUT_DOWNLOAD_BYTES = 25 * 1024 * 1024
MAX_SCAN_PAYLOAD_BYTES = 1_048_576
MAX_NOTIFICATION_PAYLOAD_BYTES = 8_192
ALLOWED_SCAN_MODES = {"queued", "immediate"}
ALLOWED_NOTIFICATION_CHANNELS = {"telegram", "slack", "discord", "email"}
ALLOWED_STAGE_GROUPS = {"dns", "subdomains", "ports", "web", "vulnerabilities", "secrets"}
ALLOWED_RESOLVERS = {"default", "cloudflare", "google", "custom"}
ALLOWED_SCAN_KEYS = {
    "target",
    "targets",
    "profile",
    "stages",
    "threads",
    "timeout",
    "rate_limit",
    "resolvers",
    "scanMode",
    "notify",
    "passive",
}
SAFE_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

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


async def _parse_json_object_or_400(request, *, max_bytes: int, error_prefix: str = "Invalid request payload") -> Dict[str, Any]:
    body = await request.body()
    if len(body) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Payload too large (max {max_bytes} bytes)")
    try:
        data = json.loads(body.decode("utf-8") if body else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=error_prefix) from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail=error_prefix)
    return data


def _normalize_profile_or_400(profile: Any) -> str:
    normalized = str(profile or "").strip().lower()
    if not normalized:
        raise HTTPException(status_code=400, detail="profile is required")
    if len(normalized) > 64 or not SAFE_PROFILE_RE.fullmatch(normalized):
        raise HTTPException(status_code=400, detail="Invalid profile")
    available_profiles = set(config.available_profiles().keys())
    fallback_profiles = {"passive", "full", "safe", "aggressive"}
    allowed_profiles = available_profiles or fallback_profiles
    if normalized not in allowed_profiles:
        allowed = ", ".join(sorted(allowed_profiles))
        raise HTTPException(status_code=400, detail=f"Unknown profile '{normalized}'. Allowed: {allowed}")
    return normalized


def _normalize_bool_or_400(value: Any, *, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a boolean")
    return value


def _parse_bounded_int_or_400(
    value: Any,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(status_code=400, detail=f"{field_name} must be an integer")
    if value < minimum or value > maximum:
        raise HTTPException(status_code=400, detail=f"{field_name} must be between {minimum} and {maximum}")
    return value


def _normalize_stage_groups_or_400(stages: Any) -> List[str]:
    if stages is None:
        return []
    if not isinstance(stages, list):
        raise HTTPException(status_code=400, detail="stages must be a list")
    if len(stages) > len(ALLOWED_STAGE_GROUPS):
        raise HTTPException(status_code=400, detail=f"Too many stages (max {len(ALLOWED_STAGE_GROUPS)})")
    normalized: List[str] = []
    seen = set()
    for raw_stage in stages:
        if not isinstance(raw_stage, str):
            raise HTTPException(status_code=400, detail="stages must contain strings only")
        stage = raw_stage.strip().lower()
        if stage not in ALLOWED_STAGE_GROUPS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid stage '{raw_stage}'. Allowed: {', '.join(sorted(ALLOWED_STAGE_GROUPS))}",
            )
        if stage not in seen:
            seen.add(stage)
            normalized.append(stage)
    return normalized


def _normalize_and_validate_targets_or_400(data: Dict[str, Any]) -> List[str]:
    raw_targets = data.get("targets")
    if raw_targets is not None and not isinstance(raw_targets, (list, str)):
        raise HTTPException(status_code=400, detail="targets must be a list or newline-delimited string")
    if isinstance(raw_targets, list) and any(not isinstance(item, str) for item in raw_targets):
        raise HTTPException(status_code=400, detail="targets must contain strings only")
    raw_target = data.get("target")
    if raw_target is not None and not isinstance(raw_target, str):
        raise HTTPException(status_code=400, detail="target must be a string")

    targets = _normalize_targets(data)
    if not targets:
        raise HTTPException(status_code=400, detail="Target is required")
    if len(targets) > MAX_WEB_TARGETS:
        raise HTTPException(status_code=400, detail=f"Too many targets (max {MAX_WEB_TARGETS})")
    if any(len(target) > MAX_TARGET_LENGTH for target in targets):
        raise HTTPException(status_code=400, detail=f"Target too long (max {MAX_TARGET_LENGTH} chars)")

    validated: List[str] = []
    seen = set()
    for raw_target in targets:
        coerced = validation._coerce_hostname(raw_target)
        allow_ip = validation.is_ip(coerced)
        try:
            normalized = validation.validate_target(raw_target, allow_ip=allow_ip)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target '{raw_target}': {exc}") from exc
        if normalized not in seen:
            seen.add(normalized)
            validated.append(normalized)
    return validated


def _sanitize_text_or_400(value: Any, *, field_name: str, max_length: int, required: bool = False) -> str:
    if value is None:
        if required:
            raise HTTPException(status_code=400, detail=f"{field_name} is required")
        return ""
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a string")
    normalized = value.strip()
    if required and not normalized:
        raise HTTPException(status_code=400, detail=f"{field_name} is required")
    if len(normalized) > max_length:
        raise HTTPException(status_code=400, detail=f"{field_name} exceeds max length {max_length}")
    return normalized


def _validate_settings_payload_or_400(data: Dict[str, Any]) -> Dict[str, Any]:
    allowed_top_level = {"notifications", "general", "profiles"}
    unexpected = sorted(set(data.keys()) - allowed_top_level)
    if unexpected:
        raise HTTPException(status_code=400, detail=f"Unsupported settings keys: {', '.join(unexpected)}")

    normalized: Dict[str, Any] = {}
    notifications = data.get("notifications", {})
    if notifications is not None:
        if not isinstance(notifications, dict):
            raise HTTPException(status_code=400, detail="notifications must be an object")
        allowed_channels = {"telegram", "slack", "discord", "email"}
        unknown_channels = sorted(set(notifications.keys()) - allowed_channels)
        if unknown_channels:
            raise HTTPException(status_code=400, detail=f"Unsupported notification channels: {', '.join(unknown_channels)}")

        normalized_notifications: Dict[str, Any] = {}
        telegram = notifications.get("telegram", {})
        if telegram is not None:
            if not isinstance(telegram, dict):
                raise HTTPException(status_code=400, detail="notifications.telegram must be an object")
            normalized_notifications["telegram"] = {
                "enabled": _normalize_bool_or_400(telegram.get("enabled"), field_name="notifications.telegram.enabled", default=False),
                "bot_token": _sanitize_text_or_400(telegram.get("bot_token"), field_name="notifications.telegram.bot_token", max_length=512),
                "chat_id": _sanitize_text_or_400(telegram.get("chat_id"), field_name="notifications.telegram.chat_id", max_length=128),
            }

        for channel in ("slack", "discord"):
            channel_data = notifications.get(channel, {})
            if channel_data is None:
                continue
            if not isinstance(channel_data, dict):
                raise HTTPException(status_code=400, detail=f"notifications.{channel} must be an object")
            normalized_notifications[channel] = {
                "enabled": _normalize_bool_or_400(
                    channel_data.get("enabled"),
                    field_name=f"notifications.{channel}.enabled",
                    default=False,
                ),
                "webhook_url": _sanitize_text_or_400(
                    channel_data.get("webhook_url"),
                    field_name=f"notifications.{channel}.webhook_url",
                    max_length=1024,
                ),
            }

        email = notifications.get("email", {})
        if email is not None:
            if not isinstance(email, dict):
                raise HTTPException(status_code=400, detail="notifications.email must be an object")
            smtp_port = _parse_bounded_int_or_400(
                email.get("smtp_port"),
                field_name="notifications.email.smtp_port",
                minimum=1,
                maximum=65535,
            )
            normalized_notifications["email"] = {
                "enabled": _normalize_bool_or_400(email.get("enabled"), field_name="notifications.email.enabled", default=False),
                "smtp_host": _sanitize_text_or_400(email.get("smtp_host"), field_name="notifications.email.smtp_host", max_length=255),
                "smtp_port": smtp_port if smtp_port is not None else 587,
                "to": _sanitize_text_or_400(email.get("to"), field_name="notifications.email.to", max_length=320),
            }
        normalized["notifications"] = normalized_notifications

    general = data.get("general", {})
    if general is not None:
        if not isinstance(general, dict):
            raise HTTPException(status_code=400, detail="general must be an object")
        log_level = _sanitize_text_or_400(general.get("log_level"), field_name="general.log_level", max_length=16)
        if log_level and log_level.lower() not in {"debug", "info", "warning", "error", "critical"}:
            raise HTTPException(status_code=400, detail="general.log_level must be one of: debug, info, warning, error, critical")
        default_profile = _sanitize_text_or_400(general.get("default_profile"), field_name="general.default_profile", max_length=64)
        if default_profile:
            _normalize_profile_or_400(default_profile)
        retention_days = _parse_bounded_int_or_400(
            general.get("retention_days"),
            field_name="general.retention_days",
            minimum=1,
            maximum=3650,
        )
        normalized["general"] = {
            "default_profile": default_profile,
            "log_level": log_level.lower() if log_level else "",
            "auto_cleanup": _normalize_bool_or_400(general.get("auto_cleanup"), field_name="general.auto_cleanup", default=False),
            "retention_days": retention_days if retention_days is not None else 30,
        }

    profiles = data.get("profiles")
    if profiles is not None:
        if not isinstance(profiles, list):
            raise HTTPException(status_code=400, detail="profiles must be a list")
        if len(profiles) > 200:
            raise HTTPException(status_code=400, detail="profiles list exceeds max items (200)")
        normalized_profiles: List[str] = []
        seen_profiles = set()
        for raw_profile in profiles:
            if not isinstance(raw_profile, str):
                raise HTTPException(status_code=400, detail="profiles must contain strings only")
            profile_name = _normalize_profile_or_400(raw_profile)
            if profile_name not in seen_profiles:
                seen_profiles.add(profile_name)
                normalized_profiles.append(profile_name)
        normalized["profiles"] = normalized_profiles

    return normalized


def _validate_notification_payload_or_400(data: Dict[str, Any]) -> Dict[str, Any]:
    channel = _sanitize_text_or_400(data.get("channel"), field_name="channel", max_length=32, required=True).lower()
    if channel not in ALLOWED_NOTIFICATION_CHANNELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid channel '{channel}'. Allowed: {', '.join(sorted(ALLOWED_NOTIFICATION_CHANNELS))}",
        )
    if channel == "telegram":
        required_keys = {"channel", "bot_token", "chat_id"}
        unexpected = sorted(set(data.keys()) - required_keys)
        if unexpected:
            raise HTTPException(status_code=400, detail=f"Unsupported telegram payload keys: {', '.join(unexpected)}")
        return {
            "channel": channel,
            "bot_token": _sanitize_text_or_400(data.get("bot_token"), field_name="bot_token", max_length=512, required=True),
            "chat_id": _sanitize_text_or_400(data.get("chat_id"), field_name="chat_id", max_length=128, required=True),
        }
    if channel in {"slack", "discord"}:
        required_keys = {"channel", "webhook_url"}
        unexpected = sorted(set(data.keys()) - required_keys)
        if unexpected:
            raise HTTPException(status_code=400, detail=f"Unsupported {channel} payload keys: {', '.join(unexpected)}")
        webhook_url = _sanitize_text_or_400(data.get("webhook_url"), field_name="webhook_url", max_length=1024, required=True)
        if not webhook_url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="webhook_url must start with http:// or https://")
        return {"channel": channel, "webhook_url": webhook_url}
    required_keys = {"channel", "smtp_host", "smtp_port", "to"}
    unexpected = sorted(set(data.keys()) - required_keys)
    if unexpected:
        raise HTTPException(status_code=400, detail=f"Unsupported email payload keys: {', '.join(unexpected)}")
    smtp_port = _parse_bounded_int_or_400(data.get("smtp_port"), field_name="smtp_port", minimum=1, maximum=65535)
    return {
        "channel": channel,
        "smtp_host": _sanitize_text_or_400(data.get("smtp_host"), field_name="smtp_host", max_length=255, required=True),
        "smtp_port": smtp_port if smtp_port is not None else 587,
        "to": _sanitize_text_or_400(data.get("to"), field_name="to", max_length=320, required=True),
    }


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
            "enable_idor_validator",
            "enable_ssrf_validator",
            "enable_open_redirect_validator",
            "enable_auth_bypass_validator",
            "enable_exploit_validation",
        ])
    if "secrets" not in selected_set:
        disable(["enable_secrets", "enable_secret_exposure_validator"])
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

        stats = record.metadata.stats or {}
        quality = stats.get("quality") if isinstance(stats, dict) else None
        display_stats = {
            key: value for key, value in stats.items()
            if key not in {"quality"} and not isinstance(value, (dict, list))
        }
        
        job = {
            "id": job_id,
            "status": record.metadata.status,
            "target": record.spec.target if hasattr(record.spec, 'target') else None,
            "profile": record.spec.profile if hasattr(record.spec, 'profile') else None,
            "started_at": record.metadata.started_at,
            "finished_at": record.metadata.finished_at,
            "stage": record.metadata.stage,
            "stats": display_stats,
            "error": record.metadata.error,
            "quality": quality,
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
            data = await _parse_json_object_or_400(request, max_bytes=MAX_SCAN_PAYLOAD_BYTES)
            unexpected = sorted(set(data.keys()) - ALLOWED_SCAN_KEYS)
            if unexpected:
                raise HTTPException(status_code=400, detail=f"Unsupported scan payload keys: {', '.join(unexpected)}")

            targets = _normalize_and_validate_targets_or_400(data)
            profile = _normalize_profile_or_400(data.get("profile", "passive"))
            scan_mode = _sanitize_text_or_400(data.get("scanMode", "queued"), field_name="scanMode", max_length=32).lower()
            stages = _normalize_stage_groups_or_400(data.get("stages"))
            passive_only = _normalize_bool_or_400(data.get("passive"), field_name="passive", default=False)
            _normalize_bool_or_400(data.get("notify"), field_name="notify", default=False)

            if scan_mode not in ALLOWED_SCAN_MODES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid scanMode '{scan_mode}'. Allowed: {', '.join(sorted(ALLOWED_SCAN_MODES))}",
                )
            resolvers = _sanitize_text_or_400(data.get("resolvers", "default"), field_name="resolvers", max_length=32).lower()
            if resolvers not in ALLOWED_RESOLVERS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid resolvers '{resolvers}'. Allowed: {', '.join(sorted(ALLOWED_RESOLVERS))}",
                )

            if passive_only:
                profile = "passive"

            runtime_overrides: Dict[str, Any] = {}
            threads = _parse_bounded_int_or_400(data.get("threads"), field_name="threads", minimum=1, maximum=500)
            if threads is not None:
                runtime_overrides["httpx_threads"] = threads
                runtime_overrides["ffuf_threads"] = max(5, int(threads // 2))
            timeout = _parse_bounded_int_or_400(data.get("timeout"), field_name="timeout", minimum=5, maximum=3600)
            if timeout is not None:
                runtime_overrides["timeout_http"] = timeout
            rate_limit = _parse_bounded_int_or_400(data.get("rate_limit"), field_name="rate_limit", minimum=1, maximum=5000)
            if rate_limit is not None:
                runtime_overrides["requests_per_second"] = rate_limit
                runtime_overrides["per_host_limit"] = max(1, int(rate_limit // 4))

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
            data = await _parse_json_object_or_400(
                request,
                max_bytes=MAX_SETTINGS_BYTES,
                error_prefix="Settings payload must be a JSON object",
            )
            normalized = _validate_settings_payload_or_400(data)
            serialized = json.dumps(normalized, indent=2)
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
            data = await _parse_json_object_or_400(request, max_bytes=MAX_NOTIFICATION_PAYLOAD_BYTES)
            payload = _validate_notification_payload_or_400(data)
            channel = payload["channel"]
            
            # Import alerting module
            from recon_cli.utils.alerting import AlertManager
            
            manager = AlertManager()
            success = await manager.send_test(channel, payload)
            
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
