from __future__ import annotations

import json
import logging
import os
import time
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich import print as rich_print

from recon_cli import config
from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.pipeline.runner import run_pipeline
from recon_cli.utils import fs
from recon_cli.utils import validation
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.sanitizer import redact
from recon_cli.active import modules as active_modules
from recon_cli.tools.executor import CommandExecutor

app = typer.Typer(
    help="Run the reconnaissance pipeline end-to-end (passive discovery -> runtime crawl -> reporting).",
    add_completion=False,
)


@app.callback()
def cli_entry(ctx: typer.Context, verbose: int = typer.Option(0, '--verbose', '-v', help='Increase log verbosity (-v info, -vv/-vvv debug)', count=True)) -> None:
    """Configure logging and shared context before dispatching commands."""
    if verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.INFO
    config.LOG_LEVEL = level
    logging.getLogger().setLevel(level)
    config.ensure_base_directories()

BASE_PROFILES = {"passive", "full", "fuzz-only"}
PROFILE_PRESETS = config.available_profiles()
PROFILE_CHOICES = sorted(BASE_PROFILES | set(PROFILE_PRESETS.keys()))
PROFILE_PRESET_NAMES = sorted(PROFILE_PRESETS.keys())
if PROFILE_PRESET_NAMES:
    PROFILE_HELP = "Scan profile (base: passive/full/fuzz-only; presets: {names})".format(names=", ".join(PROFILE_PRESET_NAMES))
else:
    PROFILE_HELP = "Scan profile (base: passive/full/fuzz-only)"
ACTIVE_MODULE_CHOICES = active_modules.available_modules()
ACTIVE_MODULE_HELP = "none available" if not ACTIVE_MODULE_CHOICES else ", ".join(ACTIVE_MODULE_CHOICES)
SCANNER_CHOICES = ["nuclei", "wpscan"]
SCANNER_HELP = ", ".join(SCANNER_CHOICES)
STATUS_CHOICES = ["queued", "running", "finished", "failed"]


def _print_job(metadata) -> None:
    rich_print(f"[bold]Job {metadata.job_id}[/bold]")
    rich_print(f"  status     : {metadata.status}")
    rich_print(f"  stage      : {metadata.stage}")
    rich_print(f"  queued_at  : {metadata.queued_at}")
    rich_print(f"  started_at : {metadata.started_at}")
    rich_print(f"  finished_at: {metadata.finished_at}")
    rich_print(f"  error      : {metadata.error}")


def _load_job_or_exit(manager: JobManager, job_id: str) -> JobRecord:
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=3)
    return record


def _auto_allow_ip(target_value: str) -> bool:
    try:
        candidate = validation._coerce_hostname(target_value)
    except Exception:
        candidate = target_value
    return validation.is_ip(candidate)


@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Domain or hostname to scan"),
    profile: str = typer.Option("passive", "--profile", case_sensitive=False, help=PROFILE_HELP, show_default=True),
    quickstart: bool = typer.Option(False, "--quickstart", help="Use the quick profile if available (passive-minimal)"),
    project: Optional[str] = typer.Option(None, "--project", help="Associate job with a project name"),
    incremental_from: Optional[str] = typer.Option(None, "--incremental-from", help="Job ID to reuse artifacts (incremental recon)"),
    inline: bool = typer.Option(False, "--inline", help="Run the pipeline immediately"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Override default wordlist"),
    max_screenshots: Optional[int] = typer.Option(None, "--max-screenshots", min=0, help="Limit screenshots"),
    force: bool = typer.Option(False, "--force", help="Re-run all stages even if checkpoints exist"),
    allow_ip: bool = typer.Option(False, "--allow-ip", help="Allow IP addresses as targets"),
    targets_file: Optional[Path] = typer.Option(None, "--targets-file", exists=True, file_okay=True, dir_okay=False, readable=True, help="File with multiple targets"),
    active_module: List[str] = typer.Option(
        [],
        "--active-module",
        help=f"Enable active intelligence module (repeatable). Choices: {ACTIVE_MODULE_HELP}",
        show_default=False,
    ),
    scanner: List[str] = typer.Option(
        [],
        "--scanner",
        help=f"Trigger smart scanner integration (repeatable). Choices: {SCANNER_HELP}",
        show_default=False,
    ),
    insecure: bool = typer.Option(False, "--insecure", help="Disable TLS verification for HTTP requests (not recommended)"),
    split_targets: bool = typer.Option(False, "--split-targets", help="When using --targets-file, create one job per target"),
) -> None:
    """Launch a reconnaissance job across the staged pipeline."""
    profile_input = profile.lower()
    available_profiles = config.available_profiles()
    profile_choices = BASE_PROFILES | set(available_profiles.keys())
    if quickstart and "quick" in available_profiles:
        profile_input = "quick"
    elif quickstart and "quick" not in available_profiles:
        profile_input = "passive"
    if profile_input not in profile_choices:
        typer.echo(f"Invalid profile: {profile_input}", err=True)
        raise typer.Exit(code=2)
    profile_errors = config.profile_errors()
    if profile_errors:
        for err in profile_errors:
            typer.echo(f"[warn] profile config: {err}", err=True)
    profile_config = available_profiles.get(profile_input)
    runtime_overrides: Dict[str, Any] = {}
    execution_profile: Optional[str] = None
    base_profile = profile_input
    if profile_config:
        execution_profile = profile_input
        base_profile = str(profile_config.get("base_profile", "full")).lower()
        runtime_values = profile_config.get("runtime", {})
        if isinstance(runtime_values, dict):
            runtime_overrides = dict(runtime_values)
    if base_profile not in BASE_PROFILES:
        typer.echo(f"Profile preset maps to unknown base profile: {base_profile}", err=True)
        raise typer.Exit(code=1)
    selected_profile = base_profile
    profile = selected_profile

    if not target and not targets_file:
        typer.echo("Provide either a target or --targets-file", err=True)
        raise typer.Exit(code=1)

    auto_allow = allow_ip
    if not allow_ip:
        if target and _auto_allow_ip(target):
            auto_allow = True
        elif targets_file:
            try:
                for line in Path(targets_file).read_text(encoding="utf-8").splitlines():
                    if line.strip() and _auto_allow_ip(line.strip()):
                        auto_allow = True
                        break
            except Exception:
                auto_allow = allow_ip
    allow_ip = auto_allow

    modules = [module.strip().lower() for module in active_module if module]
    env_active = os.environ.get("RECON_ACTIVE_MODULES")
    if not modules and env_active:
        modules = [part.strip().lower() for part in env_active.split(",") if part.strip()]
    invalid = [module for module in modules if module not in ACTIVE_MODULE_CHOICES]
    if invalid:
        typer.echo(f"Unknown active modules: {', '.join(invalid)}", err=True)
        raise typer.Exit(code=1)

    scanners = [item.strip().lower() for item in scanner if item]
    env_scanners = os.environ.get("RECON_SCANNERS")
    if not scanners and env_scanners:
        scanners = [part.strip().lower() for part in env_scanners.split(",") if part.strip()]
    invalid_scanners = [item for item in scanners if item not in SCANNER_CHOICES]
    if invalid_scanners:
        typer.echo(f"Unknown scanners: {', '.join(invalid_scanners)}", err=True)
        raise typer.Exit(code=1)

    manager = JobManager()
    created: list[str] = []
    if split_targets and targets_file:
        target_lines = Path(targets_file).read_text(encoding="utf-8").splitlines()
        targets_list = [line.strip() for line in target_lines if line.strip()]
        if not targets_list:
            typer.echo("No targets found in file", err=True)
            raise typer.Exit(code=1)
        for tgt in targets_list:
            target_allow_ip = allow_ip or _auto_allow_ip(tgt)
            record = manager.create_job(
                target=tgt,
                profile=selected_profile,
                inline=inline,
                project=project,
                wordlist=str(wordlist) if wordlist else None,
                targets_file=None,
                max_screenshots=max_screenshots,
                force=force,
                allow_ip=target_allow_ip,
                active_modules=modules,
                scanners=scanners,
                execution_profile=execution_profile,
                runtime_overrides=runtime_overrides,
                insecure=insecure,
                incremental_from=incremental_from,
            )
            created.append(record.spec.job_id)
        typer.echo(f"Jobs created: {', '.join(created)}")
        return
    record = manager.create_job(
        target=target or "",
        profile=selected_profile,
        inline=inline,
        project=project,
        wordlist=str(wordlist) if wordlist else None,
        targets_file=str(targets_file) if targets_file else None,
        max_screenshots=max_screenshots,
        force=force,
        allow_ip=allow_ip,
        active_modules=modules,
        scanners=scanners,
        execution_profile=execution_profile,
        runtime_overrides=runtime_overrides,
        insecure=insecure,
        incremental_from=incremental_from,
    )
    job_id = record.spec.job_id
    typer.echo(f"Job created: {job_id}")
    if inline:
        lifecycle = JobLifecycle(manager)
        running_record = lifecycle.move_to_running(job_id)
        if not running_record:
            typer.echo("Failed to transition job to running", err=True)
            raise typer.Exit(code=1)
        try:
            run_pipeline(running_record, manager, force=force)
        except Exception as exc:  # pragma: no cover - runtime path
            typer.echo(f"Pipeline failed: {exc}", err=True)
            lifecycle.move_to_failed(job_id)
            raise typer.Exit(code=1)
        lifecycle.move_to_finished(job_id)
        finished_results = config.FINISHED_JOBS / job_id / config.RESULTS_TEXT_NAME
        typer.echo(f"Job {job_id} finished -> {finished_results}")


@app.command("worker-run")
def worker_run(
    poll_interval: int = typer.Option(5, "--poll-interval", min=1, help="Seconds between queue checks"),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        min=1,
        help="Number of worker loops to run concurrently",
    ),
) -> None:
    """Run the job worker loop that pulls queued scans and executes the pipeline."""
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    typer.echo(f"Worker started with {max_workers} worker(s); press Ctrl+C to stop")
    stop_event = False

    def worker_loop(name: str) -> None:
        nonlocal stop_event
        while not stop_event:
            queued = manager.list_jobs("queued")
            if not queued:
                time.sleep(poll_interval)
                continue
            job_id = queued[0]
            record = lifecycle.move_to_running(job_id, owner=name)
            if not record:
                time.sleep(0.2)
                continue
            typer.echo(f"[{name}] Processing job {job_id}")
            try:
                run_pipeline(record, manager, force=record.spec.force)
            except Exception as exc:  # pragma: no cover - runtime path
                typer.echo(f"[{name}] Job {job_id} failed: {exc}", err=True)
                lifecycle.move_to_failed(job_id)
            else:
                lifecycle.move_to_finished(job_id)

    workers: list[threading.Thread] = []
    for idx in range(max_workers):
        t = threading.Thread(target=worker_loop, args=(f"worker-{idx+1}",), daemon=True)
        workers.append(t)
        t.start()

    try:
        while any(t.is_alive() for t in workers):
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event = True
        typer.echo("Worker stopped")


@app.command()
def status(job_id: str) -> None:
    """Show the latest metadata for a job."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    _print_job(record.metadata)


@app.command("tail-logs")
def tail_logs(job_id: str) -> None:
    """Stream the pipeline log for a running or finished job."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    log_path = record.paths.pipeline_log
    if not log_path.exists():
        typer.echo("Log file not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Tailing {log_path} (Ctrl+C to exit)")
    try:
        with log_path.open("r", encoding="utf-8") as handle:
            handle.seek(0, 2)
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                typer.echo(line.rstrip())
    except KeyboardInterrupt:
        typer.echo("Stopped tailing")


@app.command("list-jobs")
def list_jobs(
    status: Optional[str] = typer.Argument(None, help="Optional status filter"),
    project: Optional[str] = typer.Option(None, "--project", help="Filter jobs by project"),
) -> None:
    """List jobs, optionally filtered by status or project."""
    if status and status not in STATUS_CHOICES:
        typer.echo(f"Invalid status filter: {status}", err=True)
        raise typer.Exit(code=1)
    manager = JobManager()
    job_ids = manager.list_jobs(status)
    if not job_ids:
        typer.echo("No jobs found")
        return
    for job_id in job_ids:
        typer.echo(job_id)


@app.command()
def requeue(job_id: str) -> None:
    """Move a finished or failed job back into the queue."""
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    record = lifecycle.requeue(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Job {job_id} moved to queue")


@app.command()
def doctor(fix: bool = typer.Option(False, "--fix", help="Attempt to regenerate default configs/resolvers")) -> None:
    """Run quick environment & source sanity checks."""
    config.ensure_base_directories(force=fix)
    import io
    import tokenize
    import subprocess

    source_root = Path(__file__).resolve().parent
    issues: list[str] = []

    for py_file in source_root.rglob("*.py"):
        with py_file.open("r", encoding="utf-8") as handle:
            stream = io.StringIO(handle.read())
        for token in tokenize.generate_tokens(stream.readline):
            if token.type == tokenize.OP and token.string == "...":
                issues.append(f"ellipsis operator found in {py_file}:{token.start[0]}")

    def _version_line(tool: str, args: List[str]) -> str:
        try:
            completed = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            return ""
        output = (completed.stdout or "") + (completed.stderr or "")
        output = output.strip()
        if not output:
            return ""
        return output.splitlines()[0][:120]

    tool_checks = [
        ("subfinder", ["-version"], "install via go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("amass", ["-version"], "install via go install github.com/owasp-amass/amass/v4/...@latest"),
        ("massdns", ["-h"], "install from https://github.com/blechschmidt/massdns"),
        ("httpx", ["-version"], "install via go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("ffuf", ["-V"], "install via go install github.com/ffuf/ffuf@latest"),
        ("nuclei", ["-version"], "install via go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("naabu", ["-version"], "install via go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        ("katana", ["-version"], "install via go install github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("dalfox", ["version"], "install via go install github.com/hahwul/dalfox/v2@latest"),
        ("sqlmap", ["--version"], "install via pipx install sqlmap or apt install sqlmap"),
        ("nmap", ["--version"], "install via apt install nmap"),
        ("wpscan", ["--version"], "install via gem install wpscan"),
        ("droopescan", ["--version"], "install via pipx install droopescan or pip install droopescan"),
        ("joomscan", ["--version"], "install via apt install joomscan"),
        ("interactsh-client", ["-version"], "install via go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
        ("waybackurls", ["-h"], "install via go install github.com/tomnomnom/waybackurls@latest"),
        ("gau", ["-h"], "install via go install github.com/lc/gau/v2/cmd/gau@latest"),
    ]
    tool_results: list[tuple[str, str, str]] = []
    for tool, version_args, hint in tool_checks:
        if not CommandExecutor.available(tool):
            tool_results.append((tool, "missing", ""))
            if tool not in {"waybackurls", "gau"}:
                typer.echo(f"[warn] tool '{tool}' not found in PATH ({hint})")
            continue
        version = _version_line(tool, version_args)
        tool_results.append((tool, "ok", version))

    if not (CommandExecutor.available("waybackurls") or CommandExecutor.available("gau")):
        typer.echo("[warn] tool 'waybackurls' or 'gau' not found in PATH (install via go install github.com/tomnomnom/waybackurls@latest or go install github.com/lc/gau/v2/cmd/gau@latest)")

    typer.echo("")
    typer.echo("== Tool Health ==")
    for tool, status, version in tool_results:
        if status == "missing":
            typer.echo(f"{tool:12} : missing")
        else:
            suffix = f" ({version})" if version else ""
            typer.echo(f"{tool:12} : ok{suffix}")

    try:
        __import__("recon_cli.pipeline.stage_idor")
        __import__("recon_cli.pipeline.stage_auth_matrix")
    except Exception as exc:
        issues.append(f"stage import failed: {exc}")

    if issues:
        for issue in issues:
            typer.echo(f"[fail] {issue}")
        raise typer.Exit(code=1)

    typer.secho("All checks passed", fg=typer.colors.GREEN)



@app.command()
def prune(
    days: int = typer.Option(None, "--days", min=1, help="Remove finished jobs older than N days", show_default=False),
    archive: bool = typer.Option(False, "--archive", help="Move jobs to archive instead of deleting"),
) -> None:
    """Delete or archive finished jobs older than the given number of days."""
    if days is None:
        raise typer.BadParameter("--days is required", param_name="--days")
    manager = JobManager()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    finished_dir = config.FINISHED_JOBS
    if not finished_dir.exists():
        typer.echo("No finished jobs")
        return
    removed = 0
    for job_dir in finished_dir.iterdir():
        if not job_dir.is_dir():
            continue
        metadata_path = job_dir / config.METADATA_NAME
        payload = fs.read_json(metadata_path, default=None)
        if not payload:
            continue
        finished_at = payload.get("finished_at")
        if not finished_at:
            continue
        try:
            finished_ts = datetime.strptime(finished_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if finished_ts > cutoff:
            continue
        if archive:
            archive_path = config.ARCHIVE_ROOT / job_dir.name
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            if archive_path.exists():
                typer.echo(f"Archive target exists, skipping {job_dir.name}", err=True)
                continue
            fs.safe_move(job_dir, archive_path)
        else:
            manager.remove_job(job_dir.name)
        removed += 1
    typer.echo(f"Pruned {removed} jobs")


@app.command()
def export(job_id: str, fmt: str = typer.Option("jsonl", "--format", case_sensitive=False, help="Export format: jsonl|txt|zip")) -> None:
    """Export job artifacts in JSONL, text summary, or ZIP form."""
    fmt = fmt.lower()
    if fmt not in {"jsonl", "txt", "zip"}:
        typer.echo(f"Unsupported format: {fmt}", err=True)
        raise typer.Exit(code=1)
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    if fmt == "jsonl":
        payload = record.paths.results_jsonl.read_text(encoding="utf-8")
        typer.echo(redact(payload) or payload)
    elif fmt == "txt":
        payload = record.paths.results_txt.read_text(encoding="utf-8")
        typer.echo(redact(payload) or payload)
    else:
        import shutil

        archive_path = config.RECON_HOME / f"{job_id}.zip"
        if archive_path.exists():
            archive_path.unlink()
        shutil.make_archive(str(archive_path.with_suffix("")), "zip", record.paths.root)
        typer.echo(str(archive_path))


@app.command()
def report(job_id: str, fmt: str = typer.Option("txt", "--format", case_sensitive=False, help="Report format: txt|md|json|html")) -> None:
    """Emit a shareable report for a finished job."""
    fmt = fmt.lower()
    if fmt not in {"txt", "md", "json", "html"}:
        typer.echo(f"Unsupported format: {fmt}", err=True)
        raise typer.Exit(code=1)
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    if fmt == "txt":
        typer.echo(record.paths.results_txt.read_text(encoding="utf-8"))
        return
    if fmt == "md":
        content = record.paths.results_txt.read_text(encoding="utf-8")
        md_lines = ["# recon-cli report", f"Job: {job_id}", "", "```", content.strip(), "```"]
        typer.echo("\n".join(md_lines))
        return
    if fmt == "html":
        from recon_cli.utils.reporter import generate_html_report
        output_path = record.paths.root / "report.html"
        generate_html_report(record.paths.root, output_path)
        typer.secho(f"✅ HTML report generated: {output_path}", fg=typer.colors.GREEN)
        return
    payload = {
        "job_id": job_id,
        "spec": record.spec.to_dict(),
        "metadata": record.metadata.to_dict(),
        "stats": record.metadata.stats,
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("verify-job")
def verify_job(job_id: str) -> None:
    """Validate job files and surface corruption/errors."""
    from recon_cli.jobs.validator import validate_job

    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    issues = validate_job(record)
    if not issues:
        typer.secho(f"Job {job_id} OK", fg=typer.colors.GREEN)
        return
    typer.echo(f"Job {job_id} has {len(issues)} issue(s):", err=True)
    for issue in issues:
        typer.echo(f"- {issue}", err=True)
    raise typer.Exit(code=4)


@app.command()
def projects() -> None:
    """List configured projects."""
    from recon_cli import projects as projects_mod

    names = projects_mod.list_projects()
    if not names:
        typer.echo("No projects found")
        return
    for name in names:
        typer.echo(name)


@app.command()
def schema(fmt: str = typer.Option("json", "--format", help="Output format: json")) -> None:
    """Emit machine-readable schema for automation clients."""
    from recon_cli import api

    fmt = fmt.lower()
    if fmt != "json":
        typer.echo(f"Unsupported format: {fmt}", err=True)
        raise typer.Exit(code=1)
    typer.echo(api.schema_json())


@app.command("cache-stats")
def cache_stats() -> None:
    """Show cache statistics."""
    from recon_cli.utils.cache import HybridCache
    cache = HybridCache(config.RECON_HOME / "cache")
    stats = cache.stats()
    rich_print("[bold]📊 Cache Statistics[/bold]")
    rich_print(f"  Memory hits  : {stats.get('memory_hits', 0)}")
    rich_print(f"  Memory misses: {stats.get('memory_misses', 0)}")
    rich_print(f"  Disk hits    : {stats.get('disk_hits', 0)}")
    rich_print(f"  Disk misses  : {stats.get('disk_misses', 0)}")
    rich_print(f"  Disk size    : {stats.get('disk_size', 0)} bytes")


@app.command("cache-clear")
def cache_clear() -> None:
    """Clear all cached data."""
    from recon_cli.utils.cache import HybridCache
    cache = HybridCache(config.RECON_HOME / "cache")
    cache.clear()
    typer.secho("✅ Cache cleared", fg=typer.colors.GREEN)


@app.command("serve")
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind"),
    port: int = typer.Option(8080, "--port", help="Port to bind"),
) -> None:
    """Start the REST API server."""
    try:
        import uvicorn
        from recon_cli.api.app import app as api_app
        typer.secho(f"🚀 Starting API server at http://{host}:{port}", fg=typer.colors.GREEN)
        typer.echo("   Docs: http://{host}:{port}/docs")
        uvicorn.run(api_app, host=host, port=port)
    except ImportError:
        typer.echo("❌ FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn", err=True)
        raise typer.Exit(code=1)


@app.command("dashboard")
def dashboard(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind"),
    port: int = typer.Option(8080, "--port", help="Port to bind"),
) -> None:
    """Start the web dashboard."""
    try:
        from recon_cli.web.app import run_dashboard
        run_dashboard(host=host, port=port)
    except ImportError as e:
        typer.echo(f"❌ Missing dependencies: {e}", err=True)
        typer.echo("Run: pip install fastapi uvicorn jinja2", err=True)
        raise typer.Exit(code=1)


@app.command("notify")
def notify(
    message: str = typer.Argument("", help="Message to send"),
    channel: str = typer.Option("telegram", "--channel", "-c", help="Channel: telegram, slack, discord, email"),
) -> None:
    """Send a notification to configured channels."""
    from recon_cli.utils.notify import NotificationManager, NotificationConfig

    if not message:
        raise typer.BadParameter("message is required")
    
    # Load config from environment or defaults
    import os
    cfg = NotificationConfig(
        telegram_token=os.environ.get("TELEGRAM_TOKEN"),
        telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID"),
        slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL"),
        discord_webhook_url=os.environ.get("DISCORD_WEBHOOK_URL"),
    )
    
    manager = NotificationManager(cfg)
    results = manager.send(message, channels=[channel])
    
    for ch, success in results.items():
        if success:
            typer.secho(f"✅ {ch}: Message sent", fg=typer.colors.GREEN)
        else:
            typer.secho(f"❌ {ch}: Failed to send", fg=typer.colors.RED)


@app.command("db-init")
def db_init() -> None:
    """Initialize the SQLite database."""
    from recon_cli.db.models import init_db, get_db_path
    init_db()
    typer.secho(f"✅ Database initialized at {get_db_path()}", fg=typer.colors.GREEN)


@app.command("db-stats")
def db_stats() -> None:
    """Show database statistics."""
    from recon_cli.db.storage import get_dashboard_stats
    stats = get_dashboard_stats()
    
    rich_print("[bold]📊 Database Statistics[/bold]")
    rich_print("\n[bold]Jobs:[/bold]")
    for status, count in stats.get("jobs", {}).items():
        rich_print(f"  {status}: {count}")
    
    rich_print("\n[bold]Vulnerabilities:[/bold]")
    for severity, count in stats.get("vulnerabilities", {}).items():
        rich_print(f"  {severity}: {count}")


@app.command("optimize")
def optimize() -> None:
    """Run performance optimizations."""
    from recon_cli.utils.performance import optimize_memory, get_pool
    
    rich_print("[bold]🔧 Running optimizations...[/bold]")
    
    # Memory optimization
    result = optimize_memory()
    rich_print(f"  Resources cleaned: {result['resources_cleaned']}")
    
    # Pool stats
    pool = get_pool()
    pool_stats = pool.stats()
    rich_print(f"  Active sessions: {pool_stats['active_sessions']}")
    
    typer.secho("✅ Optimization complete", fg=typer.colors.GREEN)


@app.command("pdf")
def pdf_report(
    job_id: str = typer.Argument("", help="Job ID to generate PDF report for"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    title: str = typer.Option("تقرير الاستطلاع الأمني", "--title", help="Report title"),
) -> None:
    """Generate PDF report for a job."""
    from recon_cli.utils.pdf_reporter import generate_pdf_report, PDFReportConfig

    if not job_id:
        raise typer.BadParameter("job_id is required")
    
    manager = JobManager()
    record = manager.load_job(job_id)
    
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=3)
    
    job_path = record.path
    
    config = PDFReportConfig(
        title=title,
        company_name="ReconnV2"
    )
    
    try:
        pdf_path = generate_pdf_report(job_path, output, config)
        typer.secho(f"✅ PDF report generated: {pdf_path}", fg=typer.colors.GREEN)
    except RuntimeError as e:
        typer.secho(f"❌ Error: {e}", fg=typer.colors.RED)
        typer.secho("💡 Install dependencies with: pip install weasyprint reportlab", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)


@app.command("plugins")
def list_plugins(
    plugin_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by type: scanner, enricher, reporter, notifier"),
) -> None:
    """List available plugins."""
    from recon_cli.plugins import get_registry, PluginType
    
    registry = get_registry()
    registry.setup()
    
    type_filter = None
    if plugin_type:
        try:
            type_filter = PluginType(plugin_type.lower())
        except ValueError:
            typer.secho(f"Invalid type: {plugin_type}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
    
    plugins = registry.loader.list_plugins(plugin_type=type_filter)
    
    if not plugins:
        typer.secho("No plugins found", fg=typer.colors.YELLOW)
        return
    
    rich_print("[bold]📦 Available Plugins[/bold]")
    for meta in plugins:
        rich_print(f"\n[bold cyan]{meta.name}[/bold cyan] v{meta.version}")
        rich_print(f"  Type: {meta.plugin_type.value}")
        rich_print(f"  Description: {meta.description}")
        rich_print(f"  Author: {meta.author}")
        if meta.tags:
            rich_print(f"  Tags: {', '.join(meta.tags)}")


@app.command("run-plugin")
def run_plugin(
    name: str = typer.Argument("", help="Plugin name to run"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target for scanner plugins"),
    message: Optional[str] = typer.Option(None, "--message", "-m", help="Message for notifier plugins"),
) -> None:
    """Run a plugin."""
    from recon_cli.plugins import get_registry

    if not name:
        raise typer.BadParameter("name is required")
    
    registry = get_registry()
    registry.setup()
    
    context = {}
    if target:
        context["target"] = target
    if message:
        context["message"] = message
    
    result = registry.loader.execute_plugin(name, context)
    
    if result.success:
        typer.secho(f"✅ Plugin executed successfully", fg=typer.colors.GREEN)
        if result.data:
            rich_print(f"  Result: {result.data}")
        rich_print(f"  Execution time: {result.execution_time:.2f}s")
    else:
        typer.secho(f"❌ Plugin failed: {result.error}", fg=typer.colors.RED)


# ============================================================================
# INTERACTIVE MODE & WIZARD COMMANDS
# ============================================================================

@app.command("interactive")
def interactive_mode() -> None:
    """Start interactive wizard mode for guided scanning."""
    try:
        from recon_cli.cli_wizard import InteractiveMode
        
        rich_print("[bold cyan]🧙 ReconnV2 Interactive Mode[/bold cyan]")
        rich_print("Type 'help' for available commands, 'quit' to exit.\n")
        
        mode = InteractiveMode()
        mode.run()
    except ImportError as e:
        typer.secho(f"Interactive mode not available: {e}", fg=typer.colors.RED)
    except KeyboardInterrupt:
        rich_print("\n[yellow]Exiting interactive mode...[/yellow]")


@app.command("wizard")
def scan_wizard() -> None:
    """Launch step-by-step scan configuration wizard."""
    try:
        from recon_cli.cli_wizard import ScanWizard
        
        rich_print("[bold cyan]🧙 Scan Configuration Wizard[/bold cyan]\n")
        
        wizard = ScanWizard()
        result = wizard.run()
        
        if result.completed:
            rich_print("\n[bold green]✅ Wizard completed![/bold green]")
            rich_print(f"Configuration: {json.dumps(result.data, indent=2)}")
            
            # Ask to run scan
            if typer.confirm("Run scan with this configuration?"):
                spec = result.data
                scan(
                    target=spec.get("target"),
                    profile=spec.get("profile", "passive"),
                    inline=True,
                )
        else:
            rich_print("[yellow]Wizard cancelled.[/yellow]")
    except ImportError as e:
        typer.secho(f"Wizard not available: {e}", fg=typer.colors.RED)


# ============================================================================
# SHELL COMPLETIONS
# ============================================================================

@app.command("completions")
def setup_completions(
    shell: str = typer.Option(None, "--shell", "-s", help="Shell type: bash, zsh, fish, powershell"),
    install: bool = typer.Option(False, "--install", "-i", help="Auto-install completions"),
    show: bool = typer.Option(False, "--show", help="Show completion script without installing"),
) -> None:
    """Generate or install shell completions."""
    try:
        from recon_cli.completions import CompletionGenerator, CompletionInstaller, Shell
        
        # Auto-detect shell if not specified
        if not shell:
            import os
            shell_env = os.environ.get("SHELL", "")
            if "zsh" in shell_env:
                shell = "zsh"
            elif "fish" in shell_env:
                shell = "fish"
            elif os.name == "nt":
                shell = "powershell"
            else:
                shell = "bash"
        
        shell_enum = Shell(shell.lower())
        generator = CompletionGenerator()
        
        if show or not install:
            script = generator.generate(shell_enum)
            rich_print(f"[bold]Completion script for {shell}:[/bold]\n")
            print(script)
            rich_print(f"\n[dim]Use --install to auto-install[/dim]")
        
        if install:
            installer = CompletionInstaller()
            success, message = installer.install(shell_enum)
            if success:
                typer.secho(f"✅ {message}", fg=typer.colors.GREEN)
            else:
                typer.secho(f"❌ {message}", fg=typer.colors.RED)
                
    except ImportError as e:
        typer.secho(f"Completions module not available: {e}", fg=typer.colors.RED)
    except ValueError as e:
        typer.secho(f"Invalid shell: {shell}. Use bash, zsh, fish, or powershell", fg=typer.colors.RED)


# ============================================================================
# REPORT GENERATION
# ============================================================================

@app.command("report")
def generate_report(
    job_id: str = typer.Argument("", help="Job ID to generate report for"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, csv, markdown, xml, pdf"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    executive: bool = typer.Option(False, "--executive", "-e", help="Generate executive summary only"),
    title: Optional[str] = typer.Option(None, "--title", "-t", help="Custom report title"),
) -> None:
    """Generate a report for a completed job."""
    try:
        from recon_cli.reports import ReportGenerator, ReportConfig, ReportFormat
        from recon_cli.reports.executive import ExecutiveSummaryGenerator

        if not job_id:
            raise typer.BadParameter("job_id is required")
        
        manager = JobManager()
        record = _load_job_or_exit(manager, job_id)
        
        # Load job data
        job_data = {
            "id": job_id,
            "job_id": job_id,
            "targets": [record.spec.target] if hasattr(record.spec, 'target') else [],
            "findings": [],
            "hosts": [],
            "start_time": record.metadata.started_at,
            "end_time": record.metadata.finished_at,
        }
        
        # Load results
        if record.paths.results_jsonl.exists():
            from recon_cli.utils.jsonl import read_jsonl
            from recon_cli.utils.reporting import categorize_results
            categorized = categorize_results(read_jsonl(record.paths.results_jsonl), include_secret_in_findings=True)
            job_data["hosts"].extend(categorized["hosts"])
            job_data["findings"].extend(categorized["findings"])
        
        if executive:
            # Executive summary only
            gen = ExecutiveSummaryGenerator(author="ReconnV2")
            summary = gen.generate(job_data, title=title)
            
            if format == "html":
                content = summary.to_html()
                ext = ".html"
            else:
                content = summary.to_text()
                ext = ".txt"
            
            if output:
                output.write_text(content)
                typer.secho(f"✅ Executive summary saved to {output}", fg=typer.colors.GREEN)
            else:
                print(content)
        else:
            # Full report
            report_format = ReportFormat(format.lower())
            config = ReportConfig(
                title=title or f"Reconnaissance Report - {job_id}",
            )
            generator = ReportGenerator(config)
            import asyncio
            content = asyncio.run(generator.generate(job_data, format=report_format, output_path=output))
            if output:
                typer.secho(f"✅ Report saved to {output}", fg=typer.colors.GREEN)
            else:
                print(content)
                
    except ImportError as e:
        typer.secho(f"Reports module not available: {e}", fg=typer.colors.RED)
    except ValueError as e:
        typer.secho(f"Invalid format: {format}. Use html, json, csv, markdown, xml, or pdf", fg=typer.colors.RED)


# ============================================================================
# WEB DASHBOARD
# ============================================================================

@app.command("web")
def start_web(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload for development"),
) -> None:
    """Start the web dashboard."""
    try:
        import uvicorn
        from recon_cli.web.app import app as web_app, WEB_AVAILABLE
        
        if not WEB_AVAILABLE:
            typer.secho("Web dependencies not installed. Run: pip install fastapi uvicorn", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        
        rich_print(f"[bold cyan]🌐 Starting ReconnV2 Web Dashboard[/bold cyan]")
        rich_print(f"   URL: http://{host}:{port}")
        rich_print(f"   Press Ctrl+C to stop\n")
        
        uvicorn.run(
            "recon_cli.web.app:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info",
        )
    except ImportError:
        typer.secho("Web dependencies not installed. Run: pip install fastapi uvicorn", fg=typer.colors.RED)
        raise typer.Exit(code=1)


# ============================================================================
# QUICK START HELPER
# ============================================================================

@app.command("quickstart")
def quickstart_guide() -> None:
    """Show quick start guide for new users."""
    rich_print("""
[bold cyan]🚀 ReconnV2 Quick Start Guide[/bold cyan]

[bold]1. Basic Scan[/bold]
   recon scan example.com --profile passive

[bold]2. Full Scan with Vulnerability Detection[/bold]
   recon scan example.com --profile full --scanner nuclei

[bold]3. Interactive Mode (Recommended for Beginners)[/bold]
   recon interactive

[bold]4. Step-by-Step Wizard[/bold]
   recon wizard

[bold]5. View Job Results[/bold]
   recon results <job_id>
   recon results <job_id> --json

[bold]6. Generate Report[/bold]
   recon report <job_id> --format html --output report.html
   recon report <job_id> --executive  # Summary only

[bold]7. Start Web Dashboard[/bold]
   recon web --port 8080
   Then open http://localhost:8080

[bold]8. List All Jobs[/bold]
   recon list
   recon list --status finished

[bold]9. Install Shell Completions[/bold]
   recon completions --install

[bold]10. Get Help[/bold]
   recon --help
   recon scan --help

[dim]Tip: Use --profile passive for safe reconnaissance,
     --profile full for comprehensive scanning.[/dim]
""")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
