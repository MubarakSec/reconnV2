from __future__ import annotations

import json
import logging
import os
import time
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
        raise typer.Exit(code=1)
    return record


@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Domain or hostname to scan"),
    profile: str = typer.Option("passive", "--profile", case_sensitive=False, help=PROFILE_HELP, show_default=True),
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
) -> None:
    """Launch a reconnaissance job across the staged pipeline."""
    profile_input = profile.lower()
    available_profiles = config.available_profiles()
    profile_choices = BASE_PROFILES | set(available_profiles.keys())
    if profile_input not in profile_choices:
        typer.echo(f"Invalid profile: {profile_input}", err=True)
        raise typer.Exit(code=1)
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
    record = manager.create_job(
        target=target or "",
        profile=selected_profile,
        inline=inline,
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
        help="Reserved for future concurrency; currently runs a single worker (values >1 are ignored)",
    ),
) -> None:
    """Run the job worker loop that pulls queued scans and executes the pipeline."""
    if max_workers > 1:
        typer.echo("Single-worker mode only; ignoring max-workers > 1")
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    typer.echo("Worker started; press Ctrl+C to stop")
    try:
        while True:
            queued = manager.list_jobs("queued")
            if not queued:
                time.sleep(poll_interval)
                continue
            job_id = queued[0]
            record = lifecycle.move_to_running(job_id)
            if not record:
                time.sleep(poll_interval)
                continue
            typer.echo(f"Processing job {job_id}")
            try:
                run_pipeline(record, manager, force=record.spec.force)
            except Exception as exc:  # pragma: no cover - runtime path
                typer.echo(f"Job {job_id} failed: {exc}", err=True)
                lifecycle.move_to_failed(job_id)
            else:
                lifecycle.move_to_finished(job_id)
    except KeyboardInterrupt:
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
def list_jobs(status: Optional[str] = typer.Argument(None, help="Optional status filter")) -> None:
    """List jobs, optionally filtered by status."""
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

    source_root = Path(__file__).resolve().parent
    issues: list[str] = []

    for py_file in source_root.rglob("*.py"):
        with py_file.open("r", encoding="utf-8") as handle:
            stream = io.StringIO(handle.read())
        for token in tokenize.generate_tokens(stream.readline):
            if token.type == tokenize.OP and token.string == "...":
                issues.append(f"ellipsis operator found in {py_file}:{token.start[0]}")

    tool_hints = {
        "subfinder": "install via go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass": "install via go install github.com/owasp-amass/amass/v4/...@latest",
        "massdns": "install from https://github.com/blechschmidt/massdns",
        "httpx": "install via go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "ffuf": "install via go install github.com/ffuf/ffuf@latest",
        "nuclei": "install via go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "wpscan": "install via gem install wpscan",
    }
    for tool, hint in tool_hints.items():
        if not CommandExecutor.available(tool):
            typer.echo(f"[warn] tool '{tool}' not found in PATH ({hint})")
    if not (CommandExecutor.available("waybackurls") or CommandExecutor.available("gau")):
        typer.echo("[warn] tool 'waybackurls' or 'gau' not found in PATH (install via go install github.com/tomnomnom/waybackurls@latest or go install github.com/lc/gau/v2/cmd/gau@latest)")

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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
