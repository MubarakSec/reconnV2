from __future__ import annotations

import time
import typer
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.pipeline.runner import run_pipeline
from recon_cli.utils import fs
from recon_cli.commands.utils import (
    _load_job_or_exit, _print_job, _reset_job_state, _normalize_stage_selection,
    _read_job_lock_pid, _terminate_process, STATUS_CHOICES
)

app = typer.Typer(help="Manage reconnaissance jobs.")

@app.command("list")
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
def status(job_id: str) -> None:
    """Show the latest metadata for a job."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    _print_job(record)

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
def rerun(
    job_id: str,
    restart: bool = typer.Option(False, "--restart", help="Clear checkpoints and rerun all stages"),
    stages: List[str] = typer.Option([], "--stages", help="Replay specific stage(s)"),
    clean_results: bool = typer.Option(True, "--clean-results/--keep-results", help="Clear results before running"),
) -> None:
    """Requeue and rerun a job immediately."""
    selected_stages = _normalize_stage_selection(stages)
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    record = _load_job_or_exit(manager, job_id)
    
    if record.metadata.status == "running":
        typer.echo(f"Job {job_id} is running; stop it before rerun", err=True)
        raise typer.Exit(code=1)

    if record.metadata.status != "queued":
        record = lifecycle.requeue(job_id)
        if not record:
            typer.echo(f"Unable to requeue {job_id}", err=True)
            raise typer.Exit(code=1)

    if restart:
        _reset_job_state(record, clear_results=clean_results)
        manager.update_metadata(record)

    running_record = lifecycle.move_to_running(job_id, owner="cli-rerun")
    try:
        run_force = bool(running_record.spec.force or selected_stages)
        run_pipeline(running_record, manager, force=run_force, stages=selected_stages or None)
        lifecycle.move_to_finished(job_id)
        typer.echo(f"Job {job_id} finished")
    except Exception as exc:
        typer.echo(f"Job {job_id} failed: {exc}", err=True)
        lifecycle.move_to_failed(job_id)
        raise typer.Exit(code=1)

@app.command()
def cancel(
    job_id: str,
    requeue: bool = typer.Option(True, "--requeue/--no-requeue", help="Requeue automatically"),
    wait: int = typer.Option(30, "--wait", help="Seconds to wait"),
    hard: bool = typer.Option(False, "--hard", help="Force-kill process"),
) -> None:
    """Request stop for a running job."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    if record.metadata.status != "running":
        if requeue and record.metadata.status in {"failed", "finished"}:
            JobLifecycle(manager).requeue(job_id)
            typer.echo(f"Job {job_id} moved to queue")
        return

    stop_path = record.paths.root / "stop.request"
    fs.write_json(stop_path, {"requested_at": datetime.utcnow().isoformat(), "action": "cancel"})
    typer.echo(f"Stop requested for job {job_id}")

    deadline = time.time() + wait
    while time.time() < deadline:
        current = manager.load_job(job_id)
        if not current or current.metadata.status != "running": break
        time.sleep(1)

    current = manager.load_job(job_id)
    if current and current.metadata.status == "running" and hard:
        pid = _read_job_lock_pid(current)
        if pid and _terminate_process(pid):
            typer.echo(f"Hard stop sent to PID {pid}")
            time.sleep(1)

    if requeue:
        JobLifecycle(manager).requeue(job_id)
        typer.echo(f"Job {job_id} moved to queue")

@app.command("tail")
def tail_logs(job_id: str) -> None:
    """Stream the pipeline log."""
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
