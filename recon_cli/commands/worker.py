from __future__ import annotations

import typer
import time
import logging
from typing import Optional
from recon_cli.jobs.manager import JobManager
from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.pipeline.runner import run_pipeline

app = typer.Typer(help="Manage background workers.")

@app.command("run")
def worker_run(
    job_id: Optional[str] = typer.Option(None, help="Specific job ID to process"),
    interval: int = typer.Option(5, help="Seconds between queue checks"),
    once: bool = typer.Option(False, "--once", help="Exit after one job"),
) -> None:
    """Run a background worker to process the job queue."""
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    
    typer.echo(f"Worker started (interval={interval}s)")
    
    try:
        while True:
            # 1. Look for a specific job or pick from queue
            target_job = job_id
            if not target_job:
                queued = manager.list_jobs("queued")
                if queued:
                    target_job = queued[0]
            
            if target_job:
                typer.echo(f"Processing job {target_job}...")
                try:
                    record = lifecycle.move_to_running(target_job, owner="worker")
                    run_pipeline(record, manager)
                    lifecycle.move_to_finished(target_job)
                    typer.echo(typer.style(f"Job {target_job} FINISHED", fg=typer.colors.GREEN))
                except Exception as e:
                    # Check if it was a partial failure (scan completed but some stages failed)
                    final_record = manager.load_job(target_job)
                    if final_record and final_record.metadata.status == "partial":
                        typer.echo(typer.style(f"Job {target_job} COMPLETED with partial failures: {e}", fg=typer.colors.YELLOW))
                        lifecycle.move_to_finished(target_job, status="partial")
                    else:
                        logging.error(f"Job {target_job} FAILED: {e}")
                        lifecycle.move_to_failed(target_job)
                
                if once:
                    break
            else:
                if once:
                    typer.echo("No jobs in queue. Exiting.")
                    break
                time.sleep(interval)
    except KeyboardInterrupt:
        typer.echo("Worker stopped by user")
