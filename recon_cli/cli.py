from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

import typer

from recon_cli import config
from recon_cli import projects
from recon_cli.commands import config as config_cmd
from recon_cli.commands import db, doctor, jobs, reports, scan, trace, worker
from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.jobs.manager import JobManager
from recon_cli.tools.executor import CommandExecutor

app = typer.Typer(
    help="ReconnV2: Advanced Reconnaissance Pipeline Orchestrator.",
    add_completion=False,
)
__all__ = ["app", "main", "CommandExecutor", "JobManager", "JobLifecycle"]

@app.callback()
def cli_entry(
    ctx: typer.Context,
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        help="Increase log verbosity (-v info, -vv/-vvv debug)",
        count=True,
    ),
) -> None:
    """Configure logging and shared context before dispatching commands."""
    if verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.INFO
    config.LOG_LEVEL = level
    logging.getLogger().setLevel(level)
    config.ensure_base_directories()

# Register subcommands
app.add_typer(jobs.app, name="job", help="Manage jobs")
app.add_typer(db.app, name="db", help="Manage database")
app.add_typer(config_cmd.app, name="config", help="Manage cache and config")
app.add_typer(reports.app, name="report", help="Generate reports")

# Aliases for top-level access (Backward Compatibility)
app.command("scan")(scan.scan)
app.command("report")(reports.report)
app.command("pdf")(reports.pdf)
app.command("trace")(trace.trace)
app.command("worker-run")(worker.worker_run)


@app.command("projects")
def projects_cmd() -> None:
    """List known projects."""
    project_names = projects.list_projects()
    if not project_names:
        typer.echo("No projects found")
        return
    for name in project_names:
        typer.echo(name)


@app.command("list-jobs")
def list_jobs(status: Optional[str] = typer.Argument(None, help="Optional status filter")) -> None:
    """List jobs, optionally filtered by status."""
    manager = JobManager()
    job_ids = manager.list_jobs(status)
    if not job_ids:
        typer.echo("No jobs found")
        return
    for job_id in job_ids:
        typer.echo(job_id)


@app.command("status")
def status(job_id: str) -> None:
    """Show status for a job."""
    manager = JobManager()
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=3)
    typer.echo(f"Job {record.spec.job_id}")
    typer.echo(f"Status: {record.metadata.status}")


@app.command("requeue")
def requeue(job_id: str) -> None:
    """Move a job back to queue."""
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    record = lifecycle.requeue(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Job {job_id} moved to queue")


@app.command("export")
def export_results(
    job_id: str,
    format: str = typer.Option("jsonl", help="Export format"),
    output: Optional[Path] = typer.Option(None, help="Output path"),
) -> None:
    """Export results for a job."""
    manager = JobManager()
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=1)

    selected_format = format.lower()
    if selected_format == "jsonl":
        if record.paths.results_jsonl.exists():
            typer.echo(record.paths.results_jsonl.read_text(encoding="utf-8").rstrip())
        return
    if selected_format == "zip":
        base_name = output if output else record.paths.root
        archive_path = shutil.make_archive(str(base_name), "zip", root_dir=str(record.paths.root))
        typer.echo(archive_path)
        return

    jobs.export(job_id=job_id, format=format, output=output)


@app.command("doctor")
def doctor_cmd(
    fix: bool = typer.Option(False, "--fix", help="Attempt to regenerate default configs/resolvers"),
    fix_deps: bool = typer.Option(
        False,
        "--fix-deps",
        help="Attempt to install missing dependencies",
    ),
    seclists: bool = typer.Option(
        False,
        "--seclists",
        help="Check for SecLists in project root and download if missing",
    ),
    exit_on_fail: bool = typer.Option(
        True,
        "--exit-on-fail/--no-exit-on-fail",
        help="Exit with code 1 if issues are found",
    ),
) -> None:
    """Run environment checks."""
    doctor.doctor(fix=fix, fix_deps=fix_deps, seclists=seclists, exit_on_fail=exit_on_fail)


# Interactive / Wizard
@app.command("wizard")
def wizard():
    """Run the step-by-step scan wizard."""
    import asyncio
    from recon_cli.cli_wizard import run_scan_wizard
    asyncio.run(run_scan_wizard())

@app.command("interactive")
def interactive():
    """Run interactive mode."""
    import asyncio
    from recon_cli.cli_wizard import run_interactive
    asyncio.run(run_interactive())

@app.command("quickstart")
def quickstart():
    """Show quick start guide."""
    from recon_cli.commands.utils import quickstart_guide
    quickstart_guide()

@app.command("telegram-bot")
def telegram_bot(
    token: Optional[str] = typer.Option(None, envvar="RECON_TELEGRAM_TOKEN", help="Telegram Bot Token"),
    chat_id: Optional[str] = typer.Option(None, envvar="RECON_TELEGRAM_CHAT_ID", help="Authorized Chat ID(s)"),
) -> None:
    """Start the Telegram bot."""
    if not token or not chat_id:
        typer.echo("Missing Telegram credentials. Set token and chat_id.", err=True)
        raise typer.Exit(code=1)
    from recon_cli.commands.utils import telegram_bot_start
    telegram_bot_start(token, chat_id)

@app.command("completions")
def completions_cmd(
    shell: str = typer.Option("bash", help="Shell type"),
    install: bool = typer.Option(False, "--install", help="Install completions"),
    show: bool = typer.Option(False, "--show", help="Show completion script"),
):
    """Manage shell completions."""
    from recon_cli.completions import install_completion, generate_completion, Shell
    
    try:
        shell_enum = Shell(shell.lower())
    except ValueError:
        typer.echo(f"Unsupported shell: {shell}. Choose from: bash, zsh, fish, powershell")
        raise typer.Exit(1)

    if install:
        install_completion(shell_enum)
    elif show:
        typer.echo(generate_completion(shell_enum))
    else:
        typer.echo("Use --install or --show")

def main() -> None:
    app()

if __name__ == "__main__":
    main()
