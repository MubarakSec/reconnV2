from __future__ import annotations

import logging
import typer
from recon_cli import config
from recon_cli.commands import jobs, db, config as config_cmd, reports, doctor, scan

app = typer.Typer(
    help="ReconnV2: Advanced Reconnaissance Pipeline Orchestrator.",
    add_completion=False,
)

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
app.add_typer(doctor.app, name="doctor", help="Environment checks")

# Aliases for top-level access (Backward Compatibility)
app.command("scan")(scan.scan)
app.command("list-jobs")(jobs.list_jobs)
app.command("report")(reports.report)
app.command("pdf")(reports.pdf)
app.command("doctor")(doctor.doctor)

if __name__ == "__main__":
    app()
