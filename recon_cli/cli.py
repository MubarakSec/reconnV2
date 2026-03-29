from __future__ import annotations

import logging
import typer
from recon_cli import config
from recon_cli.commands import jobs, db, config as config_cmd, reports, doctor, scan, worker, trace
from recon_cli import cli_wizard, completions

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
app.command("trace")(trace.trace)
app.command("worker-run")(worker.worker_run)

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
    token: str = typer.Option(..., envvar="RECON_TELEGRAM_TOKEN", help="Telegram Bot Token"),
    chat_id: str = typer.Option(..., envvar="RECON_TELEGRAM_CHAT_ID", help="Authorized Chat ID(s)"),
):
    """Start the Telegram bot."""
    from recon_cli.commands.utils import telegram_bot_start
    telegram_bot_start(token, chat_id)

@app.command("completions")
def completions_cmd(
    shell: str = typer.Option("bash", help="Shell type"),
    install: bool = typer.Option(False, "--install", help="Install completions"),
    show: bool = typer.Option(False, "--show", help="Show completion script"),
):
    """Manage shell completions."""
    from recon_cli.completions import install_completions, show_completions
    if install:
        install_completions(shell)
    elif show:
        show_completions(shell)
    else:
        typer.echo("Use --install or --show")

def main():
    app()

if __name__ == "__main__":
    main()
