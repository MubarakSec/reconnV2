from __future__ import annotations

import typer
from recon_cli.tools.executor import CommandCache
from recon_cli import config

app = typer.Typer(help="Manage configuration and tool caches.")

@app.command("cache-stats")
def cache_stats() -> None:
    """Show command executor cache statistics."""
    cache = CommandCache(config.RECON_CACHE)
    # This might need a custom method in CommandCache if not present
    # For now, just show the path size
    size = sum(f.stat().st_size for f in config.RECON_CACHE.glob("*.json") if f.is_file())
    count = len(list(config.RECON_CACHE.glob("*.json")))
    typer.echo(f"Cache location: {config.RECON_CACHE}")
    typer.echo(f"Cached items  : {count}")
    typer.echo(f"Total size    : {size / 1024:.1f} KB")

@app.command("cache-clear")
def cache_clear() -> None:
    """Clear the command executor cache."""
    for f in config.RECON_CACHE.glob("*.json"):
        f.unlink()
    typer.echo("Cache cleared")

@app.command()
def notify(message: str) -> None:
    """Send a test notification (Telegram/Discord/Web)."""
    from recon_cli.utils.alerting import send_alert
    try:
        send_alert("Manual Notification", message)
        typer.echo("Notification sent")
    except Exception as e:
        typer.echo(f"Failed to send notification: {e}", err=True)
