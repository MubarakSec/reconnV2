from __future__ import annotations

import typer
from recon_cli.db import storage

app = typer.Typer(help="Manage the reconnaissance database.")

@app.command("init")
def db_init() -> None:
    """Initialize the SQLite database schema."""
    storage.initialize_database()
    typer.echo("Database initialized")

@app.command("stats")
def db_stats() -> None:
    """Show database statistics (record counts per table)."""
    stats = storage.get_stats()
    for table, count in stats.items():
        typer.echo(f"{table:12}: {count}")

@app.command()
def optimize() -> None:
    """Run VACUUM and ANALYZE on the SQLite database."""
    storage.optimize_database()
    typer.echo("Database optimized")
