from __future__ import annotations

import typer
import json
from typing import Optional
from pathlib import Path
from recon_cli.jobs.manager import JobManager
from recon_cli.utils.pipeline_trace import get_last_trace

app = typer.Typer(help="Inspect pipeline execution traces.")

@app.command()
def trace(
    job_id: Optional[str] = typer.Argument(None, help="Specific job ID to trace"),
    events: int = typer.Option(8, help="Show last N events"),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """Show the execution trace summary for a job."""
    manager = JobManager()
    
    trace_data = None
    if job_id:
        record = manager.load_job(job_id)
        if record:
            trace_path = record.paths.root / "artifacts" / "trace.json"
            if trace_path.exists():
                trace_data = json.loads(trace_path.read_text())
    else:
        trace_data = get_last_trace()

    if not trace_data:
        typer.echo("No trace data found", err=True)
        return

    if json_output:
        typer.echo(json.dumps(trace_data, indent=2))
        return

    typer.echo(f"Trace ID: {trace_data.get('trace_id')}")
    typer.echo(f"Status  : {trace_data.get('status')}")
    typer.echo(f"Stages  : {trace_data.get('stage_count')}")
    
    # Simple summary of spans
    spans = trace_data.get("spans", [])
    if spans:
        typer.echo("\nExecution Spans:")
        for span in spans[-events:]:
            name = span.get("name", "unknown")
            status = span.get("status", "unknown")
            duration = span.get("duration_ms", 0)
            typer.echo(f"  - {name:25} [{status:10}] {duration:8.1f}ms")
