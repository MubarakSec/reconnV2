from __future__ import annotations

import typer
from pathlib import Path
from typing import List, Optional
from recon_cli.jobs.manager import JobManager
from recon_cli.utils.pdf_reporter import generate_pdf_report
from recon_cli.reports import executive

app = typer.Typer(help="Generate reports.")

@app.command()
def pdf(
    job_id: str,
    output: Optional[Path] = typer.Option(None, help="Output file path"),
    template: str = typer.Option("default", help="Report template name"),
) -> None:
    """Generate a PDF report for a completed job."""
    manager = JobManager()
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=1)
    
    if not output:
        output = record.paths.root / f"report_{job_id}.pdf"
    
    typer.echo(f"Generating PDF report for {job_id}...")
    generate_pdf_report(record, output, template=template)
    typer.echo(f"Report saved to: {output}")

@app.command()
def report(
    job_id: str,
    type: str = typer.Option("summary", help="Report type (summary/full/json)"),
) -> None:
    """Show a scan summary or generate a report."""
    manager = JobManager()
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=1)
    
    if type == "summary":
        results_txt = record.paths.results_txt
        if results_txt.exists():
            typer.echo(results_txt.read_text())
        else:
            from recon_cli.jobs.summary import generate_summary
            # Create a mock context for summary generation
            class MockContext:
                def __init__(self, r, m):
                    self.record = r
                    self.manager = m
            generate_summary(MockContext(record, manager))
            typer.echo(record.paths.results_txt.read_text())
    elif type == "json":
        typer.echo(record.metadata.json())
    elif type == "full":
        executive.generate_executive_report(record)
