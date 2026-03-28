from __future__ import annotations

import os
import typer
import logging
from typing import List, Optional
from pathlib import Path
from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.jobs.manager import JobManager
from recon_cli.pipeline.runner import run_pipeline
from recon_cli import config
from recon_cli.active import modules as active_modules

app = typer.Typer(help="Run reconnaissance scans.")

BASE_PROFILES = {"passive", "full", "fuzz-only"}
ACTIVE_MODULE_CHOICES = active_modules.available_modules()
SCANNER_CHOICES = ["nuclei", "wpscan"]

@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Domain or hostname to scan"),
    profile: str = typer.Option("passive", "--profile", case_sensitive=False, help="Scan profile"),
    quickstart: bool = typer.Option(False, "--quickstart", help="Use quick profile"),
    project: Optional[str] = typer.Option(None, "--project", help="Associate job with project"),
    incremental_from: Optional[str] = typer.Option(None, "--incremental-from", help="Job ID to reuse artifacts"),
    inline: bool = typer.Option(False, "--inline", help="Run pipeline immediately"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Override wordlist"),
    max_screenshots: Optional[int] = typer.Option(None, "--max-screenshots", min=0, help="Limit screenshots"),
    force: bool = typer.Option(False, "--force", help="Re-run all stages"),
    allow_ip: bool = typer.Option(False, "--allow-ip", help="Allow IP addresses"),
    targets_file: Optional[Path] = typer.Option(None, "--targets-file", exists=True, help="File with targets"),
    scope: Optional[Path] = typer.Option(None, "--scope", exists=True, help="Scope file"),
    active_module: List[str] = typer.Option([], "--active-module", help="Enable active intel module"),
    scanner: List[str] = typer.Option([], "--scanner", help="Trigger smart scanner"),
    insecure: bool = typer.Option(False, "--insecure", help="Disable TLS verification"),
    split_targets: bool = typer.Option(False, "--split-targets", help="Create one job per target"),
    mode: str = typer.Option("default", "--mode", case_sensitive=False, help="Scan mode"),
    bearer_token: Optional[str] = typer.Option(None, "--bearer-token", help="Override Bearer token"),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Override Cookie header"),
    email_domain: Optional[str] = typer.Option(None, "--email-domain", help="Custom email domain"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP proxy URL"),
) -> None:
    """Launch a reconnaissance job across the staged pipeline."""
    profile_input = profile.lower()
    mode_input = mode.lower()
    available_profiles = config.available_profiles()
    
    if quickstart and "quick" in available_profiles:
        profile_input = "quick"
    
    profile_config = available_profiles.get(profile_input)
    runtime_overrides: Dict[str, Any] = {}
    execution_profile = None
    base_profile = profile_input
    
    if profile_config:
        execution_profile = profile_input
        base_profile = str(profile_config.get("base_profile", "full")).lower()
        runtime_overrides = dict(profile_config.get("runtime", {}))
    
    if bearer_token: runtime_overrides["auth_bearer_token"] = bearer_token
    if cookie: runtime_overrides["auth_cookies"] = cookie
    if email_domain: runtime_overrides["auth_email_domain"] = email_domain
    if proxy: runtime_overrides["proxies"] = [proxy]
    
    manager = JobManager()
    if split_targets and targets_file:
        targets = [line.strip() for line in targets_file.read_text().splitlines() if line.strip()]
        for tgt in targets:
            manager.create_job(target=tgt, profile=base_profile, project=project, force=force, 
                               active_modules=active_module, scanners=scanner, 
                               runtime_overrides=runtime_overrides, mode=mode_input)
        return

    record = manager.create_job(
        target=target or "", profile=base_profile, inline=inline, project=project,
        wordlist=str(wordlist) if wordlist else None,
        targets_file=str(targets_file) if targets_file else None,
        max_screenshots=max_screenshots, force=force, allow_ip=allow_ip,
        active_modules=active_module, scanners=scanner,
        execution_profile=execution_profile, runtime_overrides=runtime_overrides,
        insecure=insecure, incremental_from=incremental_from,
        scope_file=str(scope) if scope else None, mode=mode_input,
    )
    
    if inline:
        lifecycle = JobLifecycle(manager)
        running_record = lifecycle.move_to_running(record.spec.job_id)
        run_pipeline(running_record, manager, force=force)
        lifecycle.move_to_finished(record.spec.job_id)
