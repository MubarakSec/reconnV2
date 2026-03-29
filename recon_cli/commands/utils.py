from __future__ import annotations

import os
import json
import signal
import subprocess
import typer
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from rich import print as rich_print
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.pipeline.stages import PIPELINE_STAGES
from recon_cli.utils.sanitizer import redact_json_value

STATUS_CHOICES = ["queued", "running", "finished", "failed"]

def _last_failed_stage(metadata) -> tuple[Optional[str], Optional[str]]:
    stats = getattr(metadata, "stats", {}) or {}
    progress = stats.get("stage_progress", [])
    if isinstance(progress, list):
        for entry in reversed(progress):
            if not isinstance(entry, dict):
                continue
            if entry.get("status") != "failed":
                continue
            return entry.get("stage"), entry.get("error")
    return None, None

def _load_job_or_exit(manager: JobManager, job_id: str) -> JobRecord:
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=3)
    return record

def _print_job(record: JobRecord) -> None:
    metadata = record.metadata
    failed_stage, failed_error = _last_failed_stage(metadata)
    rich_print(f"[bold]Job {metadata.job_id}[/bold]")
    rich_print(f"  status            : {metadata.status}")
    rich_print(f"  stage             : {metadata.stage}")
    rich_print(f"  last_failed_stage : {failed_stage or '-'}")
    rich_print(f"  last_failed_error : {failed_error or '-'}")
    rich_print(f"  log_path          : {record.paths.pipeline_log}")
    rich_print(f"  queued_at         : {metadata.queued_at}")
    rich_print(f"  started_at        : {metadata.started_at}")
    rich_print(f"  finished_at       : {metadata.finished_at}")
    rich_print(f"  error             : {metadata.error}")

def _normalize_stage_selection(raw_values: List[str]) -> List[str]:
    selected: List[str] = []
    for item in raw_values:
        for part in str(item).split(","):
            value = part.strip()
            if value:
                selected.append(value)
    if not selected:
        return []
    available = {stage.name for stage in PIPELINE_STAGES}
    invalid = [name for name in selected if name not in available]
    if invalid:
        joined = ", ".join(sorted(set(invalid)))
        raise typer.BadParameter(f"Unknown stage(s): {joined}")
    ordered: List[str] = []
    seen = set()
    for name in selected:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return ordered

def _read_job_lock_pid(record: JobRecord) -> Optional[int]:
    lock_path = record.paths.root / ".lock"
    if not lock_path.exists():
        return None
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
        pid = payload.get("pid")
        return int(pid) if pid and int(pid) > 0 else None
    except Exception:
        return None

def _terminate_process(pid: int) -> bool:
    if pid <= 0: return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=10)
            return True
        os.kill(pid, signal.SIGTERM)
        return True
    except Exception:
        return False

def _reset_job_state(record: JobRecord, *, clear_results: bool) -> None:
    record.metadata.checkpoints = {}
    record.metadata.attempts = {}
    record.metadata.stats = {}
    record.metadata.error = None
    record.metadata.stage = "queued"
    if not clear_results: return
    for path in (record.paths.results_jsonl, record.paths.results_txt, record.paths.trimmed_results_jsonl):
        if path.exists(): path.write_text("", encoding="utf-8")
    (record.paths.root / "report.html").unlink(missing_ok=True)

def quickstart_guide() -> None:
    """Show quick start guide for new users."""
    rich_print("""
[bold cyan]🚀 ReconnV2 Quick Start Guide[/bold cyan]

[bold]1. Basic Scan[/bold]
   recon scan example.com --profile passive

[bold]2. Full Scan with Vulnerability Detection[/bold]
   recon scan example.com --profile full --scanner nuclei

[bold]3. Interactive Mode (Recommended for Beginners)[/bold]
   recon interactive

[bold]4. Step-by-Step Wizard[/bold]
   recon wizard

[bold]5. View Job Results[/bold]
   recon report <job_id>
   recon report <job_id> --type json

[bold]6. Tailing Logs[/bold]
   recon job tail <job_id>
""")

def telegram_bot_start(token: str, chat_id: str) -> None:
    """Start the Telegram bot."""
    import asyncio
    from recon_cli.utils.telegram_bot import TelegramBot
    
    bot = TelegramBot(token=token, allowed_chat_id=chat_id)
    try:
        asyncio.run(bot.start())
    except KeyboardInterrupt:
        bot.stop()
        typer.echo("Bot stopped")
