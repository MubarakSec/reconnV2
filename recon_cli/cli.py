from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich import print as rich_print

from recon_cli import config
from recon_cli.jobs.lifecycle import JobLifecycle
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.pipeline.runner import run_pipeline
from recon_cli.pipeline.stages import PIPELINE_STAGES
from recon_cli.utils import fs
from recon_cli.utils import validation
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.sanitizer import redact, redact_json_value
from recon_cli.active import modules as active_modules
from recon_cli.tools.executor import CommandExecutor

app = typer.Typer(
    help="Run the reconnaissance pipeline end-to-end (passive discovery -> runtime crawl -> reporting).",
    add_completion=False,
)


@app.callback()
def cli_entry(ctx: typer.Context, verbose: int = typer.Option(0, '--verbose', '-v', help='Increase log verbosity (-v info, -vv/-vvv debug)', count=True)) -> None:
    """Configure logging and shared context before dispatching commands."""
    if verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.INFO
    config.LOG_LEVEL = level
    logging.getLogger().setLevel(level)
    config.ensure_base_directories()

BASE_PROFILES = {"passive", "full", "fuzz-only"}
PROFILE_PRESETS = config.available_profiles()
PROFILE_CHOICES = sorted(BASE_PROFILES | set(PROFILE_PRESETS.keys()))
PROFILE_PRESET_NAMES = sorted(PROFILE_PRESETS.keys())
if PROFILE_PRESET_NAMES:
    PROFILE_HELP = "Scan profile (base: passive/full/fuzz-only; presets: {names})".format(names=", ".join(PROFILE_PRESET_NAMES))
else:
    PROFILE_HELP = "Scan profile (base: passive/full/fuzz-only)"
ACTIVE_MODULE_CHOICES = active_modules.available_modules()
ACTIVE_MODULE_HELP = "none available" if not ACTIVE_MODULE_CHOICES else ", ".join(ACTIVE_MODULE_CHOICES)
SCANNER_CHOICES = ["nuclei", "wpscan"]
SCANNER_HELP = ", ".join(SCANNER_CHOICES)
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


def _truncate_file(path: Path) -> None:
    try:
        path.write_text("", encoding="utf-8")
    except FileNotFoundError:
        return


def _reset_job_state(record: JobRecord, *, clear_results: bool) -> None:
    record.metadata.checkpoints = {}
    record.metadata.attempts = {}
    record.metadata.stats = {}
    record.metadata.error = None
    record.metadata.stage = "queued"
    if not clear_results:
        return
    for path in (record.paths.results_jsonl, record.paths.results_txt, record.paths.trimmed_results_jsonl):
        if path.exists():
            _truncate_file(path)
    report_path = record.paths.root / "report.html"
    report_path.unlink(missing_ok=True)


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
        raise typer.BadParameter(f"Unknown stage(s): {joined}", param_name="--stages")
    # Preserve input order but drop duplicates
    ordered: List[str] = []
    seen = set()
    for name in selected:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return ordered


def _load_job_or_exit(manager: JobManager, job_id: str) -> JobRecord:
    record = manager.load_job(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=3)
    return record


def _read_job_lock_pid(record: JobRecord) -> Optional[int]:
    lock_path = record.paths.root / ".lock"
    if not lock_path.exists():
        return None
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    pid = payload.get("pid")
    if isinstance(pid, int) and pid > 0:
        return pid
    try:
        pid_int = int(str(pid))
    except Exception:
        return None
    return pid_int if pid_int > 0 else None


def _terminate_process(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            completed = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return completed.returncode == 0
        os.kill(pid, signal.SIGTERM)
        return True
    except Exception:
        return False


def _auto_allow_ip(target_value: str) -> bool:
    try:
        candidate = validation._coerce_hostname(target_value)
    except Exception:
        candidate = target_value
    return validation.is_ip(candidate)


def _target_priority_score(record: JobRecord) -> int:
    target = str(getattr(record.spec, "target", "") or "").lower()
    profile = str(getattr(record.spec, "profile", "") or "").lower()
    score = 0
    for token, weight in (
        ("auth", 6),
        ("admin", 6),
        ("api", 5),
        ("payment", 5),
        ("account", 5),
        ("billing", 4),
    ):
        if token in target:
            score += weight
    if profile in {"full", "deep"}:
        score += 2
    if "staging" in target or "dev" in target or "test" in target:
        score -= 2
    return score


def _run_async_command(coro):
    """Run coroutine in an isolated loop without mutating global loop state."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Domain or hostname to scan"),
    profile: str = typer.Option("passive", "--profile", case_sensitive=False, help=PROFILE_HELP, show_default=True),
    quickstart: bool = typer.Option(False, "--quickstart", help="Use the quick profile if available (passive-minimal)"),
    project: Optional[str] = typer.Option(None, "--project", help="Associate job with a project name"),
    incremental_from: Optional[str] = typer.Option(None, "--incremental-from", help="Job ID to reuse artifacts (incremental recon)"),
    inline: bool = typer.Option(False, "--inline", help="Run the pipeline immediately"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Override default wordlist"),
    max_screenshots: Optional[int] = typer.Option(None, "--max-screenshots", min=0, help="Limit screenshots"),
    force: bool = typer.Option(False, "--force", help="Re-run all stages even if checkpoints exist"),
    allow_ip: bool = typer.Option(False, "--allow-ip", help="Allow IP addresses as targets"),
    targets_file: Optional[Path] = typer.Option(None, "--targets-file", exists=True, file_okay=True, dir_okay=False, readable=True, help="File with multiple targets"),
    active_module: List[str] = typer.Option(
        [],
        "--active-module",
        help=f"Enable active intelligence module (repeatable). Choices: {ACTIVE_MODULE_HELP}",
        show_default=False,
    ),
    scanner: List[str] = typer.Option(
        [],
        "--scanner",
        help=f"Trigger smart scanner integration (repeatable). Choices: {SCANNER_HELP}",
        show_default=False,
    ),
    insecure: bool = typer.Option(False, "--insecure", help="Disable TLS verification for HTTP requests (not recommended)"),
    split_targets: bool = typer.Option(False, "--split-targets", help="When using --targets-file, create one job per target"),
) -> None:
    """Launch a reconnaissance job across the staged pipeline."""
    profile_input = profile.lower()
    available_profiles = config.available_profiles()
    profile_choices = BASE_PROFILES | set(available_profiles.keys())
    if quickstart and "quick" in available_profiles:
        profile_input = "quick"
    elif quickstart and "quick" not in available_profiles:
        profile_input = "passive"
    if profile_input not in profile_choices:
        typer.echo(f"Invalid profile: {profile_input}", err=True)
        raise typer.Exit(code=2)
    profile_errors = config.profile_errors()
    if profile_errors:
        for err in profile_errors:
            typer.echo(f"[warn] profile config: {err}", err=True)
    profile_config = available_profiles.get(profile_input)
    runtime_overrides: Dict[str, Any] = {}
    execution_profile: Optional[str] = None
    base_profile = profile_input
    if profile_config:
        execution_profile = profile_input
        base_profile = str(profile_config.get("base_profile", "full")).lower()
        runtime_values = profile_config.get("runtime", {})
        if isinstance(runtime_values, dict):
            runtime_overrides = dict(runtime_values)
    if base_profile not in BASE_PROFILES:
        typer.echo(f"Profile preset maps to unknown base profile: {base_profile}", err=True)
        raise typer.Exit(code=1)
    selected_profile = base_profile
    profile = selected_profile

    if not target and not targets_file:
        typer.echo("Provide either a target or --targets-file", err=True)
        raise typer.Exit(code=1)

    auto_allow = allow_ip
    if not allow_ip:
        if target and _auto_allow_ip(target):
            auto_allow = True
        elif targets_file:
            try:
                for line in Path(targets_file).read_text(encoding="utf-8").splitlines():
                    if line.strip() and _auto_allow_ip(line.strip()):
                        auto_allow = True
                        break
            except Exception:
                auto_allow = allow_ip
    allow_ip = auto_allow

    modules = [module.strip().lower() for module in active_module if module]
    env_active = os.environ.get("RECON_ACTIVE_MODULES")
    if not modules and env_active:
        modules = [part.strip().lower() for part in env_active.split(",") if part.strip()]
    invalid = [module for module in modules if module not in ACTIVE_MODULE_CHOICES]
    if invalid:
        typer.echo(f"Unknown active modules: {', '.join(invalid)}", err=True)
        raise typer.Exit(code=1)

    scanners = [item.strip().lower() for item in scanner if item]
    env_scanners = os.environ.get("RECON_SCANNERS")
    if not scanners and env_scanners:
        scanners = [part.strip().lower() for part in env_scanners.split(",") if part.strip()]
    invalid_scanners = [item for item in scanners if item not in SCANNER_CHOICES]
    if invalid_scanners:
        typer.echo(f"Unknown scanners: {', '.join(invalid_scanners)}", err=True)
        raise typer.Exit(code=1)

    manager = JobManager()
    created: list[str] = []
    if split_targets and targets_file:
        target_lines = Path(targets_file).read_text(encoding="utf-8").splitlines()
        targets_list = [line.strip() for line in target_lines if line.strip()]
        if not targets_list:
            typer.echo("No targets found in file", err=True)
            raise typer.Exit(code=1)
        for tgt in targets_list:
            target_allow_ip = allow_ip or _auto_allow_ip(tgt)
            record = manager.create_job(
                target=tgt,
                profile=selected_profile,
                inline=inline,
                project=project,
                wordlist=str(wordlist) if wordlist else None,
                targets_file=None,
                max_screenshots=max_screenshots,
                force=force,
                allow_ip=target_allow_ip,
                active_modules=modules,
                scanners=scanners,
                execution_profile=execution_profile,
                runtime_overrides=runtime_overrides,
                insecure=insecure,
                incremental_from=incremental_from,
            )
            created.append(record.spec.job_id)
        typer.echo(f"Jobs created: {', '.join(created)}")
        return
    record = manager.create_job(
        target=target or "",
        profile=selected_profile,
        inline=inline,
        project=project,
        wordlist=str(wordlist) if wordlist else None,
        targets_file=str(targets_file) if targets_file else None,
        max_screenshots=max_screenshots,
        force=force,
        allow_ip=allow_ip,
        active_modules=modules,
        scanners=scanners,
        execution_profile=execution_profile,
        runtime_overrides=runtime_overrides,
        insecure=insecure,
        incremental_from=incremental_from,
    )
    job_id = record.spec.job_id
    typer.echo(f"Job created: {job_id}")
    if inline:
        lifecycle = JobLifecycle(manager)
        running_record = lifecycle.move_to_running(job_id)
        if not running_record:
            typer.echo("Failed to transition job to running", err=True)
            raise typer.Exit(code=1)
        try:
            run_pipeline(running_record, manager, force=force)
        except Exception as exc:  # pragma: no cover - runtime path
            typer.echo(f"Pipeline failed: {exc}", err=True)
            lifecycle.move_to_failed(job_id)
            raise typer.Exit(code=1)
        lifecycle.move_to_finished(job_id)
        finished_results = config.FINISHED_JOBS / job_id / config.RESULTS_TEXT_NAME
        typer.echo(f"Job {job_id} finished -> {finished_results}")


@app.command("worker-run")
def worker_run(
    poll_interval: int = typer.Option(5, "--poll-interval", min=1, help="Seconds between queue checks"),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        min=1,
        help="Number of worker loops to run concurrently",
    ),
    top_targets_first: bool = typer.Option(
        False,
        "--top-targets-first",
        help="Prioritize queued jobs targeting high-value assets (auth/admin/api/payment/account)",
    ),
) -> None:
    """Run the job worker loop that pulls queued scans and executes the pipeline."""
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    typer.echo(f"Worker started with {max_workers} worker(s); press Ctrl+C to stop")
    stop_event = False

    def worker_loop(name: str) -> None:
        nonlocal stop_event
        while not stop_event:
            queued = manager.list_jobs("queued")
            if not queued:
                time.sleep(poll_interval)
                continue
            if top_targets_first:
                scored: list[tuple[int, str]] = []
                for candidate in queued:
                    candidate_record = manager.load_job(candidate)
                    if not candidate_record:
                        continue
                    scored.append((_target_priority_score(candidate_record), candidate))
                if scored:
                    scored.sort(reverse=True)
                    job_id = scored[0][1]
                else:
                    job_id = queued[0]
            else:
                job_id = queued[0]
            record = lifecycle.move_to_running(job_id, owner=name)
            if not record:
                time.sleep(0.2)
                continue
            typer.echo(f"[{name}] Processing job {job_id}")
            try:
                run_pipeline(record, manager, force=record.spec.force)
            except Exception as exc:  # pragma: no cover - runtime path
                typer.echo(f"[{name}] Job {job_id} failed: {exc}", err=True)
                lifecycle.move_to_failed(job_id)
            else:
                lifecycle.move_to_finished(job_id)

    workers: list[threading.Thread] = []
    for idx in range(max_workers):
        t = threading.Thread(target=worker_loop, args=(f"worker-{idx+1}",), daemon=True)
        workers.append(t)
        t.start()

    try:
        while any(t.is_alive() for t in workers):
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event = True
        typer.echo("Worker stopped")


@app.command()
def status(job_id: str) -> None:
    """Show the latest metadata for a job."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    _print_job(record)


@app.command("tail-logs")
def tail_logs(job_id: str) -> None:
    """Stream the pipeline log for a running or finished job."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    log_path = record.paths.pipeline_log
    if not log_path.exists():
        typer.echo("Log file not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Tailing {log_path} (Ctrl+C to exit)")
    try:
        with log_path.open("r", encoding="utf-8") as handle:
            handle.seek(0, 2)
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                typer.echo(line.rstrip())
    except KeyboardInterrupt:
        typer.echo("Stopped tailing")


@app.command("list-jobs")
def list_jobs(
    status: Optional[str] = typer.Argument(None, help="Optional status filter"),
    project: Optional[str] = typer.Option(None, "--project", help="Filter jobs by project"),
) -> None:
    """List jobs, optionally filtered by status or project."""
    if status and status not in STATUS_CHOICES:
        typer.echo(f"Invalid status filter: {status}", err=True)
        raise typer.Exit(code=1)
    manager = JobManager()
    job_ids = manager.list_jobs(status)
    if not job_ids:
        typer.echo("No jobs found")
        return
    for job_id in job_ids:
        typer.echo(job_id)


@app.command()
def requeue(job_id: str) -> None:
    """Move a finished or failed job back into the queue."""
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    record = lifecycle.requeue(job_id)
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Job {job_id} moved to queue")


@app.command()
def rerun(
    job_id: str,
    restart: bool = typer.Option(False, "--restart", help="Clear checkpoints and rerun all stages"),
    stages: List[str] = typer.Option(
        [],
        "--stages",
        help="Replay specific stage(s); repeat flag or pass comma-separated names",
        show_default=False,
    ),
    clean_results: bool = typer.Option(
        True,
        "--clean-results/--keep-results",
        help="When restarting, clear results files before running",
    ),
) -> None:
    """Requeue and rerun a job immediately (resume from last checkpoint by default)."""
    selected_stages = _normalize_stage_selection(stages)
    if restart and selected_stages:
        typer.echo("--restart cannot be combined with --stages", err=True)
        raise typer.Exit(code=2)
    manager = JobManager()
    lifecycle = JobLifecycle(manager)
    record = _load_job_or_exit(manager, job_id)
    if record.metadata.status == "running":
        typer.echo(f"Job {job_id} is running; stop it before rerun", err=True)
        raise typer.Exit(code=1)

    if record.metadata.status != "queued":
        record = lifecycle.requeue(job_id)
        if not record:
            typer.echo(f"Unable to requeue {job_id}", err=True)
            raise typer.Exit(code=1)

    if restart:
        _reset_job_state(record, clear_results=clean_results)
        manager.update_metadata(record)

    running_record = lifecycle.move_to_running(job_id, owner="cli-rerun")
    if not running_record:
        typer.echo("Failed to transition job to running", err=True)
        raise typer.Exit(code=1)

    try:
        run_force = bool(running_record.spec.force or selected_stages)
        run_pipeline(running_record, manager, force=run_force, stages=selected_stages or None)
    except Exception as exc:  # pragma: no cover - runtime path
        typer.echo(f"Job {job_id} failed: {exc}", err=True)
        lifecycle.move_to_failed(job_id)
        raise typer.Exit(code=1)
    lifecycle.move_to_finished(job_id)
    typer.echo(f"Job {job_id} finished")


@app.command()
def cancel(
    job_id: str,
    requeue: bool = typer.Option(True, "--requeue/--no-requeue", help="Requeue automatically after stop"),
    wait: int = typer.Option(30, "--wait", min=0, help="Seconds to wait for graceful stop"),
    hard: bool = typer.Option(
        False,
        "--hard",
        help="Force-kill worker process if job does not stop gracefully (may stop other running jobs on same worker)",
    ),
) -> None:
    """Request stop for a running job, then optionally requeue it."""
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)

    if record.metadata.status != "running":
        typer.echo(f"Job {job_id} is not running (status={record.metadata.status})")
        if requeue and record.metadata.status in {"failed", "finished"}:
            lifecycle = JobLifecycle(manager)
            moved = lifecycle.requeue(job_id)
            if moved:
                typer.echo(f"Job {job_id} moved to queue")
            else:
                typer.echo(f"Unable to requeue {job_id}", err=True)
        return

    stop_path = record.paths.root / "stop.request"
    fs.write_json(
        stop_path,
        {"requested_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "requested_by": "cli", "action": "cancel"},
    )
    typer.echo(f"Stop requested for job {job_id}")

    deadline = time.time() + wait
    while wait > 0 and time.time() < deadline:
        current = manager.load_job(job_id)
        if not current or current.metadata.status != "running":
            break
        time.sleep(1)

    current = manager.load_job(job_id)
    still_running = bool(current and current.metadata.status == "running")

    if still_running and hard and current:
        pid = _read_job_lock_pid(current)
        if pid:
            if _terminate_process(pid):
                typer.echo(f"Hard stop sent to PID {pid}")
                time.sleep(1)
            else:
                typer.echo(f"Failed to hard-stop PID {pid}", err=True)
        else:
            typer.echo("No worker PID found in lock file; cannot hard-stop", err=True)
        current = manager.load_job(job_id)
        still_running = bool(current and current.metadata.status == "running")

    if still_running:
        typer.echo(
            "Job is still running. Wait more, or run again with --hard. Do not requeue until it fully stops.",
            err=True,
        )
        raise typer.Exit(code=1)

    if requeue:
        lifecycle = JobLifecycle(manager)
        moved = lifecycle.requeue(job_id)
        if moved:
            typer.echo(f"Job {job_id} moved to queue")
        else:
            typer.echo(f"Job {job_id} stopped but could not be requeued", err=True)
            raise typer.Exit(code=1)


@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Attempt to regenerate default configs/resolvers"),
    fix_deps: bool = typer.Option(
        False,
        "--fix-deps",
        help="Attempt to install missing dependencies (python packages, playwright browsers, interactsh-client)",
    ),
) -> None:
    """Run quick environment & source sanity checks."""
    config.ensure_base_directories(force=fix)
    import importlib.util
    import io
    import subprocess
    import tokenize

    source_root = Path(__file__).resolve().parent
    issues: list[str] = []
    warnings: list[str] = []

    for py_file in source_root.rglob("*.py"):
        with py_file.open("r", encoding="utf-8") as handle:
            stream = io.StringIO(handle.read())
        for token in tokenize.generate_tokens(stream.readline):
            if token.type == tokenize.OP and token.string == "...":
                issues.append(f"ellipsis operator found in {py_file}:{token.start[0]}")

    def _version_line(tool: str, args: List[str]) -> str:
        try:
            completed = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            return ""
        output = (completed.stdout or "") + (completed.stderr or "")
        output = output.strip()
        if not output:
            return ""
        return output.splitlines()[0][:120]

    tool_checks = [
        ("subfinder", ["-version"], "install via go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("amass", ["-version"], "install via go install github.com/owasp-amass/amass/v4/...@latest"),
        ("massdns", ["-h"], "install from https://github.com/blechschmidt/massdns"),
        ("httpx", ["-version"], "install via go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("ffuf", ["-V"], "install via go install github.com/ffuf/ffuf@latest"),
        ("nuclei", ["-version"], "install via go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("naabu", ["-version"], "install via go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        ("katana", ["-version"], "install via go install github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("dalfox", ["version"], "install via go install github.com/hahwul/dalfox/v2@latest"),
        ("sqlmap", ["--version"], "install via pipx install sqlmap or apt install sqlmap"),
        ("nmap", ["--version"], "install via apt install nmap"),
        ("wpscan", ["--version"], "install via gem install wpscan"),
        ("droopescan", ["--version"], "install via pipx install droopescan or pip install droopescan"),
        ("interactsh-client", ["-version"], "install via go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
        ("waybackurls", ["-h"], "install via go install github.com/tomnomnom/waybackurls@latest"),
        ("gau", ["-h"], "install via go install github.com/lc/gau/v2/cmd/gau@latest"),
    ]
    def _collect_tool_health(*, emit_warnings: bool) -> tuple[list[tuple[str, str, str]], list[str], list[str]]:
        tool_results: list[tuple[str, str, str]] = []
        local_warnings: list[str] = []
        missing_tools: list[str] = []
        for tool, version_args, hint in tool_checks:
            if not CommandExecutor.available(tool):
                tool_results.append((tool, "missing", ""))
                missing_tools.append(tool)
                local_warnings.append(f"tool:{tool}")
                if emit_warnings and tool not in {"waybackurls", "gau"}:
                    typer.echo(f"[warn] tool '{tool}' not found in PATH ({hint})")
                continue
            version = _version_line(tool, version_args)
            tool_results.append((tool, "ok", version))

        if not (CommandExecutor.available("waybackurls") or CommandExecutor.available("gau")):
            local_warnings.append("tool:waybackurls-or-gau")
            if emit_warnings:
                typer.echo(
                    "[warn] tool 'waybackurls' or 'gau' not found in PATH "
                    "(install via go install github.com/tomnomnom/waybackurls@latest "
                    "or go install github.com/lc/gau/v2/cmd/gau@latest)"
                )
        return tool_results, local_warnings, missing_tools

    python_dep_checks = [
        ("dnspython", "dns", "pip install dnspython"),
        ("playwright", "playwright", "pip install playwright"),
        ("requests", "requests", "pip install requests"),
        ("pyyaml", "yaml", "pip install pyyaml"),
    ]
    def _collect_python_health(
        *, emit_warnings: bool
    ) -> tuple[list[tuple[str, str, str]], str, str, list[str], list[str]]:
        python_results: list[tuple[str, str, str]] = []
        local_warnings: list[str] = []
        missing_python: list[str] = []
        for label, module_name, hint in python_dep_checks:
            if importlib.util.find_spec(module_name) is None:
                python_results.append((label, "missing", ""))
                missing_python.append(label)
                local_warnings.append(f"python:{label}")
                if emit_warnings:
                    typer.echo(f"[warn] Python package '{label}' not available ({hint})")
            else:
                python_results.append((label, "ok", ""))

        browser_status = "unknown"
        browser_detail = ""
        if any(label == "playwright" and status == "ok" for label, status, _ in python_results):
            try:
                from playwright.sync_api import sync_playwright

                with sync_playwright() as playwright:
                    chromium_path = Path(playwright.chromium.executable_path)
                if chromium_path.exists():
                    browser_status = "ok"
                    browser_detail = str(chromium_path)
                else:
                    browser_status = "missing"
                    browser_detail = "playwright install chromium"
                    local_warnings.append("python:playwright-browsers")
                    if emit_warnings:
                        typer.echo("[warn] Playwright browsers not installed (run: playwright install chromium)")
            except Exception as exc:
                browser_status = "missing"
                browser_detail = str(exc).splitlines()[0]
                local_warnings.append("python:playwright-browsers")
                if emit_warnings:
                    typer.echo("[warn] Playwright browser check failed (run: playwright install chromium)")
        return python_results, browser_status, browser_detail, local_warnings, missing_python

    tool_results, tool_warnings, missing_tools = _collect_tool_health(emit_warnings=not fix_deps)
    python_results, browser_status, browser_detail, python_warnings, missing_python = _collect_python_health(
        emit_warnings=not fix_deps
    )
    warnings = tool_warnings + python_warnings

    if fix_deps:
        typer.echo("")
        typer.echo("== Dependency Fix Attempts ==")
        attempted = False

        package_by_label = {
            "dnspython": "dnspython",
            "playwright": "playwright",
            "requests": "requests",
            "pyyaml": "pyyaml",
        }
        for package_label in missing_python:
            package_name = package_by_label.get(package_label, package_label)
            attempted = True
            typer.echo(f"[fix] Installing python package: {package_name}")
            install = subprocess.run(
                [sys.executable, "-m", "pip", "install", package_name],
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            if install.returncode == 0:
                typer.echo(f"[fix] Installed: {package_name}")
            else:
                typer.echo(f"[warn] Failed to install {package_name}")

        if "interactsh-client" in missing_tools:
            attempted = True
            if not CommandExecutor.available("go"):
                typer.echo("[warn] 'go' not found; cannot auto-install interactsh-client")
            else:
                typer.echo("[fix] Installing interactsh-client via go install")
                install = subprocess.run(
                    ["go", "install", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"],
                    capture_output=True,
                    text=True,
                    timeout=900,
                    check=False,
                )
                if install.returncode == 0:
                    typer.echo("[fix] Installed: interactsh-client")
                else:
                    typer.echo("[warn] Failed to install interactsh-client")

        if browser_status != "ok":
            attempted = True
            if importlib.util.find_spec("playwright") is None:
                typer.echo("[warn] Playwright module missing; cannot install browsers yet")
            else:
                typer.echo("[fix] Installing Playwright Chromium browser")
                install = subprocess.run(
                    [sys.executable, "-m", "playwright", "install", "chromium"],
                    capture_output=True,
                    text=True,
                    timeout=900,
                    check=False,
                )
                if install.returncode == 0:
                    typer.echo("[fix] Installed: playwright chromium browser")
                else:
                    typer.echo("[warn] Failed to install Playwright Chromium browser")

        if not attempted:
            typer.echo("[fix] No missing dependencies detected")

        tool_results, tool_warnings, _ = _collect_tool_health(emit_warnings=True)
        python_results, browser_status, browser_detail, python_warnings, _ = _collect_python_health(emit_warnings=True)
        warnings = tool_warnings + python_warnings

    typer.echo("")
    typer.echo("== Tool Health ==")
    for tool, status, version in tool_results:
        if status == "missing":
            typer.echo(f"{tool:12} : missing")
        else:
            suffix = f" ({version})" if version else ""
            typer.echo(f"{tool:12} : ok{suffix}")

    typer.echo("")
    typer.echo("== Python Dependency Health ==")
    for label, status, _ in python_results:
        typer.echo(f"{label:12} : {status}")
    if browser_status == "ok":
        typer.echo(f"{'playwright-browsers':20} : ok ({browser_detail})")
    else:
        suffix = f" ({browser_detail})" if browser_detail else ""
        typer.echo(f"{'playwright-browsers':20} : missing{suffix}")

    try:
        __import__("recon_cli.pipeline.stage_idor")
        __import__("recon_cli.pipeline.stage_auth_matrix")
    except Exception as exc:
        issues.append(f"stage import failed: {exc}")

    if issues:
        for issue in issues:
            typer.echo(f"[fail] {issue}")
        raise typer.Exit(code=1)

    if warnings:
        typer.secho(f"Doctor completed with {len(warnings)} warning(s)", fg=typer.colors.YELLOW)
        return

    typer.secho("All checks passed", fg=typer.colors.GREEN)



@app.command()
def prune(
    days: int = typer.Option(None, "--days", min=1, help="Remove finished jobs older than N days", show_default=False),
    archive: bool = typer.Option(False, "--archive", help="Move jobs to archive instead of deleting"),
) -> None:
    """Delete or archive finished jobs older than the given number of days."""
    if days is None:
        raise typer.BadParameter("--days is required", param_name="--days")
    manager = JobManager()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    finished_dir = config.FINISHED_JOBS
    if not finished_dir.exists():
        typer.echo("No finished jobs")
        return
    removed = 0
    for job_dir in finished_dir.iterdir():
        if not job_dir.is_dir():
            continue
        metadata_path = job_dir / config.METADATA_NAME
        payload = fs.read_json(metadata_path, default=None)
        if not payload:
            continue
        finished_at = payload.get("finished_at")
        if not finished_at:
            continue
        try:
            finished_ts = datetime.strptime(finished_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if finished_ts > cutoff:
            continue
        if archive:
            archive_path = config.ARCHIVE_ROOT / job_dir.name
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            if archive_path.exists():
                typer.echo(f"Archive target exists, skipping {job_dir.name}", err=True)
                continue
            fs.safe_move(job_dir, archive_path)
        else:
            manager.remove_job(job_dir.name)
        removed += 1
    typer.echo(f"Pruned {removed} jobs")


@app.command()
def export(
    job_id: str,
    fmt: str = typer.Option("jsonl", "--format", case_sensitive=False, help="Export format: jsonl|triage|txt|zip"),
    verified_only: bool = typer.Option(False, "--verified-only", help="Export only verified findings (jsonl only)"),
    proof_required: bool = typer.Option(False, "--proof-required", help="Export only findings with proof (jsonl only)"),
    hunter_mode: bool = typer.Option(
        False,
        "--hunter-mode",
        help="Export top verified findings with proof (jsonl only)",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        min=1,
        help="Limit findings exported (jsonl/triage only; used with filters/hunter-mode)",
    ),
) -> None:
    """Export job artifacts in JSONL, text summary, or ZIP form."""
    fmt = fmt.lower()
    if fmt not in {"jsonl", "triage", "txt", "zip"}:
        typer.echo(f"Unsupported format: {fmt}", err=True)
        raise typer.Exit(code=1)
    if hunter_mode:
        verified_only = True
        proof_required = True
        if limit is None:
            limit = 50
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    if fmt == "jsonl":
        from recon_cli.utils.jsonl import read_jsonl
        from recon_cli.utils.reporting import filter_findings, is_finding, rank_findings

        if verified_only or proof_required or limit is not None:
            entries = [entry for entry in read_jsonl(record.paths.results_jsonl) if is_finding(entry)]
            filtered = filter_findings(entries, verified_only=verified_only, proof_required=proof_required)
            if limit is not None:
                filtered = rank_findings(filtered, limit=limit)
            payload = "\n".join(json.dumps(item, separators=(",", ":"), ensure_ascii=True) for item in filtered) + "\n"
            typer.echo(redact(payload) or payload)
        else:
            payload = record.paths.results_jsonl.read_text(encoding="utf-8")
            typer.echo(redact(payload) or payload)
    elif fmt == "triage":
        from recon_cli.utils.jsonl import read_jsonl
        from recon_cli.utils.reporting import build_triage_entry, filter_findings, is_finding, rank_findings

        entries = [entry for entry in read_jsonl(record.paths.results_jsonl) if is_finding(entry)]
        filtered = filter_findings(entries, verified_only=verified_only, proof_required=proof_required)
        ranked = rank_findings(filtered, limit=limit)
        triage_entries = []
        triage_dir = record.paths.ensure_subdir("triage")
        for entry in ranked:
            triage_entry = build_triage_entry(entry, job_id=job_id)
            severity = str(triage_entry.get("severity") or "").lower()
            confidence = str(triage_entry.get("confidence") or "").lower()
            if severity in {"high", "critical"} and confidence == "verified":
                artifact_path = triage_dir / f"{triage_entry['finding_id']}.json"
                artifact_payload = {
                    "job_id": job_id,
                    "finding_id": triage_entry["finding_id"],
                    "severity": severity,
                    "confidence": confidence,
                    "source_finding": entry,
                    "repro_cmd": triage_entry.get("repro_cmd"),
                    "poc_steps": triage_entry.get("poc_steps", []),
                    "proof": triage_entry.get("proof"),
                    "request": entry.get("request"),
                    "response": entry.get("response"),
                }
                artifact_payload = redact_json_value(artifact_payload)
                artifact_path.write_text(
                    json.dumps(artifact_payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                triage_entry["artifact_path"] = str(artifact_path)
            triage_entries.append(triage_entry)
        payload = "\n".join(json.dumps(item, separators=(",", ":"), ensure_ascii=True) for item in triage_entries) + "\n"
        typer.echo(redact(payload) or payload)
    elif fmt == "txt":
        if verified_only or proof_required or hunter_mode or limit is not None:
            typer.echo("verified-only/proof-required filters are only supported for jsonl/triage exports", err=True)
            raise typer.Exit(code=2)
        payload = record.paths.results_txt.read_text(encoding="utf-8")
        typer.echo(redact(payload) or payload)
    else:
        if verified_only or proof_required or hunter_mode or limit is not None:
            typer.echo("verified-only/proof-required filters are only supported for jsonl/triage exports", err=True)
            raise typer.Exit(code=2)
        import shutil

        archive_path = config.RECON_HOME / f"{job_id}.zip"
        if archive_path.exists():
            archive_path.unlink()
        shutil.make_archive(str(archive_path.with_suffix("")), "zip", record.paths.root)
        typer.echo(str(archive_path))


@app.command()
def report(
    job_id: str,
    fmt: str = typer.Option("txt", "--format", case_sensitive=False, help="Report format: txt|md|json|html"),
    verified_only: bool = typer.Option(False, "--verified-only", help="Include only verified findings (html only)"),
    proof_required: bool = typer.Option(False, "--proof-required", help="Include only findings with proof (html only)"),
    hunter_mode: bool = typer.Option(False, "--hunter-mode", help="Hunter mode report preset (html only)"),
) -> None:
    """Emit a shareable report for a finished job."""
    fmt = fmt.lower()
    if fmt not in {"txt", "md", "json", "html"}:
        typer.echo(f"Unsupported format: {fmt}", err=True)
        raise typer.Exit(code=1)
    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    if fmt == "txt":
        if verified_only or proof_required or hunter_mode:
            typer.echo("verified-only/proof-required filters are only supported for html reports", err=True)
            raise typer.Exit(code=2)
        payload = record.paths.results_txt.read_text(encoding="utf-8")
        typer.echo(redact(payload) or payload)
        return
    if fmt == "md":
        if verified_only or proof_required or hunter_mode:
            typer.echo("verified-only/proof-required filters are only supported for html reports", err=True)
            raise typer.Exit(code=2)
        content = redact(record.paths.results_txt.read_text(encoding="utf-8")) or ""
        md_lines = ["# recon-cli report", f"Job: {job_id}", "", "```", content.strip(), "```"]
        typer.echo("\n".join(md_lines))
        return
    if fmt == "html":
        from recon_cli.utils.reporter import generate_html_report
        from recon_cli.utils.reporter import ReportConfig

        output_path = record.paths.root / "report.html"
        if hunter_mode:
            verified_only = True
            proof_required = True
        report_config = ReportConfig(
            verified_only=verified_only,
            proof_required=proof_required,
            hunter_mode=hunter_mode,
        )
        generate_html_report(record.paths.root, output_path, report_config)
        typer.secho(f"✅ HTML report generated: {output_path}", fg=typer.colors.GREEN)
        return
    payload = {
        "job_id": job_id,
        "spec": record.spec.to_dict(),
        "metadata": record.metadata.to_dict(),
        "stats": record.metadata.stats,
    }
    safe_payload = redact_json_value(payload)
    typer.echo(json.dumps(safe_payload, indent=2, sort_keys=True))


@app.command("verify-job")
def verify_job(job_id: str) -> None:
    """Validate job files and surface corruption/errors."""
    from recon_cli.jobs.validator import validate_job

    manager = JobManager()
    record = _load_job_or_exit(manager, job_id)
    issues = validate_job(record)
    if not issues:
        typer.secho(f"Job {job_id} OK", fg=typer.colors.GREEN)
        return
    typer.echo(f"Job {job_id} has {len(issues)} issue(s):", err=True)
    for issue in issues:
        typer.echo(f"- {issue}", err=True)
    raise typer.Exit(code=4)


@app.command()
def projects() -> None:
    """List configured projects."""
    from recon_cli import projects as projects_mod

    names = projects_mod.list_projects()
    if not names:
        typer.echo("No projects found")
        return
    for name in names:
        typer.echo(name)


@app.command()
def schema(fmt: str = typer.Option("json", "--format", help="Output format: json")) -> None:
    """Emit machine-readable schema for automation clients."""
    from recon_cli.api import schema_json

    fmt = fmt.lower()
    if fmt != "json":
        typer.echo(f"Unsupported format: {fmt}", err=True)
        raise typer.Exit(code=1)
    typer.echo(schema_json())


@app.command("cache-stats")
def cache_stats() -> None:
    """Show cache statistics."""
    from recon_cli.utils.cache import HybridCache
    cache = HybridCache(config.RECON_HOME / "cache")
    stats = cache.stats()
    rich_print("[bold]📊 Cache Statistics[/bold]")
    rich_print(f"  Memory hits  : {stats.get('memory_hits', 0)}")
    rich_print(f"  Memory misses: {stats.get('memory_misses', 0)}")
    rich_print(f"  Disk hits    : {stats.get('disk_hits', 0)}")
    rich_print(f"  Disk misses  : {stats.get('disk_misses', 0)}")
    rich_print(f"  Disk size    : {stats.get('disk_size', 0)} bytes")


@app.command("cache-clear")
def cache_clear() -> None:
    """Clear all cached data."""
    from recon_cli.utils.cache import HybridCache
    cache = HybridCache(config.RECON_HOME / "cache")
    cache.clear()
    typer.secho("✅ Cache cleared", fg=typer.colors.GREEN)


@app.command("serve")
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind"),
    port: int = typer.Option(8080, "--port", help="Port to bind"),
) -> None:
    """Start the REST API server."""
    try:
        import uvicorn
        from recon_cli.api.app import app as api_app
        typer.secho(f"🚀 Starting API server at http://{host}:{port}", fg=typer.colors.GREEN)
        typer.echo("   Docs: http://{host}:{port}/docs")
        uvicorn.run(api_app, host=host, port=port)
    except ImportError:
        typer.echo("❌ FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn", err=True)
        raise typer.Exit(code=1)


@app.command("notify")
def notify(
    message: str = typer.Argument("", help="Message to send"),
    channel: str = typer.Option("telegram", "--channel", "-c", help="Channel: telegram, slack, discord, email"),
) -> None:
    """Send a notification to configured channels."""
    from recon_cli.utils.notify import NotificationManager, NotificationConfig

    if not message:
        raise typer.BadParameter("message is required")
    
    # Load config from environment or defaults
    import os
    cfg = NotificationConfig(
        telegram_token=os.environ.get("TELEGRAM_TOKEN"),
        telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID"),
        slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL"),
        discord_webhook_url=os.environ.get("DISCORD_WEBHOOK_URL"),
    )
    
    manager = NotificationManager(cfg)
    results = manager.send(message, channels=[channel])
    
    for ch, success in results.items():
        if success:
            typer.secho(f"✅ {ch}: Message sent", fg=typer.colors.GREEN)
        else:
            typer.secho(f"❌ {ch}: Failed to send", fg=typer.colors.RED)


@app.command("db-init")
def db_init() -> None:
    """Initialize the SQLite database."""
    from recon_cli.db.models import init_db, get_db_path
    init_db()
    typer.secho(f"✅ Database initialized at {get_db_path()}", fg=typer.colors.GREEN)


@app.command("db-stats")
def db_stats() -> None:
    """Show database statistics."""
    from recon_cli.db.storage import get_dashboard_stats
    stats = get_dashboard_stats()
    
    rich_print("[bold]📊 Database Statistics[/bold]")
    rich_print("\n[bold]Jobs:[/bold]")
    for status, count in stats.get("jobs", {}).items():
        rich_print(f"  {status}: {count}")
    
    rich_print("\n[bold]Vulnerabilities:[/bold]")
    for severity, count in stats.get("vulnerabilities", {}).items():
        rich_print(f"  {severity}: {count}")


@app.command("optimize")
def optimize() -> None:
    """Run performance optimizations."""
    from recon_cli.utils.performance import optimize_memory, get_pool
    
    rich_print("[bold]🔧 Running optimizations...[/bold]")
    
    # Memory optimization
    result = optimize_memory()
    rich_print(f"  Resources cleaned: {result['resources_cleaned']}")
    
    # Pool stats
    pool = get_pool()
    pool_stats = pool.stats()
    rich_print(f"  Active sessions: {pool_stats['active_sessions']}")
    
    typer.secho("✅ Optimization complete", fg=typer.colors.GREEN)


@app.command("pdf")
def pdf_report(
    job_id: str = typer.Argument("", help="Job ID to generate PDF report for"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    title: str = typer.Option("تقرير الاستطلاع الأمني", "--title", help="Report title"),
) -> None:
    """Generate PDF report for a job."""
    from recon_cli.utils.pdf_reporter import generate_pdf_report, PDFReportConfig

    if not job_id:
        raise typer.BadParameter("job_id is required")
    
    manager = JobManager()
    record = manager.load_job(job_id)
    
    if not record:
        typer.echo(f"Job {job_id} not found", err=True)
        raise typer.Exit(code=3)
    
    job_path = record.path
    
    config = PDFReportConfig(
        title=title,
        company_name="ReconnV2"
    )
    
    try:
        pdf_path = generate_pdf_report(job_path, output, config)
        typer.secho(f"✅ PDF report generated: {pdf_path}", fg=typer.colors.GREEN)
    except RuntimeError as e:
        typer.secho(f"❌ Error: {e}", fg=typer.colors.RED)
        typer.secho("💡 Install dependencies with: pip install weasyprint reportlab", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)


@app.command("plugins")
def list_plugins(
    plugin_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by type: scanner, enricher, reporter, notifier"),
) -> None:
    """List available plugins."""
    from recon_cli.plugins import get_registry, PluginType
    
    registry = get_registry()
    registry.setup()
    
    type_filter = None
    if plugin_type:
        try:
            type_filter = PluginType(plugin_type.lower())
        except ValueError:
            typer.secho(f"Invalid type: {plugin_type}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
    
    plugins = registry.loader.list_plugins(plugin_type=type_filter)
    
    if not plugins:
        typer.secho("No plugins found", fg=typer.colors.YELLOW)
        return
    
    rich_print("[bold]📦 Available Plugins[/bold]")
    for meta in plugins:
        rich_print(f"\n[bold cyan]{meta.name}[/bold cyan] v{meta.version}")
        rich_print(f"  Type: {meta.plugin_type.value}")
        rich_print(f"  Description: {meta.description}")
        rich_print(f"  Author: {meta.author}")
        if meta.tags:
            rich_print(f"  Tags: {', '.join(meta.tags)}")


@app.command("run-plugin")
def run_plugin(
    name: str = typer.Argument("", help="Plugin name to run"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target for scanner plugins"),
    message: Optional[str] = typer.Option(None, "--message", "-m", help="Message for notifier plugins"),
) -> None:
    """Run a plugin."""
    from recon_cli.plugins import get_registry

    if not name:
        raise typer.BadParameter("name is required")
    
    registry = get_registry()
    registry.setup()
    
    context = {}
    if target:
        context["target"] = target
    if message:
        context["message"] = message
    
    result = registry.loader.execute_plugin(name, context)
    
    if result.success:
        typer.secho(f"✅ Plugin executed successfully", fg=typer.colors.GREEN)
        if result.data:
            rich_print(f"  Result: {result.data}")
        rich_print(f"  Execution time: {result.execution_time:.2f}s")
    else:
        typer.secho(f"❌ Plugin failed: {result.error}", fg=typer.colors.RED)


# ============================================================================
# INTERACTIVE MODE & WIZARD COMMANDS
# ============================================================================

@app.command("interactive")
def interactive_mode() -> None:
    """Start interactive wizard mode for guided scanning."""
    try:
        from recon_cli.cli_wizard import InteractiveMode
        
        rich_print("[bold cyan]🧙 ReconnV2 Interactive Mode[/bold cyan]")
        rich_print("Type 'help' for available commands, 'quit' to exit.\n")
        
        mode = InteractiveMode()
        _run_async_command(mode.run())
    except ImportError as e:
        typer.secho(f"Interactive mode not available: {e}", fg=typer.colors.RED)
    except KeyboardInterrupt:
        rich_print("\n[yellow]Exiting interactive mode...[/yellow]")


@app.command("wizard")
def scan_wizard() -> None:
    """Launch step-by-step scan configuration wizard."""
    try:
        from recon_cli.cli_wizard import ScanWizard
        
        rich_print("[bold cyan]🧙 Scan Configuration Wizard[/bold cyan]\n")
        
        wizard = ScanWizard()
        result = _run_async_command(wizard.run())
        
        if result.completed:
            rich_print("\n[bold green]✅ Wizard completed![/bold green]")
            rich_print(f"Configuration: {json.dumps(result.data, indent=2)}")
            
            # Ask to run scan
            if typer.confirm("Run scan with this configuration?"):
                spec = result.data
                scan(
                    target=spec.get("target"),
                    profile=spec.get("profile", "passive"),
                    inline=True,
                )
        else:
            rich_print("[yellow]Wizard cancelled.[/yellow]")
    except ImportError as e:
        typer.secho(f"Wizard not available: {e}", fg=typer.colors.RED)


# ============================================================================
# SHELL COMPLETIONS
# ============================================================================

@app.command("completions")
def setup_completions(
    shell: str = typer.Option(None, "--shell", "-s", help="Shell type: bash, zsh, fish, powershell"),
    install: bool = typer.Option(False, "--install", "-i", help="Auto-install completions"),
    show: bool = typer.Option(False, "--show", help="Show completion script without installing"),
) -> None:
    """Generate or install shell completions."""
    try:
        from recon_cli.completions import (
            CompletionGenerator,
            CompletionInstaller,
            RECON_COMMANDS,
            Shell,
        )
        
        # Auto-detect shell if not specified
        if not shell:
            import os
            shell_env = os.environ.get("SHELL", "")
            if "zsh" in shell_env:
                shell = "zsh"
            elif "fish" in shell_env:
                shell = "fish"
            elif os.name == "nt":
                shell = "powershell"
        else:
            shell = "bash"
        
        shell_enum = Shell(shell.lower())
        generator = CompletionGenerator(RECON_COMMANDS)
        
        if show or not install:
            script = generator.generate(shell_enum)
            rich_print(f"[bold]Completion script for {shell}:[/bold]\n")
            print(script)
            rich_print(f"\n[dim]Use --install to auto-install[/dim]")
        
        if install:
            installer = CompletionInstaller()
            installed_path = installer.install(shell_enum)
            typer.secho(f"✅ Installed completion script at: {installed_path}", fg=typer.colors.GREEN)
            source_command = installer.get_source_command(shell_enum)
            if source_command:
                typer.echo(source_command)
                
    except ImportError as e:
        typer.secho(f"Completions module not available: {e}", fg=typer.colors.RED)
    except ValueError as e:
        typer.secho(f"Invalid shell: {shell}. Use bash, zsh, fish, or powershell", fg=typer.colors.RED)


# ============================================================================
# REPORT GENERATION
# ============================================================================

@app.command("report")
def generate_report(
    job_id: str = typer.Argument("", help="Job ID to generate report for"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, csv, markdown, xml, pdf"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    executive: bool = typer.Option(False, "--executive", "-e", help="Generate executive summary only"),
    title: Optional[str] = typer.Option(None, "--title", "-t", help="Custom report title"),
    verified_only: bool = typer.Option(False, "--verified-only", help="Include only verified findings in the report"),
    proof_required: bool = typer.Option(False, "--proof-required", help="Include only findings with proof in the report"),
    hunter_mode: bool = typer.Option(False, "--hunter-mode", help="Hunter mode report preset (html only)"),
) -> None:
    """Generate a report for a completed job."""
    try:
        from recon_cli.reports import ReportGenerator, ReportConfig, ReportFormat
        from recon_cli.reports.executive import ExecutiveSummaryGenerator

        if not job_id:
            raise typer.BadParameter("job_id is required")
        
        manager = JobManager()
        record = _load_job_or_exit(manager, job_id)

        if hunter_mode:
            verified_only = True
            proof_required = True
        if hunter_mode and format.lower() != "html":
            typer.echo("--hunter-mode is only supported with --format html", err=True)
            raise typer.Exit(code=2)
        if executive and hunter_mode:
            typer.echo("--hunter-mode cannot be combined with --executive", err=True)
            raise typer.Exit(code=2)
        
        # Load job data
        job_data = {
            "id": job_id,
            "job_id": job_id,
            "targets": [record.spec.target] if hasattr(record.spec, 'target') else [],
            "findings": [],
            "hosts": [],
            "start_time": record.metadata.started_at,
            "end_time": record.metadata.finished_at,
        }
        
        # Load results
        if record.paths.results_jsonl.exists():
            from recon_cli.utils.jsonl import read_jsonl
            from recon_cli.utils.reporting import categorize_results, filter_findings
            categorized = categorize_results(read_jsonl(record.paths.results_jsonl), include_secret_in_findings=True)
            job_data["hosts"].extend(categorized["hosts"])
            findings = categorized["findings"]
            if verified_only or proof_required:
                findings = filter_findings(findings, verified_only=verified_only, proof_required=proof_required)
            job_data["findings"].extend(findings)
        
        if executive:
            # Executive summary only
            gen = ExecutiveSummaryGenerator(author="ReconnV2")
            summary = gen.generate(job_data, title=title)
            
            if format == "html":
                content = summary.to_html()
                ext = ".html"
            else:
                content = summary.to_text()
                ext = ".txt"
            
            if output:
                output.write_text(content)
                typer.secho(f"✅ Executive summary saved to {output}", fg=typer.colors.GREEN)
            else:
                print(content)
        else:
            # Full report
            report_format = ReportFormat(format.lower())
            if report_format == ReportFormat.HTML and (verified_only or proof_required or hunter_mode):
                from recon_cli.utils.reporter import ReportConfig as LegacyReportConfig
                from recon_cli.utils.reporter import generate_html_report as generate_legacy_html_report

                output_path = output or (record.paths.root / "report.html")
                config = LegacyReportConfig(
                    title=title or "ReconnV2 Scan Report",
                    language="en",
                    verified_only=verified_only,
                    proof_required=proof_required,
                    hunter_mode=hunter_mode,
                )
                generate_legacy_html_report(record.paths.root, output_path, config)
                typer.secho(f"✅ Report saved to {output_path}", fg=typer.colors.GREEN)
                return
            config = ReportConfig(
                title=title or f"Reconnaissance Report - {job_id}",
            )
            generator = ReportGenerator(config)
            import asyncio
            content = asyncio.run(generator.generate(job_data, format=report_format, output_path=output))
            if output:
                typer.secho(f"✅ Report saved to {output}", fg=typer.colors.GREEN)
            else:
                print(content)
                
    except ImportError as e:
        typer.secho(f"Reports module not available: {e}", fg=typer.colors.RED)
    except ValueError as e:
        typer.secho(f"Invalid format: {format}. Use html, json, csv, markdown, xml, or pdf", fg=typer.colors.RED)


# ============================================================================
# QUICK START HELPER
# ============================================================================

@app.command("quickstart")
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
   recon results <job_id>
   recon results <job_id> --json

[bold]6. Generate Report[/bold]
   recon report <job_id> --format html --output report.html
   recon report <job_id> --executive  # Summary only

[bold]7. List All Jobs[/bold]
   recon list
   recon list --status finished

[bold]8. Install Shell Completions[/bold]
   recon completions --install

[bold]9. Get Help[/bold]
   recon --help
   recon scan --help

[dim]Tip: Use --profile passive for safe reconnaissance,
     --profile full for comprehensive scanning.[/dim]
""")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
