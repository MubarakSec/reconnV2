"""
Progress Display for ReconnV2 Pipeline.

Provides rich progress bars and status displays for:
- Pipeline execution
- Stage progress
- Target processing
- Download/upload progress

Example:
    >>> from recon_cli.pipeline.progress import PipelineProgress
    >>> async with PipelineProgress() as progress:
    ...     await progress.run_pipeline(stages, targets)
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    MofNCompleteColumn,
    ProgressColumn,
    Task,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

__all__ = [
    "ProgressLogger",
    "StageStatus",
    "StageProgress",
    "TargetProgress",
    "PipelineProgress",
    "DownloadProgress",
    "MultiProgress",
    "ProgressCallback",
    "create_pipeline_progress",
]


console = Console()


class ProgressLogger:
    """Simple progress logger with throttling."""

    def __init__(self, logger, interval: float = 2.0) -> None:
        self.logger = logger
        self.interval = interval
        self.last_emit = time.perf_counter()

    def maybe(self, message: str) -> None:
        now = time.perf_counter()
        if now - self.last_emit >= self.interval:
            self.logger.info(message)
            self.last_emit = now


class StageStatus(Enum):
    """Status of a pipeline stage."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class SpeedColumn(ProgressColumn):
    """Custom column showing processing speed."""

    def render(self, task: Task) -> Text:
        if task.speed is None:
            return Text("-", style="dim")
        return Text(f"{task.speed:.1f}/s", style="cyan")


class EtaColumn(ProgressColumn):
    """Custom column showing ETA."""

    def render(self, task: Task) -> Text:
        remaining = task.time_remaining
        if remaining is None:
            return Text("-", style="dim")

        eta = timedelta(seconds=int(remaining))
        return Text(f"ETA: {eta}", style="yellow")


@dataclass
class StageProgress:
    """Progress tracker for a single stage."""

    name: str
    status: StageStatus = StageStatus.PENDING
    total: int = 0
    completed: int = 0
    failed: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None

    @property
    def progress_percent(self) -> float:
        """Get progress percentage."""
        if self.total == 0:
            return 0.0
        return (self.completed / self.total) * 100

    @property
    def duration(self) -> Optional[timedelta]:
        """Get stage duration."""
        if self.start_time is None:
            return None
        end = self.end_time or datetime.now()
        return end - self.start_time

    def start(self) -> None:
        """Mark stage as started."""
        self.status = StageStatus.RUNNING
        self.start_time = datetime.now()

    def complete(self) -> None:
        """Mark stage as completed."""
        self.status = StageStatus.COMPLETED
        self.end_time = datetime.now()

    def fail(self, error: str) -> None:
        """Mark stage as failed."""
        self.status = StageStatus.FAILED
        self.end_time = datetime.now()
        self.error_message = error

    def skip(self) -> None:
        """Mark stage as skipped."""
        self.status = StageStatus.SKIPPED
        self.end_time = datetime.now()


@dataclass
class TargetProgress:
    """Progress tracker for a single target."""

    target: str
    current_stage: Optional[str] = None
    stages_completed: List[str] = field(default_factory=list)
    stages_failed: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    findings_count: int = 0

    @property
    def is_complete(self) -> bool:
        """Check if target processing is complete."""
        return self.end_time is not None

    @property
    def duration(self) -> timedelta:
        """Get processing duration."""
        end = self.end_time or datetime.now()
        return end - self.start_time


ProgressCallback = Callable[[str, int, int], None]


class PipelineProgress:
    """Rich progress display for pipeline execution."""

    def __init__(
        self,
        title: str = "ReconnV2 Pipeline",
        show_stages: bool = True,
        show_targets: bool = True,
        show_stats: bool = True,
        refresh_rate: float = 10.0,
    ):
        self.title = title
        self.show_stages = show_stages
        self.show_targets = show_targets
        self.show_stats = show_stats
        self.refresh_rate = refresh_rate

        self.stages: Dict[str, StageProgress] = {}
        self.targets: Dict[str, TargetProgress] = {}
        self.start_time: Optional[datetime] = None
        self.total_findings = 0

        self._progress: Optional[Progress] = None
        self._live: Optional[Live] = None
        self._task_ids: Dict[str, int] = {}

    def _create_progress(self) -> Progress:
        """Create Rich Progress instance."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            SpeedColumn(),
            console=console,
            refresh_per_second=self.refresh_rate,
            expand=True,
        )

    def _create_display(self) -> Group:
        """Create the full display layout."""
        elements = []

        # Header
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            header = Text(f"⏱️ Elapsed: {elapsed}", style="dim")
            elements.append(header)

        # Progress bars
        elements.append(self._progress)  # type: ignore[arg-type]

        # Stages table
        if self.show_stages and self.stages:
            elements.append(self._create_stages_table())  # type: ignore[arg-type]

        # Stats
        if self.show_stats:
            elements.append(self._create_stats_panel())  # type: ignore[arg-type]

        return Panel(  # type: ignore[return-value]
            Group(*elements),
            title=f"🔍 {self.title}",
            border_style="cyan",
        )

    def _create_stages_table(self) -> Table:
        """Create stages status table."""
        table = Table(title="📋 Stages", show_header=True, expand=True)
        table.add_column("Stage", style="cyan", width=20)
        table.add_column("Status", width=12)
        table.add_column("Progress", width=15)
        table.add_column("Duration", width=12)
        table.add_column("Errors", width=8)

        status_styles = {
            StageStatus.PENDING: "[dim]⏳ Pending[/dim]",
            StageStatus.RUNNING: "[yellow]▶️ Running[/yellow]",
            StageStatus.COMPLETED: "[green]✅ Done[/green]",
            StageStatus.FAILED: "[red]❌ Failed[/red]",
            StageStatus.SKIPPED: "[dim]⏭️ Skipped[/dim]",
        }

        for name, stage in self.stages.items():
            status = status_styles.get(stage.status, str(stage.status))
            progress = (
                f"{stage.completed}/{stage.total} ({stage.progress_percent:.0f}%)"
            )
            duration = str(stage.duration).split(".")[0] if stage.duration else "-"
            errors = str(stage.failed) if stage.failed else "-"

            table.add_row(name, status, progress, duration, errors)

        return table

    def _create_stats_panel(self) -> Panel:
        """Create statistics panel."""
        tree = Tree("📊 Statistics")

        # Targets
        targets_branch = tree.add("🎯 Targets")
        total = len(self.targets)
        completed = sum(1 for t in self.targets.values() if t.is_complete)
        targets_branch.add(f"Total: {total}")
        targets_branch.add(f"Completed: {completed}")
        targets_branch.add(f"In Progress: {total - completed}")

        # Findings
        findings_branch = tree.add("🔎 Findings")
        findings_branch.add(f"Total: {self.total_findings}")

        # Errors
        errors = sum(s.failed for s in self.stages.values())
        if errors:
            errors_branch = tree.add("[red]⚠️ Errors[/red]")
            errors_branch.add(f"Total: {errors}")

        return Panel(tree, border_style="dim")

    async def __aenter__(self) -> "PipelineProgress":
        """Enter async context."""
        self._progress = self._create_progress()
        self._live = Live(
            self._create_display(),
            console=console,
            refresh_per_second=self.refresh_rate,
        )
        self._live.__enter__()
        self.start_time = datetime.now()
        return self

    async def __aexit__(self, *args) -> None:
        """Exit async context."""
        if self._live:
            self._live.__exit__(*args)

    def _update_display(self) -> None:
        """Update the live display."""
        if self._live:
            self._live.update(self._create_display())

    def add_stage(self, name: str, total: int = 0) -> StageProgress:
        """Add a stage to track."""
        stage = StageProgress(name=name, total=total)
        self.stages[name] = stage

        if self._progress:
            task_id = self._progress.add_task(
                f"[cyan]{name}[/cyan]",
                total=total or 100,
            )
            self._task_ids[name] = task_id

        self._update_display()
        return stage

    def start_stage(self, name: str) -> None:
        """Mark a stage as started."""
        if name in self.stages:
            self.stages[name].start()
            self._update_display()

    def update_stage(
        self,
        name: str,
        completed: Optional[int] = None,
        total: Optional[int] = None,
        increment: int = 0,
    ) -> None:
        """Update stage progress."""
        if name not in self.stages:
            return

        stage = self.stages[name]

        if completed is not None:
            stage.completed = completed
        if total is not None:
            stage.total = total
        if increment:
            stage.completed += increment

        # Update progress bar
        if name in self._task_ids and self._progress:
            self._progress.update(
                self._task_ids[name],  # type: ignore[arg-type]
                completed=stage.completed,
                total=stage.total,
            )

        self._update_display()

    def complete_stage(self, name: str) -> None:
        """Mark a stage as completed."""
        if name in self.stages:
            stage = self.stages[name]
            stage.complete()

            if name in self._task_ids and self._progress:
                self._progress.update(
                    self._task_ids[name],  # type: ignore[arg-type]
                    completed=stage.total,
                )

            self._update_display()

    def fail_stage(self, name: str, error: str) -> None:
        """Mark a stage as failed."""
        if name in self.stages:
            self.stages[name].fail(error)
            self._update_display()

    def add_target(self, target: str) -> TargetProgress:
        """Add a target to track."""
        target_progress = TargetProgress(target=target)
        self.targets[target] = target_progress
        self._update_display()
        return target_progress

    def update_target(self, target: str, stage: str, findings: int = 0) -> None:
        """Update target progress."""
        if target in self.targets:
            self.targets[target].current_stage = stage
            self.targets[target].findings_count += findings
            self.total_findings += findings
            self._update_display()

    def complete_target(self, target: str) -> None:
        """Mark target as complete."""
        if target in self.targets:
            self.targets[target].end_time = datetime.now()
            self._update_display()

    def add_findings(self, count: int) -> None:
        """Add to total findings count."""
        self.total_findings += count
        self._update_display()


class DownloadProgress:
    """Progress display for downloads/uploads."""

    def __init__(self, description: str = "Downloading"):
        self.description = description
        self._progress: Optional[Progress] = None
        self._task_id: Optional[int] = None

    def __enter__(self) -> "DownloadProgress":
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[cyan]{task.fields[speed]}[/cyan]"),
            TimeRemainingColumn(),
            console=console,
        )
        self._progress.__enter__()
        return self

    def __exit__(self, *args) -> None:
        if self._progress:
            self._progress.__exit__(*args)

    def start(self, total: int) -> None:
        """Start tracking download."""
        if self._progress:
            self._task_id = self._progress.add_task(
                self.description,
                total=total,
                speed="0 B/s",
            )

    def update(self, completed: int, speed: str = "") -> None:
        """Update download progress."""
        if self._progress and self._task_id is not None:
            self._progress.update(
                self._task_id,  # type: ignore[arg-type]
                completed=completed,
                speed=speed,
            )


class MultiProgress:
    """Track multiple concurrent operations."""

    def __init__(self, title: str = "Operations"):
        self.title = title
        self._progress: Optional[Progress] = None
        self._task_ids: Dict[str, int] = {}

    def __enter__(self) -> "MultiProgress":
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self._progress.__enter__()
        return self

    def __exit__(self, *args) -> None:
        if self._progress:
            self._progress.__exit__(*args)

    def add_task(self, name: str, total: int = 100) -> str:
        """Add a task to track."""
        if self._progress:
            task_id = self._progress.add_task(name, total=total)
            self._task_ids[name] = task_id
        return name

    def update(
        self, name: str, completed: Optional[int] = None, advance: int = 0
    ) -> None:
        """Update task progress."""
        if self._progress and name in self._task_ids:
            if completed is not None:
                self._progress.update(self._task_ids[name], completed=completed)  # type: ignore[arg-type]
            if advance:
                self._progress.advance(self._task_ids[name], advance)  # type: ignore[arg-type]

    def complete(self, name: str) -> None:
        """Mark task as complete."""
        if self._progress and name in self._task_ids:
            task = self._progress.tasks[self._task_ids[name]]
            self._progress.update(self._task_ids[name], completed=task.total)  # type: ignore[arg-type]


@asynccontextmanager
async def create_pipeline_progress(
    title: str = "ReconnV2 Pipeline",
    stages: Optional[List[str]] = None,
    targets: Optional[List[str]] = None,
):
    """Create a pipeline progress context."""
    progress = PipelineProgress(title=title)

    async with progress:
        # Add stages
        if stages:
            for stage in stages:
                progress.add_stage(stage)

        # Add targets
        if targets:
            for target in targets:
                progress.add_target(target)

        yield progress


# Simple progress functions for quick use
def show_spinner(message: str) -> Progress:
    """Create a simple spinner."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        console=console,
    )
    progress.add_task(message, total=None)
    return progress


async def show_progress_for(
    items: List[Any],
    callback: Callable[[Any], Any],
    description: str = "Processing",
) -> List[Any]:
    """Show progress while processing items."""
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(description, total=len(items))

        for item in items:
            result = (
                await callback(item)
                if asyncio.iscoroutinefunction(callback)
                else callback(item)
            )
            results.append(result)
            progress.advance(task)

    return results
