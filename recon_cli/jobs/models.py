from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon_cli import config
from recon_cli.utils import time as time_utils


@dataclass
class JobPaths:
    root: Path

    @property
    def spec_path(self) -> Path:
        return self.root / config.SPEC_NAME

    @property
    def metadata_path(self) -> Path:
        return self.root / config.METADATA_NAME

    @property
    def artifacts_dir(self) -> Path:
        return self.root / config.ARTIFACTS_DIRNAME

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def pipeline_log(self) -> Path:
        return self.logs_dir / "pipeline.log"

    @property
    def results_jsonl(self) -> Path:
        return self.root / config.RESULTS_JSONL_NAME

    @property
    def results_txt(self) -> Path:
        return self.root / config.RESULTS_TEXT_NAME

    @property
    def trimmed_results_jsonl(self) -> Path:
        return self.root / "results_trimmed.jsonl"

    def artifact(self, name: str) -> Path:
        return self.artifacts_dir / name

    def ensure_subdir(self, *parts: str) -> Path:
        path = self.artifacts_dir.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path


@dataclass
class JobSpec:
    job_id: str = ""
    target: str = ""
    profile: str = "passive"
    targets: List[str] = field(default_factory=list)
    stages: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    project: Optional[str] = None
    inline: bool = False
    wordlist: Optional[str] = None
    targets_file: Optional[str] = None
    max_screenshots: Optional[int] = None
    force: bool = False
    allow_ip: bool = False
    active_modules: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=list)
    insecure: bool = False
    created_at: str = field(default_factory=time_utils.iso_now)
    initiator: Optional[str] = None
    execution_profile: Optional[str] = None
    runtime_overrides: Dict[str, Any] = field(default_factory=dict)
    incremental_from: Optional[str] = None

    def __post_init__(self) -> None:
        if self.targets and not self.target:
            self.target = self.targets[0]
        elif self.target and not self.targets:
            self.targets = [self.target]
        if not self.profile:
            self.profile = "passive"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "profile": self.profile,
            "targets": self.targets,
            "stages": self.stages,
            "options": self.options,
            "project": self.project,
            "inline": self.inline,
            "wordlist": self.wordlist,
            "targets_file": self.targets_file,
            "max_screenshots": self.max_screenshots,
            "force": self.force,
            "allow_ip": self.allow_ip,
            "active_modules": self.active_modules,
            "scanners": self.scanners,
            "insecure": self.insecure,
            "created_at": self.created_at,
            "initiator": self.initiator,
            "execution_profile": self.execution_profile,
            "runtime_overrides": self.runtime_overrides,
            "incremental_from": self.incremental_from,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "JobSpec":
        return cls(
            job_id=payload.get("job_id", ""),
            target=payload.get("target", ""),
            profile=payload.get("profile", "passive"),
            targets=list(payload.get("targets", [])),
            stages=list(payload.get("stages", [])),
            options=dict(payload.get("options", {})),
            project=payload.get("project"),
            inline=payload.get("inline", False),
            wordlist=payload.get("wordlist"),
            targets_file=payload.get("targets_file"),
            max_screenshots=payload.get("max_screenshots"),
            force=payload.get("force", False),
            allow_ip=payload.get("allow_ip", False),
            active_modules=list(payload.get("active_modules", [])),
            scanners=list(payload.get("scanners", [])),
            insecure=payload.get("insecure", False),
            created_at=payload.get("created_at", time_utils.iso_now()),
            initiator=payload.get("initiator"),
            execution_profile=payload.get("execution_profile"),
            runtime_overrides=dict(payload.get("runtime_overrides", {})),
            incremental_from=payload.get("incremental_from"),
        )


@dataclass
class JobMetadata:
    job_id: str
    queued_at: str
    schema_version: str = "1.0.0"
    status: str = "queued"
    stage: str = "queued"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    checkpoints: Dict[str, str] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    attempts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "queued_at": self.queued_at,
            "schema_version": self.schema_version,
            "status": self.status,
            "stage": self.stage,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "checkpoints": self.checkpoints,
            "stats": self.stats,
            "error": self.error,
            "attempts": self.attempts,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "JobMetadata":
        return cls(
            job_id=payload["job_id"],
            queued_at=payload["queued_at"],
            schema_version=payload.get("schema_version", "1.0.0"),
            status=payload.get("status", "queued"),
            stage=payload.get("stage", "queued"),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            checkpoints=payload.get("checkpoints", {}),
            stats=payload.get("stats", {}),
            error=payload.get("error"),
            attempts=payload.get("attempts", {}),
        )

    def checkpoint(self, stage: str) -> None:
        self.stage = stage
        self.checkpoints[stage] = time_utils.iso_now()

    def mark_started(self) -> None:
        if not self.started_at:
            self.started_at = time_utils.iso_now()
        self.status = "running"

    def mark_finished(self, status: str = "finished") -> None:
        self.status = status
        self.finished_at = time_utils.iso_now()

    def record_error(self, message: str) -> None:
        self.error = message
        self.status = "failed"

