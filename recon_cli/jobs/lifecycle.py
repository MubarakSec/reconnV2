from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncio

from recon_cli import config
from recon_cli.jobs.manager import JobManager, JobRecord


class JobLifecycle:
    def __init__(
        self,
        manager: Optional[JobManager] = None,
        jobs_dir: Optional[Path] = None,
    ) -> None:
        if jobs_dir is not None:
            self._configure_jobs_root(Path(jobs_dir))
        self.manager = manager or JobManager()
        self.jobs_dir = jobs_dir or config.JOBS_ROOT

    def _configure_jobs_root(self, jobs_dir: Path) -> None:
        jobs_dir = jobs_dir.resolve()
        config.JOBS_ROOT = jobs_dir
        config.QUEUED_JOBS = jobs_dir / "queued"
        config.RUNNING_JOBS = jobs_dir / "running"
        config.FINISHED_JOBS = jobs_dir / "finished"
        config.FAILED_JOBS = jobs_dir / "failed"
        config.ensure_base_directories()

    def create_job(
        self,
        target: Optional[str] = None,
        targets: Optional[List[str]] = None,
        stages: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        profile: str = "passive",
        **kwargs: Any,
    ) -> str:
        resolved_target = target or (targets[0] if targets else "")
        record = self.manager.create_job(
            target=resolved_target,
            profile=profile,
            **kwargs,
        )
        if targets is not None:
            record.spec.targets = list(targets)
            if not record.spec.target and targets:
                record.spec.target = targets[0]
        if stages is not None:
            record.spec.stages = list(stages)
        if options is not None:
            record.spec.options = dict(options)
        self.manager.update_spec(record)
        return record.spec.job_id

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        return self.manager.load_job(job_id)

    def delete_job(self, job_id: str) -> bool:
        return self.manager.remove_job(job_id)

    def list_jobs(self, status: Optional[str] = None) -> List[str]:
        return self.manager.list_jobs(status=status)

    def get_status(self, job_id: str) -> Optional[str]:
        record = self.manager.load_job(job_id)
        if not record:
            return None
        return record.metadata.status

    async def run_job(self, job_id: str) -> Dict[str, Any]:
        record = self.manager.load_job(job_id)
        if not record:
            return {"success": False, "error": "Job not found"}
        from recon_cli.pipeline.runner import run_pipeline
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop and loop.is_running():
                await loop.run_in_executor(None, run_pipeline, record, self.manager)
            else:
                run_pipeline(record, self.manager)
            return {"success": True}
        except Exception as exc:  # pragma: no cover - runtime path
            return {"success": False, "error": str(exc)}

    def move_to_running(self, job_id: str, owner: Optional[str] = None) -> Optional[JobRecord]:
        if not self.manager.acquire_lock(job_id, owner=owner or "worker"):
            return None
        new_root = self.manager.move_job(job_id, config.RUNNING_JOBS)
        if not new_root:
            self.manager.release_lock(job_id)
            return None
        record = self.manager.load_job(job_id)
        if record:
            stop_path = record.paths.root / "stop.request"
            stop_path.unlink(missing_ok=True)
            record.metadata.status = "running"
            self.manager.update_metadata(record)
        return record

    def move_to_finished(self, job_id: str, status: str = "finished") -> Optional[JobRecord]:
        new_root = self.manager.move_job(job_id, config.FINISHED_JOBS)
        if not new_root:
            return None
        record = self.manager.load_job(job_id)
        if record:
            record.metadata.status = status
            self.manager.update_metadata(record)
        self.manager.release_lock(job_id)
        return record

    def move_to_failed(self, job_id: str) -> Optional[JobRecord]:
        new_root = self.manager.move_job(job_id, config.FAILED_JOBS)
        if not new_root:
            return None
        record = self.manager.load_job(job_id)
        if record:
            record.metadata.status = "failed"
            self.manager.update_metadata(record)
        self.manager.release_lock(job_id)
        return record

    def requeue(self, job_id: str) -> Optional[JobRecord]:
        new_root = self.manager.move_job(job_id, config.QUEUED_JOBS)
        if not new_root:
            return None
        self.manager.release_lock(job_id)
        record = self.manager.load_job(job_id)
        if record:
            stop_path = record.paths.root / "stop.request"
            stop_path.unlink(missing_ok=True)
            failed_stage = record.metadata.stage
            if failed_stage and failed_stage in record.metadata.checkpoints:
                record.metadata.checkpoints.pop(failed_stage, None)
            record.metadata.attempts = {}
            record.metadata.status = "queued"
            record.metadata.stage = "queued"
            record.metadata.error = None
            self.manager.update_spec(record)
            self.manager.update_metadata(record)
        return record
