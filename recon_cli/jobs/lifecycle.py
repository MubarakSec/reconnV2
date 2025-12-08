from __future__ import annotations

from pathlib import Path
from typing import Optional

from recon_cli import config
from recon_cli.jobs.manager import JobManager, JobRecord


class JobLifecycle:
    def __init__(self, manager: JobManager) -> None:
        self.manager = manager

    def move_to_running(self, job_id: str, owner: Optional[str] = None) -> Optional[JobRecord]:
        if not self.manager.acquire_lock(job_id, owner=owner or "worker"):
            return None
        new_root = self.manager.move_job(job_id, config.RUNNING_JOBS)
        if not new_root:
            self.manager.release_lock(job_id)
            return None
        record = self.manager.load_job(job_id)
        if record:
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
