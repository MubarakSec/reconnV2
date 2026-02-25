from __future__ import annotations

from recon_cli import config
from recon_cli.jobs.manager import JobManager


def _configure_jobs_root(monkeypatch, tmp_path):
    jobs_root = tmp_path / "jobs"
    monkeypatch.setattr(config, "JOBS_ROOT", jobs_root)
    monkeypatch.setattr(config, "QUEUED_JOBS", jobs_root / "queued")
    monkeypatch.setattr(config, "RUNNING_JOBS", jobs_root / "running")
    monkeypatch.setattr(config, "FINISHED_JOBS", jobs_root / "finished")
    monkeypatch.setattr(config, "FAILED_JOBS", jobs_root / "failed")
    config.ensure_base_directories()
    return jobs_root


def test_remove_job_rejects_path_traversal(monkeypatch, tmp_path):
    jobs_root = _configure_jobs_root(monkeypatch, tmp_path)
    safe_job = config.QUEUED_JOBS / "safe_job_123"
    safe_job.mkdir(parents=True, exist_ok=True)

    manager = JobManager(home=tmp_path)
    assert manager.remove_job("..") is False
    assert safe_job.exists()
    assert jobs_root.exists()


def test_remove_job_still_deletes_valid_job(monkeypatch, tmp_path):
    _configure_jobs_root(monkeypatch, tmp_path)
    safe_job = config.QUEUED_JOBS / "safe_job_123"
    safe_job.mkdir(parents=True, exist_ok=True)

    manager = JobManager(home=tmp_path)
    assert manager.remove_job("safe_job_123") is True
    assert not safe_job.exists()
