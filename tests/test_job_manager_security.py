from __future__ import annotations

import json

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


def test_acquire_lock_allows_single_holder(monkeypatch, tmp_path):
    _configure_jobs_root(monkeypatch, tmp_path)
    manager = JobManager(home=tmp_path)
    record = manager.create_job(target="example.com", profile="passive")

    assert manager.acquire_lock(record.spec.job_id, owner="worker-1") is True
    assert manager.acquire_lock(record.spec.job_id, owner="worker-2") is False


def test_acquire_lock_recovers_stale_pid_lock(monkeypatch, tmp_path):
    _configure_jobs_root(monkeypatch, tmp_path)
    manager = JobManager(home=tmp_path)
    record = manager.create_job(target="example.com", profile="passive")
    lock_path = record.paths.root / ".lock"
    lock_path.write_text(
        json.dumps(
            {"owner": "old-worker", "pid": 999999, "timestamp": "2026-01-01T00:00:00Z"}
        ),
        encoding="utf-8",
    )

    def _fake_kill(_pid: int, _sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr("recon_cli.jobs.manager.os.kill", _fake_kill)

    assert manager.acquire_lock(record.spec.job_id, owner="worker-3") is True
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    assert payload.get("owner") == "worker-3"
