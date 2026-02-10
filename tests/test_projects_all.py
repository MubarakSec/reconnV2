from __future__ import annotations

from pathlib import Path

import pytest


def _setup_temp_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from recon_cli import config

    monkeypatch.setattr(config, "RECON_HOME", tmp_path)
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "JOBS_ROOT", tmp_path / "jobs")
    monkeypatch.setattr(config, "QUEUED_JOBS", config.JOBS_ROOT / "queued")
    monkeypatch.setattr(config, "RUNNING_JOBS", config.JOBS_ROOT / "running")
    monkeypatch.setattr(config, "FINISHED_JOBS", config.JOBS_ROOT / "finished")
    monkeypatch.setattr(config, "FAILED_JOBS", config.JOBS_ROOT / "failed")
    monkeypatch.setattr(config, "ARCHIVE_ROOT", tmp_path / "archive")
    monkeypatch.setattr(config, "DEFAULT_RESOLVERS", config.CONFIG_DIR / "resolvers.txt")
    monkeypatch.setattr(config, "DEFAULT_RESOLVERS_PARENT", config.DEFAULT_RESOLVERS.parent)
    monkeypatch.setattr(config, "DEFAULT_PROFILES", config.CONFIG_DIR / "profiles.json")
    config.ensure_base_directories(force=True)


def test_projects_list_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_temp_home(tmp_path, monkeypatch)

    from recon_cli import projects

    projects.ensure_project("alpha", scope=["alpha.example.com"])
    projects.ensure_project("beta", scope=["beta.example.com"])

    names = projects.list_projects()
    assert names == ["alpha", "beta"]
    assert projects.get_project("alpha")["name"] == "alpha"


def test_job_manager_filters_by_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_temp_home(tmp_path, monkeypatch)

    from recon_cli.jobs.manager import JobManager

    manager = JobManager()
    job_a = manager.create_job(target="a.example.com", profile="passive", project="alpha")
    job_b = manager.create_job(target="b.example.com", profile="passive", project="beta")

    all_jobs = set(manager.list_jobs())
    assert job_a.spec.job_id in all_jobs
    assert job_b.spec.job_id in all_jobs

    alpha_jobs = manager.list_jobs(project="alpha")
    assert alpha_jobs == [job_a.spec.job_id]
    assert manager.list_jobs(project="beta") == [job_b.spec.job_id]
    assert manager.list_jobs(project="missing") == []
