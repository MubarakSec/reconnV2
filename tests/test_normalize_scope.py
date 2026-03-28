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
    monkeypatch.setattr(
        config, "DEFAULT_RESOLVERS", config.CONFIG_DIR / "resolvers.txt"
    )
    monkeypatch.setattr(
        config, "DEFAULT_RESOLVERS_PARENT", config.DEFAULT_RESOLVERS.parent
    )
    monkeypatch.setattr(config, "DEFAULT_PROFILES", config.CONFIG_DIR / "profiles.json")
    config.ensure_base_directories(force=True)


def test_normalize_stage_uses_inputs_after_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _setup_temp_home(tmp_path, monkeypatch)

    from recon_cli.jobs.lifecycle import JobLifecycle
    from recon_cli.jobs.manager import JobManager
    from recon_cli.pipeline.context import PipelineContext
    from recon_cli.pipeline.stages.core.stage_normalize import NormalizeStage

    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("example.com\n", encoding="utf-8")

    manager = JobManager()
    record = manager.create_job(
        target="example.com",
        profile="passive",
        targets_file=str(targets_file),
    )
    job_id = record.spec.job_id

    lifecycle = JobLifecycle(manager)
    record = lifecycle.move_to_running(job_id)
    assert record is not None
    assert record.spec.targets_file

    context = PipelineContext(record=record, manager=manager)
    stage = NormalizeStage()
    stage.run(context)

    assert "example.com" in context.targets
    assert Path(record.spec.targets_file).exists()
    assert str(record.paths.root) in str(record.spec.targets_file)
