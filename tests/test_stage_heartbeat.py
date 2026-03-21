import time
from pathlib import Path

import pytest

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, StageStopRequested
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


class SlowStage(Stage):
    name = "slow_stage"

    def execute(self, context) -> None:
        time.sleep(2.2)


class DisabledStage(Stage):
    name = "disabled_stage"

    def is_enabled(self, context) -> bool:
        return False

    def execute(self, context) -> None:
        raise AssertionError("should not execute")


class CheckpointedStage(Stage):
    name = "checkpointed_stage"

    def execute(self, context) -> None:
        raise AssertionError("should not execute")


class StopAwareStage(Stage):
    name = "stop_aware_stage"

    def execute(self, context) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-heartbeat"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-heartbeat",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-heartbeat", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_stage_heartbeat_is_logged(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "retry_count": 0,
            "stage_heartbeat_seconds": 1,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager())
    stage = SlowStage()
    stage.run(context)
    context.close()

    log_text = record.paths.pipeline_log.read_text(encoding="utf-8")
    assert "Stage slow_stage heartbeat: still running" in log_text
    stage_heartbeat = record.metadata.stats.get("stage_heartbeats", {}).get(
        "slow_stage", {}
    )
    assert int(stage_heartbeat.get("count", 0)) >= 1
    assert int(stage_heartbeat.get("last_elapsed_seconds", 0)) >= 1


def test_stage_sla_warning_and_metadata(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "retry_count": 0,
            "stage_heartbeat_seconds": 1,
            "stage_sla_seconds": 1,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager())
    stage = SlowStage()
    stage.run(context)
    context.close()

    log_text = record.paths.pipeline_log.read_text(encoding="utf-8")
    assert "Stage slow_stage exceeded SLA (1s)" in log_text
    alerts = record.metadata.stats.get("stage_runtime_alerts", {})
    stage_alert = alerts.get("slow_stage", {})
    assert stage_alert.get("sla_seconds") == 1
    assert int(stage_alert.get("alert_elapsed_seconds", 0)) >= 1


def test_disabled_stage_records_skip_reason(tmp_path: Path):
    record = _make_record(tmp_path, {"retry_count": 0})
    context = PipelineContext(record=record, manager=DummyManager())
    stage = DisabledStage()
    ran = stage.run(context)
    context.close()

    assert ran is False
    skip_entry = record.metadata.stats.get("stage_skips", {}).get("disabled_stage", {})
    assert skip_entry.get("reason") == "disabled"
    assert int(skip_entry.get("count", 0)) >= 1


def test_checkpointed_stage_records_skip_reason(tmp_path: Path):
    record = _make_record(tmp_path, {"retry_count": 0})
    record.metadata.checkpoints["checkpointed_stage"] = "2020-01-01T00:00:00Z"
    context = PipelineContext(record=record, manager=DummyManager())
    stage = CheckpointedStage()
    ran = stage.run(context)
    context.close()

    assert ran is False
    skip_entry = record.metadata.stats.get("stage_skips", {}).get(
        "checkpointed_stage", {}
    )
    assert skip_entry.get("reason") == "checkpointed"
    assert int(skip_entry.get("count", 0)) >= 1


def test_stage_stop_request_raises_and_records_skip(tmp_path: Path):
    record = _make_record(tmp_path, {"retry_count": 0})
    stop_path = record.paths.root / "stop.request"
    stop_path.write_text('{"reason":"test"}', encoding="utf-8")
    context = PipelineContext(record=record, manager=DummyManager())
    stage = StopAwareStage()

    with pytest.raises(StageStopRequested):
        stage.run(context)
    context.close()

    skip_entry = record.metadata.stats.get("stage_skips", {}).get(
        "stop_aware_stage", {}
    )
    assert skip_entry.get("reason") == "stop_requested"
    assert int(skip_entry.get("count", 0)) >= 1
