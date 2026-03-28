import asyncio
from pathlib import Path

import pytest

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.runner import PipelineRunner
from recon_cli.pipeline.stages.core.stage_base import Stage, StageError
from recon_cli.utils import fs


class FailingStage(Stage):
    name = "failing_stage"

    def execute(self, context):
        raise StageError("boom")


class DummyManager:
    def update_metadata(self, record):
        return None

    def update_spec(self, record):
        return None


def make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job1"
    paths = JobPaths(root)
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(job_id="job1", target="example.com", profile="passive")
    metadata = JobMetadata(job_id="job1", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_pipeline_records_failure(tmp_path: Path):
    record = make_record(tmp_path)
    manager = DummyManager()
    runner = PipelineRunner(stages=[FailingStage()], continue_on_error=False)
    ctx = type("Ctx", (), {})()
    ctx.record = record
    ctx.manager = manager
    ctx.mark_started = lambda *_, **__: None
    ctx.mark_finished = lambda *_, **__: None
    ctx.mark_error = lambda msg: setattr(record.metadata, "error", msg)
    ctx.close = lambda *_, **__: None
    ctx.logger = type(
        "L",
        (),
        {
            "info": lambda *a, **k: None,
            "warning": lambda *a, **k: None,
            "exception": lambda *a, **k: None,
        },
    )()
    ctx.max_retries = 0
    ctx.results = None
    ctx.targets = []
    ctx.runtime_config = type(
        "RC", (), {"retry_backoff_base": 1, "retry_backoff_factor": 2}
    )()
    ctx.force = False
    ctx.increment_attempt = lambda *_: None
    ctx.checkpoint = lambda *_: None
    with pytest.raises(StageError):
        asyncio.run(runner.run(ctx))
    assert record.metadata.error
    taxonomy = record.metadata.stats.get("error_taxonomy", {})
    assert taxonomy.get("last", {}).get("code")
    assert taxonomy.get("counts")
    partial = record.metadata.stats.get("partial_results", {})
    assert partial.get("generated_after_failure") is True
    assert record.paths.results_txt.read_text(encoding="utf-8").strip()
