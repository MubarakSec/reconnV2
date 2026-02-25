import time
import asyncio
from pathlib import Path

import pytest

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.runner import PipelineRunner
from recon_cli.pipeline.stage_base import Stage, StageError
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record):
        return None

    def update_spec(self, record):
        return None


def make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-parallel"
    paths = JobPaths(root)
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths.results_jsonl.touch(exist_ok=True)
    paths.results_txt.touch(exist_ok=True)
    spec = JobSpec(
        job_id="job-parallel",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-parallel", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _timestamp(events, key):
    for name, ts in events:
        if name == key:
            return ts
    return None


def test_parallel_pipeline_respects_dependencies(tmp_path: Path):
    events = []

    class DedupeStage(Stage):
        name = "dedupe_canonicalize"

        def execute(self, context):
            events.append(("dedupe_start", time.time()))
            time.sleep(0.05)
            events.append(("dedupe_end", time.time()))

    class DnsStage(Stage):
        name = "dns_resolve"

        def execute(self, context):
            events.append(("dns_start", time.time()))
            time.sleep(0.1)
            events.append(("dns_end", time.time()))

    class HttpStage(Stage):
        name = "http_probe"

        def execute(self, context):
            events.append(("http_start", time.time()))
            time.sleep(0.1)
            events.append(("http_end", time.time()))

    record = make_record(
        tmp_path,
        {
            "parallel_stages": True,
            "max_parallel_stages": 2,
            "retry_count": 0,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager(), force=False)
    runner = PipelineRunner(stages=[DedupeStage(), DnsStage(), HttpStage()])

    runner.run(context, stages=["dedupe_canonicalize", "dns_resolve", "http_probe"])

    dedupe_end = _timestamp(events, "dedupe_end")
    dns_start = _timestamp(events, "dns_start")
    dns_end = _timestamp(events, "dns_end")
    http_start = _timestamp(events, "http_start")
    http_end = _timestamp(events, "http_end")

    assert dedupe_end is not None
    assert dns_start is not None
    assert http_start is not None
    assert dns_end is not None
    assert http_end is not None

    assert dns_start >= dedupe_end
    assert http_start >= dedupe_end
    # Ensure DNS and HTTP overlapped (parallel batch)
    assert dns_start < http_end
    assert http_start < dns_end


def test_parallel_pipeline_failure_marks_error(tmp_path: Path):
    class DedupeStage(Stage):
        name = "dedupe_canonicalize"

        def execute(self, context):
            return None

    class FailingDns(Stage):
        name = "dns_resolve"

        def execute(self, context):
            raise StageError("boom")

    class HttpStage(Stage):
        name = "http_probe"

        def execute(self, context):
            time.sleep(0.05)

    record = make_record(
        tmp_path,
        {
            "parallel_stages": True,
            "max_parallel_stages": 2,
            "retry_count": 0,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager(), force=False)
    runner = PipelineRunner(stages=[DedupeStage(), FailingDns(), HttpStage()])

    with pytest.raises(StageError):
        runner.run(context, stages=["dedupe_canonicalize", "dns_resolve", "http_probe"])

    assert record.metadata.error


def test_parallel_pipeline_supports_async_stage(tmp_path: Path):
    events = []

    class DedupeStage(Stage):
        name = "dedupe_canonicalize"

        def execute(self, context):
            events.append(("dedupe_start", time.time()))
            time.sleep(0.02)
            events.append(("dedupe_end", time.time()))

    class AsyncDnsStage(Stage):
        name = "dns_resolve"

        async def run_async(self, context):
            events.append(("dns_start", time.time()))
            await asyncio.sleep(0.05)
            events.append(("dns_end", time.time()))
            return True

    class HttpStage(Stage):
        name = "http_probe"

        def execute(self, context):
            events.append(("http_start", time.time()))
            time.sleep(0.05)
            events.append(("http_end", time.time()))

    record = make_record(
        tmp_path,
        {
            "parallel_stages": True,
            "max_parallel_stages": 2,
            "retry_count": 0,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager(), force=False)
    runner = PipelineRunner(stages=[DedupeStage(), AsyncDnsStage(), HttpStage()])

    runner.run(context, stages=["dedupe_canonicalize", "dns_resolve", "http_probe"])

    dedupe_end = _timestamp(events, "dedupe_end")
    dns_start = _timestamp(events, "dns_start")
    http_start = _timestamp(events, "http_start")
    assert dedupe_end is not None
    assert dns_start is not None
    assert http_start is not None
    assert dns_start >= dedupe_end
    assert http_start >= dedupe_end
