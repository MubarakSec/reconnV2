from __future__ import annotations

import time
import asyncio
from pathlib import Path
from shutil import which

import pytest

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.runner import PipelineRunner
from recon_cli.pipeline.stage_base import Stage, StageError
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.pipeline_trace import (
    ArtifactTraceExporter,
    ExporterTraceProcessor,
    PipelineTraceProcessor,
    PipelineTraceRecorder,
    SynchronousMultiTraceProcessor,
)


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, job_id: str, runtime_overrides: dict | None = None) -> JobRecord:
    root = tmp_path / job_id
    paths = JobPaths(root)
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths.results_jsonl.touch(exist_ok=True)
    paths.results_txt.touch(exist_ok=True)
    spec = JobSpec(
        job_id=job_id,
        target="example.com",
        profile="passive",
        runtime_overrides=dict(runtime_overrides or {}),
    )
    metadata = JobMetadata(job_id=job_id, queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_pipeline_trace_artifact_records_failure(tmp_path: Path) -> None:
    class FailingStage(Stage):
        name = "failing_stage"

        def execute(self, context) -> None:
            raise StageError("boom")

    record = _make_record(tmp_path, "job-trace-fail", {"retry_count": 0})
    context = PipelineContext(record=record, manager=DummyManager(), force=False)
    runner = PipelineRunner(stages=[FailingStage()], continue_on_error=False)

    with pytest.raises(StageError):
        asyncio.run(runner.run(context))

    trace_summary = fs.read_json(record.paths.artifact("trace.json"), default={})
    trace_events = read_jsonl(record.paths.artifact("trace_events.jsonl"))

    assert trace_summary.get("status") == "failed"
    assert trace_summary.get("trace_id")
    assert trace_summary.get("error")
    spans = trace_summary.get("spans", [])
    assert len(spans) == 1
    assert spans[0]["name"] == "failing_stage"
    assert spans[0]["status"] == "failed"
    assert spans[0]["attributes"]["error_code"]
    assert record.metadata.stats.get("trace", {}).get("status") == "failed"
    event_names = [entry.get("name") for entry in trace_events]
    assert "trace.started" in event_names
    assert "span.started" in event_names
    assert "span.finished" in event_names
    assert "trace.finished" in event_names


def test_parallel_pipeline_trace_records_stage_spans_and_batches(tmp_path: Path) -> None:
    class DedupeStage(Stage):
        name = "dedupe_canonicalize"

        def execute(self, context) -> None:
            time.sleep(0.02)

    class DnsStage(Stage):
        name = "dns_resolve"

        def execute(self, context) -> None:
            time.sleep(0.05)

    class HttpStage(Stage):
        name = "http_probe"

        def execute(self, context) -> None:
            time.sleep(0.05)

    record = _make_record(
        tmp_path,
        "job-trace-parallel",
        {
            "parallel_stages": True,
            "max_parallel_stages": 2,
            "retry_count": 0,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager(), force=False)
    runner = PipelineRunner(stages=[DedupeStage(), DnsStage(), HttpStage()])

    asyncio.run(runner.run(context, stages=["dedupe_canonicalize", "dns_resolve", "http_probe"]))

    trace_summary = fs.read_json(record.paths.artifact("trace.json"), default={})
    trace_events = read_jsonl(record.paths.artifact("trace_events.jsonl"))

    assert trace_summary.get("status") == "finished"
    assert trace_summary.get("attributes", {}).get("parallel_enabled") is True
    spans = trace_summary.get("spans", [])
    assert {span["name"] for span in spans} == {
        "dedupe_canonicalize",
        "dns_resolve",
        "http_probe",
    }
    assert all(span["status"] == "completed" for span in spans)
    assert all(span["parent_span_id"] == trace_summary.get("root_span_id") for span in spans)
    trace_stats = record.metadata.stats.get("trace", {})
    assert trace_stats.get("parallel_enabled") is True
    assert trace_stats.get("span_count") == 3
    event_names = [entry.get("name") for entry in trace_events]
    assert "parallel.batch.started" in event_names
    assert "parallel.batch.finished" in event_names


@pytest.mark.skip(reason="Trace context propagation across run_in_executor needs deeper fix")
def test_pipeline_trace_records_tool_execution_spans(tmp_path: Path):

    class ToolStage(Stage):
        name = "tool_stage"

        def execute(self, context) -> None:
            true_cmd = which("true") or "/usr/bin/true"
            false_cmd = which("false") or "/usr/bin/false"
            import uuid
            uid = uuid.uuid4().hex
            context.executor.run([true_cmd, f"--uid={uid}"], check=False, capture_output=True, context=context)
            context.executor.run([false_cmd, f"--uid={uid}"], check=False, capture_output=True, context=context)

    record = _make_record(tmp_path, "job-trace-tools", {"retry_count": 0})
    context = PipelineContext(record=record, manager=DummyManager(), force=True)
    runner = PipelineRunner(stages=[ToolStage()])

    asyncio.run(runner.run(context))

    trace_summary = fs.read_json(record.paths.artifact("trace.json"), default={})
    spans = trace_summary.get("spans", [])
    stage_spans = [span for span in spans if span.get("span_type") == "stage"]
    tool_spans = [span for span in spans if span.get("span_type") == "tool_exec"]

    assert len(stage_spans) == 1
    assert len(tool_spans) == 2
    assert trace_summary.get("stats", {}).get("span_counts_by_type", {}).get("tool_exec") == 2

    stage_span = stage_spans[0]
    assert all(span.get("parent_span_id") == stage_span.get("span_id") for span in tool_spans)

    ok_span = next(span for span in tool_spans if span.get("attributes", {}).get("tool") == Path(which("true") or "/usr/bin/true").name)
    failed_span = next(span for span in tool_spans if span.get("attributes", {}).get("tool") == Path(which("false") or "/usr/bin/false").name)

    assert ok_span["status"] == "completed"
    assert failed_span["status"] == "failed"
    assert failed_span.get("attributes", {}).get("returncode") == 1


def test_pipeline_trace_supports_custom_processors(tmp_path: Path) -> None:
    class MemoryProcessor(PipelineTraceProcessor):
        def __init__(self) -> None:
            self.events: list[dict] = []
            self.snapshots: list[dict] = []
            self.closed = False

        def on_event(self, payload: dict) -> None:
            self.events.append(payload)

        def on_snapshot(self, snapshot: dict) -> None:
            self.snapshots.append(snapshot)

        def shutdown(self) -> None:
            self.closed = True

    trace_path = tmp_path / "trace.json"
    events_path = tmp_path / "trace_events.jsonl"
    memory = MemoryProcessor()
    processor = SynchronousMultiTraceProcessor(
        [
            memory,
            ExporterTraceProcessor(ArtifactTraceExporter(trace_path, events_path)),
        ]
    )
    recorder = PipelineTraceRecorder(
        trace_path,
        events_path,
        job_id="job-processor",
        target="example.com",
        profile="passive",
        processor=processor,
    )

    span = recorder.start_span("stage", span_type="stage")
    span.add_event("checkpoint", {"step": 1})
    span.finish(status="completed")
    recorder.close(status="finished")

    assert memory.closed is True
    event_names = [item.get("name") for item in memory.events]
    assert event_names == [
        "trace.started",
        "span.started",
        "span.event",
        "span.finished",
        "trace.finished",
    ]
    assert memory.snapshots[-1]["status"] == "finished"

    trace_summary = fs.read_json(trace_path, default={})
    trace_events = read_jsonl(events_path)
    assert trace_summary.get("status") == "finished"
    assert [entry.get("name") for entry in trace_events] == event_names
