import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages import CorrelationStage, PassiveEnumerationStage
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def make_record(tmp_path: Path, *, runtime_overrides=None, target: str = "example.com") -> JobRecord:
    root = tmp_path / "job1"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(
        job_id="job1",
        target=target,
        profile="passive",
        runtime_overrides=runtime_overrides or {},
    )
    metadata = JobMetadata(job_id="job1", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_passive_stage_seeds_input(monkeypatch, tmp_path):
    record = make_record(tmp_path)
    manager = DummyManager()
    context = PipelineContext(record=record, manager=manager)
    context.targets = [record.spec.target]
    monkeypatch.setattr(
        "recon_cli.tools.executor.CommandExecutor.available",
        staticmethod(lambda *_: False),
    )
    stage = PassiveEnumerationStage()
    stage.run(context)
    entries = read_jsonl(record.paths.results_jsonl)
    assert any(
        entry.get("source") == "input" and entry.get("hostname") == record.spec.target
        for entry in entries
    )
    passive_hosts = (record.paths.artifact("passive_hosts.txt")).read_text(encoding="utf-8").splitlines()
    assert record.spec.target in passive_hosts


def test_correlation_truncates_large_inputs(tmp_path):
    overrides = {"correlation_max_records": 5, "correlation_svg_node_limit": 1000}
    record = make_record(tmp_path, runtime_overrides=overrides)
    manager = DummyManager()
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for i in range(10):
            payload = {
                "type": "url",
                "url": f"https://h{i}.example.com/",
                "hostname": f"h{i}.example.com",
                "tags": [],
            }
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")
    context = PipelineContext(record=record, manager=manager)
    stage = CorrelationStage()
    stage.run(context)
    stats = record.metadata.stats.get("correlation", {})
    assert stats.get("truncated") is True
    assert stats.get("processed") == 5
    assert stats.get("max_records") == 5


def test_correlation_skips_svg_when_graph_large(tmp_path):
    overrides = {"correlation_svg_node_limit": 1}
    record = make_record(tmp_path, runtime_overrides=overrides)
    manager = DummyManager()
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for i in range(3):
            payload = {
                "type": "url",
                "url": f"https://node{i}.example.com/path{i}",
                "hostname": f"node{i}.example.com",
                "tags": [],
            }
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")
    context = PipelineContext(record=record, manager=manager)
    stage = CorrelationStage()
    stage.run(context)
    stats = record.metadata.stats.get("correlation", {})
    assert stats.get("graph_nodes", 0) > 1
    assert "graph_svg" not in stats
