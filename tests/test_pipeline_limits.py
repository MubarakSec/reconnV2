import json
import subprocess
from collections import Counter
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_http_probe import HttpProbeStage
from recon_cli.pipeline.stages import CorrelationStage, PassiveEnumerationStage
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def make_record(
    tmp_path: Path, *, runtime_overrides=None, target: str = "example.com"
) -> JobRecord:
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
    # Mock wayback to avoid real network requests
    monkeypatch.setattr(PassiveEnumerationStage, "_run_wayback", lambda *_: None)

    stage = PassiveEnumerationStage()
    stage.run(context)
    entries = read_jsonl(record.paths.results_jsonl)
    assert any(
        entry.get("source") == "input" and entry.get("hostname") == record.spec.target
        for entry in entries
    )
    passive_hosts = (
        (record.paths.artifact("passive_hosts.txt"))
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert record.spec.target in passive_hosts


def test_correlation_truncates_large_inputs(tmp_path):
    overrides = {
        "correlation_max_records": 5,
        "correlation_svg_node_limit": 1000,
        "enable_correlation": True,
    }
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
    overrides = {"correlation_svg_node_limit": 1, "enable_correlation": True}
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


def test_http_probe_fallback_respects_host_caps(monkeypatch, tmp_path):
    overrides = {"max_probe_hosts": 2, "httpx_max_hosts": 2}
    record = make_record(tmp_path, runtime_overrides=overrides)
    manager = DummyManager()
    dedupe_hosts = record.paths.artifact("dedupe_hosts.txt")
    dedupe_hosts.write_text(
        "\n".join(
            [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    context = PipelineContext(record=record, manager=manager)

    monkeypatch.setattr(
        "recon_cli.tools.executor.CommandExecutor.available",
        staticmethod(lambda command: command != "httpx"),
    )

    captured: dict = {}

    def fake_fallback(self, _context, hosts, _seen_urls):
        captured["hosts"] = list(hosts)

    monkeypatch.setattr(HttpProbeStage, "_fallback_probe", fake_fallback)
    monkeypatch.setattr(
        HttpProbeStage, "_probe_additional_paths", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(HttpProbeStage, "_probe_soft_404", lambda *args, **kwargs: None)

    stage = HttpProbeStage()
    stage.run(context)

    assert captured["hosts"] == ["a.example.com", "b.example.com"]


def test_passive_wayback_fair_share_prevents_target_starvation(monkeypatch, tmp_path):
    overrides = {
        "wayback_max_urls": 6,
        "wayback_max_per_target": 0,
        "wayback_fair_share": True,
    }
    record = make_record(tmp_path, runtime_overrides=overrides, target="a.example.com")
    manager = DummyManager()
    context = PipelineContext(record=record, manager=manager)
    context.targets = ["a.example.com", "b.example.com", "c.example.com"]

    monkeypatch.setattr(
        "recon_cli.tools.executor.CommandExecutor.available",
        staticmethod(lambda command: command == "waybackurls"),
    )

    def fake_run_to_file(self, command, output_path, **_kwargs):
        target = str(command[-1])
        urls = [f"https://{target}/path{i}" for i in range(10)]
        output_path.write_text("\n".join(urls) + "\n", encoding="utf-8")
        return subprocess.CompletedProcess([str(part) for part in command], 0, "", "")

    monkeypatch.setattr(
        "recon_cli.tools.executor.CommandExecutor.run_to_file",
        fake_run_to_file,
    )

    stage = PassiveEnumerationStage()
    stage.run(context)

    entries = read_jsonl(record.paths.results_jsonl)
    wayback_urls = [
        entry
        for entry in entries
        if entry.get("type") == "url" and entry.get("source") == "waybackurls"
    ]
    assert len(wayback_urls) == 6
    counts = Counter(entry.get("hostname") for entry in wayback_urls)
    assert counts["a.example.com"] == 2
    assert counts["b.example.com"] == 2
    assert counts["c.example.com"] == 2
    stats = record.metadata.stats.get("wayback", {})
    assert stats.get("targets_processed") == 3
    assert stats.get("targets_skipped") == 0
    assert stats.get("urls_ingested") == 6
    assert stats.get("global_cap_hit") is True
