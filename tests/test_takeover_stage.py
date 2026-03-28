import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.vuln.stage_takeover import TakeoverStage
from recon_cli.takeover.detector import TakeoverFinding
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-takeover"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-takeover",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-takeover", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_hostname(path: Path, hostname: str) -> None:
    payload = {"type": "hostname", "hostname": hostname, "source": "test"}
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


def test_takeover_provider_filtering(monkeypatch, tmp_path: Path):
    from recon_cli.pipeline import stage_takeover as stage_mod

    record = make_record(
        tmp_path,
        {
            "enable_takeover": True,
            "takeover_require_cname": True,
            "takeover_max_hosts": 2,
        },
    )
    _write_hostname(record.paths.results_jsonl, "dangling.example.com")
    context = PipelineContext(record=record, manager=DummyManager())

    class DummyRdata:
        def __str__(self):
            return "alias.s3.amazonaws.com."

    class DummyResolver:
        def __init__(self):
            self.timeout = 1
            self.lifetime = 1

        def resolve(self, _current, _rtype):
            return [DummyRdata()]

    class DummyDNS:
        resolver = type("ResolverMod", (), {"Resolver": DummyResolver})

    monkeypatch.setattr(stage_mod, "dns", DummyDNS)

    class FakeDetector:
        last_providers = None

        def __init__(self, *args, **kwargs):
            return None

        async def check_host(self, hostname, providers=None):
            FakeDetector.last_providers = providers
            return TakeoverFinding(
                hostname=hostname, provider="aws_s3", evidence="NoSuchBucket"
            )

    monkeypatch.setattr(stage_mod, "TakeoverDetector", FakeDetector)

    stage = TakeoverStage()
    monkeypatch.setattr(stage, "_has_wildcard_dns", lambda *_a, **_k: False)
    stage.run(context)

    assert FakeDetector.last_providers == {"aws_s3"}
    findings = [
        r
        for r in read_jsonl(record.paths.results_jsonl)
        if r.get("finding_type") == "subdomain_takeover"
    ]
    assert len(findings) == 1


def test_takeover_requires_cname_skips(monkeypatch, tmp_path: Path):
    from recon_cli.pipeline import stage_takeover as stage_mod

    record = make_record(
        tmp_path,
        {
            "enable_takeover": True,
            "takeover_require_cname": True,
            "takeover_max_hosts": 1,
        },
    )
    _write_hostname(record.paths.results_jsonl, "no-cname.example.com")
    context = PipelineContext(record=record, manager=DummyManager())

    class DummyDNS:
        resolver = type("ResolverMod", (), {"Resolver": object})

    monkeypatch.setattr(stage_mod, "dns", DummyDNS)

    stage = TakeoverStage()
    monkeypatch.setattr(stage, "_resolve_cname_chain", lambda *_args, **_kwargs: [])

    stage.run(context)
    stats = record.metadata.stats.get("takeover", {})
    assert stats.get("skipped_no_cname") == 1
