from __future__ import annotations

from pathlib import Path
import pytest


from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.discovery.stage_cms_scan import CMSScanStage
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-cms"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-cms",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-cms", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


@pytest.mark.asyncio
async def test_cms_scan_prefers_droopescan_for_joomla(monkeypatch, tmp_path: Path):
    from recon_cli.pipeline import stage_cms_scan as stage_mod

    record = make_record(tmp_path, {"enable_cms_scan": True})
    context = PipelineContext(record=record, manager=DummyManager())
    stage = CMSScanStage()

    class DummyExecutor:
        def __init__(self):
            self.commands = []

        def run(self, cmd, check=False, timeout=None, capture_output=False):
            self.commands.append(cmd)

            class Result:
                stdout = "droopescan ok"
                stderr = ""
                returncode = 0

            return Result()

        async def run_async(self, cmd, **kwargs):
            return self.run(cmd, **kwargs)

    dummy_executor = DummyExecutor()
    context.executor = dummy_executor

    def fake_available(tool: str) -> bool:
        if tool == "droopescan":
            return True
        if tool == "joomscan":
            raise AssertionError("joomscan should not be used")
        return False

    monkeypatch.setattr(
        stage_mod.CommandExecutor, "available", staticmethod(fake_available)
    )

    cms_dir = context.record.paths.ensure_subdir("cms")
    result = await stage._run_scan(
        context, "joomla", "example.com", "https://example.com", 10, cms_dir
    )
    assert result["tool"] == "droopescan"
    assert dummy_executor.commands
    assert dummy_executor.commands[0][:3] == ["droopescan", "scan", "joomla"]


@pytest.mark.asyncio
async def test_cms_scan_falls_back_to_nuclei_when_droopescan_missing(
    monkeypatch, tmp_path: Path
):
    from recon_cli.pipeline import stage_cms_scan as stage_mod

    record = make_record(tmp_path, {"enable_cms_scan": True})
    context = PipelineContext(record=record, manager=DummyManager())
    stage = CMSScanStage()

    class DummyFinding:
        def __init__(self, payload):
            self.payload = payload

    class DummyResult:
        def __init__(self):
            self.findings = [
                {"type": "finding", "details": {"template_id": "joomla-test"}}
            ]
            self.artifact_path = None

    class DummyIntegrations:
        @staticmethod
        def run_nuclei(*_args, **_kwargs):
            return DummyResult()

    monkeypatch.setattr(stage_mod, "scanner_integrations", DummyIntegrations)

    def fake_available(tool: str) -> bool:
        if tool == "droopescan":
            return False
        if tool == "joomscan":
            raise AssertionError("joomscan should not be used")
        if tool == "nuclei":
            return True
        return False

    monkeypatch.setattr(
        stage_mod.CommandExecutor, "available", staticmethod(fake_available)
    )

    cms_dir = context.record.paths.ensure_subdir("cms")
    result = await stage._run_scan(
        context, "joomla", "example.com", "https://example.com", 10, cms_dir
    )
    assert result["tool"] == "nuclei"
    assert result["findings"]
