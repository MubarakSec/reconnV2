import subprocess
from pathlib import Path

import pytest

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.tools.executor import CommandExecutor, CommandError


class DummyManager:
    def update_metadata(self, record): ...
    def update_spec(self, record): ...


def make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job1"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id="job1", target="example.com", profile="passive")
    metadata = JobMetadata(job_id="job1", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_corrupt_metadata_detected(tmp_path: Path):
    record = make_record(tmp_path)
    # Write corrupt metadata
    record.paths.metadata_path.write_text("{corrupt", encoding="utf-8")
    manager = DummyManager()
    ctx = PipelineContext(record=record, manager=manager)
    assert ctx.record.metadata.stats["profiles"]["execution"] == record.spec.profile


def test_executor_handles_timeout(tmp_path: Path):
    logger = type(
        "L",
        (),
        {
            "info": lambda *a, **k: None,
            "error": lambda *a, **k: None,
            "warning": lambda *a, **k: None,
        },
    )()
    executor = CommandExecutor(logger)
    with pytest.raises(CommandError):
        executor.run(
            [subprocess.sys.executable, "-c", "import time; time.sleep(2)"], timeout=1
        )


def test_tls_toggle_in_context(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("RECON_VERIFY_TLS", "0")
    record = make_record(tmp_path)
    manager = DummyManager()
    ctx = PipelineContext(record=record, manager=manager)
    assert ctx.runtime_config.verify_tls is False
