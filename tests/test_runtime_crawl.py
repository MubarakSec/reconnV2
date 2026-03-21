import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages import RuntimeCrawlStage


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job1"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(
        job_id="job1",
        target="example.com",
        profile="passive",
        runtime_overrides={
            "enable_runtime_crawl": True,
            "runtime_crawl_max_urls": 1,
            "runtime_crawl_timeout": 1,
            "runtime_crawl_concurrency": 1,
        },
    )
    metadata = JobMetadata(job_id="job1", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_runtime_crawl_skips_when_playwright_browsers_missing(
    monkeypatch, tmp_path: Path
):
    record = make_record(tmp_path)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        payload = {
            "type": "url",
            "url": "https://example.com/",
            "hostname": "example.com",
            "status_code": 200,
            "tags": [],
            "score": 10,
        }
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")
    context = PipelineContext(record=record, manager=DummyManager())

    import recon_cli.pipeline.stage_runtime_crawl as stages_module

    monkeypatch.setattr(stages_module, "PLAYWRIGHT_AVAILABLE", True)

    def _raise(*_args, **_kwargs):
        raise RuntimeError("playwright install required")

    monkeypatch.setattr(stages_module, "crawl_urls", _raise)

    stage = RuntimeCrawlStage()
    stage.run(context)

    stats = record.metadata.stats.get("runtime_crawl", {})
    assert stats.get("status") == "playwright_browsers_missing"
