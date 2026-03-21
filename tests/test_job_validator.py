from pathlib import Path

from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.validator import validate_job
from recon_cli.utils import fs


def build_job(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job1"
    paths = JobPaths(root)
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths.pipeline_log.touch()
    fs.write_json(
        paths.spec_path,
        JobSpec(job_id="job1", target="example.com", profile="passive").to_dict(),
    )
    fs.write_json(
        paths.metadata_path,
        JobMetadata(job_id="job1", queued_at="2020-01-01T00:00:00Z").to_dict(),
    )
    paths.results_jsonl.write_text(
        '{"type":"meta","schema_version":"1.0.0"}\n', encoding="utf-8"
    )
    return JobRecord(
        spec=JobSpec.from_dict(fs.read_json(paths.spec_path)),
        metadata=JobMetadata.from_dict(fs.read_json(paths.metadata_path)),
        paths=paths,
    )


def test_validate_job_ok(tmp_path: Path):
    record = build_job(tmp_path)
    issues = validate_job(record)
    assert issues == []


def test_validate_job_with_corrupt_results(tmp_path: Path):
    record = build_job(tmp_path)
    record.paths.results_jsonl.write_text("not-json\n", encoding="utf-8")
    issues = validate_job(record)
    assert any("invalid lines" in issue for issue in issues)
