from __future__ import annotations

import json
import os
import asyncio
from pathlib import Path
from unittest.mock import patch

from recon_cli import config
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.runner import PipelineRunner
from recon_cli.pipeline.stage_base import Stage
from recon_cli.reports.generator import ReportFormat, ReportGenerator
from recon_cli.utils import fs
from recon_cli.utils.last_run import refresh_job_pointers
from recon_cli.utils.pdf_reporter import PDFReporter
from recon_cli.utils.reporter import generate_html_report


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _configure_recon_home(monkeypatch, tmp_path: Path) -> None:
    jobs_root = tmp_path / "jobs"
    config_dir = tmp_path / "config"
    monkeypatch.setattr(config, "RECON_HOME", tmp_path)
    monkeypatch.setattr(config, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(config, "JOBS_ROOT", jobs_root)
    monkeypatch.setattr(config, "QUEUED_JOBS", jobs_root / "queued")
    monkeypatch.setattr(config, "RUNNING_JOBS", jobs_root / "running")
    monkeypatch.setattr(config, "FINISHED_JOBS", jobs_root / "finished")
    monkeypatch.setattr(config, "FAILED_JOBS", jobs_root / "failed")
    monkeypatch.setattr(config, "ARCHIVE_ROOT", tmp_path / "archive")
    monkeypatch.setattr(config, "DEFAULT_RESOLVERS_PARENT", config_dir)
    monkeypatch.setattr(config, "DEFAULT_RESOLVERS", config_dir / "resolvers.txt")
    monkeypatch.setattr(config, "DEFAULT_PROFILES", config_dir / "profiles.json")
    config.ensure_base_directories(force=True)


def _pointer_target(pointer_path: Path) -> Path:
    assert os.path.lexists(pointer_path)
    if pointer_path.is_symlink():
        return pointer_path.resolve()
    if pointer_path.is_file():
        payload = pointer_path.read_text(encoding="utf-8").strip()
        if payload:
            return Path(payload).resolve()
    return pointer_path.resolve()


def _make_record(root: Path, job_id: str) -> JobRecord:
    paths = JobPaths(root)
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths.results_jsonl.touch(exist_ok=True)
    paths.results_txt.touch(exist_ok=True)
    spec = JobSpec(job_id=job_id, target="example.com", profile="passive")
    metadata = JobMetadata(job_id=job_id, queued_at="2026-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_job_manager_refreshes_last_pointers_on_move(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_recon_home(monkeypatch, tmp_path)
    manager = JobManager(home=tmp_path)

    record = manager.create_job(target="example.com", profile="passive")
    assert _pointer_target(config.JOBS_ROOT / "last") == record.paths.root.resolve()

    (record.paths.root / "report.html").write_text("<html></html>", encoding="utf-8")
    record.paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    (record.paths.artifacts_dir / "trace.json").write_text("{}", encoding="utf-8")
    (record.paths.artifacts_dir / "trace_events.jsonl").write_text(
        "{}\n", encoding="utf-8"
    )

    moved_root = manager.move_job(record.spec.job_id, config.FINISHED_JOBS)
    assert moved_root is not None
    assert _pointer_target(config.JOBS_ROOT / "last") == moved_root.resolve()
    assert (
        _pointer_target(config.RECON_HOME / "reports" / "last")
        == (moved_root / "report.html").resolve()
    )
    assert (
        _pointer_target(config.RECON_HOME / "artifacts" / "last-trace.json")
        == (moved_root / "artifacts" / "trace.json").resolve()
    )
    assert (
        _pointer_target(config.RECON_HOME / "artifacts" / "last-trace-events.jsonl")
        == (moved_root / "artifacts" / "trace_events.jsonl").resolve()
    )


def test_remove_job_clears_last_pointers(monkeypatch, tmp_path: Path) -> None:
    _configure_recon_home(monkeypatch, tmp_path)
    manager = JobManager(home=tmp_path)
    record = manager.create_job(target="example.com", profile="passive")

    (record.paths.root / "report.html").write_text("<html></html>", encoding="utf-8")
    (record.paths.artifacts_dir / "trace.json").write_text("{}", encoding="utf-8")
    (record.paths.artifacts_dir / "trace_events.jsonl").write_text(
        "{}\n", encoding="utf-8"
    )
    refresh_job_pointers(record.paths.root)

    assert manager.remove_job(record.spec.job_id) is True
    assert not os.path.lexists(config.JOBS_ROOT / "last")
    assert not os.path.lexists(config.RECON_HOME / "reports" / "last")
    assert not os.path.lexists(config.RECON_HOME / "artifacts" / "last-trace.json")
    assert not os.path.lexists(
        config.RECON_HOME / "artifacts" / "last-trace-events.jsonl"
    )


def test_pipeline_trace_updates_last_trace_pointer(monkeypatch, tmp_path: Path) -> None:
    class SuccessStage(Stage):
        name = "success"

        def execute(self, context) -> None:
            return None

    _configure_recon_home(monkeypatch, tmp_path)
    record = _make_record(config.RUNNING_JOBS / "job-trace-last", "job-trace-last")
    context = PipelineContext(record=record, manager=DummyManager(), force=False)
    runner = PipelineRunner(stages=[SuccessStage()])

    asyncio.run(runner.run(context))

    assert (
        _pointer_target(config.RECON_HOME / "artifacts" / "last-trace.json")
        == record.paths.artifact("trace.json").resolve()
    )
    assert (
        _pointer_target(config.RECON_HOME / "artifacts" / "last-trace-events.jsonl")
        == record.paths.artifact("trace_events.jsonl").resolve()
    )


def test_generate_html_report_updates_last_report_pointer(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_recon_home(monkeypatch, tmp_path)
    job_dir = tmp_path / "job-html"
    job_dir.mkdir()
    (job_dir / "metadata.json").write_text(
        json.dumps({"job_id": "job-html", "status": "finished"}), encoding="utf-8"
    )
    (job_dir / "results.jsonl").write_text("", encoding="utf-8")

    output_path = tmp_path / "exports" / "report.html"
    generate_html_report(job_dir, output_path)

    assert (
        _pointer_target(config.RECON_HOME / "reports" / "last") == output_path.resolve()
    )


def test_report_generator_updates_last_report_pointer(
    monkeypatch, tmp_path: Path, event_loop
) -> None:
    _configure_recon_home(monkeypatch, tmp_path)
    output_path = tmp_path / "exports" / "report.json"
    generator = ReportGenerator()

    event_loop.run_until_complete(
        generator.generate(
            {
                "job_id": "job-report-generator",
                "targets": ["example.com"],
                "findings": [{"title": "example finding", "severity": "high"}],
            },
            format=ReportFormat.JSON,
            output_path=output_path,
        )
    )

    assert (
        _pointer_target(config.RECON_HOME / "reports" / "last") == output_path.resolve()
    )


def test_pdf_reporter_updates_last_report_pointer(monkeypatch, tmp_path: Path) -> None:
    _configure_recon_home(monkeypatch, tmp_path)
    output_path = tmp_path / "exports" / "report.pdf"
    reporter = PDFReporter()
    reporter.use_weasyprint = False
    reporter.use_reportlab = True

    def _fake_generate(_job_data, path: Path, _results=None) -> Path:
        path.write_bytes(b"%PDF-1.4\n")
        return path

    with patch.object(
        PDFReporter, "_generate_with_reportlab", side_effect=_fake_generate
    ):
        result = reporter.generate_report({"target": "example.com"}, output_path, [])

    assert result == output_path
    assert (
        _pointer_target(config.RECON_HOME / "reports" / "last") == output_path.resolve()
    )
