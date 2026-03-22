
import json
import os
import sys
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from recon_cli.cli import app
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec

runner = CliRunner()

@pytest.fixture
def mock_job_manager():
    with patch("recon_cli.cli.JobManager") as mock:
        yield mock

@pytest.fixture
def mock_job_lifecycle():
    with patch("recon_cli.cli.JobLifecycle") as mock:
        yield mock

@pytest.fixture
def mock_projects():
    with patch("recon_cli.projects.list_projects") as mock_list:
        yield mock_list

def create_mock_record(job_id="test_job", base_dir=None):
    if base_dir is None:
        base_dir = Path("/tmp/recon_test")
    spec = JobSpec(job_id=job_id, target="example.com", profile="passive")
    metadata = JobMetadata(job_id=job_id, queued_at="2024-01-01T00:00:00Z", status="finished")
    root = base_dir / job_id
    root.mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    # Create required files
    paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    paths.spec_path.write_text(json.dumps(spec.to_dict()))
    paths.metadata_path.write_text(json.dumps(metadata.to_dict()))
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    paths.pipeline_log.touch()
    
    return JobRecord(spec=spec, metadata=metadata, paths=paths)

def test_doctor_command():
    with patch("recon_cli.cli.CommandExecutor.available", return_value=True), \
         patch("subprocess.run") as mock_run, \
         patch("importlib.util.find_spec", return_value=MagicMock()):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v1.0.0"
        mock_run.return_value.stderr = ""
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Tool Health" in result.stdout

def test_doctor_command_fix():
    with patch("recon_cli.cli.config.ensure_base_directories") as mock_ensure, \
         patch("recon_cli.cli.CommandExecutor.available", return_value=False), \
         patch("importlib.util.find_spec", return_value=None), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        result = runner.invoke(app, ["doctor", "--fix", "--fix-deps"])
        assert result.exit_code == 0
        mock_ensure.assert_called()

def test_projects_command(mock_projects):
    mock_projects.return_value = ["proj1", "proj2"]
    result = runner.invoke(app, ["projects"])
    assert result.exit_code == 0
    assert "proj1" in result.stdout
    assert "proj2" in result.stdout

def test_projects_command_empty(mock_projects):
    mock_projects.return_value = []
    result = runner.invoke(app, ["projects"])
    assert result.exit_code == 0
    assert "No projects found" in result.stdout

def test_list_jobs_command(mock_job_manager):
    instance = mock_job_manager.return_value
    instance.list_jobs.return_value = ["job1", "job2"]
    result = runner.invoke(app, ["list-jobs"])
    assert result.exit_code == 0
    assert "job1" in result.stdout
    assert "job2" in result.stdout

def test_list_jobs_command_empty(mock_job_manager):
    instance = mock_job_manager.return_value
    instance.list_jobs.return_value = []
    result = runner.invoke(app, ["list-jobs"])
    assert result.exit_code == 0
    assert "No jobs found" in result.stdout

def test_status_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    result = runner.invoke(app, ["status", "job1"])
    assert result.exit_code == 0
    assert "Job job1" in result.stdout

def test_status_command_not_found(mock_job_manager):
    instance = mock_job_manager.return_value
    instance.load_job.return_value = None
    result = runner.invoke(app, ["status", "nonexistent"])
    assert result.exit_code == 3
    assert "Job nonexistent not found" in (result.stdout + result.stderr)

def test_requeue_command(mock_job_manager, mock_job_lifecycle, tmp_path):
    lifecycle_instance = mock_job_lifecycle.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    lifecycle_instance.requeue.return_value = record
    result = runner.invoke(app, ["requeue", "job1"])
    assert result.exit_code == 0
    assert "Job job1 moved to queue" in result.stdout

def test_requeue_command_fail(mock_job_manager, mock_job_lifecycle):
    lifecycle_instance = mock_job_lifecycle.return_value
    lifecycle_instance.requeue.return_value = None
    result = runner.invoke(app, ["requeue", "job1"])
    assert result.exit_code == 1
    assert "Job job1 not found" in (result.stdout + result.stderr)

def test_export_jsonl(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    record.paths.results_jsonl.write_text('{"finding":"test"}\n')
    instance.load_job.return_value = record
    result = runner.invoke(app, ["export", "job1", "--format", "jsonl"])
    assert result.exit_code == 0
    assert '{"finding":"test"}' in result.stdout

def test_export_zip(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    with patch("shutil.make_archive") as mock_zip:
        result = runner.invoke(app, ["export", "job1", "--format", "zip"])
        assert result.exit_code == 0
        mock_zip.assert_called()

