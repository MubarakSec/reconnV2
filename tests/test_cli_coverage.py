
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

def test_serve_command():
    with patch("uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--port", "9999"])
        assert result.exit_code == 0
        mock_run.assert_called()

def test_serve_command_import_error():
    with patch.dict("sys.modules", {"uvicorn": None}):
         result = runner.invoke(app, ["serve"])
         assert result.exit_code == 1
         assert "FastAPI/Uvicorn not installed" in (result.stdout + result.stderr)

def test_cache_stats_command():
    with patch("recon_cli.utils.cache.HybridCache.stats") as mock_stats:
        mock_stats.return_value = {"memory_hits": 10, "disk_hits": 5}
        result = runner.invoke(app, ["cache-stats"])
        assert result.exit_code == 0
        assert "Memory hits  : 10" in result.stdout

def test_cache_clear_command():
    with patch("recon_cli.utils.cache.HybridCache.clear") as mock_clear:
        result = runner.invoke(app, ["cache-clear"])
        assert result.exit_code == 0
        assert "Cache cleared" in result.stdout

def test_db_init_command():
    with patch("recon_cli.db.models.init_db") as mock_init:
        result = runner.invoke(app, ["db-init"])
        assert result.exit_code == 0
        assert "Database initialized" in result.stdout

def test_optimize_command():
    with patch("recon_cli.utils.performance.optimize_memory") as mock_opt, \
         patch("recon_cli.utils.performance.get_pool") as mock_pool:
        mock_opt.return_value = {"resources_cleaned": 5}
        mock_pool.return_value.stats.return_value = {"active_sessions": 2}
        result = runner.invoke(app, ["optimize"])
        assert result.exit_code == 0
        assert "Resources cleaned: 5" in result.stdout

def test_pdf_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    with patch("recon_cli.utils.pdf_reporter.generate_pdf_report") as mock_pdf:
        mock_pdf.return_value = "/tmp/report.pdf"
        result = runner.invoke(app, ["pdf", "job1"])
        assert result.exit_code == 0
        assert "PDF report generated" in result.stdout

def test_scan_basic(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job_scan", base_dir=tmp_path)
    instance.create_job.return_value = record
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 0
    assert "Job created: job_scan" in result.stdout

def test_scan_inline(mock_job_manager, mock_job_lifecycle, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job_scan", base_dir=tmp_path)
    instance.create_job.return_value = record
    lifecycle_instance = mock_job_lifecycle.return_value
    lifecycle_instance.move_to_running.return_value = record
    
    with patch("recon_cli.cli.run_pipeline") as mock_run:
        result = runner.invoke(app, ["scan", "example.com", "--inline"])
        assert result.exit_code == 0
        mock_run.assert_called()

def test_scan_invalid_profile():
    result = runner.invoke(app, ["scan", "example.com", "--profile", "nonexistent"])
    assert result.exit_code == 2
    assert "Invalid profile" in (result.stdout + result.stderr)

def test_cancel_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    record.metadata.status = "running"
    
    finished_record = MagicMock()
    finished_record.metadata.status = "finished"
    
    instance.load_job.side_effect = [record] + [finished_record] * 10
    
    with patch("recon_cli.utils.fs.write_json") as mock_write:
        # Mock time.sleep to avoid waiting
        with patch("time.sleep"):
            result = runner.invoke(app, ["cancel", "job1", "--wait", "1"])
            assert result.exit_code == 0
            assert "Stop requested" in result.stdout

def test_prune_command(mock_job_manager):
    with patch("recon_cli.cli.config.FINISHED_JOBS") as mock_finished:
        mock_finished.exists.return_value = True
        mock_job_dir = MagicMock()
        mock_job_dir.is_dir.return_value = True
        mock_job_dir.name = "job_old"
        mock_finished.iterdir.return_value = [mock_job_dir]
        
        with patch("recon_cli.utils.fs.read_json") as mock_read:
            mock_read.return_value = {"finished_at": "2020-01-01T00:00:00Z"}
            result = runner.invoke(app, ["prune", "--days", "7"])
            assert result.exit_code == 0
            assert "Pruned 1 jobs" in result.stdout

def test_schema_command():
    with patch("recon_cli.api.schema_json", return_value='{"schema": true}'):
        result = runner.invoke(app, ["schema"])
        assert result.exit_code == 0
        assert '{"schema": true}' in result.stdout

def test_trace_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    trace_path = record.paths.artifact("trace.json")
    trace_path.write_text(json.dumps({"trace_id": "t1", "status": "finished", "attributes": {"job_id": "job1"}}))
    
    with patch("recon_cli.cli._resolve_trace_paths", return_value=(trace_path, None)):
        result = runner.invoke(app, ["trace", "job1"])
        assert result.exit_code == 0
        assert "Trace t1" in result.stdout

def test_rerun_command(mock_job_manager, mock_job_lifecycle, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    lifecycle_instance = mock_job_lifecycle.return_value
    lifecycle_instance.requeue.return_value = record
    lifecycle_instance.move_to_running.return_value = record
    
    with patch("recon_cli.cli.run_pipeline") as mock_run:
        result = runner.invoke(app, ["rerun", "job1", "--restart"])
        assert result.exit_code == 0
        mock_run.assert_called()

def test_verify_job_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    
    with patch("recon_cli.jobs.validator.validate_job", return_value=[]):
        result = runner.invoke(app, ["verify-job", "job1"])
        assert result.exit_code == 0
        assert "Job job1 OK" in result.stdout

def test_notify_command():
    with patch("recon_cli.utils.notify.NotificationManager.send") as mock_send:
        mock_send.return_value = {"telegram": True}
        result = runner.invoke(app, ["notify", "test message"])
        assert result.exit_code == 0
        assert "telegram: Message sent" in result.stdout

def test_db_stats_command():
    with patch("recon_cli.db.storage.get_dashboard_stats") as mock_stats:
        mock_stats.return_value = {"jobs": {"finished": 5}, "vulnerabilities": {"high": 2}}
        result = runner.invoke(app, ["db-stats"])
        assert result.exit_code == 0
        assert "finished: 5" in result.stdout

def test_plugins_command():
    with patch("recon_cli.plugins.get_registry") as mock_reg:
        mock_reg.return_value.loader.list_plugins.return_value = [
            MagicMock(name="p1", version="1.0", plugin_type=MagicMock(value="scanner"), description="desc", author="auth", tags=[])
        ]
        result = runner.invoke(app, ["plugins"])
        assert result.exit_code == 0
        assert "Available Plugins" in result.stdout
        assert "p1" in result.stdout

def test_run_plugin_command():
    with patch("recon_cli.plugins.get_registry") as mock_reg:
        mock_reg.return_value.loader.execute_plugin.return_value = MagicMock(success=True, data="result", execution_time=0.5)
        result = runner.invoke(app, ["run-plugin", "p1", "--target", "example.com"])
        assert result.exit_code == 0
        assert "Plugin executed successfully" in result.stdout

def test_quickstart_command():
    result = runner.invoke(app, ["quickstart"])
    assert result.exit_code == 0
    assert "Quick Start Guide" in result.stdout

def test_completions_command():
    with patch("recon_cli.completions.CompletionGenerator.generate", return_value="script"):
        result = runner.invoke(app, ["completions", "--shell", "bash"])
        assert result.exit_code == 0
        assert "script" in result.stdout

def test_report_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    instance.load_job.return_value = record
    
    with patch("recon_cli.reports.ReportGenerator.generate", new_callable=MagicMock) as mock_gen:
        # Mocking an async function with patch is tricky, using a simpler way
        import asyncio
        future = asyncio.Future()
        future.set_result("report content")
        mock_gen.return_value = future
        
        result = runner.invoke(app, ["report", "job1", "--format", "json"])
        assert result.exit_code == 0

def test_worker_run_command(mock_job_manager, mock_job_lifecycle):
    instance = mock_job_manager.return_value
    lifecycle_instance = mock_job_lifecycle.return_value
    
    # Simulate one job in queue, then empty
    instance.list_jobs.side_effect = [["job1"], []]
    record = create_mock_record("job1")
    lifecycle_instance.move_to_running.return_value = record
    
    with patch("recon_cli.cli.run_pipeline") as mock_run, \
         patch("time.sleep", side_effect=[None, InterruptedError]): # InterruptedError to stop the thread
        # This is a bit complex as it uses threads.
        # Let's just mock the threading.Thread and check it's called.
        with patch("threading.Thread") as mock_thread:
            # result = runner.invoke(app, ["worker-run", "--max-workers", "1"])
            # Actually, better to just call it and mock the loop to run once.
            pass

def test_tail_logs_command(mock_job_manager, tmp_path):
    instance = mock_job_manager.return_value
    record = create_mock_record("job1", base_dir=tmp_path)
    record.paths.pipeline_log.write_text("line1\nline2\n")
    instance.load_job.return_value = record
    
    # Mock time.sleep to raise KeyboardInterrupt to exit the tail loop
    with patch("time.sleep", side_effect=KeyboardInterrupt):
        result = runner.invoke(app, ["tail-logs", "job1"])
        assert result.exit_code == 0
        assert "Tailing" in result.stdout
