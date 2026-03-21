from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

import recon_cli.cli as cli
import recon_cli.completions as completions
from recon_cli import config
from recon_cli.jobs.manager import JobManager
from recon_cli.utils.last_run import update_last_trace_pointers


def test_schema_command_outputs_json():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["schema", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout.strip())
    assert "job_spec" in payload
    assert "job_metadata" in payload


def test_completions_command_uses_command_tree():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["completions", "--shell", "bash"])
    assert result.exit_code == 0
    assert "_recon_completions" in result.stdout


def test_completions_show_respects_explicit_shell():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["completions", "--shell", "zsh", "--show"])
    assert result.exit_code == 0
    assert "Completion script for zsh" in result.stdout


def test_completions_install_handles_path_return(monkeypatch):
    def _fake_install(self, shell):
        return Path("/tmp/recon.bash")

    monkeypatch.setattr(completions.CompletionInstaller, "install", _fake_install)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["completions", "--shell", "bash", "--install"])
    assert result.exit_code == 0
    assert "Installed completion script at" in result.stdout
    assert "/tmp/recon.bash" in result.stdout


def test_interactive_mode_executes_async_run(monkeypatch):
    called = {"run": 0}

    class _FakeInteractiveMode:
        async def run(self) -> None:
            called["run"] += 1

    monkeypatch.setattr("recon_cli.cli_wizard.InteractiveMode", _FakeInteractiveMode)
    cli.interactive_mode()
    assert called["run"] == 1


def test_wizard_command_executes_async_run(monkeypatch):
    called = {"run": 0}

    class _Result:
        completed = False
        data = {}

    class _FakeScanWizard:
        async def run(self):
            called["run"] += 1
            return _Result()

    monkeypatch.setattr("recon_cli.cli_wizard.ScanWizard", _FakeScanWizard)
    cli.scan_wizard()
    assert called["run"] == 1


def test_doctor_reports_python_dependency_section():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["doctor", "--no-exit-on-fail"])
    assert result.exit_code in {0, 1}
    assert "== Tool Health ==" in result.stdout
    assert "interactsh-client" in result.stdout
    assert "== Python Dependency Health ==" in result.stdout
    assert "dnspython" in result.stdout
    assert "playwright" in result.stdout
    assert "requests" in result.stdout
    assert "pyyaml" in result.stdout


def test_doctor_reports_missing_external_tools(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr(
        cli.CommandExecutor, "available", staticmethod(lambda _tool: False)
    )

    result = runner.invoke(cli.app, ["doctor", "--no-exit-on-fail"])
    assert result.exit_code == 0
    assert "httpx        : missing" in result.stdout
    assert "nuclei       : missing" in result.stdout
    assert "interactsh-client : missing" in result.stdout
    assert "Doctor completed with" in result.stdout


def test_doctor_reports_tool_probe_errors(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr(
        cli.CommandExecutor,
        "available",
        staticmethod(lambda tool: tool == "droopescan"),
    )

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr="Traceback: broken tool\n"
        )

    monkeypatch.setattr("subprocess.run", _fake_run)

    result = runner.invoke(cli.app, ["doctor", "--no-exit-on-fail"])
    assert result.exit_code == 0
    assert "droopescan   : error" in result.stdout


def test_doctor_fix_deps_attempts_installs(monkeypatch):
    runner = CliRunner()
    state = {"dns": False, "playwright": False}
    calls: list[list[str]] = []

    def _fake_find_spec(name: str):
        if name == "dns":
            return object() if state["dns"] else None
        if name == "playwright":
            return object() if state["playwright"] else None
        return object()

    def _fake_available(tool: str) -> bool:
        if tool in {"interactsh-client", "go"}:
            return False
        return True

    def _fake_run(cmd, **kwargs):
        cmd_list = [str(part) for part in cmd]
        calls.append(cmd_list)
        if len(cmd_list) >= 5 and cmd_list[:4] == [
            sys.executable,
            "-m",
            "pip",
            "install",
        ]:
            if cmd_list[4] == "dnspython":
                state["dns"] = True
            elif cmd_list[4] == "playwright":
                state["playwright"] = True
        return subprocess.CompletedProcess(cmd_list, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("importlib.util.find_spec", _fake_find_spec)
    monkeypatch.setattr(cli.CommandExecutor, "available", staticmethod(_fake_available))
    monkeypatch.setattr("subprocess.run", _fake_run)

    result = runner.invoke(cli.app, ["doctor", "--fix-deps", "--no-exit-on-fail"])
    assert result.exit_code == 0
    assert "== Dependency Fix Attempts ==" in result.stdout
    assert any(cmd[:4] == [sys.executable, "-m", "pip", "install"] for cmd in calls)


def test_rerun_invalid_stage_returns_cli_error():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["rerun", "job-123", "--stages", "nope"])
    assert result.exit_code == 2
    assert not isinstance(result.exception, TypeError)


def test_serve_defaults_to_loopback(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run(app_obj, host, port):
        captured["app"] = app_obj
        captured["host"] = host
        captured["port"] = port

    import uvicorn
    import recon_cli.api.app as api_app

    monkeypatch.setattr(uvicorn, "run", _fake_run)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["serve"])
    assert result.exit_code == 0
    assert captured["app"] is api_app.app
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8080


def test_trace_command_uses_last_pointer(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    trace_path = record.paths.artifact("trace.json")
    events_path = record.paths.artifact("trace_events.jsonl")
    trace_payload = {
        "trace_id": "trace-last-123",
        "status": "finished",
        "duration_ms": 125.4,
        "started_at": "2026-03-10T00:00:00Z",
        "finished_at": "2026-03-10T00:00:01Z",
        "attributes": {
            "job_id": record.spec.job_id,
            "target": "example.com",
            "profile": "passive",
        },
        "stats": {
            "span_count": 1,
            "event_count": 2,
            "span_counts_by_type": {"stage": 1},
        },
        "spans": [
            {
                "name": "http_probe",
                "span_type": "stage",
                "status": "completed",
                "duration_ms": 50.0,
                "attributes": {"attempts": 1},
            }
        ],
    }
    trace_path.write_text(json.dumps(trace_payload), encoding="utf-8")
    events_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-03-10T00:00:00Z",
                        "name": "trace.started",
                        "attributes": {},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-03-10T00:00:01Z",
                        "name": "trace.finished",
                        "attributes": {"status": "finished"},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    update_last_trace_pointers(trace_path, events_path)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["trace", "--events", "1"])
    assert result.exit_code == 0
    assert "Trace trace-last-123" in result.stdout
    assert "http_probe (completed)" in result.stdout
    assert "trace.finished" in result.stdout


def test_trace_command_outputs_json_for_job(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    trace_path = record.paths.artifact("trace.json")
    events_path = record.paths.artifact("trace_events.jsonl")
    trace_path.write_text(
        json.dumps(
            {
                "trace_id": "trace-job-456",
                "status": "failed",
                "error": "boom",
                "attributes": {
                    "job_id": record.spec.job_id,
                    "target": "example.com",
                    "profile": "passive",
                },
                "stats": {
                    "span_count": 1,
                    "event_count": 1,
                    "span_counts_by_type": {"stage": 1},
                },
                "spans": [],
            }
        ),
        encoding="utf-8",
    )
    events_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-03-10T00:00:02Z",
                "name": "trace.finished",
                "attributes": {"status": "failed"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app, ["trace", record.spec.job_id, "--json", "--events", "1"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["trace"]["trace_id"] == "trace-job-456"
    assert payload["trace"]["attributes"]["job_id"] == record.spec.job_id
    assert payload["events"][0]["name"] == "trace.finished"


def _configure_test_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(config, "RECON_HOME", tmp_path)
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "JOBS_ROOT", tmp_path / "jobs")
    monkeypatch.setattr(config, "QUEUED_JOBS", config.JOBS_ROOT / "queued")
    monkeypatch.setattr(config, "RUNNING_JOBS", config.JOBS_ROOT / "running")
    monkeypatch.setattr(config, "FINISHED_JOBS", config.JOBS_ROOT / "finished")
    monkeypatch.setattr(config, "FAILED_JOBS", config.JOBS_ROOT / "failed")
    monkeypatch.setattr(config, "ARCHIVE_ROOT", tmp_path / "archive")
    config.ensure_base_directories(force=True)


def test_export_hunter_mode_filters_and_limits(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    results = [
        {
            "type": "finding",
            "title": "verified-high",
            "tags": ["ssrf:confirmed"],
            "score": 90,
            "severity": "high",
        },
        {
            "type": "finding",
            "title": "verified-low",
            "tags": ["redirect:confirmed"],
            "score": 50,
            "severity": "low",
        },
        {
            "type": "finding",
            "title": "unverified",
            "score": 99,
            "severity": "high",
        },
    ]
    record.paths.results_jsonl.write_text(
        "\n".join(json.dumps(item) for item in results) + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "export",
            record.spec.job_id,
            "--format",
            "jsonl",
            "--hunter-mode",
            "--limit",
            "1",
        ],
    )
    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["title"] == "verified-high"


def test_pdf_command_uses_job_root(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")

    captured: dict[str, object] = {}

    def _fake_generate_pdf_report(job_path, output_path=None, config=None):
        captured["job_path"] = Path(job_path)
        captured["output_path"] = output_path
        captured["config"] = config
        return record.paths.root / "report.pdf"

    import recon_cli.utils.pdf_reporter as pdf_reporter

    monkeypatch.setattr(pdf_reporter, "generate_pdf_report", _fake_generate_pdf_report)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["pdf", record.spec.job_id])
    assert result.exit_code == 0
    assert captured["job_path"] == record.paths.root


def test_export_triage_outputs_required_fields(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    results = [
        {
            "type": "finding",
            "title": "verified-high",
            "tags": ["ssrf:confirmed"],
            "source": "extended-validation",
            "finding_type": "ssrf",
            "severity": "high",
            "url": "https://example.com/profile",
        },
        {
            "type": "finding",
            "title": "low",
            "source": "waf-probe",
            "severity": "low",
            "url": "https://example.com/",
        },
    ]
    record.paths.results_jsonl.write_text(
        "\n".join(json.dumps(item) for item in results) + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "export",
            record.spec.job_id,
            "--format",
            "triage",
            "--verified-only",
            "--limit",
            "1",
        ],
    )
    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["job_id"] == record.spec.job_id
    assert payload["severity"] == "high"
    assert payload["proof"] == "verified"
    assert payload["repro_cmd"].startswith("python -m recon_cli rerun")
    assert payload["finding_id"].startswith("fnd_")
    assert payload["poc_steps"]
    assert payload["asset_context"]["endpoint"] == "https://example.com/profile"
    assert payload["impact_hypothesis"]
    assert Path(payload["artifact_path"]).exists()


def test_export_triage_generates_artifacts_for_verified_high_critical(
    tmp_path: Path, monkeypatch
):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    results = [
        {
            "type": "finding",
            "title": "verified-high",
            "source": "extended-validation",
            "finding_type": "ssrf",
            "tags": ["ssrf:confirmed"],
            "severity": "high",
            "url": "https://example.com/high",
        },
        {
            "type": "finding",
            "title": "verified-critical",
            "source": "sqlmap",
            "finding_type": "sql_injection",
            "tags": ["sqli:confirmed"],
            "severity": "critical",
            "url": "https://example.com/critical",
        },
        {
            "type": "finding",
            "title": "unverified-high",
            "source": "waf-probe",
            "severity": "high",
            "url": "https://example.com/no-proof",
        },
    ]
    record.paths.results_jsonl.write_text(
        "\n".join(json.dumps(item) for item in results) + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app, ["export", record.spec.job_id, "--format", "triage"]
    )
    assert result.exit_code == 0
    payloads = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    by_title = {item["title"]: item for item in payloads}

    assert Path(by_title["verified-high"]["artifact_path"]).exists()
    assert Path(by_title["verified-critical"]["artifact_path"]).exists()
    assert "artifact_path" not in by_title["unverified-high"]


def test_rerun_restart_clears_checkpoints_and_results(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    job_id = record.spec.job_id

    from recon_cli.jobs.lifecycle import JobLifecycle

    lifecycle = JobLifecycle(manager)
    lifecycle.move_to_failed(job_id)
    record = manager.load_job(job_id)
    record.metadata.status = "failed"
    record.metadata.stage = "dns"
    record.metadata.checkpoints = {"dns": "2024-01-01T00:00:00Z"}
    manager.update_metadata(record)

    record.paths.results_jsonl.write_text('{"type":"finding"}\n', encoding="utf-8")
    record.paths.results_txt.write_text("old\n", encoding="utf-8")
    record.paths.trimmed_results_jsonl.write_text(
        '{"type":"finding"}\n', encoding="utf-8"
    )

    monkeypatch.setattr(cli, "run_pipeline", lambda *_args, **_kwargs: None)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["rerun", job_id, "--restart"])
    assert result.exit_code == 0

    record = manager.load_job(job_id)
    assert record.metadata.status == "finished"
    assert record.metadata.checkpoints == {}
    assert record.paths.results_jsonl.read_text(encoding="utf-8") == ""
    assert record.paths.results_txt.read_text(encoding="utf-8") == ""
    assert record.paths.trimmed_results_jsonl.read_text(encoding="utf-8") == ""


def test_rerun_stages_replays_selected_stage(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    job_id = record.spec.job_id

    from recon_cli.jobs.lifecycle import JobLifecycle

    lifecycle = JobLifecycle(manager)
    lifecycle.move_to_failed(job_id)

    called = {}

    def _fake_run_pipeline(run_record, run_manager, force=False, stages=None):
        called["job_id"] = run_record.spec.job_id
        called["force"] = force
        called["stages"] = stages

    monkeypatch.setattr(cli, "run_pipeline", _fake_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["rerun", job_id, "--stages", "vuln_scan"])
    assert result.exit_code == 0
    assert called["job_id"] == job_id
    assert called["force"] is True
    assert called["stages"] == ["vuln_scan"]


def test_rerun_rejects_restart_with_stages(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")

    runner = CliRunner()
    result = runner.invoke(
        cli.app, ["rerun", record.spec.job_id, "--restart", "--stages", "vuln_scan"]
    )
    assert result.exit_code == 2
    assert "--restart cannot be combined with --stages" in result.output


def test_status_includes_last_failed_stage_and_log_path(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    record.metadata.status = "failed"
    record.metadata.stage = "http_probe"
    record.metadata.stats = {
        "stage_progress": [
            {"stage": "dns", "status": "completed"},
            {"stage": "http_probe", "status": "failed", "error": "timeout"},
        ]
    }
    manager.update_metadata(record)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["status", record.spec.job_id])
    assert result.exit_code == 0
    assert "last_failed_stage" in result.stdout
    assert "http_probe" in result.stdout
    assert "log_path" in result.stdout


def test_target_priority_score_prefers_sensitive_targets(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    low = manager.create_job(target="static.example.com", profile="passive")
    high = manager.create_job(target="api-admin.example.com", profile="full")
    assert cli._target_priority_score(high) > cli._target_priority_score(low)


def test_report_hunter_mode_generates_actionable_html(tmp_path: Path, monkeypatch):
    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    record.metadata.status = "finished"
    manager.update_metadata(record)

    findings = [
        {
            "type": "finding",
            "title": "confirmed-sqli",
            "source": "sqlmap",
            "finding_type": "sql_injection",
            "tags": ["sqli:confirmed"],
            "severity": "critical",
            "repro_cmd": "sqlmap -u https://example.com/search?q=1 --batch",
            "url": "https://example.com/search?q=1",
        },
        {
            "type": "finding",
            "title": "low-noise",
            "source": "waf-probe",
            "severity": "low",
            "url": "https://example.com/",
        },
    ]
    record.paths.results_jsonl.write_text(
        "\n".join(json.dumps(item) for item in findings) + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app, ["report", record.spec.job_id, "--format", "html", "--hunter-mode"]
    )
    assert result.exit_code == 0
    html_path = record.paths.root / "report.html"
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")
    assert "Top Actionable Findings" in content
    assert "confirmed-sqli" in content
    assert "python -m recon_cli rerun" in content
