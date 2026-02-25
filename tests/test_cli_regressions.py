from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import recon_cli.cli as cli
import recon_cli.completions as completions


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
