from __future__ import annotations

import json
import subprocess
import sys
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


def test_doctor_reports_python_dependency_section():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code in {0, 1}
    assert "interactsh-client" in result.stdout
    assert "== Python Dependency Health ==" in result.stdout
    assert "dnspython" in result.stdout
    assert "playwright" in result.stdout


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
        if len(cmd_list) >= 5 and cmd_list[:4] == [sys.executable, "-m", "pip", "install"]:
            if cmd_list[4] == "dnspython":
                state["dns"] = True
            elif cmd_list[4] == "playwright":
                state["playwright"] = True
        return subprocess.CompletedProcess(cmd_list, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("importlib.util.find_spec", _fake_find_spec)
    monkeypatch.setattr(cli.CommandExecutor, "available", staticmethod(_fake_available))
    monkeypatch.setattr("subprocess.run", _fake_run)

    result = runner.invoke(cli.app, ["doctor", "--fix-deps"])
    assert result.exit_code == 0
    assert "== Dependency Fix Attempts ==" in result.stdout
    assert any(cmd[:4] == [sys.executable, "-m", "pip", "install"] for cmd in calls)
