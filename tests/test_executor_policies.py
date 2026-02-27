from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from recon_cli.tools.executor import CommandError, CommandExecutor
from recon_cli.utils.circuit_breaker import registry as circuit_registry


class DummyLogger:
    def info(self, *a, **k): ...
    def error(self, *a, **k): ...
    def warning(self, *a, **k): ...


@pytest.fixture(autouse=True)
def _reset_circuits() -> None:
    circuit_registry.reset_all()


def test_run_uses_tool_class_default_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = CommandExecutor(DummyLogger())
    executor.run(["httpx", "-version"], check=False, capture_output=True)
    assert seen["timeout"] == 150


def test_run_retries_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_run(cmd, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("time.sleep", lambda _s: None)
    executor = CommandExecutor(DummyLogger())
    result = executor.run(["httpx", "-l", "targets.txt"], check=True, capture_output=True)
    assert result.returncode == 0
    assert calls["count"] == 2


def test_circuit_breaker_blocks_after_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_run(cmd, **kwargs):
        calls["count"] += 1
        raise subprocess.CalledProcessError(returncode=2, cmd=cmd, stderr="failed")

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = CommandExecutor(DummyLogger())

    for _ in range(3):
        with pytest.raises(CommandError):
            executor.run(["nuclei", "-version"])

    with pytest.raises(CommandError, match="Circuit open"):
        executor.run(["nuclei", "-version"])
    assert calls["count"] == 3


def test_run_to_file_retries_non_zero_exit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = {"count": 0}

    def fake_run(cmd, **kwargs):
        calls["count"] += 1
        handle = kwargs.get("stdout")
        if handle:
            handle.write(f"attempt={calls['count']}\n")
        return subprocess.CompletedProcess(cmd, 1 if calls["count"] == 1 else 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("time.sleep", lambda _s: None)
    executor = CommandExecutor(DummyLogger())
    out_path = tmp_path / "cmd.log"
    result = executor.run_to_file(["httpx", "-version"], out_path)
    assert result.returncode == 0
    assert calls["count"] == 2
    assert out_path.exists()
