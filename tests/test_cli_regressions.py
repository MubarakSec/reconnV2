from __future__ import annotations

import pytest
from typer.testing import CliRunner

from recon_cli import cli

runner = CliRunner()


def test_completions_command_uses_command_tree():
    """Verify completions logic doesn't crash and returns shell script."""
    result = runner.invoke(cli.app, ["completions", "--show", "--shell", "bash"])
    assert result.exit_code == 0
    assert "_recon_completions" in result.stdout


def test_completions_show_respects_explicit_shell():
    result = runner.invoke(cli.app, ["completions", "--show", "--shell", "zsh"])
    assert result.exit_code == 0
    assert "compdef" in result.stdout


def test_completions_install_handles_path_return(monkeypatch):
    """
    If installer.install returns a Path, the code used to fail
    because it tried to 'echo' a Path object.
    """
    from pathlib import Path

    class _FakeInstaller:
        def install(self, *args, **kwargs):
            return Path("/tmp/.bashrc")

    monkeypatch.setattr("recon_cli.completions.CompletionInstaller", _FakeInstaller)
    result = runner.invoke(cli.app, ["completions", "--install"])
    # It might fail because /tmp/.bashrc doesn't exist, but it shouldn't be a TypeError
    assert result.exit_code != 0
    assert not isinstance(result.exception, TypeError)


def test_interactive_mode_command_exists():
    """Verify the command is registered."""
    result = runner.invoke(cli.app, ["interactive", "--help"])
    assert result.exit_code == 0
    assert "Run interactive mode." in result.stdout


def test_scan_wizard_command_exists():
    """Verify the command is registered."""
    result = runner.invoke(cli.app, ["wizard", "--help"])
    assert result.exit_code == 0
    assert "Run the step-by-step scan wizard." in result.stdout
