from __future__ import annotations

from recon_cli.tools.executor import CommandError
from recon_cli.utils.error_taxonomy import classify_exception


def test_classify_command_timeout() -> None:
    exc = CommandError("Command timeout after 10s")
    payload = classify_exception(exc)
    assert payload["code"] == "tool.timeout"
    assert payload["category"] == "tooling"
    assert payload["retryable"] is True


def test_classify_missing_dependency() -> None:
    exc = ModuleNotFoundError("No module named 'fastapi'")
    payload = classify_exception(exc)
    assert payload["code"] == "dependency.missing_component"
    assert payload["category"] == "dependency"
    assert payload["retryable"] is False


def test_classify_stage_error_uses_root_cause() -> None:
    root = ValueError("invalid payload")
    outer = RuntimeError("stage failed")
    outer.__cause__ = root
    payload = classify_exception(outer)
    assert payload["code"] == "input.invalid_value"
    assert payload["root_exception_type"] == "ValueError"
