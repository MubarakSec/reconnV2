from __future__ import annotations

import socket
import subprocess
from typing import Any, Dict

from recon_cli.tools.executor import CommandError


def _root_cause(exc: BaseException) -> BaseException:
    current = exc
    while getattr(current, "__cause__", None) is not None:
        current = current.__cause__  # type: ignore[assignment]
    return current


def classify_exception(exc: BaseException) -> Dict[str, Any]:
    """Map runtime exceptions to stable error taxonomy fields."""
    root = _root_cause(exc)
    exc_name = exc.__class__.__name__
    root_name = root.__class__.__name__
    message = str(root or exc)
    message_lower = message.lower()
    code = "unknown.unhandled"
    category = "unknown"
    retryable = False

    if root_name == "StageStopRequested":
        code = "control.stop_requested"
        category = "control"
        retryable = True
    elif isinstance(root, CommandError):
        category = "tooling"
        if "timeout" in message_lower:
            code = "tool.timeout"
            retryable = True
        elif "not found" in message_lower:
            code = "dependency.missing_tool"
        elif root.returncode is not None:
            code = "tool.non_zero_exit"
            retryable = True
        else:
            code = "tool.execution_error"
            retryable = True
    elif isinstance(root, subprocess.TimeoutExpired) or isinstance(root, TimeoutError):
        code = "runtime.timeout"
        category = "runtime"
        retryable = True
    elif isinstance(root, (FileNotFoundError, ModuleNotFoundError, ImportError)):
        code = "dependency.missing_component"
        category = "dependency"
    elif isinstance(root, PermissionError):
        code = "system.permission_denied"
        category = "system"
    elif isinstance(root, (ConnectionError, socket.gaierror)):
        code = "network.connectivity"
        category = "network"
        retryable = True
    elif isinstance(root, ValueError):
        code = "input.invalid_value"
        category = "input"
    elif root_name == "StageError" or exc_name == "StageError":
        code = "pipeline.stage_failure"
        category = "pipeline"

    return {
        "code": code,
        "category": category,
        "retryable": retryable,
        "exception_type": exc_name,
        "root_exception_type": root_name,
        "message": str(exc),
        "root_message": message,
    }


__all__ = ["classify_exception"]
