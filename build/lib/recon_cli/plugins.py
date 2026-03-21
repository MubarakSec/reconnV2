from __future__ import annotations

import importlib
import os
from typing import List

from recon_cli.pipeline.stages import Stage


def _log(logger, level: str, message: str) -> None:
    if logger is None:
        return
    log_fn = getattr(logger, level, None)
    if callable(log_fn):
        log_fn(message)


def load_stage_plugins(logger=None) -> List[Stage]:
    """Load extra pipeline stages from RECON_PLUGIN_STAGES (comma-separated module:Class)."""
    env = os.environ.get("RECON_PLUGIN_STAGES", "")
    if not env:
        return []
    stages: List[Stage] = []
    for entry in env.split(","):
        token = entry.strip()
        if not token:
            continue
        if ":" not in token:
            _log(
                logger,
                "warning",
                f"Plugin stage '{token}' invalid, expected module:Class",
            )
            continue
        mod_name, class_name = token.split(":", 1)
        try:
            module = importlib.import_module(mod_name)
        except Exception as exc:
            _log(logger, "warning", f"Failed to import plugin module {mod_name}: {exc}")
            continue
        cls = getattr(module, class_name, None)
        if cls is None:
            _log(
                logger,
                "warning",
                f"Plugin stage class {class_name} not found in {mod_name}",
            )
            continue
        try:
            instance = cls() if isinstance(cls, type) else cls
        except Exception as exc:
            _log(
                logger,
                "warning",
                f"Failed to instantiate plugin stage {class_name}: {exc}",
            )
            continue
        if not isinstance(instance, Stage):
            _log(logger, "warning", f"Plugin {class_name} is not a Stage; skipping")
            continue
        stages.append(instance)
    return stages
