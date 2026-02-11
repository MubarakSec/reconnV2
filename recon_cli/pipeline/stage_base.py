from __future__ import annotations

import time
import threading
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from recon_cli.pipeline.context import PipelineContext


class StageError(RuntimeError):
    pass


@dataclass
class StageResult:
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


try:  # pragma: no cover - test helper
    import builtins
    builtins.StageResult = StageResult
except Exception:
    pass


def note_missing_tool(context: PipelineContext, tool: str) -> None:
    missing = context.record.metadata.stats.setdefault("missing_tools", [])
    if tool not in missing:
        missing.append(tool)
        context.manager.update_metadata(context.record)


class Stage(ABC):
    name: str = "stage"
    optional: bool = False

    def is_enabled(self, context: PipelineContext) -> bool:
        return True

    def should_run(self, context: PipelineContext) -> bool:
        if context.force:
            return True
        return self.name not in context.record.metadata.checkpoints

    def before(self, context: PipelineContext) -> None:  # pragma: no cover - hook
        pass

    def execute(self, context: PipelineContext) -> None:
        raise NotImplementedError("Stage subclasses must implement execute()")

    def after(self, context: PipelineContext) -> None:  # pragma: no cover - hook
        pass

    def _run_with_heartbeat(self, context: PipelineContext) -> None:
        heartbeat_seconds = int(getattr(context.runtime_config, "stage_heartbeat_seconds", 0) or 0)
        sla_seconds = int(getattr(context.runtime_config, "stage_sla_seconds", 0) or 0)
        if heartbeat_seconds <= 0:
            self.before(context)
            self.execute(context)
            self.after(context)
            return

        logger = context.logger
        started = time.monotonic()
        done = threading.Event()
        sla_alerted = threading.Event()
        sla_alert_elapsed = {"seconds": 0}

        def _heartbeat() -> None:
            while not done.wait(timeout=heartbeat_seconds):
                elapsed = int(time.monotonic() - started)
                if sla_seconds > 0 and elapsed >= sla_seconds and not sla_alerted.is_set():
                    sla_alert_elapsed["seconds"] = elapsed
                    sla_alerted.set()
                    logger.warning(
                        "Stage %s exceeded SLA (%ss); still running (%ss elapsed)",
                        self.name,
                        sla_seconds,
                        elapsed,
                    )
                logger.info("Stage %s heartbeat: still running (%ss elapsed)", self.name, elapsed)

        thread = threading.Thread(target=_heartbeat, daemon=True, name=f"heartbeat-{self.name}")
        thread.start()
        try:
            self.before(context)
            self.execute(context)
            self.after(context)
        finally:
            done.set()
            thread.join()
            if sla_alerted.is_set() and getattr(context, "record", None) and getattr(context, "manager", None):
                stats = context.record.metadata.stats.setdefault("stage_runtime_alerts", {})
                stats[self.name] = {
                    "sla_seconds": sla_seconds,
                    "alert_elapsed_seconds": int(sla_alert_elapsed["seconds"] or 0),
                }
                context.manager.update_metadata(context.record)

    def run(self, context: PipelineContext) -> bool:
        logger = context.logger
        if not self.is_enabled(context):
            logger.info("Stage %s disabled for this profile", self.name)
            return False
        if not self.should_run(context):
            logger.info("Stage %s already checkpointed; skipping", self.name)
            return False
        attempts = context.max_retries + 1
        backoff_base = max(0.1, float(context.runtime_config.retry_backoff_base))
        backoff_factor = max(1.0, float(context.runtime_config.retry_backoff_factor))
        for attempt in range(1, attempts + 1):
            context.increment_attempt(self.name)
            context.record.metadata.stage = self.name
            context.manager.update_metadata(context.record)
            logger.info("Stage %s attempt %s/%s", self.name, attempt, attempts)
            try:
                self._run_with_heartbeat(context)
                context.checkpoint(self.name)
                logger.info("Stage %s completed", self.name)
                return True
            except Exception as exc:  # pragma: no cover - runtime path
                logger.exception("Stage %s failed: %s", self.name, exc)
                if attempt >= attempts:
                    raise StageError(f"Stage {self.name} failed after {attempts} attempts") from exc
                delay = backoff_base * (backoff_factor ** (attempt - 1))
                logger.info("Retrying stage %s after %ss", self.name, delay)
                time.sleep(delay)
        return False
