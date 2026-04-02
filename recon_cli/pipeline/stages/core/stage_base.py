from __future__ import annotations

import time
import threading
import asyncio
from abc import ABC
from typing import Any, Dict, Optional, List

from pydantic import BaseModel, ConfigDict, Field
from recon_cli.pipeline.context import PipelineContext
from recon_cli.utils import time as time_utils


class StageError(RuntimeError):
    pass


class StageStopRequested(RuntimeError):
    pass


class StageResult(BaseModel):
    """Result of a pipeline stage execution."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


try:  # pragma: no cover - test helper
    import builtins

    builtins.StageResult = StageResult  # type: ignore[attr-defined]
except Exception:
    pass


def note_missing_tool(context: PipelineContext, tool: str) -> None:
    if not context.record:
        return
    with context._lock:
        missing = context.record.metadata.stats.setdefault("missing_tools", [])
        if tool not in missing:
            missing.append(tool)
            context.manager.update_metadata(context.record)


class Stage(ABC):
    name: str = "stage"
    optional: bool = False

    # Dynamic Dependency attributes
    # What data types (e.g. 'hostname', 'url') this stage provides
    provides: List[str] = []
    # What data types this stage requires to function
    requires: List[str] = []

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

    @staticmethod
    def _stop_requested(context: PipelineContext) -> bool:
        checker = getattr(context, "stop_requested", None)
        if callable(checker):
            try:
                return bool(checker())
            except Exception:
                return False
        return False

    def _ensure_not_stopped(self, context: PipelineContext) -> None:
        if self._stop_requested(context):
            raise StageStopRequested(f"Stop requested while running stage {self.name}")

    def _run_with_heartbeat(self, context: PipelineContext) -> None:
        heartbeat_seconds = int(
            getattr(context.runtime_config, "stage_heartbeat_seconds", 0) or 0
        )
        sla_seconds = int(getattr(context.runtime_config, "stage_sla_seconds", 0) or 0)
        if heartbeat_seconds <= 0:
            self._ensure_not_stopped(context)
            self.before(context)
            self.execute(context)
            self.after(context)
            self._ensure_not_stopped(context)
            return

        # logger = context.logger
        started = time.monotonic()
        done = threading.Event()
        sla_alerted = threading.Event()
        stop_alerted = threading.Event()
        sla_alert_elapsed = {"seconds": 0}
        
        with context._lock:
            heartbeat_stats = context.record.metadata.stats.setdefault(
                "stage_heartbeats", {}
            )
            stage_heartbeat = heartbeat_stats.setdefault(self.name, {})
            stage_heartbeat["last_started_at"] = time_utils.iso_now()
            stage_heartbeat["sla_seconds"] = sla_seconds
            stage_heartbeat["count"] = int(stage_heartbeat.get("count", 0))
            context.manager.update_metadata(context.record)

        def _heartbeat() -> None:
            check_interval = max(1, min(heartbeat_seconds, 2))
            next_heartbeat = started + heartbeat_seconds
            while not done.wait(timeout=check_interval):
                if self._stop_requested(context) and not stop_alerted.is_set():
                    stop_alerted.set()
                    context.logger.warning(
                        "Stage %s received stop request; waiting for current operation to finish",
                        self.name,
                    )
                now = time.monotonic()
                if now < next_heartbeat:
                    continue
                elapsed = int(time.monotonic() - started)
                if (
                    sla_seconds > 0
                    and elapsed >= sla_seconds
                    and not sla_alerted.is_set()
                ):
                    sla_alert_elapsed["seconds"] = elapsed
                    sla_alerted.set()
                    context.logger.warning(
                        "Stage %s exceeded SLA (%ss); still running (%ss elapsed)",
                        self.name,
                        sla_seconds,
                        elapsed,
                    )
                context.logger.info(
                    "Stage %s heartbeat: still running (%ss elapsed)",
                    self.name,
                    elapsed,
                )
                with context._lock:
                    heartbeat_entry = context.record.metadata.stats.setdefault(
                        "stage_heartbeats", {}
                    ).setdefault(self.name, {})
                    heartbeat_entry["count"] = int(heartbeat_entry.get("count", 0)) + 1
                    heartbeat_entry["last_heartbeat_at"] = time_utils.iso_now()
                    heartbeat_entry["last_elapsed_seconds"] = elapsed
                    context.manager.update_metadata(context.record)
                next_heartbeat = now + heartbeat_seconds

        thread = threading.Thread(
            target=_heartbeat, daemon=True, name=f"heartbeat-{self.name}"
        )
        thread.start()
        stage_error: Optional[Exception] = None
        try:
            self._ensure_not_stopped(context)
            self.before(context)
            self.execute(context)
            self.after(context)
            self._ensure_not_stopped(context)
        except Exception as exc:
            stage_error = exc
            raise
        finally:
            done.set()
            thread.join()
            final_elapsed = int(time.monotonic() - started)
            with context._lock:
                heartbeat_entry = context.record.metadata.stats.setdefault(
                    "stage_heartbeats", {}
                ).setdefault(self.name, {})
                heartbeat_entry["last_finished_at"] = time_utils.iso_now()
                heartbeat_entry["last_elapsed_seconds"] = final_elapsed
                if (
                    sla_alerted.is_set()
                    and getattr(context, "record", None)
                    and getattr(context, "manager", None)
                ):
                    stats = context.record.metadata.stats.setdefault(
                        "stage_runtime_alerts", {}
                    )
                    stats[self.name] = {
                        "sla_seconds": sla_seconds,
                        "alert_elapsed_seconds": int(sla_alert_elapsed["seconds"] or 0),
                    }
                context.manager.update_metadata(context.record)
            if stage_error is None and (
                stop_alerted.is_set() or self._stop_requested(context)
            ):
                raise StageStopRequested(
                    f"Stop requested while running stage {self.name}"
                )

    def _note_skip(self, context: PipelineContext, reason: str) -> None:
        with context._lock:
            stats = context.record.metadata.stats.setdefault("stage_skips", {})
            entry = stats.setdefault(self.name, {})
            entry["reason"] = reason
            entry["count"] = int(entry.get("count", 0)) + 1
            entry["last_skipped_at"] = time_utils.iso_now()
            context.manager.update_metadata(context.record)

    async def iter_events(
        self,
        context: PipelineContext,
        event_types: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
    ):
        """
        Consumes events from the event bus in real-time.
        Yields (event_type, data) tuples.
        """
        queue = context.event_bus.subscribe(event_types)
        # If no dependencies provided, we might never know when to stop
        # unless the whole pipeline is finishing.
        upstream = set(dependencies) if dependencies else set()

        try:
            while True:
                # Check for stop request
                if self._stop_requested(context):
                    break

                try:
                    # Wait for an event with a short timeout
                    event = await asyncio.wait_for(queue.get(), timeout=0.5)
                    yield event["type"], event["data"]
                    queue.task_done()
                except (asyncio.TimeoutError, TimeoutError):
                    # Check if all upstream stages are in finished_stages
                    if upstream and upstream.issubset(context.finished_stages):
                        # All upstream done, and queue is empty? then we are done.
                        if queue.empty():
                            break

                    # If the whole pipeline runner signaled finish (fallback)
                    if getattr(context, "_all_upstream_done", False) and queue.empty():
                        break
                    continue
        finally:
            await context.event_bus.unsubscribe(queue)

    async def run_async_wrapped(self, context: PipelineContext) -> bool:
        # logger = context.logger
        if self._stop_requested(context):
            context.logger.warning("Stage %s skipped because stop was requested", self.name)
            self._note_skip(context, "stop_requested")
            raise StageStopRequested(f"Stop requested before stage {self.name}")
        if not self.is_enabled(context):
            context.logger.info("Stage %s disabled for this profile", self.name)
            self._note_skip(context, "disabled")
            return False
        if not self.should_run(context):
            context.logger.info("Stage %s already checkpointed; skipping", self.name)
            self._note_skip(context, "checkpointed")
            return False
        
        attempts = context.max_retries + 1
        backoff_base = max(0.1, float(context.runtime_config.retry_backoff_base))
        backoff_factor = max(1.0, float(context.runtime_config.retry_backoff_factor))
        
        for attempt in range(1, attempts + 1):
            context.increment_attempt(self.name)
            context.record.metadata.stage = self.name
            context.manager.update_metadata(context.record)
            context.logger.info("Stage %s attempt %s/%s", self.name, attempt, attempts)
            
            try:
                # We need an async version of _run_with_heartbeat
                await self._run_async_with_heartbeat(context)
                context.checkpoint(self.name)
                context.logger.info("Stage %s completed", self.name)
                return True
            except StageStopRequested as exc:
                context.logger.warning("Stage %s stopped: %s", self.name, exc)
                self._note_skip(context, "stop_requested")
                raise
            except Exception as exc:
                context.logger.exception("Stage %s failed: %s", self.name, exc)
                if attempt >= attempts:
                    raise StageError(
                        f"Stage {self.name} failed after {attempts} attempts"
                    ) from exc
                delay = backoff_base * (backoff_factor ** (attempt - 1))
                context.logger.info("Retrying stage %s after %ss", self.name, delay)
                await asyncio.sleep(delay)
        return False

    async def _run_async_with_heartbeat(self, context: PipelineContext) -> None:
        # logger = context.logger
        heartbeat_seconds = int(
            getattr(context.runtime_config, "stage_heartbeat_seconds", 0) or 0
        )
        sla_seconds = int(getattr(context.runtime_config, "stage_sla_seconds", 0) or 0)
        
        if heartbeat_seconds <= 0:
            self._ensure_not_stopped(context)
            self.before(context)
            if hasattr(self, "run_async"):
                await self.run_async(context)
            else:
                from recon_cli.utils.pipeline_trace import (
                    CURRENT_TRACE_SCOPE,
                    run_in_scope,
                )
                trace_scope = CURRENT_TRACE_SCOPE.get()
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    None, run_in_scope, trace_scope, self.execute, context
                )
            self.after(context)
            self._ensure_not_stopped(context)
            return

        # Handle heartbeat for async
        done = asyncio.Event()
        sla_alerted = asyncio.Event()
        
        async def _heartbeat_task():
            started = time.monotonic()
            next_heartbeat = started + heartbeat_seconds
            sla_alert_at = started + sla_seconds if sla_seconds > 0 else 0
            
            while not done.is_set():
                now = time.monotonic()
                if sla_alert_at > 0 and now >= sla_alert_at:
                    # Alert logic
                    elapsed = int(now - started)
                    sla_alerted.set()
                    context.logger.warning(
                        "Stage %s exceeded SLA (%ss); still running (%ss elapsed)",
                        self.name,
                        sla_seconds,
                        elapsed,
                    )
                    with context._lock:
                        stats = context.record.metadata.stats.setdefault(
                            "stage_runtime_alerts", {}
                        )
                        stats[self.name] = {
                            "sla_seconds": sla_seconds,
                            "alert_elapsed_seconds": elapsed,
                        }
                    sla_alert_at = 0 # only alert once
                    
                if now >= next_heartbeat:
                    elapsed = int(now - started)
                    context.logger.info(
                        "Stage %s heartbeat: still running (%ss elapsed)",
                        self.name,
                        elapsed,
                    )
                    with context._lock:
                        heartbeat_entry = context.record.metadata.stats.setdefault(
                            "stage_heartbeats", {}
                        ).setdefault(self.name, {})
                        heartbeat_entry["count"] = int(heartbeat_entry.get("count", 0)) + 1
                        heartbeat_entry["last_heartbeat_at"] = time_utils.iso_now()
                        heartbeat_entry["last_elapsed_seconds"] = elapsed
                        context.manager.update_metadata(context.record)
                    next_heartbeat = now + heartbeat_seconds
                
                try:
                    await asyncio.wait_for(done.wait(), timeout=min(1.0, float(heartbeat_seconds) if heartbeat_seconds > 0 else 1.0))
                except (asyncio.TimeoutError, TimeoutError):
                    continue

        heartbeat_fut = asyncio.create_task(_heartbeat_task())
        started = time.monotonic()
        try:
            self._ensure_not_stopped(context)
            self.before(context)
            if hasattr(self, "run_async"):
                await self.run_async(context)
            else:
                from recon_cli.utils.pipeline_trace import (
                    CURRENT_TRACE_SCOPE,
                    run_in_scope,
                )
                trace_scope = CURRENT_TRACE_SCOPE.get()
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    None, run_in_scope, trace_scope, self.execute, context
                )
            self.after(context)
            self._ensure_not_stopped(context)
        finally:
            done.set()
            await heartbeat_fut
            final_elapsed = int(time.monotonic() - started)
            with context._lock:
                heartbeat_entry = context.record.metadata.stats.setdefault(
                    "stage_heartbeats", {}
                ).setdefault(self.name, {})
                heartbeat_entry["last_finished_at"] = time_utils.iso_now()
                heartbeat_entry["last_elapsed_seconds"] = final_elapsed
                context.manager.update_metadata(context.record)

    def run(self, context: PipelineContext) -> bool:
        try:
            loop = asyncio.get_running_loop()
            # If we are already in a loop, we can't use asyncio.run
            # We must run the sync version of the loop logic
            return self._run_sync_fallback(context)
        except RuntimeError:
            # No loop running, we can use asyncio.run
            return asyncio.run(self.run_async_wrapped(context))

    def _run_sync_fallback(self, context: PipelineContext) -> bool:
        # logger = context.logger
        if self._stop_requested(context):
            context.logger.warning("Stage %s skipped because stop was requested", self.name)
            self._note_skip(context, "stop_requested")
            raise StageStopRequested(f"Stop requested before stage {self.name}")
        if not self.is_enabled(context):
            context.logger.info("Stage %s disabled for this profile", self.name)
            self._note_skip(context, "disabled")
            return False
        if not self.should_run(context):
            context.logger.info("Stage %s already checkpointed; skipping", self.name)
            self._note_skip(context, "checkpointed")
            return False
        attempts = context.max_retries + 1
        backoff_base = max(0.1, float(context.runtime_config.retry_backoff_base))
        backoff_factor = max(1.0, float(context.runtime_config.retry_backoff_factor))
        for attempt in range(1, attempts + 1):
            context.increment_attempt(self.name)
            context.record.metadata.stage = self.name
            context.manager.update_metadata(context.record)
            context.logger.info("Stage %s attempt %s/%s", self.name, attempt, attempts)
            try:
                self._run_with_heartbeat(context)
                context.checkpoint(self.name)
                context.logger.info("Stage %s completed", self.name)
                return True
            except StageStopRequested as exc:
                context.logger.warning("Stage %s stopped: %s", self.name, exc)
                self._note_skip(context, "stop_requested")
                raise
            except Exception as exc:  # pragma: no cover - runtime path
                context.logger.exception("Stage %s failed: %s", self.name, exc)
                if attempt >= attempts:
                    raise StageError(
                        f"Stage {self.name} failed after {attempts} attempts"
                    ) from exc
                delay = backoff_base * (backoff_factor ** (attempt - 1))
                context.logger.info("Retrying stage %s after %ss", self.name, delay)
                time.sleep(delay)
        return False
