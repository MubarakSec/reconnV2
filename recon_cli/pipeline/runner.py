from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from recon_cli.jobs import summary
from recon_cli.jobs.manager import JobManager
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, StageResult
from recon_cli.pipeline.stages import PIPELINE_STAGES
from recon_cli.pipeline.parallel import DependencyResolver
from recon_cli.utils.notify import send_pipeline_notification
from recon_cli.utils import time as time_utils
from recon_cli.utils.error_taxonomy import classify_exception
from recon_cli.utils.pipeline_trace import PipelineTraceRecorder, PipelineTraceSpan, bind_trace_scope
# Stage plugin loader lives on the plugins package to avoid name collisions.
import recon_cli.plugins as plugins_module
from recon_cli import metrics
import os


@dataclass
class StageExecutionOutcome:
    result: Optional[bool] = None
    error: Optional[Exception] = None
    span: Optional[PipelineTraceSpan] = None


class PipelineRunner:
    def __init__(
        self,
        stages: Iterable[Stage] | None = None,
        work_dir: Optional[Path] = None,
        continue_on_error: bool = True,
    ) -> None:
        self.stages = list(stages or PIPELINE_STAGES)
        self.work_dir = work_dir
        self.continue_on_error = continue_on_error

    def register_stage(self, stage: Stage) -> None:
        self.stages.append(stage)

    @staticmethod
    def _record_error_event(context: PipelineContext, exc: Exception, *, stage: Optional[str] = None) -> dict[str, object]:
        classification = classify_exception(exc)
        stats = context.record.metadata.stats.setdefault("error_taxonomy", {})
        events = stats.setdefault("events", [])
        code = str(classification.get("code") or "unknown.unhandled")
        event = {
            "timestamp": time_utils.iso_now(),
            "stage": stage or context.record.metadata.stage,
            "code": code,
            "category": classification.get("category"),
            "retryable": bool(classification.get("retryable")),
            "message": str(exc),
            "root_message": classification.get("root_message"),
            "exception_type": classification.get("exception_type"),
            "root_exception_type": classification.get("root_exception_type"),
        }
        events.append(event)
        if len(events) > 100:
            del events[:-100]
        counts = stats.setdefault("counts", {})
        counts[code] = int(counts.get(code, 0)) + 1
        stats["last"] = event
        context.manager.update_metadata(context.record)
        return classification

    @staticmethod
    def _generate_partial_summary(context: PipelineContext, error: Exception) -> None:
        try:
            summary.generate_summary(context)
            partial = context.record.metadata.stats.setdefault("partial_results", {})
            partial["generated_after_failure"] = True
            partial["last_failure_at"] = time_utils.iso_now()
            partial["failure_stage"] = context.record.metadata.stage
            partial["failure_message"] = str(error)
            context.manager.update_metadata(context.record)
        except Exception as summary_exc:  # pragma: no cover - defensive path
            context.logger.warning("Failed to generate partial summary: %s", summary_exc)

    def _resolve_stages(self, stage_names: Optional[Sequence[str]]) -> list[Stage]:
        if not stage_names:
            return list(self.stages)
        wanted = list(stage_names)
        name_map = {stage.name: stage for stage in self.stages}
        resolved: list[Stage] = []
        for name in wanted:
            stage = name_map.get(name)
            if stage:
                resolved.append(stage)
        return resolved

    @staticmethod
    def _artifact_relpath(context: PipelineContext, path: Path) -> str:
        try:
            return str(path.relative_to(context.record.paths.root))
        except Exception:
            return str(path)

    def _start_trace(
        self,
        context: PipelineContext,
        selected_stages: Sequence[Stage],
        *,
        parallel_enabled: bool,
    ) -> PipelineTraceRecorder:
        trace = PipelineTraceRecorder(
            context.record.paths.artifact("trace.json"),
            context.record.paths.artifact("trace_events.jsonl"),
            job_id=context.record.spec.job_id,
            target=context.record.spec.target,
            profile=context.record.spec.profile,
            execution_profile=getattr(context.record.spec, "execution_profile", None),
            stages=[stage.name for stage in selected_stages],
            parallel_enabled=parallel_enabled,
        )
        stats = context.record.metadata.stats.setdefault("trace", {})
        stats.update(
            {
                "trace_id": trace.trace_id,
                "status": "running",
                "artifact": self._artifact_relpath(context, trace.trace_path),
                "events_artifact": self._artifact_relpath(context, trace.events_path),
                "parallel_enabled": bool(parallel_enabled),
                "stage_count": len(selected_stages),
                "started_at": trace.started_at,
            }
        )
        context.manager.update_metadata(context.record)
        return trace

    def _finish_trace(
        self,
        context: PipelineContext,
        trace: Optional[PipelineTraceRecorder],
        *,
        status: str,
        error: Optional[Exception] = None,
    ) -> None:
        if trace is None:
            return
        summary = trace.close(status=status, error=error)
        stats = context.record.metadata.stats.setdefault("trace", {})
        stats.update(
            {
                "trace_id": summary.get("trace_id"),
                "status": summary.get("status"),
                "span_count": summary.get("stats", {}).get("span_count"),
                "event_count": summary.get("stats", {}).get("event_count"),
                "duration_ms": summary.get("duration_ms"),
                "finished_at": summary.get("finished_at"),
                "error": summary.get("error"),
                "artifact": self._artifact_relpath(context, trace.trace_path),
                "events_artifact": self._artifact_relpath(context, trace.events_path),
            }
        )
        context.manager.update_metadata(context.record)

    def _start_stage_span(
        self,
        context: PipelineContext,
        stage: Stage,
        trace: Optional[PipelineTraceRecorder],
    ) -> Optional[PipelineTraceSpan]:
        if trace is None:
            return None
        return trace.start_span(
            stage.name,
            span_type="stage",
            attributes={
                "stage": stage.name,
                "job_id": context.record.spec.job_id,
                "target": context.record.spec.target,
            },
        )

    def _update_stage_progress(
        self,
        context: PipelineContext,
        stage_name: str,
        status: str,
        *,
        started_at: Optional[str] = None,
        finished_at: Optional[str] = None,
        error: Optional[Exception] = None,
        classification: Optional[dict[str, object]] = None,
        progress_map: Optional[dict[str, dict[str, object]]] = None,
    ) -> None:
        if progress_map is not None:
            entry = progress_map.get(stage_name)
        else:
            progress = context.record.metadata.stats.get("stage_progress", [])
            entry = progress[-1] if progress and progress[-1].get("stage") == stage_name else None

        if entry is None:
            return

        entry["status"] = status
        if started_at:
            entry["started_at"] = started_at
        if finished_at:
            entry["finished_at"] = finished_at
        if error:
            entry["error"] = str(error)
        if classification:
            entry["error_code"] = classification.get("code")
            entry["error_category"] = classification.get("category")

        context.manager.update_metadata(context.record)

    def _handle_stage_failure(
        self,
        context: PipelineContext,
        stage: Stage,
        span: Optional[PipelineTraceSpan],
        exc: Exception,
        progress_map: Optional[dict[str, dict[str, object]]] = None,
        finished_at: Optional[str] = None,
    ) -> dict[str, object]:
        classification = self._record_error_event(context, exc, stage=stage.name)
        self._update_stage_progress(
            context,
            stage.name,
            "failed",
            error=exc,
            classification=classification,
            progress_map=progress_map,
            finished_at=finished_at,
        )
        self._finalize_stage_span(
            context,
            stage,
            span,
            status="failed",
            error=exc,
            classification=classification,
        )
        context.mark_error(f"[{classification.get('code')}] {exc}")
        return classification

    def _handle_stage_success(
        self,
        context: PipelineContext,
        stage: Stage,
        span: Optional[PipelineTraceSpan],
        result: bool,
        progress_map: Optional[dict[str, dict[str, object]]] = None,
        finished_at: Optional[str] = None,
    ) -> None:
        status = "completed" if result else "skipped"
        self._update_stage_progress(
            context,
            stage.name,
            status,
            progress_map=progress_map,
            finished_at=finished_at,
        )
        self._finalize_stage_span(
            context,
            stage,
            span,
            status=status,
        )

    def _initialize_progress(
        self,
        context: PipelineContext,
        stages: Sequence[Stage],
        *,
        parallel: bool = False,
    ) -> dict[str, dict[str, object]]:
        progress = []
        progress_map = {}
        for stage in stages:
            entry = {"stage": stage.name, "status": "pending"}
            progress.append(entry)
            progress_map[stage.name] = entry

        context.record.metadata.stats["stage_progress"] = progress
        if parallel:
            context.record.metadata.stats["parallel_execution"] = True
        context.manager.update_metadata(context.record)
        return progress_map

    def _get_execution_plan(
        self,
        context: PipelineContext,
        stages: Sequence[Stage],
    ) -> list[list[str]]:
        stage_order = [stage.name for stage in stages]
        dependency_map = {
            name: set(deps) for name, deps in DependencyResolver.STAGE_DEPENDENCIES.items()
        }
        previous = None
        for name in stage_order:
            if name not in dependency_map:
                dependency_map[name] = set()
                if previous:
                    dependency_map[name].add(previous)
            previous = name

        resolver = DependencyResolver(dependency_map)
        execution_order = resolver.resolve(stage_order)
        context.record.metadata.stats["parallel_groups"] = len(execution_order)
        context.manager.update_metadata(context.record)
        return execution_order

    def _get_max_parallel(self, context: PipelineContext) -> int:
        max_parallel = int(getattr(context.runtime_config, "max_parallel_stages", 4) or 4)
        return max(1, max_parallel)

    @staticmethod
    def _finalize_stage_span(
        context: PipelineContext,
        stage: Stage,
        span: Optional[PipelineTraceSpan],
        *,
        status: str,
        error: Optional[Exception] = None,
        classification: Optional[dict[str, object]] = None,
    ) -> None:
        if span is None:
            return
        attributes: dict[str, object] = {
            "attempts": int(context.record.metadata.attempts.get(stage.name, 0)),
        }
        if status == "skipped":
            skip_entry = context.record.metadata.stats.get("stage_skips", {}).get(stage.name, {})
            if skip_entry.get("reason"):
                attributes["skip_reason"] = skip_entry.get("reason")
                span.add_event("stage.skipped", {"reason": skip_entry.get("reason")})
        if classification:
            if classification.get("code"):
                attributes["error_code"] = classification.get("code")
            if classification.get("category"):
                attributes["error_category"] = classification.get("category")
            span.add_event("stage.error", {k: v for k, v in classification.items() if v is not None})
        span.finish(status=status, error=error, attributes=attributes)

    def _run_stage_threaded(
        self,
        stage: Stage,
        context: PipelineContext,
        trace: Optional[PipelineTraceRecorder] = None,
    ) -> StageExecutionOutcome:
        span = self._start_stage_span(context, stage, trace)
        try:
            with bind_trace_scope(trace, span):
                if hasattr(stage, "run_async"):
                    result = asyncio.run(stage.run_async(context))
                else:
                    result = stage.run(context)
                    if asyncio.iscoroutine(result):
                        result = asyncio.run(result)
            return StageExecutionOutcome(result=bool(result), span=span)
        except Exception as exc:
            return StageExecutionOutcome(error=exc, span=span)

    def run(self, context: PipelineContext, stages: Optional[Sequence[str]] = None):
        if getattr(context, "_simple_mode", False):
            async def _run_async() -> list[StageResult]:
                results: list[StageResult] = []
                for stage in self._resolve_stages(stages):
                    try:
                        result_obj = stage.run(context)
                        if asyncio.iscoroutine(result_obj):
                            result_obj = await result_obj
                        if isinstance(result_obj, StageResult):
                            result = result_obj
                        else:
                            result = StageResult(success=bool(result_obj))
                    except Exception as exc:  # pragma: no cover - runtime path
                        result = StageResult(success=False, error=str(exc))
                        results.append(result)
                        if not self.continue_on_error:
                            break
                        continue
                    results.append(result)
                    if not result.success and not self.continue_on_error:
                        break
                return results
            return _run_async()

        selected_stages = self._resolve_stages(stages)
        context.mark_started()
        error: Exception | None = None
        error_recorded = False
        trace: Optional[PipelineTraceRecorder] = None
        try:
            use_parallel = bool(getattr(context.runtime_config, "parallel_stages", False))
            if use_parallel:
                stage_names = [stage.name for stage in selected_stages]
                if len(set(stage_names)) != len(stage_names):
                    context.logger.warning("Duplicate stage names detected; running sequentially")
                    use_parallel = False
            trace = self._start_trace(context, selected_stages, parallel_enabled=use_parallel)
            if use_parallel:
                self._run_parallel_sync(context, selected_stages, trace=trace)
                return

            progress_map = self._initialize_progress(context, selected_stages)
            for stage in selected_stages:
                started_at = time_utils.iso_now()
                self._update_stage_progress(
                    context, stage.name, "running", started_at=started_at, progress_map=progress_map
                )

                span = self._start_stage_span(context, stage, trace)
                try:
                    with bind_trace_scope(trace, span):
                        ran = stage.run(context)
                    self._handle_stage_success(
                        context, stage, span, bool(ran), progress_map=progress_map
                    )
                except Exception as exc:
                    error_recorded = True
                    self._handle_stage_failure(context, stage, span, exc, progress_map=progress_map)
                    error = exc
                    raise
                finally:
                    self._update_stage_progress(
                        context,
                        stage.name,
                        str(progress_map[stage.name]["status"]),
                        finished_at=time_utils.iso_now(),
                        progress_map=progress_map,
                    )
            context.mark_finished()
            summary.generate_summary(context)
        except Exception as exc:
            error = error or exc
            if not error_recorded:
                self._record_error_event(context, error, stage=context.record.metadata.stage)
            self._generate_partial_summary(context, error)
            raise
        finally:
            status = "finished" if error is None else "failed"
            message = str(error) if error else None
            self._finish_trace(context, trace, status=status, error=error)
            send_pipeline_notification(context, status=status, error=message)
            context.close()

    def _run_parallel_sync(
        self,
        context: PipelineContext,
        stages: Sequence[Stage],
        *,
        trace: Optional[PipelineTraceRecorder] = None,
    ) -> None:
        try:
            loop = asyncio.get_running_loop()
            future = asyncio.run_coroutine_threadsafe(self._run_parallel(context, stages, trace=trace), loop)
            future.result()
        except RuntimeError:
            asyncio.run(self._run_parallel(context, stages, trace=trace))

    def _run_parallel_threaded(
        self,
        context: PipelineContext,
        stages: Sequence[Stage],
        *,
        trace: Optional[PipelineTraceRecorder] = None,
    ) -> None:
        stage_list = list(stages)
        stage_map = {stage.name: stage for stage in stage_list}
        progress_map = self._initialize_progress(context, stage_list, parallel=True)
        execution_order = self._get_execution_plan(context, stage_list)
        max_parallel = self._get_max_parallel(context)

        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            for group_index, group in enumerate(execution_order, start=1):
                for i in range(0, len(group), max_parallel):
                    batch = group[i : i + max_parallel]
                    now = time_utils.iso_now()
                    if trace is not None:
                        trace.emit(
                            "parallel.batch.started",
                            {
                                "group_index": group_index,
                                "batch": list(batch),
                                "batch_size": len(batch),
                            },
                        )
                    for name in batch:
                        self._update_stage_progress(
                            context, name, "running", started_at=now, progress_map=progress_map
                        )

                    future_map = {
                        executor.submit(
                            self._run_stage_threaded, stage_map[name], context, trace
                        ): name
                        for name in batch
                    }
                    outcomes: dict[str, StageExecutionOutcome] = {}
                    errors: list[StageExecutionOutcome] = []
                    first_failure_code: Optional[str] = None
                    for future, name in future_map.items():
                        outcome = future.result()
                        outcomes[name] = outcome
                        if outcome.error is not None:
                            errors.append(outcome)

                    finished_at = time_utils.iso_now()
                    for name in batch:
                        outcome = outcomes.get(name) or StageExecutionOutcome()
                        if outcome.error is not None:
                            classification = self._handle_stage_failure(
                                context,
                                stage_map[name],
                                outcome.span,
                                outcome.error,
                                progress_map=progress_map,
                                finished_at=finished_at,
                            )
                            if first_failure_code is None:
                                first_failure_code = str(classification.get("code") or "")
                        else:
                            self._handle_stage_success(
                                context,
                                stage_map[name],
                                outcome.span,
                                bool(outcome.result),
                                progress_map=progress_map,
                                finished_at=finished_at,
                            )
                    if trace is not None:
                        trace.emit(
                            "parallel.batch.finished",
                            {
                                "group_index": group_index,
                                "batch": list(batch),
                                "batch_size": len(batch),
                                "failed": len(errors),
                            },
                        )

                    if errors:
                        message = str(errors[0].error)
                        if first_failure_code:
                            message = f"[{first_failure_code}] {message}"
                        context.mark_error(message)
                        raise errors[0].error

        context.mark_finished()
        summary.generate_summary(context)

    async def _run_parallel(
        self,
        context: PipelineContext,
        stages: Sequence[Stage],
        *,
        trace: Optional[PipelineTraceRecorder] = None,
    ) -> None:
        stage_list = list(stages)
        stage_map = {stage.name: stage for stage in stage_list}
        progress_map = self._initialize_progress(context, stage_list, parallel=True)
        execution_order = self._get_execution_plan(context, stage_list)
        max_parallel = self._get_max_parallel(context)

        async def _run_stage(stage: Stage) -> StageExecutionOutcome:
            span = self._start_stage_span(context, stage, trace)
            try:
                with bind_trace_scope(trace, span):
                    if hasattr(stage, "run_async"):
                        result = await stage.run_async(context)
                    else:
                        loop = asyncio.get_running_loop()
                        result = await loop.run_in_executor(None, stage.run, context)
                        if asyncio.iscoroutine(result):
                            result = await result
                return StageExecutionOutcome(result=bool(result), span=span)
            except Exception as exc:
                return StageExecutionOutcome(error=exc, span=span)

        for group_index, group in enumerate(execution_order, start=1):
            for i in range(0, len(group), max_parallel):
                batch = group[i : i + max_parallel]
                now = time_utils.iso_now()
                if trace is not None:
                    trace.emit(
                        "parallel.batch.started",
                        {
                            "group_index": group_index,
                            "batch": list(batch),
                            "batch_size": len(batch),
                        },
                    )
                for name in batch:
                    self._update_stage_progress(
                        context, name, "running", started_at=now, progress_map=progress_map
                    )

                tasks = [asyncio.create_task(_run_stage(stage_map[name])) for name in batch]
                results = await asyncio.gather(*tasks)

                errors: list[StageExecutionOutcome] = []
                first_failure_code: Optional[str] = None
                finished_at = time_utils.iso_now()
                for name, outcome in zip(batch, results):
                    if outcome.error is not None:
                        classification = self._handle_stage_failure(
                            context,
                            stage_map[name],
                            outcome.span,
                            outcome.error,
                            progress_map=progress_map,
                            finished_at=finished_at,
                        )
                        if first_failure_code is None:
                            first_failure_code = str(classification.get("code") or "")
                        errors.append(outcome)
                    else:
                        self._handle_stage_success(
                            context,
                            stage_map[name],
                            outcome.span,
                            outcome.result if outcome.result is not None else False,
                            progress_map=progress_map,
                            finished_at=finished_at,
                        )
                if trace is not None:
                    trace.emit(
                        "parallel.batch.finished",
                        {
                            "group_index": group_index,
                            "batch": list(batch),
                            "batch_size": len(batch),
                            "failed": len(errors),
                        },
                    )

                if errors:
                    message = str(errors[0].error)
                    if first_failure_code:
                        message = f"[{first_failure_code}] {message}"
                    context.mark_error(message)
                    raise errors[0].error

        context.mark_finished()
        summary.generate_summary(context)


def run_pipeline(
    record,
    manager: JobManager,
    force: bool = False,
    stages: Optional[Sequence[str]] = None,
) -> None:
    context = PipelineContext(record=record, manager=manager, force=force)
    plugin_stages = plugins_module.load_stage_plugins(logger=context.logger)
    runner = PipelineRunner(list(PIPELINE_STAGES) + plugin_stages)
    runner.run(context, stages=stages)
    if os.environ.get("RECON_METRICS", "0") not in {"0", "false", "False"}:
        stats = {
            "job_id": record.spec.job_id,
            "target": record.spec.target,
            "status": record.metadata.status,
            "started_at": record.metadata.started_at,
            "finished_at": record.metadata.finished_at,
            "stage_progress": record.metadata.stats.get("stage_progress", []),
            "stats": record.metadata.stats,
        }
        metrics.emit_metrics(stats, record.paths.artifact("metrics.json"))
