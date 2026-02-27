from __future__ import annotations

from typing import Iterable, Optional, Sequence

import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path

from recon_cli.jobs import summary
from recon_cli.jobs.manager import JobManager
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages import PIPELINE_STAGES, Stage, StageError, StageResult
from recon_cli.pipeline.parallel import DependencyResolver
from recon_cli.utils.notify import send_pipeline_notification
from recon_cli.utils import time as time_utils
# Stage plugin loader lives on the plugins package to avoid name collisions.
import recon_cli.plugins as plugins_module
from recon_cli import metrics
import os


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
        try:
            use_parallel = bool(getattr(context.runtime_config, "parallel_stages", False))
            if use_parallel:
                stage_names = [stage.name for stage in selected_stages]
                if len(set(stage_names)) != len(stage_names):
                    context.logger.warning("Duplicate stage names detected; running sequentially")
                    use_parallel = False
            if use_parallel:
                self._run_parallel_sync(context, selected_stages)
                return

            progress = []
            context.record.metadata.stats["stage_progress"] = progress
            context.manager.update_metadata(context.record)
            for stage in selected_stages:
                started_at = time_utils.iso_now()
                progress.append({"stage": stage.name, "status": "running", "started_at": started_at})
                context.manager.update_metadata(context.record)
                try:
                    ran = stage.run(context)
                    progress[-1]["status"] = "completed" if ran else "skipped"
                except StageError as exc:
                    progress[-1]["status"] = "failed"
                    progress[-1]["error"] = str(exc)
                    context.mark_error(str(exc))
                    error = exc
                    raise
                except Exception as exc:
                    progress[-1]["status"] = "failed"
                    progress[-1]["error"] = str(exc)
                    context.mark_error(str(exc))
                    error = exc
                    raise
                finally:
                    progress[-1]["finished_at"] = time_utils.iso_now()
                    context.manager.update_metadata(context.record)
            context.mark_finished()
            summary.generate_summary(context)
        except Exception as exc:
            error = error or exc
            raise
        finally:
            status = "finished" if error is None else "failed"
            message = str(error) if error else None
            send_pipeline_notification(context, status=status, error=message)
            context.close()

    def _run_parallel_sync(self, context: PipelineContext, stages: Sequence[Stage]) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            self._run_parallel_threaded(context, stages)
            return

        error_holder: list[Exception] = []

        def _runner() -> None:
            try:
                self._run_parallel_threaded(context, stages)
            except Exception as exc:
                error_holder.append(exc)

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()
        if error_holder:
            raise error_holder[0]

    @staticmethod
    def _run_stage_threaded(stage: Stage, context: PipelineContext) -> bool:
        if hasattr(stage, "run_async"):
            result = asyncio.run(stage.run_async(context))
            return bool(result)
        result = stage.run(context)
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
        return bool(result)

    def _run_parallel_threaded(self, context: PipelineContext, stages: Sequence[Stage]) -> None:
        stage_list = list(stages)
        stage_map = {stage.name: stage for stage in stage_list}
        stage_order = [stage.name for stage in stage_list]

        progress = []
        progress_map = {}
        for stage in stage_list:
            entry = {"stage": stage.name, "status": "pending"}
            progress.append(entry)
            progress_map[stage.name] = entry
        context.record.metadata.stats["stage_progress"] = progress
        context.record.metadata.stats["parallel_execution"] = True
        context.manager.update_metadata(context.record)

        dependency_map = {name: set(deps) for name, deps in DependencyResolver.STAGE_DEPENDENCIES.items()}
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

        max_parallel = int(getattr(context.runtime_config, "max_parallel_stages", 4) or 4)
        max_parallel = max(1, max_parallel)

        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            for group in execution_order:
                for i in range(0, len(group), max_parallel):
                    batch = group[i:i + max_parallel]
                    now = time_utils.iso_now()
                    for name in batch:
                        entry = progress_map.get(name)
                        if entry is None:
                            continue
                        entry["status"] = "running"
                        entry["started_at"] = now
                    context.manager.update_metadata(context.record)

                    future_map = {
                        executor.submit(self._run_stage_threaded, stage_map[name], context): name
                        for name in batch
                    }
                    results_by_name: dict[str, object] = {}
                    errors: list[Exception] = []
                    for future, name in future_map.items():
                        try:
                            results_by_name[name] = future.result()
                        except Exception as exc:
                            results_by_name[name] = exc
                            errors.append(exc)

                    finished_at = time_utils.iso_now()
                    for name in batch:
                        entry = progress_map.get(name)
                        if entry is None:
                            continue
                        result = results_by_name.get(name)
                        entry["finished_at"] = finished_at
                        if isinstance(result, Exception):
                            entry["status"] = "failed"
                            entry["error"] = str(result)
                        else:
                            entry["status"] = "completed" if bool(result) else "skipped"
                    context.manager.update_metadata(context.record)

                    if errors:
                        message = str(errors[0])
                        context.mark_error(message)
                        raise errors[0]

        context.mark_finished()
        summary.generate_summary(context)

    async def _run_parallel(self, context: PipelineContext, stages: Sequence[Stage]) -> None:
        stage_list = list(stages)
        stage_map = {stage.name: stage for stage in stage_list}
        stage_order = [stage.name for stage in stage_list]

        progress = []
        progress_map = {}
        for stage in stage_list:
            entry = {"stage": stage.name, "status": "pending"}
            progress.append(entry)
            progress_map[stage.name] = entry
        context.record.metadata.stats["stage_progress"] = progress
        context.record.metadata.stats["parallel_execution"] = True
        context.manager.update_metadata(context.record)

        dependency_map = {name: set(deps) for name, deps in DependencyResolver.STAGE_DEPENDENCIES.items()}
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

        max_parallel = int(getattr(context.runtime_config, "max_parallel_stages", 4) or 4)
        max_parallel = max(1, max_parallel)

        async def _run_stage(stage: Stage) -> bool:
            if hasattr(stage, "run_async"):
                result = await stage.run_async(context)
                return bool(result)
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, stage.run, context)
            if asyncio.iscoroutine(result):
                result = await result
            return bool(result)

        for group in execution_order:
            for i in range(0, len(group), max_parallel):
                batch = group[i:i + max_parallel]
                now = time_utils.iso_now()
                for name in batch:
                    entry = progress_map.get(name)
                    if entry is None:
                        continue
                    entry["status"] = "running"
                    entry["started_at"] = now
                context.manager.update_metadata(context.record)

                tasks = [asyncio.create_task(_run_stage(stage_map[name])) for name in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                errors: list[Exception] = []
                finished_at = time_utils.iso_now()
                for name, result in zip(batch, results):
                    entry = progress_map.get(name)
                    if entry is None:
                        continue
                    entry["finished_at"] = finished_at
                    if isinstance(result, Exception):
                        entry["status"] = "failed"
                        entry["error"] = str(result)
                        errors.append(result)
                    else:
                        entry["status"] = "completed" if result else "skipped"
                context.manager.update_metadata(context.record)

                if errors:
                    message = str(errors[0])
                    context.mark_error(message)
                    raise errors[0]

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
