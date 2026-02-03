from __future__ import annotations

from typing import Iterable, Optional, Sequence

import asyncio
from pathlib import Path

from recon_cli.jobs import summary
from recon_cli.jobs.manager import JobManager
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages import PIPELINE_STAGES, Stage, StageError, StageResult
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
        progress = []
        context.record.metadata.stats["stage_progress"] = progress
        context.manager.update_metadata(context.record)
        try:
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


def run_pipeline(record, manager: JobManager, force: bool = False) -> None:
    context = PipelineContext(record=record, manager=manager, force=force)
    plugin_stages = plugins_module.load_stage_plugins(logger=context.logger)
    runner = PipelineRunner(list(PIPELINE_STAGES) + plugin_stages)
    runner.run(context)
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
