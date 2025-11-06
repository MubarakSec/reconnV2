from __future__ import annotations

from typing import Iterable

from recon_cli.jobs import summary
from recon_cli.jobs.manager import JobManager
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages import PIPELINE_STAGES, Stage, StageError
from recon_cli.utils.notify import send_pipeline_notification


class PipelineRunner:
    def __init__(self, stages: Iterable[Stage] | None = None) -> None:
        self.stages = list(stages or PIPELINE_STAGES)

    def run(self, context: PipelineContext) -> None:
        context.mark_started()
        error: Exception | None = None
        try:
            for stage in self.stages:
                try:
                    stage.run(context)
                except StageError as exc:
                    context.mark_error(str(exc))
                    error = exc
                    raise
                except Exception as exc:
                    context.mark_error(str(exc))
                    error = exc
                    raise
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
    runner = PipelineRunner()
    runner.run(context)
