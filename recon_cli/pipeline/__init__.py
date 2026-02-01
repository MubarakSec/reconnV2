"""
Pipeline Module - Scan Pipeline Orchestration

This package provides the pipeline execution framework:
- runner: Pipeline executor (lazy import to avoid circular deps)
- stages: Stage definitions and base classes
- context: Pipeline execution context
- parallel: Parallel stage execution with DAG
- progress: Progress logging
"""

from .context import PipelineContext
from .stages import Stage, StageError
from .parallel import ParallelStageExecutor, DependencyResolver
from .progress import ProgressLogger

# Lazy import for PipelineRunner to avoid circular import with plugins
def get_pipeline_runner():
    """Get PipelineRunner class (lazy import to avoid circular deps)."""
    from .runner import PipelineRunner
    return PipelineRunner

__all__ = [
    # Context
    "PipelineContext",
    # Stages
    "Stage",
    "StageError",
    # Parallel
    "ParallelStageExecutor",
    "DependencyResolver",
    # Progress
    "ProgressLogger",
    # Runner (lazy)
    "get_pipeline_runner",
]

