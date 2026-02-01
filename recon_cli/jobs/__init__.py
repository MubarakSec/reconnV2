"""
Jobs Module - Job Management and Lifecycle

This package handles job creation, execution, and monitoring:
- lifecycle: Job state management
- manager: Job queue and scheduling
- models: Job data models (JobSpec, JobMetadata, JobPaths)
- results: Result handling and tracking
- streaming: Async result streaming
- summary: Job summary generation
- validator: Job specification validation
"""

from .models import JobSpec, JobMetadata, JobPaths
from .lifecycle import JobLifecycle
from .manager import JobManager
from .results import ResultsTracker, dedupe_key
from .streaming import ResultStream, AsyncResultStream, ResultWriter, StreamingConfig
from .summary import generate_summary
from .validator import validate_job

__all__ = [
    # Models
    "JobSpec",
    "JobMetadata",
    "JobPaths",
    # Lifecycle
    "JobLifecycle",
    # Manager
    "JobManager",
    # Results
    "ResultsTracker",
    "dedupe_key",
    # Streaming
    "StreamingConfig",
    "ResultStream",
    "AsyncResultStream",
    "ResultWriter",
    # Summary
    "generate_summary",
    # Validator
    "validate_job",
]



