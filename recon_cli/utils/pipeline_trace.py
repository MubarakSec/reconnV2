from __future__ import annotations

import contextvars
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from recon_cli.utils import fs, time as time_utils
from recon_cli.utils.jsonl import JsonlWriter


@dataclass(frozen=True)
class _PipelineTraceScope:
    recorder: "PipelineTraceRecorder"
    parent_span_id: Optional[str]


_CURRENT_TRACE_SCOPE: contextvars.ContextVar[Optional[_PipelineTraceScope]] = contextvars.ContextVar(
    "recon_pipeline_trace_scope",
    default=None,
)


@dataclass
class PipelineTraceSpan:
    recorder: "PipelineTraceRecorder"
    span_id: str
    name: str
    parent_span_id: Optional[str]
    started_at: str
    _started_monotonic: float
    span_type: str = "custom"
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "running"
    finished_at: Optional[str] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    _finished: bool = False

    def set_attribute(self, key: str, value: Any) -> None:
        self.recorder.set_span_attribute(self, key, value)

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        self.recorder.add_span_event(self, name, attributes=attributes)

    def finish(
        self,
        *,
        status: str,
        error: Optional[Exception | str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.recorder.finish_span(self, status=status, error=error, attributes=attributes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "span_type": self.span_type,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "events": self.events,
            "error": self.error,
        }


class PipelineTraceRecorder:
    def __init__(
        self,
        trace_path: Path,
        events_path: Path,
        *,
        job_id: str,
        target: str,
        profile: str,
        execution_profile: Optional[str] = None,
        stages: Optional[List[str]] = None,
        parallel_enabled: bool = False,
    ) -> None:
        self.trace_path = trace_path
        self.events_path = events_path
        self.trace_id = uuid.uuid4().hex
        self.root_span_id = uuid.uuid4().hex[:16]
        self.name = f"pipeline:{job_id}"
        self.status = "running"
        self.error: Optional[str] = None
        self.started_at = time_utils.iso_now()
        self.finished_at: Optional[str] = None
        self._started_monotonic = time.monotonic()
        self._finished_monotonic_value: Optional[float] = None
        self._lock = threading.RLock()
        self._spans: List[PipelineTraceSpan] = []
        self._events_count = 0
        self.attributes: Dict[str, Any] = {
            "job_id": job_id,
            "target": target,
            "profile": profile,
            "parallel_enabled": bool(parallel_enabled),
            "stages": list(stages or []),
        }
        if execution_profile:
            self.attributes["execution_profile"] = execution_profile
        self._writer = JsonlWriter(events_path)
        self._writer.__enter__()
        self.emit(
            "trace.started",
            {
                "trace_name": self.name,
                "root_span_id": self.root_span_id,
                "attributes": dict(self.attributes),
            },
        )
        self._persist_snapshot_locked()

    def start_span(
        self,
        name: str,
        *,
        span_type: str = "custom",
        attributes: Optional[Dict[str, Any]] = None,
        parent_span_id: Optional[str] = None,
    ) -> PipelineTraceSpan:
        with self._lock:
            span = PipelineTraceSpan(
                recorder=self,
                span_id=uuid.uuid4().hex[:16],
                name=name,
                parent_span_id=parent_span_id or self.root_span_id,
                started_at=time_utils.iso_now(),
                _started_monotonic=time.monotonic(),
                span_type=span_type,
                attributes=dict(attributes or {}),
            )
            self._spans.append(span)
            self._emit_locked(
                "span.started",
                {
                    "span_id": span.span_id,
                    "parent_span_id": span.parent_span_id,
                    "name": span.name,
                    "span_type": span.span_type,
                    "attributes": dict(span.attributes),
                },
            )
            self._persist_snapshot_locked()
            return span

    def set_span_attribute(self, span: PipelineTraceSpan, key: str, value: Any) -> None:
        with self._lock:
            span.attributes[str(key)] = value

    def add_span_event(
        self,
        span: PipelineTraceSpan,
        name: str,
        *,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            event = {
                "name": str(name),
                "timestamp": time_utils.iso_now(),
                "attributes": dict(attributes or {}),
            }
            span.events.append(event)
            self._emit_locked(
                "span.event",
                {
                    "span_id": span.span_id,
                    "name": span.name,
                    "event": event,
                },
            )

    def finish_span(
        self,
        span: PipelineTraceSpan,
        *,
        status: str,
        error: Optional[Exception | str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            if span._finished:
                return
            if attributes:
                span.attributes.update(attributes)
            if error is not None:
                span.error = str(error)
            span.status = str(status)
            span.finished_at = time_utils.iso_now()
            span.duration_ms = round((time.monotonic() - span._started_monotonic) * 1000, 3)
            span._finished = True
            self._emit_locked(
                "span.finished",
                {
                    "span_id": span.span_id,
                    "name": span.name,
                    "span_type": span.span_type,
                    "status": span.status,
                    "duration_ms": span.duration_ms,
                    "error": span.error,
                    "attributes": dict(span.attributes),
                },
            )
            self._persist_snapshot_locked()

    def emit(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self._emit_locked(name, attributes or {})

    def close(self, *, status: str, error: Optional[Exception | str] = None) -> Dict[str, Any]:
        with self._lock:
            if self.finished_at is not None:
                return self.to_dict()
            self.status = str(status)
            if error is not None:
                self.error = str(error)
            self.finished_at = time_utils.iso_now()
            self._finished_monotonic_value = time.monotonic()
            self._emit_locked(
                "trace.finished",
                {
                    "status": self.status,
                    "error": self.error,
                    "duration_ms": self.duration_ms,
                },
            )
            self._persist_snapshot_locked()
            self._writer.__exit__(None, None, None)
            return self.to_dict()

    @property
    def duration_ms(self) -> float:
        end = self._finished_monotonic_value if self._finished_monotonic_value is not None else time.monotonic()
        return round((end - self._started_monotonic) * 1000, 3)

    def stats(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "status": self.status,
            "span_count": len(self._spans),
            "event_count": self._events_count,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "name": self.name,
            "status": self.status,
            "error": self.error,
            "root_span_id": self.root_span_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "attributes": dict(self.attributes),
            "spans": [span.to_dict() for span in self._spans],
            "stats": {
                "span_count": len(self._spans),
                "event_count": self._events_count,
                "span_counts_by_type": self._span_counts_by_type(),
            },
        }

    def _emit_locked(self, name: str, attributes: Dict[str, Any]) -> None:
        payload = {
            "type": "trace_event",
            "trace_id": self.trace_id,
            "name": str(name),
            "timestamp": time_utils.iso_now(),
            "attributes": dict(attributes),
        }
        self._writer.write(payload)
        self._events_count += 1

    def _persist_snapshot_locked(self) -> None:
        snapshot = self.to_dict()
        snapshot["artifacts"] = {
            "events": self.events_path.name,
        }
        fs.write_json(self.trace_path, snapshot)

    def _span_counts_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for span in self._spans:
            counts[span.span_type] = counts.get(span.span_type, 0) + 1
        return counts


def current_trace_recorder() -> Optional[PipelineTraceRecorder]:
    scope = _CURRENT_TRACE_SCOPE.get()
    if scope is None:
        return None
    return scope.recorder


def current_parent_span_id() -> Optional[str]:
    scope = _CURRENT_TRACE_SCOPE.get()
    if scope is None:
        return None
    return scope.parent_span_id


@contextmanager
def bind_trace_scope(
    recorder: Optional[PipelineTraceRecorder],
    parent_span: Optional[PipelineTraceSpan] = None,
) -> Generator[None, None, None]:
    if recorder is None:
        yield
        return
    token = _CURRENT_TRACE_SCOPE.set(
        _PipelineTraceScope(
            recorder=recorder,
            parent_span_id=parent_span.span_id if parent_span is not None else recorder.root_span_id,
        )
    )
    try:
        yield
    finally:
        _CURRENT_TRACE_SCOPE.reset(token)
