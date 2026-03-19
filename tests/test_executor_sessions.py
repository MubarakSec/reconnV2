from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

import recon_cli.tools.executor as executor_mod
from recon_cli.tools.executor import CommandExecutor
from recon_cli.utils.circuit_breaker import registry as circuit_registry
from recon_cli.utils.pipeline_trace import PipelineTraceRecorder, bind_trace_scope
from recon_cli.utils import fs


class DummyLogger:
    def info(self, *a, **k): ...
    def error(self, *a, **k): ...
    def warning(self, *a, **k): ...


class CapturingLogger(DummyLogger):
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def warning(self, message, *args, **kwargs):
        if args:
            message = message % args
        self.warnings.append(str(message))


def _cleanup_sessions() -> None:
    with executor_mod._SESSION_LOCK:
        sessions = list(executor_mod._SESSIONS.values())
        executor_mod._SESSIONS.clear()
        executor_mod._SESSION_ALIASES.clear()
        executor_mod._SESSION_COUNTER = 0
    for session in sessions:
        try:
            session.terminate()
        except Exception:
            pass


@pytest.fixture(autouse=True)
def _reset_executor_runtime() -> None:
    _cleanup_sessions()
    circuit_registry.reset_all()
    yield
    _cleanup_sessions()
    circuit_registry.reset_all()


def _interactive_command() -> list[str]:
    code = (
        "import sys,time;"
        "print('ready', flush=True);"
        "line=sys.stdin.readline().strip();"
        "print(f'echo:{line}', flush=True);"
        "time.sleep(60)"
    )
    return [sys.executable, "-u", "-c", code]


def _large_output_command(size: int = 4096) -> list[str]:
    code = (
        "import sys,time;"
        f"sys.stdout.write('X'*{size});"
        "sys.stdout.flush();"
        "time.sleep(60)"
    )
    return [sys.executable, "-u", "-c", code]


def _quick_command(message: str = "done") -> list[str]:
    return [sys.executable, "-u", "-c", f"print({message!r})"]


def _wait_for_output(
    executor: CommandExecutor,
    session_identifier: str,
    needle: str,
    *,
    timeout: float = 3.0,
) -> tuple[object, str]:
    deadline = time.monotonic() + timeout
    chunks: list[str] = []
    info = None
    while time.monotonic() < deadline:
        info = executor.read_session(session_identifier, clear_output=True)
        if info.output:
            chunks.append(info.output)
        combined = "".join(chunks)
        if needle in combined:
            return info, combined
        if not info.running:
            break
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for {needle!r}; saw {''.join(chunks)!r}")


@pytest.mark.asyncio
async def test_command_executor_run_async_supports_default_logger() -> None:
    executor = CommandExecutor()
    result = await executor.run_async(
        [sys.executable, "-c", "print('ok')"],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "ok" in result.stdout


def test_command_executor_session_lifecycle() -> None:
    executor = CommandExecutor(DummyLogger())

    info = executor.start_session(_interactive_command())
    assert info.alias == "S1"
    assert info.running is True
    assert info.finished_at is None

    _ready_info, ready_output = _wait_for_output(executor, info.alias, "ready")
    assert "ready" in ready_output

    echo_snapshot = executor.send_session_input(info.alias, "hello")
    echo_output = echo_snapshot.output
    if "echo:hello" not in echo_output:
        _echo_info, echoed_output = _wait_for_output(executor, info.session_id, "echo:hello")
        echo_output += echoed_output
    assert "echo:hello" in echo_output

    running_sessions = executor.list_sessions(include_finished=False, clear_output=True)
    assert any(item.session_id == info.session_id for item in running_sessions)

    terminated = executor.terminate_session(info.alias)
    final = executor.wait_session(info.session_id, timeout=2.0, clear_output=True)

    assert terminated.error == "Session terminated by user"
    assert final.running is False
    assert final.finished_at is not None
    assert final.error == "Session terminated by user"
    assert final.returncode is not None
    assert all(item.session_id != info.session_id for item in executor.list_sessions(include_finished=False))


def test_command_session_records_tool_trace(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.json"
    events_path = tmp_path / "trace_events.jsonl"
    recorder = PipelineTraceRecorder(
        trace_path,
        events_path,
        job_id="job-session-trace",
        target="example.com",
        profile="passive",
    )
    stage_span = recorder.start_span("session_stage", span_type="stage")
    executor = CommandExecutor(DummyLogger())

    try:
        with bind_trace_scope(recorder, stage_span.span_id):
            info = executor.start_session(_interactive_command())
            _wait_for_output(executor, info.session_id, "ready")
            echo_snapshot = executor.send_session_input(info.alias, "trace")
            if "echo:trace" not in echo_snapshot.output:
                _wait_for_output(executor, info.alias, "echo:trace")
            executor.terminate_session(info.session_id)
            executor.wait_session(info.alias, timeout=2.0, clear_output=True)
        stage_span.finish(status="completed")
        recorder.close(status="finished")
    finally:
        recorder.close(status="finished")

    trace_summary = fs.read_json(trace_path, default={})
    tool_spans = [span for span in trace_summary.get("spans", []) if span.get("span_type") == "tool_exec"]

    assert len(tool_spans) == 1
    tool_span = tool_spans[0]
    assert tool_span.get("parent_span_id") == stage_span.span_id
    assert tool_span.get("status") == "terminated"
    assert tool_span.get("attributes", {}).get("interactive") is True
    assert tool_span.get("attributes", {}).get("session_alias") == info.alias
    assert tool_span.get("attributes", {}).get("session_id") in {info.session_id, "***"}

    event_names = [event.get("name") for event in tool_span.get("events", [])]
    assert "session.started" in event_names
    assert "session.input" in event_names
    assert "session.terminate" in event_names


def test_command_session_truncates_buffer_and_records_trace(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.json"
    events_path = tmp_path / "trace_events.jsonl"
    recorder = PipelineTraceRecorder(
        trace_path,
        events_path,
        job_id="job-session-truncate",
        target="example.com",
        profile="passive",
    )
    stage_span = recorder.start_span("truncate_stage", span_type="stage")
    logger = CapturingLogger()
    executor = CommandExecutor(logger)

    try:
        with bind_trace_scope(recorder, stage_span.span_id):
            info = executor.start_session(_large_output_command(4096), max_output_chars=128)
            deadline = time.monotonic() + 3.0
            snapshot = info
            while time.monotonic() < deadline:
                snapshot = executor.read_session(info.alias, clear_output=False)
                if snapshot.output_truncated:
                    break
                time.sleep(0.05)
            assert snapshot.output_truncated is True
            assert snapshot.max_output_chars == 128
            assert snapshot.output_dropped_chars >= 3968
            assert len(snapshot.output) <= 128
            assert snapshot.output == "X" * len(snapshot.output)
            executor.terminate_session(info.session_id)
            executor.wait_session(info.alias, timeout=2.0, clear_output=True)
        stage_span.finish(status="completed")
        recorder.close(status="finished")
    finally:
        recorder.close(status="finished")

    assert any("output exceeded 128 chars" in message for message in logger.warnings)

    trace_summary = fs.read_json(trace_path, default={})
    tool_spans = [span for span in trace_summary.get("spans", []) if span.get("span_type") == "tool_exec"]
    assert len(tool_spans) == 1
    tool_span = tool_spans[0]
    assert tool_span.get("attributes", {}).get("session_output_truncated") is True
    assert tool_span.get("attributes", {}).get("session_dropped_output_chars", 0) >= 3968
    event_names = [event.get("name") for event in tool_span.get("events", [])]
    assert "session.output.truncated" in event_names


def test_list_sessions_prunes_finished_sessions_by_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_EXECUTOR_SESSION_FINISHED_TTL_SECONDS", "1")
    executor = CommandExecutor(DummyLogger())

    stale = executor.start_session(_quick_command("stale"))
    stale_final = executor.wait_session(stale.alias, timeout=2.0, clear_output=False)
    assert stale_final.running is False

    fresh = executor.start_session(_quick_command("fresh"))
    fresh_final = executor.wait_session(fresh.alias, timeout=2.0, clear_output=False)
    assert fresh_final.running is False

    stale_session = executor_mod._resolve_session(stale.session_id)
    stale_session._finished_monotonic = time.monotonic() - 10.0

    sessions = executor.list_sessions(include_finished=True)

    assert all(item.session_id != stale.session_id for item in sessions)
    assert any(item.session_id == fresh.session_id for item in sessions)


def test_cleanup_sessions_keeps_running_and_honors_finished_limit() -> None:
    executor = CommandExecutor(DummyLogger())

    running = executor.start_session(_interactive_command())

    first = executor.start_session(_quick_command("first"))
    first_final = executor.wait_session(first.alias, timeout=2.0, clear_output=False)
    assert first_final.running is False

    second = executor.start_session(_quick_command("second"))
    second_final = executor.wait_session(second.alias, timeout=2.0, clear_output=False)
    assert second_final.running is False

    cleaned = executor.cleanup_sessions(max_finished=1, finished_ttl_seconds=0)
    sessions = executor.list_sessions(include_finished=True, clear_output=False)

    assert cleaned["terminated_running_sessions"] == 0
    assert cleaned["pruned_finished_sessions"] == 1
    assert cleaned["remaining_sessions"] == 2
    assert any(item.session_id == running.session_id and item.running for item in sessions)
    assert any(item.session_id == second.session_id and not item.running for item in sessions)
    assert all(item.session_id != first.session_id for item in sessions)

    executor.terminate_session(running.alias)
    executor.wait_session(running.session_id, timeout=2.0)
