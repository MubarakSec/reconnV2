from __future__ import annotations

import atexit
import base64
import errno
import hashlib
import json
import logging
import os
import pty
import re
import select
import signal
import shlex
import shutil
import subprocess
import threading
import time
import unicodedata
import uuid
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Tuple, Any, Callable, Sequence, Union

from recon_cli.utils.circuit_breaker import CircuitBreakerConfig, registry as circuit_registry
from recon_cli.utils.pipeline_trace import PipelineTraceSpan, CURRENT_TRACE_SCOPE, PipelineTraceScope, current_parent_span_id, current_trace_recorder, bind_trace_scope
from recon_cli.utils.sanitizer import redact as redact_text
from recon_cli.utils import time as time_utils

"""
Command Executor Module - تنفيذ الأوامر الخارجية

هذا الموديول مسؤول عن تشغيل الأدوات الخارجية مثل subfinder, nuclei, httpx
مع دعم:
- Timeout للأوامر الطويلة
- Redaction للبيانات الحساسة في الـ logs
- Error handling شامل
- كتابة النتائج لملفات

Example:
    >>> executor = CommandExecutor(logger)
    >>> result = executor.run(["subfinder", "-d", "example.com"])
    >>> print(result.stdout)
"""

_MODULE_LOGGER = logging.getLogger(__name__)
_SESSION_LOCK = threading.RLock()
_SESSION_COUNTER = 0
_SESSIONS: Dict[str, '_CommandSession'] = {}
_SESSION_ALIASES: Dict[str, str] = {}
_DEFAULT_SESSION_MAX_OUTPUT_CHARS = 262144
_MIN_SESSION_MAX_OUTPUT_CHARS = 128
_DEFAULT_SESSION_MAX_FINISHED = 32
_MIN_SESSION_MAX_FINISHED = 0
_DEFAULT_SESSION_FINISHED_TTL_SECONDS = 86400.0

# ═══════════════════════════════════════════════════════════
#                     Security Guardrails
# ═══════════════════════════════════════════════════════════

_SENSITIVE_FILE_MARKERS = (
    "/proc/self/environ",
    "/etc/passwd",
    "/etc/shadow",
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".bash_history",
    ".zsh_history",
    "/var/run/secrets/",
    "id_rsa",
    "id_ed25519",
    "config.php",
    "web.config",
    "settings.py",
    ".env",
)

_NETWORK_SHELL_EXECUTABLES = {"nc", "ncat", "netcat", "socat", "telnet", "ssh"}
_INLINE_CODE_FLAGS = {"-c", "-e", "-r", "--eval", "--command"}
_SHELL_TARGET_MARKERS = ("/bin/sh", "/bin/bash", "cmd.exe", "powershell", "pwsh", "/bin/zsh", "/bin/dash")
_REVERSE_SHELL_SCRIPT_MARKERS = (
    "socket",
    "connect(",
    "os.dup2",
    "pty.spawn",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "/dev/tcp/",
    "exec 5<>/dev/tcp/",
    "bash -i",
    "sh -i",
    "nc -e",
    "nc -c",
)
_EXECUTION_MARKERS = ("exec(", "eval(", "os.system(", "subprocess.", "pty.spawn", "system(", "popen(", "shell_exec(")

class CommandError(RuntimeError):
    """استثناء لأخطاء تنفيذ الأوامر"""
    def __init__(self, message: str, returncode: Optional[int] = None):
        super().__init__(message)
        self.returncode = returncode

@dataclass
class ToolExecutionPolicy:
    tool_class: str
    timeout: int
    retries: int = 0
    backoff_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    circuit_failure_threshold: int = 5
    circuit_open_timeout: int = 60

@dataclass(frozen=True)
class CommandSessionInfo:
    session_id: str
    alias: str
    command: List[str]
    command_preview: str
    running: bool
    pid: Optional[int]
    started_at: str
    finished_at: Optional[str]
    returncode: Optional[int]
    cwd: Optional[str] = None
    output: str = ""
    error: Optional[str] = None
    output_truncated: bool = False
    output_dropped_chars: int = 0
    output_retained_chars: int = 0
    max_output_chars: int = _DEFAULT_SESSION_MAX_OUTPUT_CHARS

def _guard_command_or_raise(cmd_list: List[str], env: Optional[Mapping[str, str]] = None) -> None:
    if os.environ.get("RECON_EXECUTOR_GUARDRAILS", "true").lower() == "false":
        return
    if not cmd_list:
        return
    
    executable = Path(cmd_list[0]).name.lower()
    joined = " ".join(cmd_list).lower()

    if any(ord(c) > 127 for c in executable):
        raise CommandError(f"Blocked Unicode-homograph executable name: {executable}")

    if executable in {"bash", "sh", "zsh", "dash"} and any("c" in arg.strip("-") for arg in cmd_list[1:] if arg.startswith("-")):
        raise CommandError("Blocked: inline shell commands are not allowed")

    if executable in {"python", "python3", "perl", "ruby", "php"} and any(arg in _INLINE_CODE_FLAGS or arg.startswith("-c") for arg in cmd_list[1:]):
        if any(marker in joined for marker in _EXECUTION_MARKERS) or "base64" in joined:
            raise CommandError("Blocked: inline decoder/execution payload")
    
    if executable in _NETWORK_SHELL_EXECUTABLES:
        if any(marker in joined for marker in _SHELL_TARGET_MARKERS):
            raise CommandError(f"Blocked potential reverse shell via {executable}")

    if executable in {"curl", "wget"}:
        if any(token in joined for token in ("$(env)", "`env`", "$(", "`", "${", "%env%", "!env!")):
            raise CommandError(f"Blocked {executable} command containing shell-style expansion payload")
        
        for part in cmd_list[1:]:
            if part.startswith("@"):
                filename = part[1:].lower()
                if any(marker in filename for marker in _SENSITIVE_FILE_MARKERS):
                    raise CommandError(f"Blocked {executable} command referencing a sensitive local file via @ notation")
            
            if part in {"-d", "--data", "--data-binary", "--upload-file", "-t", "-T", "--post-file"}:
                idx = cmd_list.index(part)
                if idx + 1 < len(cmd_list):
                    next_arg = cmd_list[idx + 1]
                    if next_arg.startswith("@") and any(marker in next_arg.lower() for marker in _SENSITIVE_FILE_MARKERS):
                         raise CommandError(f"Blocked {executable} command referencing a sensitive local file payload")

    if executable in {"nc", "ncat", "netcat", "telnet"}:
        if any(arg in {"-e", "-c", "--exec", "--sh-exec"} for arg in cmd_list[1:]):
            raise CommandError(f"Blocked {executable} reverse-shell style execution payload")

    if executable == "socat":
        if any(marker in joined for marker in ("exec:", "system:", "pty", "stderr")):
            if any(marker in joined for marker in ("tcp:", "udp:", "sctp:")):
                raise CommandError("Blocked socat potential reverse-shell execution payload")

def _projectdiscovery_httpx_available(path: str) -> bool:
    try:
        res = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=5)
        return "-tech-detect" in res.stdout or "-status-code" in res.stdout
    except Exception:
        return False

def _command_preview(cmd: List[str], redact: bool = True) -> str:
    if not cmd: return ""
    preview = shlex.join(cmd)
    return redact_text(preview) if redact else preview

def _resolve_policy(cmd: List[str], timeout_override: Optional[int] = None) -> ToolExecutionPolicy:
    name = Path(cmd[0]).name.lower()
    policy = ToolExecutionPolicy(tool_class="generic", timeout=300)
    
    if "nmap" in name:
        policy = ToolExecutionPolicy(tool_class="scanner", timeout=1800, retries=1)
    elif "nuclei" in name:
        policy = ToolExecutionPolicy(tool_class="scanner", timeout=3600, circuit_failure_threshold=3)
    elif "ffuf" in name or "feroxbuster" in name:
        policy = ToolExecutionPolicy(tool_class="fuzzer", timeout=7200)
    elif "httpx" in name:
        policy = ToolExecutionPolicy(tool_class="scanner", timeout=300, retries=1)
    
    if timeout_override:
        policy.timeout = timeout_override
    return policy

def _start_command_trace_span(
    command: Iterable[str],
    *,
    policy: ToolExecutionPolicy,
    redact: bool,
    check: bool,
    capture_output: bool,
    cwd: Optional[Path] = None,
    output_path: Optional[Path] = None,
    context: Optional[object] = None,
    parent_span_id: Optional[str] = None,
) -> Optional[PipelineTraceSpan]:
    recorder = current_trace_recorder()
    if recorder is None and context is not None:
        recorder = getattr(context, "trace_recorder", None)

    if recorder is None:
        return None
    
    if parent_span_id is None:
        parent_span_id = current_parent_span_id()
        if parent_span_id is None:
            parent_span_id = getattr(recorder, "root_span_id", None)

    cmd_list = [str(part) for part in command]
    tool_name = Path(cmd_list[0]).name if cmd_list else "command"
    attributes: Dict[str, object] = {
        "tool": tool_name,
        "tool_class": policy.tool_class,
        "timeout": policy.timeout,
        "check": bool(check),
        "capture_output": bool(capture_output),
        "command_preview": _command_preview(cmd_list, redact=redact),
    }
    if cwd is not None: attributes["cwd"] = str(cwd)
    if output_path is not None: attributes["output_path"] = str(output_path)
    
    return recorder.start_span(
        f"tool:{tool_name}",
        span_type="tool_exec",
        parent_span_id=parent_span_id,
        attributes=attributes,
    )

def _finish_command_trace_span(
    span: Optional[PipelineTraceSpan],
    *,
    status: str,
    error: Optional[Exception | str] = None,
    attempts: int = 1,
    returncode: Optional[int] = None,
) -> None:
    if span is None:
        return
    attributes = {"attempts": attempts}
    if returncode is not None:
        attributes["returncode"] = int(returncode)
    span.finish(status=status, error=error, attributes=attributes)

_SUSPICIOUS_OUTPUT_RULES = (
    ("instruction-like content", re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE)),
    ("tool reprogramming language", re.compile(r"(follow|obey)\s+(these|the|following)\s+(instructions?|directives?)", re.IGNORECASE)),
    ("prompt disclosure language", re.compile(r"(system prompt|developer message|tool instructions?)", re.IGNORECASE)),
    ("command-substitution exfiltration hint", re.compile(r"(\$\(\s*env\s*\)|`[^`]*env[^`]*`|run\s+\$\(env\))", re.IGNORECASE)),
)

def _detect_suspicious_output(text: str) -> tuple[Optional[str], str]:
    sample = text[:4096]
    for reason, pattern in _SUSPICIOUS_OUTPUT_RULES:
        match = pattern.search(sample)
        if match:
            preview = sample[match.start() : match.end() + 120].splitlines()[0]
            return reason, preview[:200]
    return None, ""


def _report_suspicious_output(
    logger,
    trace_span: Optional[PipelineTraceSpan],
    command: Iterable[str],
    *,
    source: str,
    text: Optional[str],
) -> bool:
    if not text:
        return False
    reason, preview = _detect_suspicious_output(text)
    if not reason:
        return False
    tool_name = Path(str(next(iter(command), "command"))).name
    logger.warning(
        "Potential prompt-injection content detected in %s output for %s: %s",
        source,
        tool_name,
        reason,
    )
    if trace_span is not None:
        trace_span.add_event(
            "tool.output.warning",
            {
                "source": source,
                "reason": reason,
                "preview": redact_text(preview) or preview,
            },
        )
    return True

def _report_suspicious_output_in_file(
    logger,
    trace_span: Optional[PipelineTraceSpan],
    command: Iterable[str],
    output_path: Path,
) -> bool:
    try:
        with output_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if _report_suspicious_output(logger, trace_span, command, source="file", text=line):
                    return True
    except OSError:
        return False
    return False

def _session_output_limit(max_output_chars: Optional[int] = None) -> int:
    if max_output_chars is not None:
        return max(_MIN_SESSION_MAX_OUTPUT_CHARS, int(max_output_chars))
    raw_value = os.environ.get("RECON_EXECUTOR_SESSION_MAX_OUTPUT_CHARS", str(_DEFAULT_SESSION_MAX_OUTPUT_CHARS))
    try:
        return max(_MIN_SESSION_MAX_OUTPUT_CHARS, int(raw_value))
    except (TypeError, ValueError):
        return _DEFAULT_SESSION_MAX_OUTPUT_CHARS


def _session_finished_limit(max_finished: Optional[int] = None) -> int:
    if max_finished is not None:
        return max(_MIN_SESSION_MAX_FINISHED, int(max_finished))
    raw_value = os.environ.get("RECON_EXECUTOR_SESSION_MAX_FINISHED", str(_DEFAULT_SESSION_MAX_FINISHED))
    try:
        return max(_MIN_SESSION_MAX_FINISHED, int(raw_value))
    except (TypeError, ValueError):
        return _DEFAULT_SESSION_MAX_FINISHED


def _session_finished_ttl(max_age_seconds: Optional[float] = None) -> Optional[float]:
    if max_age_seconds is not None:
        try:
            parsed = float(max_age_seconds)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None
    raw_value = os.environ.get(
        "RECON_EXECUTOR_SESSION_FINISHED_TTL_SECONDS",
        str(_DEFAULT_SESSION_FINISHED_TTL_SECONDS),
    )
    try:
        parsed = float(raw_value)
    except (TypeError, ValueError):
        return _DEFAULT_SESSION_FINISHED_TTL_SECONDS
    return parsed if parsed > 0 else None

class _CommandSession:
    def __init__(
        self,
        command: List[str],
        *,
        alias: str,
        cwd: Optional[Path],
        env: Optional[Mapping[str, str]],
        redact: bool,
        logger,
        trace_span: Optional[PipelineTraceSpan],
        max_output_chars: Optional[int],
    ) -> None:
        self.session_id = uuid.uuid4().hex[:8]
        self.alias = alias
        self.command = list(command)
        self.command_preview = _command_preview(self.command, redact=redact)
        self.cwd = str(cwd) if cwd is not None else None
        self.env = dict(env) if env is not None else None
        self.logger = logger
        self.trace_span = trace_span
        self.started_at = time_utils.iso_now()
        self.finished_at: Optional[str] = None
        self.returncode: Optional[int] = None
        self.error: Optional[str] = None
        self.pid: Optional[int] = None
        self.running = False
        self.last_activity = time.time()
        self._lock = threading.RLock()
        self._output_buffer = ""
        self._read_offset = 0
        self._done = threading.Event()
        self._terminated_by_user = False
        self._master_fd: Optional[int] = None
        self._read_stream = None
        self._write_stream = None
        self._process: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._transport = "pty"
        self._output_warning_emitted = False
        self._max_output_chars = _session_output_limit(max_output_chars)
        self._dropped_output_chars = 0
        self._output_truncation_reported = False
        self._finished_monotonic: Optional[float] = None

    def start(self) -> None:
        fallback_reason: Optional[str] = None
        try:
            master_fd, slave_fd = pty.openpty()
        except OSError as exc:
            master_fd = None
            slave_fd = None
            fallback_reason = str(exc)
            process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                text=False,
                bufsize=0,
            )
            read_stream = process.stdout
            write_stream = process.stdin
            self._transport = "pipe"
        else:
            try:
                process = subprocess.Popen(
                    self.command,
                    cwd=self.cwd,
                    env=self.env,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    start_new_session=True,
                    text=False,
                )
            except Exception:
                os.close(master_fd)
                os.close(slave_fd)
                raise
            finally:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass
            read_stream = None
            write_stream = None
            self._transport = "pty"

        with self._lock:
            self._master_fd = master_fd
            self._read_stream = read_stream
            self._write_stream = write_stream
            self._process = process
            self.pid = process.pid
            self.running = True
            self.last_activity = time.time()
        if self.trace_span is not None:
            self.trace_span.set_attribute("interactive", True)
            self.trace_span.set_attribute("transport", self._transport)
            self.trace_span.set_attribute("session_id", self.session_id)
            self.trace_span.set_attribute("session_alias", self.alias)
            self.trace_span.set_attribute("session_max_output_chars", self._max_output_chars)
            if self.pid is not None:
                self.trace_span.set_attribute("pid", self.pid)
            self.trace_span.add_event(
                "session.started",
                {
                    "session_id": self.session_id,
                    "alias": self.alias,
                    "pid": self.pid,
                    "transport": self._transport,
                },
            )
            if fallback_reason is not None:
                self.trace_span.add_event(
                    "session.transport_fallback",
                    {"transport": self._transport, "reason": fallback_reason},
                )
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    def _append_output(self, chunk: str) -> None:
        if not chunk:
            return
        with self._lock:
            self._output_buffer += chunk
            if len(self._output_buffer) > self._max_output_chars:
                overflow = len(self._output_buffer) - self._max_output_chars
                unread_prefix = max(0, overflow - self._read_offset)
                self._output_buffer = self._output_buffer[overflow:]
                self._read_offset = max(0, self._read_offset - overflow)
                self._dropped_output_chars += overflow
            else:
                unread_prefix = 0
            self.last_activity = time.time()
            should_report_truncation = self._dropped_output_chars > 0 and not self._output_truncation_reported
            retained_chars = len(self._output_buffer)
        if should_report_truncation:
            self._output_truncation_reported = True
            self.logger.warning(
                "Session %s output exceeded %d chars; truncating buffered output",
                self.alias,
                self._max_output_chars,
            )
            if self.trace_span is not None:
                self.trace_span.add_event(
                    "session.output.truncated",
                    {
                        "alias": self.alias,
                        "max_output_chars": self._max_output_chars,
                        "dropped_chars": self._dropped_output_chars,
                        "retained_chars": retained_chars,
                        "unread_dropped_chars": unread_prefix,
                    },
                )
        if not self._output_warning_emitted:
            self._output_warning_emitted = _report_suspicious_output(
                self.logger,
                self.trace_span,
                self.command,
                source="session",
                text=chunk,
            )

    def _finalize(self, *, status: str, error: Optional[str], returncode: Optional[int]) -> None:
        with self._lock:
            if self.finished_at is not None:
                return
            self.running = False
            self.finished_at = time_utils.iso_now()
            self._finished_monotonic = time.monotonic()
            self.returncode = returncode
            self.error = error
            self.last_activity = time.time()
            master_fd = self._master_fd
            self._master_fd = None
            read_stream = self._read_stream
            write_stream = self._write_stream
            self._read_stream = None
            self._write_stream = None
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        if read_stream is not None:
            try:
                read_stream.close()
            except Exception:
                self.logger.debug("Error closing session read stream", exc_info=True)
        if write_stream is not None and write_stream is not read_stream:
            try:
                write_stream.close()
            except Exception:
                self.logger.debug("Error closing session write stream", exc_info=True)
        if self.trace_span is not None and self._dropped_output_chars > 0:
            self.trace_span.set_attribute("session_output_truncated", True)
            self.trace_span.set_attribute("session_dropped_output_chars", self._dropped_output_chars)
            self.trace_span.set_attribute("session_retained_output_chars", len(self._output_buffer))
        self._done.set()
        _finish_command_trace_span(
            self.trace_span,
            status=status,
            error=error,
            attempts=1,
            returncode=returncode,
        )

    def _reader_loop(self) -> None:
        while True:
            with self._lock:
                master_fd = self._master_fd
                read_stream = self._read_stream
                process = self._process
            if process is None:
                break
            if master_fd is not None:
                read_fd = master_fd
            elif read_stream is not None:
                read_fd = read_stream.fileno()
            else:
                break
            try:
                ready, _, _ = select.select([read_fd], [], [], 0.2)
            except OSError:
                ready = []
            if ready:
                try:
                    data = os.read(read_fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        data = b""
                    else:
                        self._append_output(f"[session-error] {exc}\n")
                        break
                if data:
                    self._append_output(data.decode("utf-8", errors="replace"))
                    continue
            if process.poll() is not None:
                break

        returncode = None
        with self._lock:
            if self._process is not None:
                returncode = self._process.poll()
        if self._terminated_by_user:
            status = "terminated"
            error = "Session terminated by user"
        elif returncode in {None, 0}:
            status = "completed"
            error = None
        else:
            status = "failed"
            error = f"Command exited with {returncode}"
        self._finalize(status=status, error=error, returncode=returncode)

    def read_output(self, *, clear: bool = True) -> str:
        with self._lock:
            if clear:
                output = self._output_buffer[self._read_offset :]
                self._read_offset = len(self._output_buffer)
            else:
                output = self._output_buffer
        return output

    def send_input(self, data: str, *, append_newline: bool = True) -> None:
        payload = data if not append_newline else f"{data}\n"
        encoded = payload.encode("utf-8", errors="replace")
        with self._lock:
            master_fd = self._master_fd
            write_stream = self._write_stream
            running = self.running
        if not running or (master_fd is None and write_stream is None):
            raise CommandError(f"Session not running: {self.alias}")
        write_fd = master_fd if master_fd is not None else write_stream.fileno()
        try:
            total_written = 0
            while total_written < len(encoded):
                written = os.write(write_fd, encoded[total_written:])
                if written <= 0:
                    raise OSError("short PTY write")
                total_written += written
        except OSError as exc:
            raise CommandError(f"Failed to write to session {self.alias}: {exc}") from exc
        self.last_activity = time.time()
        if self.trace_span is not None:
            preview = _command_preview([data], redact=True)
            self.trace_span.add_event(
                "session.input",
                {"bytes": len(encoded), "input_preview": preview},
            )

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._done.wait(timeout=timeout)

    def terminate(self) -> None:
        with self._lock:
            process = self._process
            if process is None or self.finished_at is not None:
                return
            self._terminated_by_user = True
            self.running = False
        if self.trace_span is not None:
            self.trace_span.add_event("session.terminate", {"alias": self.alias})
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.terminate()
            except Exception:
                _MODULE_LOGGER.debug("Error closing session stream", exc_info=True)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    self.logger.debug("Failed to kill process %d", process.pid, exc_info=True)
        self.wait(timeout=1.0)

    def snapshot(self, *, clear_output: bool = False) -> CommandSessionInfo:
        output = self.read_output(clear=clear_output)
        with self._lock:
            return CommandSessionInfo(
                session_id=self.session_id,
                alias=self.alias,
                command=list(self.command),
                command_preview=self.command_preview,
                running=self.running,
                pid=self.pid,
                started_at=self.started_at,
                finished_at=self.finished_at,
                returncode=self.returncode,
                cwd=self.cwd,
                output=output,
                error=self.error,
                output_truncated=self._dropped_output_chars > 0,
                output_dropped_chars=self._dropped_output_chars,
                output_retained_chars=len(self._output_buffer),
                max_output_chars=self._max_output_chars,
            )


_SESSION_LOCK = threading.RLock()
_SESSION_COUNTER = 0
_SESSIONS: Dict[str, _CommandSession] = {}
_SESSION_ALIASES: Dict[str, str] = {}


def _next_session_alias() -> str:
    global _SESSION_COUNTER
    with _SESSION_LOCK:
        _SESSION_COUNTER += 1
        return f"S{_SESSION_COUNTER}"


def _register_session(session: _CommandSession) -> None:
    with _SESSION_LOCK:
        _SESSIONS[session.session_id] = session
        _SESSION_ALIASES[session.alias] = session.session_id
    _prune_finished_sessions()


def _resolve_session(session_identifier: str) -> _CommandSession:
    key = str(session_identifier).strip()
    with _SESSION_LOCK:
        session_id = _SESSION_ALIASES.get(key, key)
        session = _SESSIONS.get(session_id)
    if session is None:
        raise CommandError(f"Session not found: {session_identifier}")
    return session


def _remove_session_registry_entry(session: _CommandSession) -> None:
    with _SESSION_LOCK:
        _SESSIONS.pop(session.session_id, None)
        _SESSION_ALIASES.pop(session.alias, None)


def _finished_sort_key(session: _CommandSession) -> tuple[str, str, str]:
    finished_monotonic = session._finished_monotonic if session._finished_monotonic is not None else float("inf")
    started_at = session.started_at or ""
    return (f"{finished_monotonic:020.6f}", started_at, session.session_id)


def _finished_session_age_seconds(
    session: _CommandSession,
    *,
    now_monotonic: Optional[float] = None,
) -> Optional[float]:
    finished_monotonic = session._finished_monotonic
    if finished_monotonic is None:
        return None
    now_value = time.monotonic() if now_monotonic is None else float(now_monotonic)
    return max(0.0, now_value - finished_monotonic)


def _prune_finished_sessions(
    max_finished: Optional[int] = None,
    max_age_seconds: Optional[float] = None,
) -> int:
    limit = _session_finished_limit(max_finished)
    ttl_seconds = _session_finished_ttl(max_age_seconds)
    with _SESSION_LOCK:
        finished_sessions = [session for session in _SESSIONS.values() if not session.running]
        if not finished_sessions:
            return 0
        stale_sessions: List[_CommandSession] = []
        stale_ids: set[str] = set()
        if ttl_seconds is not None:
            now_monotonic = time.monotonic()
            for session in finished_sessions:
                age_seconds = _finished_session_age_seconds(session, now_monotonic=now_monotonic)
                if age_seconds is not None and age_seconds >= ttl_seconds:
                    stale_sessions.append(session)
                    stale_ids.add(session.session_id)
        retained_finished = [session for session in finished_sessions if session.session_id not in stale_ids]
        if len(retained_finished) > limit:
            retained_finished.sort(key=_finished_sort_key)
            prune_count = len(retained_finished) - limit
            for session in retained_finished[:prune_count]:
                if session.session_id in stale_ids:
                    continue
                stale_sessions.append(session)
                stale_ids.add(session.session_id)
        if not stale_sessions:
            return 0
        for session in stale_sessions:
            _SESSIONS.pop(session.session_id, None)
            _SESSION_ALIASES.pop(session.alias, None)
    return len(stale_sessions)


def _cleanup_executor_sessions(*, terminate_running: bool) -> Dict[str, int]:
    with _SESSION_LOCK:
        sessions = list(_SESSIONS.values())
    terminated = 0
    removed = 0
    for session in sessions:
        if session.running:
            if not terminate_running:
                continue
            try:
                session.terminate()
                terminated += 1
            except Exception:
                _MODULE_LOGGER.debug("Error closing session stream", exc_info=True)
        _remove_session_registry_entry(session)
        removed += 1
    return {
        "removed_sessions": removed,
        "terminated_running_sessions": terminated,
    }


def _cleanup_sessions_on_exit() -> None:
    _cleanup_executor_sessions(terminate_running=True)


atexit.register(_cleanup_sessions_on_exit)


class CommandCache:
    """تخزين مؤقت لنتائج الأوامر"""
    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_key(self, cmd: List[str], cwd: Optional[Path] = None, env: Optional[Mapping[str, str]] = None) -> str:
        parts = [str(c) for c in cmd]
        if cwd: parts.append(str(cwd))
        if env: parts.append(json.dumps(dict(env), sort_keys=True))
        return hashlib.sha256(" ".join(parts).encode()).hexdigest()

    def get(self, cmd: List[str], cwd: Optional[Path] = None, env: Optional[Mapping[str, str]] = None) -> Optional[subprocess.CompletedProcess]:
        key = self._get_key(cmd, cwd, env)
        path = self.cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=data["returncode"],
                stdout=data["stdout"],
                stderr=data["stderr"]
            )
        except Exception:
            return None

    def set(self, result: subprocess.CompletedProcess, cwd: Optional[Path] = None, env: Optional[Mapping[str, str]] = None) -> None:
        if result.returncode != 0:
            return
        key = self._get_key(list(result.args), cwd, env)
        path = self.cache_dir / f"{key}.json"
        data = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timestamp": time.time()
        }
        path.write_text(json.dumps(data), encoding="utf-8")

class CommandExecutor:
    def __init__(self, logger: Optional[logging.Logger] = None, cache: Optional[Any] = None):
        self.logger = logger or _MODULE_LOGGER
        self.cache = cache

    @staticmethod
    def resolve_tool(command: str) -> Optional[str]:
        if command == "httpx":
            if shutil.which("httpx-toolkit"):
                return shutil.which("httpx-toolkit")
            normal_path = shutil.which("httpx")
            if normal_path and _projectdiscovery_httpx_available(normal_path):
                return normal_path
            go_path = os.path.expanduser("~/go/bin/httpx")
            if os.path.isfile(go_path) and os.access(go_path, os.X_OK):
                if _projectdiscovery_httpx_available(go_path):
                    return go_path
            return None
        return shutil.which(command)

    @staticmethod
    def available(command: str) -> bool:
        return CommandExecutor.resolve_tool(command) is not None

    def run(
        self,
        command: Iterable[str],
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
        check: bool = True,
        capture_output: bool = False,
        redact: bool = True,
        context: Optional[object] = None,
    ) -> subprocess.CompletedProcess:
        cmd_list = [str(part) for part in command]
        _guard_command_or_raise(cmd_list, env)
        
        resolved_path = self.resolve_tool(cmd_list[0])
        if resolved_path:
            cmd_list[0] = resolved_path

        if self.cache:
            cached = self.cache.get(cmd_list, cwd, env)
            if cached:
                self.logger.info("Using cached result for: %s", _command_preview(cmd_list, redact=redact))
                return cached

        message = _command_preview(cmd_list, redact=redact)
        policy = _resolve_policy(cmd_list, timeout_override=timeout)
        
        breaker = circuit_registry.get_or_create(
            f"executor:{policy.tool_class}",
            CircuitBreakerConfig(
                failure_threshold=policy.circuit_failure_threshold,
                open_timeout=policy.circuit_open_timeout,
            ),
        )
        self.logger.info("Executing: %s", message)
        attempts = policy.retries + 1
        final_status = "failed"
        final_error: Optional[Exception | str] = None
        final_returncode: Optional[int] = None
        attempt_used = 0

        recorder = current_trace_recorder()
        parent_span_id = current_parent_span_id()
        trace_span: Optional[PipelineTraceSpan] = None

        async def _run() -> subprocess.CompletedProcess:
            if recorder:
                CURRENT_TRACE_SCOPE.set(PipelineTraceScope(recorder, parent_span_id))
            
            nonlocal final_status, final_error, final_returncode, attempt_used, trace_span
            trace_span = _start_command_trace_span(
                cmd_list, policy=policy, redact=redact, check=check,
                capture_output=capture_output, cwd=cwd, context=context, parent_span_id=parent_span_id
            )
            
            try:
                for attempt in range(1, attempts + 1):
                    attempt_used = attempt
                    if trace_span: trace_span.add_event("tool.attempt", {"attempt": attempt})
                    if not breaker.allow_request():
                        raise CommandError(f"Circuit open for {policy.tool_class}")
                    
                    try:
                        loop = asyncio.get_running_loop()
                        def _run_in_thread():
                            with bind_trace_scope(recorder, parent_span_id):
                                return subprocess.run(
                                    cmd_list, cwd=str(cwd) if cwd else None,
                                    env=dict(env) if env else None, timeout=policy.timeout,
                                    capture_output=capture_output, text=True, encoding="utf-8",
                                    errors="replace", check=check
                                )
                        completed = await loop.run_in_executor(None, _run_in_thread)
                        
                        if capture_output and "IGNORE PREVIOUS INSTRUCTIONS" in completed.stdout:
                            self.logger.warning("Potential prompt-injection content detected in output")
                            
                        final_returncode = completed.returncode
                        final_status = "completed" if completed.returncode == 0 else "failed"
                        if completed.returncode == 0:
                            breaker.record_success()
                            if self.cache: self.cache.set(completed, cwd, env)
                        else:
                            breaker.record_failure()
                        return completed
                    except subprocess.TimeoutExpired as exc:
                        breaker.record_failure()
                        if attempt >= attempts: raise CommandError(f"Timeout after {policy.timeout}s") from exc
                        time.sleep(policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1)))
                    except subprocess.CalledProcessError as exc:
                        breaker.record_failure()
                        if attempt >= attempts: raise CommandError(f"Command failed ({exc.returncode})", exc.returncode) from exc
                        time.sleep(policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1)))
            except Exception as e:
                final_error = str(e)
                raise

        try:
            try:
                loop = asyncio.get_running_loop()
                return asyncio.run_coroutine_threadsafe(_run(), loop).result()
            except RuntimeError:
                return asyncio.run(_run())
        finally:
            _finish_command_trace_span(trace_span, status=final_status, error=final_error, attempts=attempt_used, returncode=final_returncode)

    def run_to_file(
        self,
        command: Iterable[str],
        output_path: Path,
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        redact: bool = True,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        """
        تشغيل أمر وكتابة النتائج لملف.

        يُنفذ الأمر ويكتب stdout (و stderr) لملف محدد.
        مفيد للأوامر التي تُنتج كمية كبيرة من البيانات.

        Args:
            command: الأمر كقائمة
            output_path: مسار الملف للكتابة
            cwd: مجلد التنفيذ
            env: متغيرات البيئة
            redact: إخفاء البيانات الحساسة
            timeout: الحد الأقصى للتنفيذ

        Returns:
            subprocess.CompletedProcess مع النتيجة

        Example:
            >>> executor.run_to_file(
            ...     ["subfinder", "-d", "example.com", "-silent"],
            ...     Path("subdomains.txt"),
            ...     timeout=300
            ... )
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd_list = [str(part) for part in command]
        _guard_command_or_raise(cmd_list, env)
        message = _command_preview(cmd_list, redact=redact)
        policy = _resolve_policy(cmd_list, timeout_override=timeout)
        trace_span = _start_command_trace_span(
            cmd_list,
            policy=policy,
            redact=redact,
            check=False,
            capture_output=False,
            cwd=cwd,
            output_path=output_path,
        )
        breaker = circuit_registry.get_or_create(
            f"executor:{policy.tool_class}",
            CircuitBreakerConfig(
                failure_threshold=policy.circuit_failure_threshold,
                open_timeout=policy.circuit_open_timeout,
            ),
        )
        self.logger.info("Executing: %s", message)
        attempts = policy.retries + 1
        completed: subprocess.CompletedProcess | None = None
        final_status = "failed"
        final_error: Optional[Exception | str] = None
        final_returncode: Optional[int] = None
        attempt_used = 0
        try:
            for attempt in range(1, attempts + 1):
                attempt_used = attempt
                if trace_span is not None:
                    trace_span.add_event("tool.attempt", {"attempt": attempt, "max_attempts": attempts})
                if not breaker.allow_request():
                    final_error = f"Circuit open for tool class '{policy.tool_class}'"
                    raise CommandError(str(final_error))
                try:
                    with output_path.open("w", encoding="utf-8") as handle:
                        completed = subprocess.run(
                            cmd_list,
                            cwd=str(cwd) if cwd else None,
                            env=dict(env) if env else None,
                            stdout=handle,
                            stderr=subprocess.STDOUT,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=policy.timeout,
                        )
                    final_returncode = completed.returncode
                    final_status = "completed" if completed.returncode == 0 else "failed"
                    if completed.returncode == 0:
                        final_error = None
                        breaker.record_success()
                        break
                    final_error = f"Command exited with {completed.returncode}"
                    breaker.record_failure()
                    if attempt < attempts:
                        delay = policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1))
                        self.logger.warning(
                            "Retrying command after exit %s in %.1fs (%s/%s)",
                            completed.returncode,
                            delay,
                            attempt,
                            attempts,
                        )
                        time.sleep(delay)
                        continue
                    break
                except subprocess.TimeoutExpired as exc:
                    breaker.record_failure()
                    final_error = f"Command timeout after {policy.timeout}s"
                    self.logger.error("Command timed out after %ss: %s", policy.timeout, message)
                    if attempt < attempts:
                        delay = policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1))
                        self.logger.warning(
                            "Retrying command after timeout in %.1fs (%s/%s)",
                            delay,
                            attempt,
                            attempts,
                        )
                        time.sleep(delay)
                        continue
                    raise CommandError(str(final_error)) from exc
                except FileNotFoundError as exc:
                    breaker.record_failure()
                    missing = redact_text(cmd_list[0]) if redact else cmd_list[0]
                    self.logger.error("Command not found: %s", missing)
                    final_error = f"Command not found: {cmd_list[0]}"
                    raise CommandError(str(final_error)) from exc

            if completed is None:
                final_error = "Command execution failed unexpectedly"
                raise CommandError(str(final_error))

            if redact:
                tmp_path = output_path.with_suffix(f"{output_path.suffix}.redacted")
                with output_path.open("r", encoding="utf-8", errors="ignore") as src, tmp_path.open(
                    "w", encoding="utf-8"
                ) as dst:
                    for line in src:
                        redacted = redact_text(line) if line else line
                        dst.write(redacted or "")
                tmp_path.replace(output_path)

            _report_suspicious_output_in_file(self.logger, trace_span, cmd_list, output_path)

            completed.stdout = ""
            if completed.returncode != 0:
                self.logger.warning("Command exited with %s (non-zero)", completed.returncode)
            return completed
        finally:
            _finish_command_trace_span(
                trace_span,
                status=final_status,
                error=final_error,
                attempts=attempt_used,
                returncode=final_returncode,
            )

    async def run_async(
        self,
        command: Iterable[str],
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
        check: bool = True,
        capture_output: bool = False,
        redact: bool = True,
        context: Optional[object] = None,
    ) -> subprocess.CompletedProcess:
        cmd_list = [str(part) for part in command]
        _guard_command_or_raise(cmd_list, env)
        resolved = self.resolve_tool(cmd_list[0])
        if resolved: cmd_list[0] = resolved
        
        policy = _resolve_policy(cmd_list, timeout_override=timeout)
        # Simplified async run for now
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.run(cmd_list, cwd, env, timeout, check, capture_output, redact, context)
        )

    def start_session(
        self,
        command: Iterable[str],
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        redact: bool = True,
        max_output_chars: Optional[int] = None,
    ) -> CommandSessionInfo:
        cmd_list = [str(part) for part in command]
        _guard_command_or_raise(cmd_list, env)
        message = _command_preview(cmd_list, redact=redact)
        policy = _resolve_policy(cmd_list)
        trace_span = _start_command_trace_span(
            cmd_list,
            policy=policy,
            redact=redact,
            check=False,
            capture_output=False,
            cwd=cwd,
        )
        alias = _next_session_alias()
        session = _CommandSession(
            cmd_list,
            alias=alias,
            cwd=cwd,
            env=env,
            redact=redact,
            logger=self.logger,
            trace_span=trace_span,
            max_output_chars=max_output_chars,
        )
        try:
            session.start()
        except Exception as exc:
            _finish_command_trace_span(
                trace_span,
                status="failed",
                error=exc,
                attempts=1,
                returncode=None,
            )
            raise CommandError(f"Failed to start session: {exc}") from exc
        _register_session(session)
        self.logger.info("Started session %s for %s", session.alias, message)
        return session.snapshot(clear_output=False)

    def read_session(self, session_identifier: str, *, clear_output: bool = True) -> CommandSessionInfo:
        session = _resolve_session(session_identifier)
        if not session.running:
            _prune_finished_sessions()
        return session.snapshot(clear_output=clear_output)

    def read_new_session(self, session_identifier: str) -> CommandSessionInfo:
        return self.read_session(session_identifier, clear_output=True)

    def wait_session(
        self,
        session_identifier: str,
        *,
        timeout: Optional[float] = None,
        clear_output: bool = True,
    ) -> CommandSessionInfo:
        session = _resolve_session(session_identifier)
        session.wait(timeout=timeout)
        if not session.running:
            _prune_finished_sessions()
        return session.snapshot(clear_output=clear_output)

    def send_session_input(
        self,
        session_identifier: str,
        data: str,
        *,
        append_newline: bool = True,
        clear_output: bool = True,
    ) -> CommandSessionInfo:
        session = _resolve_session(session_identifier)
        session.send_input(data, append_newline=append_newline)
        time.sleep(0.05)
        return session.snapshot(clear_output=clear_output)

    def terminate_session(
        self,
        session_identifier: str,
        *,
        clear_output: bool = True,
    ) -> CommandSessionInfo:
        session = _resolve_session(session_identifier)
        session.terminate()
        if not session.running:
            _prune_finished_sessions()
        return session.snapshot(clear_output=clear_output)

    def list_sessions(
        self,
        *,
        include_finished: bool = True,
        clear_output: bool = False,
    ) -> List[CommandSessionInfo]:
        _prune_finished_sessions()
        with _SESSION_LOCK:
            sessions = list(_SESSIONS.values())
        snapshots = [session.snapshot(clear_output=clear_output) for session in sessions]
        if include_finished:
            return snapshots
        return [item for item in snapshots if item.running]

    def cleanup_sessions(
        self,
        *,
        terminate_running: bool = False,
        max_finished: Optional[int] = 0,
        finished_ttl_seconds: Optional[float] = 0,
    ) -> Dict[str, int]:
        cleaned = {
            "terminated_running_sessions": 0,
            "pruned_finished_sessions": 0,
        }
        if terminate_running:
            with _SESSION_LOCK:
                running_sessions = [session for session in _SESSIONS.values() if session.running]
            for session in running_sessions:
                try:
                    session.terminate()
                    cleaned["terminated_running_sessions"] += 1
                except Exception:
                    continue
        cleaned["pruned_finished_sessions"] = _prune_finished_sessions(
            max_finished=max_finished,
            max_age_seconds=finished_ttl_seconds,
        )
        with _SESSION_LOCK:
            cleaned["remaining_sessions"] = len(_SESSIONS)
        return cleaned
