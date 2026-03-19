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

@dataclass
class CommandSessionInfo:
    alias: str
    command: List[str]
    status: str
    started_at: str
    finished_at: Optional[str] = None
    returncode: Optional[int] = None
    output_tail: str = ""
    pid: Optional[int] = None

def _guard_command_or_raise(cmd_list: List[str], env: Optional[Mapping[str, str]] = None) -> None:
    if not cmd_list:
        return
    
    executable = Path(cmd_list[0]).name.lower()
    joined = " ".join(cmd_list).lower()
    
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
        policy = ToolExecutionPolicy(tool_class="scanner", timeout=3600)
    elif "ffuf" in name or "feroxbuster" in name:
        policy = ToolExecutionPolicy(tool_class="fuzzer", timeout=7200)
    
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
            from recon_cli.utils.pipeline_trace import PipelineTraceScope, CURRENT_TRACE_SCOPE
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
        cmd_list = [str(part) for part in command]
        _guard_command_or_raise(cmd_list, env)
        resolved = self.resolve_tool(cmd_list[0])
        if resolved: cmd_list[0] = resolved
        
        policy = _resolve_policy(cmd_list, timeout_override=timeout)
        message = _command_preview(cmd_list, redact=redact)
        self.logger.info("Executing (to file): %s", message)
        
        with output_path.open("w", encoding="utf-8") as handle:
            return subprocess.run(
                cmd_list, cwd=str(cwd) if cwd else None,
                env=dict(env) if env else None, timeout=policy.timeout,
                stdout=handle, stderr=subprocess.STDOUT, check=False
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
