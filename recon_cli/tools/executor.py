from __future__ import annotations

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

import shlex
import shutil
import subprocess
import time
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional

from recon_cli.utils.circuit_breaker import CircuitBreakerConfig, registry as circuit_registry
from recon_cli.utils.pipeline_trace import PipelineTraceSpan, current_parent_span_id, current_trace_recorder
from recon_cli.utils.sanitizer import redact as redact_text


class CommandError(RuntimeError):
    """
    استثناء لأخطاء تنفيذ الأوامر.
    
    Attributes:
        message: رسالة الخطأ
        returncode: كود الخروج من الأمر (None إذا لم يبدأ)
    
    Example:
        >>> try:
        ...     executor.run(["nonexistent-tool"])
        ... except CommandError as e:
        ...     print(f"Failed with code {e.returncode}: {e}")
    """
    
    def __init__(self, message: str, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


_SHELL_LAUNCHERS = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "pwsh",
}

_INLINE_SHELL_FLAGS = {
    "-c",
    "-lc",
    "-cl",
    "/c",
    "-command",
    "/command",
    "-encodedcommand",
    "/encodedcommand",
}

_HOMOGRAPH_MAP = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0410": "A",  # Cyrillic А
    "\u0415": "E",  # Cyrillic Е
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0421": "C",  # Cyrillic С
    "\u0425": "X",  # Cyrillic Х
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
    "\u03c5": "u",  # Greek υ
    "\u03c7": "x",  # Greek χ
    "\u0391": "A",  # Greek Α
    "\u039f": "O",  # Greek Ο
    "\u03a1": "P",  # Greek Ρ
    "\u2010": "-",  # Hyphen
    "\u2011": "-",  # Non-breaking hyphen
    "\u2212": "-",  # Minus sign
    "\uff0d": "-",  # Fullwidth hyphen-minus
}

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
)


def _guardrails_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    source = env if env is not None else os.environ
    value = str(source.get("RECON_EXECUTOR_GUARDRAILS", "true")).strip().lower()
    return value not in {"0", "false", "no", "off"}


def _normalize_guardrail_text(value: str) -> str:
    normalized = str(value)
    for homograph, replacement in _HOMOGRAPH_MAP.items():
        normalized = normalized.replace(homograph, replacement)
    return unicodedata.normalize("NFKD", normalized)


def _guard_command_or_raise(
    command: Iterable[str],
    env: Optional[Mapping[str, str]] = None,
) -> None:
    cmd_list = [str(part) for part in command]
    if not cmd_list or not _guardrails_enabled(env):
        return

    normalized = [_normalize_guardrail_text(part) for part in cmd_list]
    executable = Path(normalized[0]).name.lower()
    joined = " ".join(normalized[1:]).lower()

    # Block shell-launcher trampoline patterns; the executor is intended to run
    # concrete tool binaries, not arbitrary shell payloads.
    if executable in _SHELL_LAUNCHERS:
        if any(str(part).lower() in _INLINE_SHELL_FLAGS for part in normalized[1:]):
            raise CommandError(
                f"Blocked shell launcher invocation via {Path(cmd_list[0]).name}: "
                "inline shell commands are not allowed"
            )

    if executable in {"curl", "wget"}:
        if normalized[0] != cmd_list[0]:
            raise CommandError(
                f"Blocked suspicious Unicode-homograph executable name for {Path(normalized[0]).name}"
            )
        if any(token in joined for token in ("$(env)", "`env`", "$(", "`", "${")):
            raise CommandError(
                f"Blocked {executable} command containing shell-style expansion payload"
            )
        if any(marker in joined for marker in _SENSITIVE_FILE_MARKERS) and any(
            part.startswith("@") or part in {"-d", "--data", "--data-binary", "--upload-file", "-t", "-T"}
            for part in normalized[1:]
        ):
            raise CommandError(
                f"Blocked {executable} command referencing a sensitive local file payload"
            )


@dataclass(frozen=True)
class ToolExecutionPolicy:
    tool_class: str
    timeout: int
    retries: int
    backoff_seconds: float
    backoff_multiplier: float
    circuit_failure_threshold: int
    circuit_open_timeout: float


_DEFAULT_POLICY = ToolExecutionPolicy(
    tool_class="default",
    timeout=120,
    retries=0,
    backoff_seconds=1.0,
    backoff_multiplier=2.0,
    circuit_failure_threshold=5,
    circuit_open_timeout=30.0,
)

_TOOL_CLASS_POLICIES: Dict[str, ToolExecutionPolicy] = {
    "dns": ToolExecutionPolicy("dns", timeout=90, retries=1, backoff_seconds=1.0, backoff_multiplier=1.8, circuit_failure_threshold=4, circuit_open_timeout=30.0),
    "http": ToolExecutionPolicy("http", timeout=150, retries=1, backoff_seconds=1.0, backoff_multiplier=2.0, circuit_failure_threshold=5, circuit_open_timeout=45.0),
    "vuln": ToolExecutionPolicy("vuln", timeout=300, retries=0, backoff_seconds=2.0, backoff_multiplier=2.0, circuit_failure_threshold=3, circuit_open_timeout=120.0),
    "fuzz": ToolExecutionPolicy("fuzz", timeout=420, retries=0, backoff_seconds=2.0, backoff_multiplier=2.0, circuit_failure_threshold=2, circuit_open_timeout=120.0),
    "browser": ToolExecutionPolicy("browser", timeout=240, retries=0, backoff_seconds=2.0, backoff_multiplier=2.0, circuit_failure_threshold=2, circuit_open_timeout=90.0),
}

_TOOL_CLASS_MAP: Dict[str, str] = {
    "subfinder": "dns",
    "assetfinder": "dns",
    "dnsx": "dns",
    "puredns": "dns",
    "massdns": "dns",
    "amass": "dns",
    "dig": "dns",
    "httpx": "http",
    "curl": "http",
    "wget": "http",
    "nuclei": "vuln",
    "sqlmap": "vuln",
    "dalfox": "vuln",
    "wpscan": "vuln",
    "nikto": "vuln",
    "ffuf": "fuzz",
    "gobuster": "fuzz",
    "dirsearch": "fuzz",
    "playwright": "browser",
    "chromium": "browser",
    "google-chrome": "browser",
}


def _projectdiscovery_httpx_available(command_path: str) -> bool:
    try:
        completed = subprocess.run(
            [command_path, "-h"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return False
    output = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0:
        return False
    required_flags = ("-tech-detect", "-status-code", "-follow-redirects")
    return all(flag in output for flag in required_flags)


def _tool_class_for_command(command_name: str) -> str:
    return _TOOL_CLASS_MAP.get(command_name.lower(), "default")


def _resolve_policy(command: Iterable[str], timeout_override: Optional[int] = None) -> ToolExecutionPolicy:
    cmd_list = [str(part) for part in command]
    command_name = Path(cmd_list[0]).name if cmd_list else ""
    tool_class = _tool_class_for_command(command_name)
    base_policy = _TOOL_CLASS_POLICIES.get(tool_class, _DEFAULT_POLICY)
    if timeout_override is None:
        return base_policy
    return ToolExecutionPolicy(
        tool_class=base_policy.tool_class,
        timeout=max(1, int(timeout_override)),
        retries=base_policy.retries,
        backoff_seconds=base_policy.backoff_seconds,
        backoff_multiplier=base_policy.backoff_multiplier,
        circuit_failure_threshold=base_policy.circuit_failure_threshold,
        circuit_open_timeout=base_policy.circuit_open_timeout,
    )


def _command_preview(command: Iterable[str], *, redact: bool) -> str:
    command_str = " ".join(shlex.quote(str(part)) for part in command)
    preview = redact_text(command_str) if redact else command_str
    preview = preview or ""
    if len(preview) > 240:
        preview = preview[:240] + " [truncated]"
    return preview


def _start_command_trace_span(
    command: Iterable[str],
    *,
    policy: ToolExecutionPolicy,
    redact: bool,
    check: bool,
    capture_output: bool,
    cwd: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> Optional[PipelineTraceSpan]:
    recorder = current_trace_recorder()
    if recorder is None:
        return None
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
    if cwd is not None:
        attributes["cwd"] = str(cwd)
    if output_path is not None:
        attributes["output_path"] = str(output_path)
    return recorder.start_span(
        f"tool:{tool_name}",
        span_type="tool_exec",
        parent_span_id=current_parent_span_id(),
        attributes=attributes,
    )


def _finish_command_trace_span(
    span: Optional[PipelineTraceSpan],
    *,
    status: str,
    error: Optional[Exception | str],
    attempts: int,
    returncode: Optional[int] = None,
) -> None:
    if span is None:
        return
    attributes: Dict[str, object] = {"attempts": attempts}
    if returncode is not None:
        attributes["returncode"] = int(returncode)
        if returncode != 0:
            span.add_event("tool.nonzero_exit", {"returncode": int(returncode)})
    span.finish(status=status, error=error, attributes=attributes)


class CommandExecutor:
    """
    منفذ الأوامر الخارجية مع دعم كامل للـ logging والـ error handling.
    
    يوفر واجهة موحدة لتشغيل أي أداة خارجية مع:
    - تسجيل الأوامر في الـ log
    - إخفاء البيانات الحساسة (API keys, tokens)
    - التعامل مع Timeout
    - كتابة النتائج لملفات
    
    Attributes:
        logger: كائن الـ logger للتسجيل
    
    Example:
        >>> import logging
        >>> logger = logging.getLogger("recon")
        >>> executor = CommandExecutor(logger)
        >>> 
        >>> # تشغيل أمر بسيط
        >>> result = executor.run(["echo", "hello"])
        >>> 
        >>> # تشغيل مع timeout
        >>> result = executor.run(["nuclei", "-u", "target.com"], timeout=300)
        >>> 
        >>> # كتابة النتائج لملف
        >>> executor.run_to_file(["subfinder", "-d", "target.com"], Path("subs.txt"))
    """
    
    def __init__(self, logger) -> None:
        """
        تهيئة المنفذ.
        
        Args:
            logger: كائن logging.Logger للتسجيل
        """
        self.logger = logger

    @staticmethod
    def available(command: str) -> bool:
        """
        التحقق من وجود أداة في النظام.
        
        Args:
            command: اسم الأداة (مثل "subfinder", "nuclei")
            
        Returns:
            True إذا كانت الأداة متاحة، False خلاف ذلك
            
        Example:
            >>> if CommandExecutor.available("subfinder"):
            ...     print("Subfinder is installed")
        """
        command_path = shutil.which(command)
        if command_path is None:
            return False
        if command == "httpx":
            return _projectdiscovery_httpx_available(command_path)
        return True

    def run(
        self,
        command: Iterable[str],
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
        check: bool = True,
        capture_output: bool = False,
        redact: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        تشغيل أمر خارجي.
        
        Args:
            command: الأمر كقائمة من السلاسل النصية
            cwd: المجلد الذي سيُنفذ فيه الأمر
            env: متغيرات البيئة الإضافية
            timeout: الحد الأقصى للتنفيذ بالثواني
            check: رفع استثناء عند الفشل
            capture_output: التقاط stdout و stderr
            redact: إخفاء البيانات الحساسة في الـ logs
            
        Returns:
            subprocess.CompletedProcess مع نتيجة التنفيذ
            
        Raises:
            CommandError: عند فشل الأمر أو انتهاء الوقت
            
        Example:
            >>> result = executor.run(
            ...     ["httpx", "-l", "urls.txt", "-sc"],
            ...     timeout=120,
            ...     capture_output=True
            ... )
            >>> print(result.stdout)
        """
        cmd_list = [str(part) for part in command]
        _guard_command_or_raise(cmd_list, env)
        message = _command_preview(cmd_list, redact=redact)
        policy = _resolve_policy(cmd_list, timeout_override=timeout)
        trace_span = _start_command_trace_span(
            cmd_list,
            policy=policy,
            redact=redact,
            check=check,
            capture_output=capture_output,
            cwd=cwd,
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
                    completed = subprocess.run(
                        cmd_list,
                        cwd=str(cwd) if cwd else None,
                        env=dict(env) if env else None,
                        timeout=policy.timeout,
                        capture_output=capture_output,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        check=check,
                    )
                    final_returncode = completed.returncode
                    final_status = "completed" if completed.returncode == 0 else "failed"
                    if completed.returncode == 0:
                        final_error = None
                        breaker.record_success()
                    else:
                        final_error = f"Command exited with {completed.returncode}"
                        breaker.record_failure()
                    return completed
                except subprocess.TimeoutExpired as exc:
                    breaker.record_failure()
                    final_error = f"Command timeout after {policy.timeout}s"
                    self.logger.error("Command timed out after %ss: %s", policy.timeout, message)
                    if attempt < attempts:
                        delay = policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1))
                        self.logger.warning("Retrying command after timeout in %.1fs (%s/%s)", delay, attempt, attempts)
                        time.sleep(delay)
                        continue
                    raise CommandError(str(final_error)) from exc
                except FileNotFoundError as exc:
                    breaker.record_failure()
                    missing = redact_text(cmd_list[0]) if redact else cmd_list[0]
                    self.logger.error("Command not found: %s", missing)
                    final_error = f"Command not found: {cmd_list[0]}"
                    raise CommandError(str(final_error)) from exc
                except subprocess.CalledProcessError as exc:
                    breaker.record_failure()
                    final_returncode = exc.returncode
                    final_error = f"Command failed ({exc.returncode})"
                    if capture_output:
                        stderr_text = exc.stderr or ""
                        if redact:
                            stderr_text = redact_text(stderr_text) or ""
                        self.logger.error("Command failed (%s): %s", exc.returncode, stderr_text)
                    else:
                        self.logger.error("Command failed (%s)", exc.returncode)
                    if check and attempt < attempts:
                        delay = policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1))
                        self.logger.warning("Retrying command after failure in %.1fs (%s/%s)", delay, attempt, attempts)
                        time.sleep(delay)
                        continue
                    if check:
                        raise CommandError(str(final_error), exc.returncode) from exc
                    return exc
            final_error = "Command execution failed unexpectedly"
            raise CommandError(str(final_error))
        finally:
            _finish_command_trace_span(
                trace_span,
                status=final_status,
                error=final_error,
                attempts=attempt_used,
                returncode=final_returncode,
            )

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
                        self.logger.warning("Retrying command after exit %s in %.1fs (%s/%s)", completed.returncode, delay, attempt, attempts)
                        time.sleep(delay)
                        continue
                    break
                except subprocess.TimeoutExpired as exc:
                    breaker.record_failure()
                    final_error = f"Command timeout after {policy.timeout}s"
                    self.logger.error("Command timed out after %ss: %s", policy.timeout, message)
                    if attempt < attempts:
                        delay = policy.backoff_seconds * (policy.backoff_multiplier ** (attempt - 1))
                        self.logger.warning("Retrying command after timeout in %.1fs (%s/%s)", delay, attempt, attempts)
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
