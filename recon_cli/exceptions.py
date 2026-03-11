"""
Custom Exceptions - استثناءات مخصصة

هرمية استثناءات شاملة للتعامل مع الأخطاء بشكل منظم.

Hierarchy:
    ReconError (base)
    ├── ConfigError
    │   ├── ConfigNotFoundError
    │   ├── ConfigValidationError
    │   └── ConfigMigrationError
    ├── JobError
    │   ├── JobNotFoundError
    │   ├── JobAlreadyExistsError
    │   ├── JobValidationError
    │   └── JobStateError
    ├── PipelineError
    │   ├── StageError
    │   ├── StageTimeoutError
    │   ├── StageDependencyError
    │   └── PipelineAbortedError
    ├── ToolError
    │   ├── ToolNotFoundError
    │   ├── ToolExecutionError
    │   └── ToolTimeoutError
    ├── NetworkError
    │   ├── ConnectionError
    │   ├── TimeoutError
    │   ├── SSLError
    │   └── DNSError
    ├── DatabaseError
    │   ├── ConnectionError
    │   ├── QueryError
    │   └── IntegrityError
    ├── ScanError
    │   ├── TargetError
    │   ├── ScanTimeoutError
    │   └── ScanAbortedError
    └── PluginError
        ├── PluginLoadError
        ├── PluginValidationError
        └── PluginExecutionError

Example:
    >>> try:
    ...     run_stage("nuclei")
    ... except StageTimeoutError as e:
    ...     logger.error(f"Stage {e.stage_name} timed out after {e.timeout}s")
    ... except StageError as e:
    ...     logger.error(f"Stage failed: {e}")
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════
#                     Base Exception
# ═══════════════════════════════════════════════════════════

class ReconError(Exception):
    """
    الاستثناء الأساسي لجميع أخطاء ReconnV2.
    
    Attributes:
        message: رسالة الخطأ
        code: رمز الخطأ (للـ API)
        details: تفاصيل إضافية
        recoverable: هل يمكن التعافي
    """
    
    code: str = "RECON_ERROR"
    http_status: int = 500
    recoverable: bool = False
    
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        self.message = message
        if code:
            self.code = code
        self.details = details or {}
        self.cause = cause
        
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل لـ dictionary للـ API"""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
            "recoverable": self.recoverable,
        }
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message} ({self.details})"
        return self.message


# ═══════════════════════════════════════════════════════════
#                     Config Errors
# ═══════════════════════════════════════════════════════════

class ConfigError(ReconError):
    """خطأ في الإعدادات"""
    code = "CONFIG_ERROR"
    http_status = 400


class ConfigNotFoundError(ConfigError):
    """ملف الإعدادات غير موجود"""
    code = "CONFIG_NOT_FOUND"
    
    def __init__(self, path: str):
        super().__init__(
            f"Configuration file not found: {path}",
            details={"path": path},
        )


class ConfigValidationError(ConfigError):
    """خطأ في التحقق من الإعدادات"""
    code = "CONFIG_VALIDATION_ERROR"
    
    def __init__(self, errors: List[str], path: Optional[str] = None):
        super().__init__(
            f"Configuration validation failed: {len(errors)} error(s)",
            details={"errors": errors, "path": path},
        )
        self.errors = errors


class ConfigMigrationError(ConfigError):
    """خطأ في ترحيل الإعدادات"""
    code = "CONFIG_MIGRATION_ERROR"
    
    def __init__(self, from_version: str, to_version: str, reason: str):
        super().__init__(
            f"Failed to migrate config from {from_version} to {to_version}: {reason}",
            details={
                "from_version": from_version,
                "to_version": to_version,
                "reason": reason,
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Job Errors
# ═══════════════════════════════════════════════════════════

class JobError(ReconError):
    """خطأ في الـ Job"""
    code = "JOB_ERROR"


class JobNotFoundError(JobError):
    """الـ Job غير موجود"""
    code = "JOB_NOT_FOUND"
    http_status = 404
    
    def __init__(self, job_id: str):
        super().__init__(
            f"Job not found: {job_id}",
            details={"job_id": job_id},
        )


class JobAlreadyExistsError(JobError):
    """الـ Job موجود مسبقاً"""
    code = "JOB_EXISTS"
    http_status = 409
    
    def __init__(self, job_id: str):
        super().__init__(
            f"Job already exists: {job_id}",
            details={"job_id": job_id},
        )


class JobValidationError(JobError):
    """خطأ في التحقق من الـ Job"""
    code = "JOB_VALIDATION_ERROR"
    http_status = 400
    
    def __init__(self, errors: List[str], job_id: Optional[str] = None):
        super().__init__(
            f"Job validation failed: {len(errors)} error(s)",
            details={"errors": errors, "job_id": job_id},
        )
        self.errors = errors


class JobStateError(JobError):
    """خطأ في حالة الـ Job"""
    code = "JOB_STATE_ERROR"
    http_status = 409
    
    def __init__(self, job_id: str, current_state: str, expected_state: str):
        super().__init__(
            f"Job {job_id} is in state '{current_state}', expected '{expected_state}'",
            details={
                "job_id": job_id,
                "current_state": current_state,
                "expected_state": expected_state,
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Pipeline Errors
# ═══════════════════════════════════════════════════════════

class PipelineError(ReconError):
    """خطأ في الـ Pipeline"""
    code = "PIPELINE_ERROR"


class StageError(PipelineError):
    """خطأ في مرحلة"""
    code = "STAGE_ERROR"
    recoverable = True
    
    def __init__(
        self,
        stage_name: str,
        message: str,
        target: Optional[str] = None,
        attempt: int = 1,
    ):
        super().__init__(
            f"Stage '{stage_name}' failed: {message}",
            details={
                "stage": stage_name,
                "target": target,
                "attempt": attempt,
            },
        )
        self.stage_name = stage_name
        self.target = target
        self.attempt = attempt


class StageTimeoutError(StageError):
    """انتهاء مهلة المرحلة"""
    code = "STAGE_TIMEOUT"
    
    def __init__(
        self,
        stage_name: str,
        timeout: float,
        target: Optional[str] = None,
    ):
        super().__init__(
            stage_name,
            f"Timed out after {timeout}s",
            target=target,
        )
        self.timeout = timeout
        self.details["timeout"] = timeout


class StageDependencyError(PipelineError):
    """خطأ في تبعيات المرحلة"""
    code = "STAGE_DEPENDENCY_ERROR"
    
    def __init__(self, stage_name: str, missing_deps: List[str]):
        super().__init__(
            f"Stage '{stage_name}' has unmet dependencies: {missing_deps}",
            details={
                "stage": stage_name,
                "missing_dependencies": missing_deps,
            },
        )


class PipelineAbortedError(PipelineError):
    """تم إلغاء الـ Pipeline"""
    code = "PIPELINE_ABORTED"
    
    def __init__(self, reason: str, completed_stages: List[str] = None):
        super().__init__(
            f"Pipeline aborted: {reason}",
            details={
                "reason": reason,
                "completed_stages": completed_stages or [],
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Tool Errors
# ═══════════════════════════════════════════════════════════

class ToolError(ReconError):
    """خطأ في أداة خارجية"""
    code = "TOOL_ERROR"


class ToolNotFoundError(ToolError):
    """الأداة غير موجودة"""
    code = "TOOL_NOT_FOUND"
    
    def __init__(self, tool_name: str, searched_paths: List[str] = None):
        super().__init__(
            f"Tool not found: {tool_name}",
            details={
                "tool": tool_name,
                "searched_paths": searched_paths or [],
            },
        )
        self.tool_name = tool_name


class ToolExecutionError(ToolError):
    """خطأ في تنفيذ الأداة"""
    code = "TOOL_EXECUTION_ERROR"
    recoverable = True
    
    def __init__(
        self,
        tool_name: str,
        exit_code: int,
        stderr: str = "",
        command: str = "",
    ):
        super().__init__(
            f"Tool '{tool_name}' failed with exit code {exit_code}",
            details={
                "tool": tool_name,
                "exit_code": exit_code,
                "stderr": stderr[:500],  # Truncate
                "command": command,
            },
        )
        self.tool_name = tool_name
        self.exit_code = exit_code
        self.stderr = stderr


class ToolTimeoutError(ToolError):
    """انتهاء مهلة الأداة"""
    code = "TOOL_TIMEOUT"
    recoverable = True
    
    def __init__(self, tool_name: str, timeout: float, command: str = ""):
        super().__init__(
            f"Tool '{tool_name}' timed out after {timeout}s",
            details={
                "tool": tool_name,
                "timeout": timeout,
                "command": command,
            },
        )
        self.tool_name = tool_name
        self.timeout = timeout


# ═══════════════════════════════════════════════════════════
#                     Network Errors
# ═══════════════════════════════════════════════════════════

class NetworkError(ReconError):
    """خطأ في الشبكة"""
    code = "NETWORK_ERROR"
    recoverable = True


class ConnectionError(NetworkError):
    """خطأ في الاتصال"""
    code = "CONNECTION_ERROR"
    
    def __init__(self, host: str, port: int = 0, reason: str = ""):
        super().__init__(
            f"Connection failed to {host}:{port}" if port else f"Connection failed to {host}",
            details={
                "host": host,
                "port": port,
                "reason": reason,
            },
        )


class TimeoutError(NetworkError):
    """انتهاء مهلة الاتصال"""
    code = "TIMEOUT_ERROR"
    
    def __init__(self, url: str, timeout: float):
        super().__init__(
            f"Request to {url} timed out after {timeout}s",
            details={
                "url": url,
                "timeout": timeout,
            },
        )


class SSLError(NetworkError):
    """خطأ SSL"""
    code = "SSL_ERROR"
    
    def __init__(self, host: str, reason: str):
        super().__init__(
            f"SSL error for {host}: {reason}",
            details={
                "host": host,
                "reason": reason,
            },
        )


class DNSError(NetworkError):
    """خطأ DNS"""
    code = "DNS_ERROR"
    
    def __init__(self, domain: str, reason: str = ""):
        super().__init__(
            f"DNS resolution failed for {domain}",
            details={
                "domain": domain,
                "reason": reason,
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Database Errors
# ═══════════════════════════════════════════════════════════

class DatabaseError(ReconError):
    """خطأ في قاعدة البيانات"""
    code = "DATABASE_ERROR"


class DatabaseConnectionError(DatabaseError):
    """خطأ في الاتصال بقاعدة البيانات"""
    code = "DB_CONNECTION_ERROR"
    
    def __init__(self, path: str, reason: str = ""):
        super().__init__(
            f"Failed to connect to database: {path}",
            details={
                "path": path,
                "reason": reason,
            },
        )


class QueryError(DatabaseError):
    """خطأ في الاستعلام"""
    code = "QUERY_ERROR"
    
    def __init__(self, query: str, reason: str):
        super().__init__(
            f"Query failed: {reason}",
            details={
                "query": query[:200],  # Truncate
                "reason": reason,
            },
        )


class IntegrityError(DatabaseError):
    """خطأ في سلامة البيانات"""
    code = "INTEGRITY_ERROR"
    
    def __init__(self, table: str, reason: str):
        super().__init__(
            f"Integrity error in table '{table}': {reason}",
            details={
                "table": table,
                "reason": reason,
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Scan Errors
# ═══════════════════════════════════════════════════════════

class ScanError(ReconError):
    """خطأ في الفحص"""
    code = "SCAN_ERROR"


class TargetError(ScanError):
    """خطأ في الهدف"""
    code = "TARGET_ERROR"
    http_status = 400
    
    def __init__(self, target: str, reason: str):
        super().__init__(
            f"Invalid target '{target}': {reason}",
            details={
                "target": target,
                "reason": reason,
            },
        )


class ScanTimeoutError(ScanError):
    """انتهاء مهلة الفحص"""
    code = "SCAN_TIMEOUT"
    recoverable = True
    
    def __init__(self, target: str, timeout: float):
        super().__init__(
            f"Scan of {target} timed out after {timeout}s",
            details={
                "target": target,
                "timeout": timeout,
            },
        )


class ScanAbortedError(ScanError):
    """تم إلغاء الفحص"""
    code = "SCAN_ABORTED"
    
    def __init__(self, target: str, reason: str, partial_results: int = 0):
        super().__init__(
            f"Scan of {target} aborted: {reason}",
            details={
                "target": target,
                "reason": reason,
                "partial_results": partial_results,
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Plugin Errors
# ═══════════════════════════════════════════════════════════

class PluginError(ReconError):
    """خطأ في الـ Plugin"""
    code = "PLUGIN_ERROR"


class PluginLoadError(PluginError):
    """خطأ في تحميل الـ Plugin"""
    code = "PLUGIN_LOAD_ERROR"
    
    def __init__(self, plugin_name: str, reason: str):
        super().__init__(
            f"Failed to load plugin '{plugin_name}': {reason}",
            details={
                "plugin": plugin_name,
                "reason": reason,
            },
        )


class PluginValidationError(PluginError):
    """خطأ في التحقق من الـ Plugin"""
    code = "PLUGIN_VALIDATION_ERROR"
    http_status = 400
    
    def __init__(self, plugin_name: str, errors: List[str]):
        super().__init__(
            f"Plugin '{plugin_name}' validation failed",
            details={
                "plugin": plugin_name,
                "errors": errors,
            },
        )


class PluginExecutionError(PluginError):
    """خطأ في تنفيذ الـ Plugin"""
    code = "PLUGIN_EXECUTION_ERROR"
    recoverable = True
    
    def __init__(self, plugin_name: str, method: str, reason: str):
        super().__init__(
            f"Plugin '{plugin_name}.{method}()' failed: {reason}",
            details={
                "plugin": plugin_name,
                "method": method,
                "reason": reason,
            },
        )


# ═══════════════════════════════════════════════════════════
#                     Rate Limit Errors
# ═══════════════════════════════════════════════════════════

class RateLimitError(ReconError):
    """خطأ في الحد الأقصى"""
    code = "RATE_LIMIT_ERROR"
    http_status = 429
    recoverable = True
    
    def __init__(self, limit: int, window: str, retry_after: int = 0):
        super().__init__(
            f"Rate limit exceeded: {limit} requests per {window}",
            details={
                "limit": limit,
                "window": window,
                "retry_after": retry_after,
            },
        )
        self.retry_after = retry_after


# ═══════════════════════════════════════════════════════════
#                     Helper Functions
# ═══════════════════════════════════════════════════════════

def is_recoverable(error: Exception) -> bool:
    """هل يمكن التعافي من الخطأ"""
    if isinstance(error, ReconError):
        return error.recoverable
    return False


def get_error_code(error: Exception) -> str:
    """الحصول على رمز الخطأ"""
    if isinstance(error, ReconError):
        return error.code
    return "UNKNOWN_ERROR"


def wrap_exception(error: Exception, context: str = "") -> ReconError:
    """تغليف استثناء عادي في ReconError"""
    if isinstance(error, ReconError):
        return error
    
    message = str(error)
    if context:
        message = f"{context}: {message}"
    
    return ReconError(
        message=message,
        details={"original_type": type(error).__name__},
        cause=error,
    )
