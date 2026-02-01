"""
Structured Logging - تسجيل منظم بصيغة JSON

يوفر تسجيل منظم مع:
- صيغة JSON للتحليل الآلي
- Context إضافي لكل رسالة
- دعم للـ trace IDs
- تكامل مع أنظمة المراقبة

Example:
    >>> from recon_cli.utils.structured_logging import setup_logging, get_logger
    >>> 
    >>> setup_logging(level="INFO", json_format=True)
    >>> logger = get_logger("pipeline")
    >>> logger.info("Stage started", extra={"stage": "passive", "target": "example.com"})
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


# Thread-local storage for context
_context = threading.local()


class StructuredFormatter(logging.Formatter):
    """
    Formatter لتحويل الـ logs لصيغة JSON.
    
    ينتج logs بصيغة JSON مع:
    - timestamp (ISO 8601)
    - level
    - message
    - module, function, line
    - extra fields
    - trace_id (إذا متاح)
    
    Example output:
        {"timestamp": "2026-02-01T10:30:00Z", "level": "INFO", 
         "message": "Stage started", "stage": "passive"}
    """
    
    def __init__(
        self,
        include_timestamp: bool = True,
        include_location: bool = True,
        extra_fields: Optional[Dict[str, Any]] = None,
    ):
        """
        تهيئة الـ Formatter.
        
        Args:
            include_timestamp: تضمين الوقت
            include_location: تضمين الموقع (module, function, line)
            extra_fields: حقول إضافية ثابتة
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_location = include_location
        self.extra_fields = extra_fields or {}
    
    def format(self, record: logging.LogRecord) -> str:
        """تحويل LogRecord لـ JSON string."""
        log_entry: Dict[str, Any] = {}
        
        # Timestamp
        if self.include_timestamp:
            log_entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        # Basic fields
        log_entry["level"] = record.levelname
        log_entry["message"] = record.getMessage()
        
        # Location
        if self.include_location:
            log_entry["module"] = record.module
            log_entry["function"] = record.funcName
            log_entry["line"] = record.lineno
        
        # Logger name
        log_entry["logger"] = record.name
        
        # Trace ID from context
        trace_id = getattr(_context, "trace_id", None)
        if trace_id:
            log_entry["trace_id"] = trace_id
        
        # Job ID from context
        job_id = getattr(_context, "job_id", None)
        if job_id:
            log_entry["job_id"] = job_id
        
        # Extra fields from record
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_entry.update(record.extra)
        
        # Check for common extra attributes
        for key in ["stage", "target", "host", "url", "error", "duration", "count"]:
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        
        # Static extra fields
        log_entry.update(self.extra_fields)
        
        # Exception info
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, ensure_ascii=False, default=str)


class PrettyFormatter(logging.Formatter):
    """
    Formatter للعرض الملون في Terminal.
    
    يُستخدم للتطوير والـ debugging.
    """
    
    COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m", # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """Format with colors."""
        color = self.COLORS.get(record.levelname, "")
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Build message
        parts = [
            f"{color}[{timestamp}]",
            f"{record.levelname:8}{self.RESET}",
            f"{record.name}:",
            record.getMessage(),
        ]
        
        # Add extra context
        trace_id = getattr(_context, "trace_id", None)
        if trace_id:
            parts.append(f"[trace:{trace_id[:8]}]")
        
        job_id = getattr(_context, "job_id", None)
        if job_id:
            parts.append(f"[job:{job_id[:12]}]")
        
        message = " ".join(parts)
        
        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)
        
        return message


class ContextLogger(logging.LoggerAdapter):
    """
    Logger adapter مع دعم للـ context.
    
    يسمح بإضافة context إضافي لكل رسالة.
    
    Example:
        >>> logger = ContextLogger(base_logger, {"job_id": "123"})
        >>> logger.info("Processing", extra={"stage": "dns"})
    """
    
    def process(self, msg: str, kwargs: Dict) -> tuple:
        """Add context to kwargs."""
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: Optional[Path] = None,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> None:
    """
    إعداد نظام الـ logging.
    
    Args:
        level: مستوى الـ logging (DEBUG, INFO, WARNING, ERROR)
        json_format: استخدام صيغة JSON
        log_file: ملف للحفظ (إضافة للـ console)
        extra_fields: حقول إضافية ثابتة
    
    Example:
        >>> setup_logging(level="DEBUG", json_format=True)
        >>> setup_logging(level="INFO", log_file=Path("app.log"))
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if json_format:
        console_handler.setFormatter(StructuredFormatter(extra_fields=extra_fields))
    else:
        console_handler.setFormatter(PrettyFormatter())
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(StructuredFormatter(extra_fields=extra_fields))
        root_logger.addHandler(file_handler)


def get_logger(name: str, **context) -> logging.Logger:
    """
    الحصول على logger مع context.
    
    Args:
        name: اسم الـ logger
        **context: context إضافي
        
    Returns:
        Logger جاهز للاستخدام
        
    Example:
        >>> logger = get_logger("pipeline", job_id="123")
        >>> logger.info("Started")
    """
    logger = logging.getLogger(name)
    if context:
        return ContextLogger(logger, context)
    return logger


def set_trace_id(trace_id: Optional[str] = None) -> str:
    """
    تعيين trace ID للـ thread الحالي.
    
    Args:
        trace_id: ID موجود أو None لإنشاء جديد
        
    Returns:
        الـ trace ID المستخدم
    """
    if trace_id is None:
        trace_id = str(uuid.uuid4())
    _context.trace_id = trace_id
    return trace_id


def get_trace_id() -> Optional[str]:
    """الحصول على trace ID الحالي."""
    return getattr(_context, "trace_id", None)


def set_job_context(job_id: str) -> None:
    """
    تعيين job context للـ logging.
    
    Args:
        job_id: معرف الـ job
    """
    _context.job_id = job_id


def clear_context() -> None:
    """مسح كل الـ context."""
    if hasattr(_context, "trace_id"):
        del _context.trace_id
    if hasattr(_context, "job_id"):
        del _context.job_id


class LogContext:
    """
    Context manager للـ logging context.
    
    Example:
        >>> with LogContext(job_id="123", trace_id="abc"):
        ...     logger.info("Processing")  # يتضمن job_id و trace_id تلقائياً
    """
    
    def __init__(self, job_id: Optional[str] = None, trace_id: Optional[str] = None):
        self.job_id = job_id
        self.trace_id = trace_id or str(uuid.uuid4())
        self._old_job_id = None
        self._old_trace_id = None
    
    def __enter__(self):
        self._old_job_id = getattr(_context, "job_id", None)
        self._old_trace_id = getattr(_context, "trace_id", None)
        
        _context.trace_id = self.trace_id
        if self.job_id:
            _context.job_id = self.job_id
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._old_trace_id:
            _context.trace_id = self._old_trace_id
        elif hasattr(_context, "trace_id"):
            del _context.trace_id
        
        if self._old_job_id:
            _context.job_id = self._old_job_id
        elif hasattr(_context, "job_id"):
            del _context.job_id
        
        return False


# ═══════════════════════════════════════════════════════════
#                     Log Helpers
# ═══════════════════════════════════════════════════════════

def log_stage_start(logger: logging.Logger, stage: str, target: str) -> None:
    """Log stage start."""
    logger.info(
        f"Stage '{stage}' started for {target}",
        extra={"stage": stage, "target": target, "event": "stage_start"}
    )


def log_stage_end(logger: logging.Logger, stage: str, duration: float, success: bool = True) -> None:
    """Log stage completion."""
    status = "completed" if success else "failed"
    logger.info(
        f"Stage '{stage}' {status} in {duration:.2f}s",
        extra={"stage": stage, "duration": duration, "success": success, "event": "stage_end"}
    )


def log_tool_execution(logger: logging.Logger, tool: str, target: str, success: bool = True) -> None:
    """Log external tool execution."""
    status = "succeeded" if success else "failed"
    logger.info(
        f"Tool '{tool}' {status} for {target}",
        extra={"tool": tool, "target": target, "success": success, "event": "tool_exec"}
    )


def log_finding(
    logger: logging.Logger, 
    finding_type: str, 
    target: str, 
    severity: str = "info",
    details: Optional[Dict] = None
) -> None:
    """Log a security finding."""
    logger.info(
        f"Found {finding_type} on {target} [{severity}]",
        extra={
            "finding_type": finding_type,
            "target": target,
            "severity": severity,
            "details": details or {},
            "event": "finding"
        }
    )
