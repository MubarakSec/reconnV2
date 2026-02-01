"""
Error Recovery Module - التعافي من الأخطاء

يوفر آليات للتعافي الذكي من الأخطاء:
- Graceful degradation للمراحل غير الحرجة
- حفظ النتائج الجزئية عند الفشل
- سياق تفصيلي للأخطاء
- استراتيجيات إعادة المحاولة

Example:
    >>> with error_recovery_context("nuclei_scan", target="example.com") as ctx:
    ...     run_nuclei(target)
    ...     ctx.record_result({"findings": 5})
    ... # Even on failure, partial results are saved
"""

from __future__ import annotations

import json
import logging
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Set,
    TypeVar,
    Union,
)


logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     Error Severity
# ═══════════════════════════════════════════════════════════

class ErrorSeverity(Enum):
    """مستويات خطورة الأخطاء"""
    
    CRITICAL = "critical"      # يجب إيقاف العملية
    HIGH = "high"              # خطأ مهم لكن يمكن الاستمرار
    MEDIUM = "medium"          # خطأ متوسط، يمكن تجاهله
    LOW = "low"                # تحذير بسيط
    INFO = "info"              # معلومات فقط


class RecoveryAction(Enum):
    """إجراءات التعافي الممكنة"""
    
    ABORT = "abort"            # إيقاف فوري
    RETRY = "retry"            # إعادة المحاولة
    SKIP = "skip"              # تخطي وإكمال
    FALLBACK = "fallback"      # استخدام بديل
    DEGRADE = "degrade"        # تقليل الوظائف


# ═══════════════════════════════════════════════════════════
#                     Error Context
# ═══════════════════════════════════════════════════════════

@dataclass
class ErrorContext:
    """
    سياق تفصيلي للخطأ.
    
    يحتوي على جميع المعلومات اللازمة لفهم الخطأ وتتبعه.
    """
    
    # معلومات أساسية
    error_id: str = ""
    error_type: str = ""
    message: str = ""
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    
    # معلومات المرحلة
    stage_name: str = ""
    stage_attempt: int = 1
    max_attempts: int = 3
    
    # معلومات الهدف
    target: str = ""
    target_type: str = ""  # domain, ip, url, etc.
    
    # معلومات التنفيذ
    job_id: str = ""
    started_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # تفاصيل تقنية
    exception_type: str = ""
    exception_message: str = ""
    traceback: str = ""
    
    # سياق إضافي
    metadata: Dict[str, Any] = field(default_factory=dict)
    partial_results: List[Dict[str, Any]] = field(default_factory=list)
    recovery_attempts: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.error_id:
            import uuid
            self.error_id = str(uuid.uuid4())[:8]
        if not self.started_at:
            self.started_at = datetime.now()
    
    def add_partial_result(self, result: Dict[str, Any]) -> None:
        """إضافة نتيجة جزئية"""
        self.partial_results.append({
            "timestamp": datetime.now().isoformat(),
            "data": result,
        })
    
    def record_recovery_attempt(
        self,
        action: RecoveryAction,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """تسجيل محاولة تعافي"""
        self.recovery_attempts.append({
            "timestamp": datetime.now().isoformat(),
            "action": action.value,
            "success": success,
            "details": details or {},
        })
    
    def mark_failed(self, exc: Exception) -> None:
        """تعليم السياق كفاشل"""
        self.failed_at = datetime.now()
        if self.started_at:
            self.duration_seconds = (self.failed_at - self.started_at).total_seconds()
        self.exception_type = type(exc).__name__
        self.exception_message = str(exc)
        self.traceback = traceback.format_exc()
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل لـ dictionary"""
        return {
            "error_id": self.error_id,
            "error_type": self.error_type,
            "message": self.message,
            "severity": self.severity.value,
            "stage": {
                "name": self.stage_name,
                "attempt": self.stage_attempt,
                "max_attempts": self.max_attempts,
            },
            "target": {
                "value": self.target,
                "type": self.target_type,
            },
            "job_id": self.job_id,
            "timing": {
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "failed_at": self.failed_at.isoformat() if self.failed_at else None,
                "duration_seconds": self.duration_seconds,
            },
            "exception": {
                "type": self.exception_type,
                "message": self.exception_message,
                "traceback": self.traceback,
            },
            "metadata": self.metadata,
            "partial_results_count": len(self.partial_results),
            "recovery_attempts": self.recovery_attempts,
        }
    
    def to_json(self) -> str:
        """تحويل لـ JSON"""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ═══════════════════════════════════════════════════════════
#                     Recovery Strategy
# ═══════════════════════════════════════════════════════════

@dataclass
class RecoveryStrategy:
    """
    استراتيجية التعافي من الأخطاء.
    
    تحدد كيفية التعامل مع أنواع مختلفة من الأخطاء.
    """
    
    # الإجراء الافتراضي
    default_action: RecoveryAction = RecoveryAction.SKIP
    
    # إعدادات إعادة المحاولة
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    retry_max_delay: float = 60.0
    
    # أخطاء قابلة لإعادة المحاولة
    retryable_exceptions: Set[str] = field(default_factory=lambda: {
        "TimeoutError",
        "ConnectionError", 
        "ConnectionRefusedError",
        "ConnectionResetError",
        "TemporaryError",
    })
    
    # أخطاء تتطلب إيقاف
    fatal_exceptions: Set[str] = field(default_factory=lambda: {
        "AuthenticationError",
        "PermissionError",
        "ConfigurationError",
        "OutOfMemoryError",
    })
    
    # مراحل غير حرجة (يمكن تخطيها)
    optional_stages: Set[str] = field(default_factory=lambda: {
        "screenshot",
        "runtime_crawl",
        "learning",
        "correlation",
        "active_intelligence",
    })
    
    def get_action(
        self,
        exc: Exception,
        stage_name: str,
        attempt: int,
    ) -> RecoveryAction:
        """تحديد الإجراء المناسب للخطأ"""
        exc_name = type(exc).__name__
        
        # أخطاء تتطلب إيقاف
        if exc_name in self.fatal_exceptions:
            return RecoveryAction.ABORT
        
        # أخطاء قابلة لإعادة المحاولة
        if exc_name in self.retryable_exceptions and attempt < self.max_retries:
            return RecoveryAction.RETRY
        
        # مراحل اختيارية
        if stage_name in self.optional_stages:
            return RecoveryAction.SKIP
        
        return self.default_action
    
    def get_retry_delay(self, attempt: int) -> float:
        """حساب تأخير إعادة المحاولة"""
        delay = self.retry_delay * (self.retry_backoff ** (attempt - 1))
        return min(delay, self.retry_max_delay)


# ═══════════════════════════════════════════════════════════
#                     Partial Result Saver
# ═══════════════════════════════════════════════════════════

class PartialResultSaver:
    """
    حافظ النتائج الجزئية.
    
    يحفظ النتائج حتى عند فشل المرحلة لتجنب فقدان العمل المنجز.
    """
    
    def __init__(self, output_dir: Path, job_id: str):
        self.output_dir = output_dir
        self.job_id = job_id
        self.partial_dir = output_dir / "partial"
        self.partial_dir.mkdir(parents=True, exist_ok=True)
        self._results: Dict[str, List[Dict[str, Any]]] = {}
    
    def add_result(self, stage: str, result: Dict[str, Any]) -> None:
        """إضافة نتيجة للمرحلة"""
        if stage not in self._results:
            self._results[stage] = []
        self._results[stage].append(result)
    
    def add_results(self, stage: str, results: List[Dict[str, Any]]) -> None:
        """إضافة عدة نتائج"""
        for result in results:
            self.add_result(stage, result)
    
    def get_results(self, stage: str) -> List[Dict[str, Any]]:
        """الحصول على نتائج المرحلة"""
        return self._results.get(stage, [])
    
    def save_checkpoint(self, stage: str) -> Path:
        """حفظ checkpoint للمرحلة"""
        results = self._results.get(stage, [])
        if not results:
            return self.partial_dir
        
        checkpoint_file = self.partial_dir / f"{stage}_partial.jsonl"
        with checkpoint_file.open("a", encoding="utf-8") as f:
            for result in results:
                json.dump(result, f, default=str)
                f.write("\n")
        
        logger.info(
            "Saved %d partial results for stage %s to %s",
            len(results), stage, checkpoint_file
        )
        return checkpoint_file
    
    def save_all(self) -> Dict[str, Path]:
        """حفظ جميع النتائج الجزئية"""
        saved = {}
        for stage in self._results:
            saved[stage] = self.save_checkpoint(stage)
        return saved
    
    def load_checkpoint(self, stage: str) -> List[Dict[str, Any]]:
        """تحميل checkpoint محفوظ"""
        checkpoint_file = self.partial_dir / f"{stage}_partial.jsonl"
        if not checkpoint_file.exists():
            return []
        
        results = []
        with checkpoint_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return results
    
    def merge_with_final(self, final_results_path: Path) -> int:
        """دمج النتائج الجزئية مع النتائج النهائية"""
        merged_count = 0
        
        for stage, results in self._results.items():
            if not results:
                continue
            
            with final_results_path.open("a", encoding="utf-8") as f:
                for result in results:
                    result["_partial"] = True
                    result["_stage"] = stage
                    json.dump(result, f, default=str)
                    f.write("\n")
                    merged_count += 1
        
        logger.info("Merged %d partial results to %s", merged_count, final_results_path)
        return merged_count
    
    def cleanup(self) -> None:
        """تنظيف الملفات المؤقتة"""
        import shutil
        if self.partial_dir.exists():
            shutil.rmtree(self.partial_dir)


# ═══════════════════════════════════════════════════════════
#                     Graceful Degradation
# ═══════════════════════════════════════════════════════════

class GracefulDegradation:
    """
    التدهور الرشيق.
    
    يسمح بإكمال العمليات مع تقليل الوظائف عند حدوث أخطاء.
    """
    
    def __init__(self, strategy: Optional[RecoveryStrategy] = None):
        self.strategy = strategy or RecoveryStrategy()
        self._disabled_features: Set[str] = set()
        self._degraded_stages: Set[str] = set()
        self._fallback_used: Dict[str, str] = {}
    
    def disable_feature(self, feature: str, reason: str) -> None:
        """تعطيل ميزة"""
        self._disabled_features.add(feature)
        logger.warning("Feature '%s' disabled: %s", feature, reason)
    
    def is_feature_enabled(self, feature: str) -> bool:
        """التحقق من تفعيل الميزة"""
        return feature not in self._disabled_features
    
    def mark_stage_degraded(self, stage: str, reason: str) -> None:
        """تعليم المرحلة كمتدهورة"""
        self._degraded_stages.add(stage)
        logger.warning("Stage '%s' running in degraded mode: %s", stage, reason)
    
    def is_stage_degraded(self, stage: str) -> bool:
        """التحقق من تدهور المرحلة"""
        return stage in self._degraded_stages
    
    def use_fallback(self, feature: str, fallback: str) -> None:
        """استخدام بديل للميزة"""
        self._fallback_used[feature] = fallback
        logger.info("Using fallback '%s' for feature '%s'", fallback, feature)
    
    def get_fallback(self, feature: str) -> Optional[str]:
        """الحصول على البديل المستخدم"""
        return self._fallback_used.get(feature)
    
    def should_continue(
        self,
        exc: Exception,
        stage_name: str,
        attempt: int,
    ) -> tuple[bool, RecoveryAction]:
        """تحديد ما إذا كان يجب الاستمرار"""
        action = self.strategy.get_action(exc, stage_name, attempt)
        
        if action == RecoveryAction.ABORT:
            return False, action
        
        if action == RecoveryAction.SKIP:
            self.mark_stage_degraded(stage_name, str(exc))
            return True, action
        
        return True, action
    
    def get_status(self) -> Dict[str, Any]:
        """الحصول على حالة التدهور"""
        return {
            "disabled_features": list(self._disabled_features),
            "degraded_stages": list(self._degraded_stages),
            "fallbacks_used": self._fallback_used,
            "is_degraded": bool(self._disabled_features or self._degraded_stages),
        }


# ═══════════════════════════════════════════════════════════
#                     Recovery Context Manager
# ═══════════════════════════════════════════════════════════

class RecoveryContext:
    """
    سياق التعافي.
    
    يجمع بين جميع مكونات التعافي في واجهة واحدة.
    """
    
    def __init__(
        self,
        stage_name: str,
        target: str = "",
        job_id: str = "",
        output_dir: Optional[Path] = None,
        strategy: Optional[RecoveryStrategy] = None,
    ):
        self.stage_name = stage_name
        self.target = target
        self.job_id = job_id
        self.strategy = strategy or RecoveryStrategy()
        
        # مكونات
        self.error_context = ErrorContext(
            stage_name=stage_name,
            target=target,
            job_id=job_id,
        )
        
        if output_dir:
            self.result_saver = PartialResultSaver(output_dir, job_id)
        else:
            self.result_saver = None
        
        self.degradation = GracefulDegradation(strategy)
        
        # حالة
        self._success = False
        self._exception: Optional[Exception] = None
    
    def record_result(self, result: Dict[str, Any]) -> None:
        """تسجيل نتيجة"""
        self.error_context.add_partial_result(result)
        if self.result_saver:
            self.result_saver.add_result(self.stage_name, result)
    
    def set_metadata(self, key: str, value: Any) -> None:
        """إضافة بيانات وصفية"""
        self.error_context.metadata[key] = value
    
    def mark_success(self) -> None:
        """تعليم كناجح"""
        self._success = True
    
    def mark_failed(self, exc: Exception) -> None:
        """تعليم كفاشل"""
        self._success = False
        self._exception = exc
        self.error_context.mark_failed(exc)
    
    @property
    def is_success(self) -> bool:
        return self._success
    
    @property
    def exception(self) -> Optional[Exception]:
        return self._exception
    
    def save_partial_results(self) -> Optional[Path]:
        """حفظ النتائج الجزئية"""
        if self.result_saver:
            return self.result_saver.save_checkpoint(self.stage_name)
        return None
    
    def get_report(self) -> Dict[str, Any]:
        """الحصول على تقرير"""
        return {
            "success": self._success,
            "error": self.error_context.to_dict() if not self._success else None,
            "degradation": self.degradation.get_status(),
            "partial_results_saved": bool(self.result_saver and self.error_context.partial_results),
        }


@contextmanager
def error_recovery_context(
    stage_name: str,
    target: str = "",
    job_id: str = "",
    output_dir: Optional[Path] = None,
    strategy: Optional[RecoveryStrategy] = None,
    save_on_error: bool = True,
) -> Generator[RecoveryContext, None, None]:
    """
    Context manager للتعافي من الأخطاء.
    
    Example:
        >>> with error_recovery_context("nuclei_scan", target="example.com") as ctx:
        ...     for result in scan():
        ...         ctx.record_result(result)
        ...     ctx.mark_success()
        ... # حتى عند الفشل، النتائج الجزئية محفوظة
    """
    ctx = RecoveryContext(
        stage_name=stage_name,
        target=target,
        job_id=job_id,
        output_dir=output_dir,
        strategy=strategy,
    )
    
    try:
        yield ctx
    except Exception as exc:
        ctx.mark_failed(exc)
        
        if save_on_error:
            ctx.save_partial_results()
        
        logger.error(
            "Stage %s failed for target %s: %s",
            stage_name, target, exc
        )
        logger.debug("Error context:\n%s", ctx.error_context.to_json())
        
        raise
    else:
        ctx.mark_success()


# ═══════════════════════════════════════════════════════════
#                     Decorators
# ═══════════════════════════════════════════════════════════

F = TypeVar('F', bound=Callable[..., Any])


def with_recovery(
    stage_name: str = "",
    save_partial: bool = True,
    strategy: Optional[RecoveryStrategy] = None,
) -> Callable[[F], F]:
    """
    Decorator للتعافي التلقائي.
    
    Example:
        >>> @with_recovery("nuclei_scan", save_partial=True)
        ... def run_nuclei(target: str) -> List[Dict]:
        ...     ...
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            name = stage_name or func.__name__
            target = kwargs.get("target", str(args[0]) if args else "")
            
            with error_recovery_context(
                stage_name=name,
                target=target,
                strategy=strategy,
                save_on_error=save_partial,
            ) as ctx:
                result = func(*args, **kwargs)
                ctx.mark_success()
                return result
        
        return wrapper  # type: ignore
    return decorator


def graceful_stage(
    optional: bool = True,
    fallback: Optional[Callable[..., Any]] = None,
) -> Callable[[F], F]:
    """
    Decorator للمراحل القابلة للتدهور.
    
    Example:
        >>> @graceful_stage(optional=True)
        ... def screenshot_stage(context):
        ...     # إذا فشل، يتم تخطيه بدون إيقاف الـ pipeline
        ...     ...
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                if optional:
                    logger.warning(
                        "Optional stage %s failed, skipping: %s",
                        func.__name__, exc
                    )
                    if fallback:
                        logger.info("Using fallback for %s", func.__name__)
                        return fallback(*args, **kwargs)
                    return None
                raise
        
        return wrapper  # type: ignore
    return decorator


# ═══════════════════════════════════════════════════════════
#                     Error Report Generator
# ═══════════════════════════════════════════════════════════

class ErrorReportGenerator:
    """
    مولد تقارير الأخطاء.
    
    ينشئ تقارير شاملة عن الأخطاء التي حدثت.
    """
    
    def __init__(self, job_id: str, output_dir: Path):
        self.job_id = job_id
        self.output_dir = output_dir
        self._errors: List[ErrorContext] = []
    
    def add_error(self, error: ErrorContext) -> None:
        """إضافة خطأ"""
        self._errors.append(error)
    
    def generate_summary(self) -> Dict[str, Any]:
        """إنشاء ملخص الأخطاء"""
        if not self._errors:
            return {
                "total_errors": 0,
                "errors_by_severity": {},
                "errors_by_stage": {},
                "partial_results_count": 0,
            }
        
        by_severity: Dict[str, int] = {}
        by_stage: Dict[str, int] = {}
        partial_count = 0
        
        for error in self._errors:
            sev = error.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            stage = error.stage_name
            by_stage[stage] = by_stage.get(stage, 0) + 1
            
            partial_count += len(error.partial_results)
        
        return {
            "total_errors": len(self._errors),
            "errors_by_severity": by_severity,
            "errors_by_stage": by_stage,
            "partial_results_count": partial_count,
            "recoverable_count": sum(1 for e in self._errors if e.severity != ErrorSeverity.CRITICAL),
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """إنشاء تقرير كامل"""
        return {
            "job_id": self.job_id,
            "generated_at": datetime.now().isoformat(),
            "summary": self.generate_summary(),
            "errors": [e.to_dict() for e in self._errors],
        }
    
    def save_report(self, filename: str = "error_report.json") -> Path:
        """حفظ التقرير"""
        report_path = self.output_dir / filename
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(self.generate_report(), f, indent=2, default=str)
        return report_path


# ═══════════════════════════════════════════════════════════
#                     Global Handler
# ═══════════════════════════════════════════════════════════

class GlobalRecoveryHandler:
    """
    معالج التعافي العام.
    
    يدير التعافي على مستوى التطبيق.
    """
    
    _instance: Optional["GlobalRecoveryHandler"] = None
    
    def __new__(cls) -> "GlobalRecoveryHandler":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._strategy = RecoveryStrategy()
        self._degradation = GracefulDegradation(self._strategy)
        self._error_contexts: List[ErrorContext] = []
        self._active_recovery: Dict[str, RecoveryContext] = {}
    
    def set_strategy(self, strategy: RecoveryStrategy) -> None:
        """تعيين الاستراتيجية"""
        self._strategy = strategy
        self._degradation = GracefulDegradation(strategy)
    
    def start_recovery(
        self,
        stage_name: str,
        target: str = "",
        job_id: str = "",
    ) -> RecoveryContext:
        """بدء سياق تعافي"""
        ctx = RecoveryContext(
            stage_name=stage_name,
            target=target,
            job_id=job_id,
            strategy=self._strategy,
        )
        self._active_recovery[stage_name] = ctx
        return ctx
    
    def end_recovery(self, stage_name: str) -> Optional[RecoveryContext]:
        """إنهاء سياق تعافي"""
        ctx = self._active_recovery.pop(stage_name, None)
        if ctx and not ctx.is_success:
            self._error_contexts.append(ctx.error_context)
        return ctx
    
    def get_degradation_status(self) -> Dict[str, Any]:
        """الحصول على حالة التدهور العامة"""
        return self._degradation.get_status()
    
    def get_all_errors(self) -> List[ErrorContext]:
        """الحصول على جميع الأخطاء"""
        return self._error_contexts.copy()
    
    def reset(self) -> None:
        """إعادة تعيين"""
        self._error_contexts.clear()
        self._active_recovery.clear()
        self._degradation = GracefulDegradation(self._strategy)


def get_recovery_handler() -> GlobalRecoveryHandler:
    """الحصول على المعالج العام"""
    return GlobalRecoveryHandler()


# ═══════════════════════════════════════════════════════════
#                     Exports
# ═══════════════════════════════════════════════════════════

__all__ = [
    # Enums
    "ErrorSeverity",
    "RecoveryAction",
    # Classes
    "ErrorContext",
    "RecoveryStrategy",
    "PartialResultSaver",
    "GracefulDegradation",
    "RecoveryContext",
    "ErrorReportGenerator",
    "GlobalRecoveryHandler",
    # Functions
    "error_recovery_context",
    "get_recovery_handler",
    # Decorators
    "with_recovery",
    "graceful_stage",
]
