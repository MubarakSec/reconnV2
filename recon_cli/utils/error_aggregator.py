"""
Error Aggregation and Reporting - تجميع الأخطاء وتقاريرها

أدوات لـ:
- تجميع الأخطاء المتشابهة
- إنشاء تقارير مفصلة
- تتبع أنماط الأخطاء

Example:
    >>> aggregator = ErrorAggregator()
    >>> aggregator.add(StageError("nuclei", "timeout"))
    >>> aggregator.add(StageError("nuclei", "timeout"))
    >>> print(aggregator.summary())
    # StageError (nuclei): 2 occurrences
"""

from __future__ import annotations

import hashlib
import json
import logging
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type

from recon_cli.exceptions import get_error_code, is_recoverable

logger = logging.getLogger(__name__)


@dataclass
class ErrorInstance:
    """نسخة واحدة من خطأ"""

    error: Exception
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    traceback: Optional[str] = None

    @property
    def error_type(self) -> str:
        return type(self.error).__name__

    @property
    def error_code(self) -> str:
        return get_error_code(self.error)

    @property
    def message(self) -> str:
        return str(self.error)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.error_type,
            "code": self.error_code,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "recoverable": is_recoverable(self.error),
        }


@dataclass
class ErrorGroup:
    """مجموعة أخطاء متشابهة"""

    key: str
    error_type: str
    error_code: str
    sample_message: str
    instances: List[ErrorInstance] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    @property
    def count(self) -> int:
        return len(self.instances)

    @property
    def is_recoverable(self) -> bool:
        if self.instances:
            return is_recoverable(self.instances[0].error)
        return False

    def add(self, instance: ErrorInstance) -> None:
        self.instances.append(instance)

        if self.first_seen is None or instance.timestamp < self.first_seen:
            self.first_seen = instance.timestamp

        if self.last_seen is None or instance.timestamp > self.last_seen:
            self.last_seen = instance.timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.error_type,
            "error_code": self.error_code,
            "sample_message": self.sample_message,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "recoverable": self.is_recoverable,
        }


class ErrorAggregator:
    """
    مُجمّع الأخطاء.

    يجمع الأخطاء المتشابهة ويقدم إحصائيات.

    Example:
        >>> aggregator = ErrorAggregator()
        >>>
        >>> for url in urls:
        ...     try:
        ...         fetch(url)
        ...     except Exception as e:
        ...         aggregator.add(e, context={"url": url})
        >>>
        >>> print(aggregator.summary())
    """

    def __init__(
        self,
        group_by: str = "type_and_code",
        max_instances_per_group: int = 10,
    ):
        """
        Args:
            group_by: طريقة التجميع (type, code, type_and_code, message)
            max_instances_per_group: أقصى عدد نسخ محفوظة لكل مجموعة
        """
        self.group_by = group_by
        self.max_instances = max_instances_per_group
        self._groups: Dict[str, ErrorGroup] = {}
        self._total_count = 0

    def _get_group_key(self, error: Exception) -> str:
        """حساب مفتاح المجموعة"""
        error_type = type(error).__name__
        error_code = get_error_code(error)
        message = str(error)

        if self.group_by == "type":
            return error_type
        elif self.group_by == "code":
            return error_code
        elif self.group_by == "type_and_code":
            return f"{error_type}:{error_code}"
        elif self.group_by == "message":
            # Hash the message for grouping
            msg_hash = hashlib.md5(message.encode(), usedforsecurity=False).hexdigest()[:8]
            return f"{error_type}:{msg_hash}"
        else:
            return error_type

    def add(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        include_traceback: bool = False,
    ) -> None:
        """
        إضافة خطأ.

        Args:
            error: الخطأ
            context: سياق إضافي
            include_traceback: تضمين traceback
        """
        self._total_count += 1

        instance = ErrorInstance(
            error=error,
            context=context or {},
            traceback=traceback.format_exc() if include_traceback else None,
        )

        key = self._get_group_key(error)

        if key not in self._groups:
            self._groups[key] = ErrorGroup(
                key=key,
                error_type=type(error).__name__,
                error_code=get_error_code(error),
                sample_message=str(error)[:200],
            )

        group = self._groups[key]

        # Limit stored instances
        if len(group.instances) < self.max_instances:
            group.add(instance)
        else:
            # Just update counts and timestamps
            group.last_seen = instance.timestamp
            group.instances.append(instance)
            group.instances = group.instances[-self.max_instances :]

    @property
    def total_count(self) -> int:
        """إجمالي الأخطاء"""
        return self._total_count

    @property
    def group_count(self) -> int:
        """عدد المجموعات"""
        return len(self._groups)

    def groups(self) -> List[ErrorGroup]:
        """جميع المجموعات مرتبة بالعدد"""
        return sorted(
            self._groups.values(),
            key=lambda g: g.count,
            reverse=True,
        )

    def top_errors(self, n: int = 5) -> List[ErrorGroup]:
        """أكثر الأخطاء شيوعاً"""
        return self.groups()[:n]

    def by_type(self, error_type: str) -> List[ErrorGroup]:
        """أخطاء بنوع معين"""
        return [g for g in self._groups.values() if g.error_type == error_type]

    def by_code(self, error_code: str) -> List[ErrorGroup]:
        """أخطاء برمز معين"""
        return [g for g in self._groups.values() if g.error_code == error_code]

    def recoverable_only(self) -> List[ErrorGroup]:
        """الأخطاء القابلة للتعافي فقط"""
        return [g for g in self._groups.values() if g.is_recoverable]

    def non_recoverable_only(self) -> List[ErrorGroup]:
        """الأخطاء غير القابلة للتعافي"""
        return [g for g in self._groups.values() if not g.is_recoverable]

    def summary(self) -> str:
        """ملخص نصي"""
        lines = [
            f"Error Summary: {self.total_count} total, {self.group_count} unique",
            "-" * 50,
        ]

        for group in self.top_errors(10):
            recoverable = "✓" if group.is_recoverable else "✗"
            lines.append(
                f"  [{recoverable}] {group.error_type} ({group.error_code}): "
                f"{group.count} occurrences"
            )
            lines.append(f"      Sample: {group.sample_message[:60]}...")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """تصدير كـ dictionary"""
        return {
            "total_count": self.total_count,
            "group_count": self.group_count,
            "groups": [g.to_dict() for g in self.groups()],
        }

    def to_json(self) -> str:
        """تصدير كـ JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def clear(self) -> None:
        """مسح جميع الأخطاء"""
        self._groups.clear()
        self._total_count = 0


@dataclass
class ErrorReport:
    """تقرير أخطاء مفصل"""

    job_id: str
    start_time: datetime
    end_time: datetime
    aggregator: ErrorAggregator
    stage_errors: Dict[str, List[ErrorInstance]] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def has_errors(self) -> bool:
        return self.aggregator.total_count > 0

    @property
    def has_critical_errors(self) -> bool:
        return len(self.aggregator.non_recoverable_only()) > 0

    def add_stage_error(
        self,
        stage_name: str,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """إضافة خطأ مرحلة"""
        instance = ErrorInstance(
            error=error,
            context=context or {},
        )

        if stage_name not in self.stage_errors:
            self.stage_errors[stage_name] = []
        self.stage_errors[stage_name].append(instance)

        self.aggregator.add(error, context={"stage": stage_name, **(context or {})})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration,
            "has_critical_errors": self.has_critical_errors,
            "summary": self.aggregator.to_dict(),
            "stage_errors": {
                stage: [e.to_dict() for e in errors]
                for stage, errors in self.stage_errors.items()
            },
        }

    def generate_markdown(self) -> str:
        """إنشاء تقرير Markdown"""
        lines = [
            f"# Error Report: {self.job_id}",
            "",
            f"**Duration:** {self.duration:.1f} seconds",
            f"**Total Errors:** {self.aggregator.total_count}",
            f"**Unique Errors:** {self.aggregator.group_count}",
            f"**Critical Errors:** {'Yes' if self.has_critical_errors else 'No'}",
            "",
            "## Error Summary",
            "",
        ]

        for group in self.aggregator.top_errors(10):
            status = "⚠️" if group.is_recoverable else "❌"
            lines.extend(
                [
                    f"### {status} {group.error_type}",
                    f"- **Code:** `{group.error_code}`",
                    f"- **Count:** {group.count}",
                    f"- **First seen:** {group.first_seen}",
                    f"- **Last seen:** {group.last_seen}",
                    f"- **Sample:** `{group.sample_message[:100]}`",
                    "",
                ]
            )

        if self.stage_errors:
            lines.extend(["", "## Errors by Stage", ""])

            for stage, errors in self.stage_errors.items():
                lines.append(f"### {stage}")
                for error in errors[:5]:
                    lines.append(f"- [{error.error_code}] {error.message[:80]}")
                if len(errors) > 5:
                    lines.append(f"- ... and {len(errors) - 5} more")
                lines.append("")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════
#                     Global Error Handler
# ═══════════════════════════════════════════════════════════


class GlobalErrorHandler:
    """
    معالج أخطاء عام.

    يوفر نقطة مركزية لمعالجة الأخطاء.

    Example:
        >>> handler = GlobalErrorHandler()
        >>> handler.register(StageError, handle_stage_error)
        >>>
        >>> try:
        ...     run_stage()
        ... except Exception as e:
        ...     handler.handle(e)
    """

    def __init__(self):
        self._handlers: Dict[Type[Exception], Callable] = {}
        self._default_handler: Optional[Callable] = None
        self.aggregator = ErrorAggregator()

    def register(
        self,
        error_type: Type[Exception],
        handler: Callable[[Exception], None],
    ) -> None:
        """تسجيل handler لنوع خطأ"""
        self._handlers[error_type] = handler

    def set_default_handler(
        self,
        handler: Callable[[Exception], None],
    ) -> None:
        """تعيين handler افتراضي"""
        self._default_handler = handler

    def handle(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        reraise: bool = False,
    ) -> None:
        """
        معالجة خطأ.

        Args:
            error: الخطأ
            context: سياق إضافي
            reraise: إعادة رفع الخطأ بعد المعالجة
        """
        # Add to aggregator
        self.aggregator.add(error, context=context)

        # Find handler
        handler = None
        for error_type, h in self._handlers.items():
            if isinstance(error, error_type):
                handler = h
                break

        if handler is None:
            handler = self._default_handler

        # Execute handler
        if handler:
            try:
                handler(error)
            except Exception as handler_error:
                logger.error(
                    "Error handler failed: %s",
                    handler_error,
                )

        if reraise:
            raise error

    def get_summary(self) -> str:
        """ملخص الأخطاء"""
        return self.aggregator.summary()

    def clear(self) -> None:
        """مسح الأخطاء"""
        self.aggregator.clear()


# Singleton instance
global_error_handler = GlobalErrorHandler()
