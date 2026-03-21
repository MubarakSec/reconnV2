"""
Job Scheduler - جدولة المهام

نظام جدولة لتشغيل الفحوصات بشكل دوري.

Features:
- جدولة بتعبيرات Cron
- فترات زمنية بسيطة
- تشغيل مرة واحدة
- إدارة المهام

Example:
    >>> scheduler = JobScheduler()
    >>> scheduler.add_cron_job(
    ...     "daily-scan",
    ...     scan_spec,
    ...     cron="0 2 * * *"  # كل يوم الساعة 2 صباحاً
    ... )
    >>> await scheduler.start()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     Cron Parser
# ═══════════════════════════════════════════════════════════


class CronField:
    """حقل Cron واحد"""

    def __init__(
        self,
        expr: str,
        min_val: int,
        max_val: int,
        names: Optional[Dict[str, int]] = None,
    ):
        self.expr = expr
        self.min_val = min_val
        self.max_val = max_val
        self.names = names or {}
        self.values = self._parse(expr)

    def _parse(self, expr: str) -> set:
        """تحليل التعبير"""
        values: Set[int] = set()

        # Replace names
        for name, val in self.names.items():
            expr = expr.lower().replace(name.lower(), str(val))

        for part in expr.split(","):
            if part == "*":
                values.update(range(self.min_val, self.max_val + 1))
            elif "/" in part:
                # Step: */5 or 0-30/5
                range_part, step = part.split("/")
                step = int(step)  # type: ignore[assignment]

                if range_part == "*":
                    start, end = self.min_val, self.max_val
                elif "-" in range_part:
                    start, end = map(int, range_part.split("-"))
                else:
                    start = int(range_part)
                    end = self.max_val

                values.update(range(start, end + 1, step))  # type: ignore[call-overload]
            elif "-" in part:
                # Range: 1-5
                start, end = map(int, part.split("-"))
                values.update(range(start, end + 1))
            else:
                # Single value
                values.add(int(part))

        return values

    def matches(self, value: int) -> bool:
        """هل القيمة مطابقة"""
        return value in self.values


@dataclass
class CronExpression:
    """
    تعبير Cron.

    Format: minute hour day_of_month month day_of_week

    Example:
        >>> cron = CronExpression("0 2 * * *")  # كل يوم الساعة 2
        >>> cron.matches(datetime.now())
    """

    WEEKDAYS = {
        "mon": 0,
        "tue": 1,
        "wed": 2,
        "thu": 3,
        "fri": 4,
        "sat": 5,
        "sun": 6,
    }

    MONTHS = {
        "jan": 1,
        "feb": 2,
        "mar": 3,
        "apr": 4,
        "may": 5,
        "jun": 6,
        "jul": 7,
        "aug": 8,
        "sep": 9,
        "oct": 10,
        "nov": 11,
        "dec": 12,
    }

    expression: str
    minute: CronField = field(init=False)
    hour: CronField = field(init=False)
    day: CronField = field(init=False)
    month: CronField = field(init=False)
    weekday: CronField = field(init=False)

    def __post_init__(self):
        parts = self.expression.split()
        if len(parts) != 5:
            raise ValueError(
                f"Invalid cron expression: {self.expression}. "
                "Expected 5 fields: minute hour day month weekday"
            )

        self.minute = CronField(parts[0], 0, 59)
        self.hour = CronField(parts[1], 0, 23)
        self.day = CronField(parts[2], 1, 31)
        self.month = CronField(parts[3], 1, 12, self.MONTHS)
        self.weekday = CronField(parts[4], 0, 6, self.WEEKDAYS)

    def matches(self, dt: datetime) -> bool:
        """هل الوقت مطابق"""
        return (
            self.minute.matches(dt.minute)
            and self.hour.matches(dt.hour)
            and self.day.matches(dt.day)
            and self.month.matches(dt.month)
            and self.weekday.matches(dt.weekday())
        )

    def next_run(self, after: Optional[datetime] = None) -> datetime:
        """الوقت التالي للتشغيل"""
        dt = after or datetime.now()
        dt = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Search for next matching time (max 2 years)
        for _ in range(365 * 24 * 60 * 2):
            if self.matches(dt):
                return dt
            dt += timedelta(minutes=1)

        raise ValueError("Could not find next run time")


# ═══════════════════════════════════════════════════════════
#                     Scheduled Job
# ═══════════════════════════════════════════════════════════


class JobTriggerType(Enum):
    """نوع المحفز"""

    CRON = "cron"
    INTERVAL = "interval"
    ONCE = "once"


@dataclass
class ScheduledJob:
    """مهمة مجدولة"""

    id: str
    name: str
    trigger_type: JobTriggerType
    scan_spec: Dict[str, Any]
    enabled: bool = True

    # Trigger settings
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    run_at: Optional[datetime] = None

    # State
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    last_error: Optional[str] = None

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.id:
            self.id = self._generate_id()
        self._calculate_next_run()

    def _generate_id(self) -> str:
        """توليد ID"""
        content = f"{self.name}-{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]

    def _calculate_next_run(self) -> None:
        """حساب وقت التشغيل التالي"""
        if not self.enabled:
            self.next_run = None
            return

        if self.trigger_type == JobTriggerType.CRON:
            if self.cron_expression:
                cron = CronExpression(self.cron_expression)
                self.next_run = cron.next_run(self.last_run)

        elif self.trigger_type == JobTriggerType.INTERVAL:
            if self.interval_seconds:
                base = self.last_run or datetime.now()
                self.next_run = base + timedelta(seconds=self.interval_seconds)

        elif self.trigger_type == JobTriggerType.ONCE:
            if self.run_at and self.run_count == 0:
                self.next_run = self.run_at
            else:
                self.next_run = None

    def should_run(self, now: Optional[datetime] = None) -> bool:
        """هل يجب التشغيل الآن"""
        if not self.enabled:
            return False

        if self.next_run is None:
            return False

        now = now or datetime.now()
        return now >= self.next_run

    def mark_run(self, error: Optional[str] = None) -> None:
        """تسجيل التشغيل"""
        self.last_run = datetime.now()
        self.run_count += 1
        self.last_error = error
        self._calculate_next_run()

    def to_dict(self) -> Dict[str, Any]:
        """تحويل لـ dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "trigger_type": self.trigger_type.value,
            "scan_spec": self.scan_spec,
            "enabled": self.enabled,
            "cron_expression": self.cron_expression,
            "interval_seconds": self.interval_seconds,
            "run_at": self.run_at.isoformat() if self.run_at else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "last_error": self.last_error,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledJob":
        """إنشاء من dictionary"""
        data = data.copy()
        data["trigger_type"] = JobTriggerType(data["trigger_type"])

        for dt_field in ["run_at", "last_run", "next_run"]:
            if data.get(dt_field):
                data[dt_field] = datetime.fromisoformat(data[dt_field])

        return cls(**data)


# ═══════════════════════════════════════════════════════════
#                     Job Scheduler
# ═══════════════════════════════════════════════════════════


class JobScheduler:
    """
    جدولة المهام.

    Example:
        >>> scheduler = JobScheduler()
        >>>
        >>> # إضافة مهمة Cron
        >>> scheduler.add_cron_job(
        ...     "nightly-scan",
        ...     {"targets": ["example.com"]},
        ...     cron="0 2 * * *"
        ... )
        >>>
        >>> # إضافة مهمة بفترة
        >>> scheduler.add_interval_job(
        ...     "hourly-check",
        ...     {"targets": ["api.example.com"]},
        ...     hours=1
        ... )
        >>>
        >>> await scheduler.start()
    """

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        run_callback: Optional[Callable[[Dict], Any]] = None,
    ):
        """
        Args:
            storage_path: مسار حفظ المهام
            run_callback: دالة تنفيذ الفحص
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self.run_callback = run_callback

        self._jobs: Dict[str, ScheduledJob] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def add_cron_job(
        self,
        name: str,
        scan_spec: Dict[str, Any],
        cron: str,
        tags: Optional[List[str]] = None,
    ) -> ScheduledJob:
        """
        إضافة مهمة Cron.

        Args:
            name: اسم المهمة
            scan_spec: مواصفات الفحص
            cron: تعبير Cron
            tags: وسوم

        Returns:
            ScheduledJob
        """
        # Validate cron
        CronExpression(cron)

        job = ScheduledJob(
            id="",
            name=name,
            trigger_type=JobTriggerType.CRON,
            scan_spec=scan_spec,
            cron_expression=cron,
            tags=tags or [],
        )

        self._jobs[job.id] = job
        self._save()

        logger.info("Added cron job: %s (%s)", name, cron)
        return job

    def add_interval_job(
        self,
        name: str,
        scan_spec: Dict[str, Any],
        seconds: int = 0,
        minutes: int = 0,
        hours: int = 0,
        days: int = 0,
        tags: Optional[List[str]] = None,
    ) -> ScheduledJob:
        """
        إضافة مهمة بفترة.

        Args:
            name: اسم المهمة
            scan_spec: مواصفات الفحص
            seconds/minutes/hours/days: الفترة
            tags: وسوم

        Returns:
            ScheduledJob
        """
        total_seconds = seconds + minutes * 60 + hours * 3600 + days * 86400

        if total_seconds < 60:
            raise ValueError("Interval must be at least 60 seconds")

        job = ScheduledJob(
            id="",
            name=name,
            trigger_type=JobTriggerType.INTERVAL,
            scan_spec=scan_spec,
            interval_seconds=total_seconds,
            tags=tags or [],
        )

        self._jobs[job.id] = job
        self._save()

        logger.info("Added interval job: %s (every %ds)", name, total_seconds)
        return job

    def add_once_job(
        self,
        name: str,
        scan_spec: Dict[str, Any],
        run_at: datetime,
        tags: Optional[List[str]] = None,
    ) -> ScheduledJob:
        """
        إضافة مهمة لمرة واحدة.

        Args:
            name: اسم المهمة
            scan_spec: مواصفات الفحص
            run_at: وقت التشغيل
            tags: وسوم

        Returns:
            ScheduledJob
        """
        if run_at < datetime.now():
            raise ValueError("run_at must be in the future")

        job = ScheduledJob(
            id="",
            name=name,
            trigger_type=JobTriggerType.ONCE,
            scan_spec=scan_spec,
            run_at=run_at,
            tags=tags or [],
        )

        self._jobs[job.id] = job
        self._save()

        logger.info("Added one-time job: %s (at %s)", name, run_at)
        return job

    def remove_job(self, job_id: str) -> bool:
        """حذف مهمة"""
        if job_id in self._jobs:
            del self._jobs[job_id]
            self._save()
            logger.info("Removed job: %s", job_id)
            return True
        return False

    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        """الحصول على مهمة"""
        return self._jobs.get(job_id)

    def list_jobs(
        self,
        enabled_only: bool = False,
        tag: Optional[str] = None,
    ) -> List[ScheduledJob]:
        """قائمة المهام"""
        jobs = list(self._jobs.values())

        if enabled_only:
            jobs = [j for j in jobs if j.enabled]

        if tag:
            jobs = [j for j in jobs if tag in j.tags]

        return sorted(jobs, key=lambda j: j.next_run or datetime.max)

    def enable_job(self, job_id: str) -> bool:
        """تفعيل مهمة"""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = True
            self._jobs[job_id]._calculate_next_run()
            self._save()
            return True
        return False

    def disable_job(self, job_id: str) -> bool:
        """تعطيل مهمة"""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = False
            self._jobs[job_id].next_run = None
            self._save()
            return True
        return False

    async def start(self) -> None:
        """بدء المجدول"""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Scheduler started")

    async def stop(self) -> None:
        """إيقاف المجدول"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Scheduler stopped")

    async def _run_loop(self) -> None:
        """حلقة التشغيل"""
        while self._running:
            try:
                now = datetime.now()

                for job in self._jobs.values():
                    if job.should_run(now):
                        await self._execute_job(job)

                # Check every minute
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Scheduler error: %s", e)
                await asyncio.sleep(60)

    async def _execute_job(self, job: ScheduledJob) -> None:
        """تنفيذ مهمة"""
        logger.info("Executing scheduled job: %s", job.name)

        error = None
        try:
            if self.run_callback:
                result = self.run_callback(job.scan_spec)
                if asyncio.iscoroutine(result):
                    await result
        except Exception as e:
            error = str(e)
            logger.error("Job %s failed: %s", job.name, e)

        job.mark_run(error)
        self._save()

    def _save(self) -> None:
        """حفظ المهام"""
        if not self.storage_path:
            return

        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        data = {job_id: job.to_dict() for job_id, job in self._jobs.items()}

        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load(self) -> int:
        """تحميل المهام"""
        if not self.storage_path or not self.storage_path.exists():
            return 0

        with open(self.storage_path, "r") as f:
            data = json.load(f)

        for job_id, job_data in data.items():
            job_data["scan_spec"] = job_data.get("scan_spec", {})
            self._jobs[job_id] = ScheduledJob.from_dict(job_data)

        logger.info("Loaded %d scheduled jobs", len(self._jobs))
        return len(self._jobs)

    def stats(self) -> Dict[str, Any]:
        """إحصائيات"""
        jobs = list(self._jobs.values())

        return {
            "total_jobs": len(jobs),
            "enabled_jobs": sum(1 for j in jobs if j.enabled),
            "total_runs": sum(j.run_count for j in jobs),
            "jobs_with_errors": sum(1 for j in jobs if j.last_error),
            "next_job": min(
                (j for j in jobs if j.next_run),
                key=lambda j: j.next_run,
                default=None,
            ),
        }


# ═══════════════════════════════════════════════════════════
#                     CLI Helpers
# ═══════════════════════════════════════════════════════════


def format_schedule(job: ScheduledJob) -> str:
    """تنسيق الجدول للعرض"""
    if job.trigger_type == JobTriggerType.CRON:
        return f"Cron: {job.cron_expression}"
    elif job.trigger_type == JobTriggerType.INTERVAL:
        hours = job.interval_seconds // 3600
        minutes = (job.interval_seconds % 3600) // 60
        if hours > 0:
            return f"Every {hours}h {minutes}m"
        return f"Every {minutes}m"
    elif job.trigger_type == JobTriggerType.ONCE:
        return f"Once at {job.run_at}"
    return "Unknown"
