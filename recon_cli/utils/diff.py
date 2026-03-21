"""
Diff & Comparison - مقارنة نتائج الفحص

نظام لمقارنة نتائج الفحوصات عبر الزمن.

Features:
- مقارنة فحصين
- تتبع التغييرات
- اكتشاف التغييرات المهمة
- تقارير Diff

Example:
    >>> diff = ScanDiff()
    >>> changes = diff.compare(old_results, new_results)
    >>> print(diff.format_changes(changes))
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════
#                     Change Types
# ═══════════════════════════════════════════════════════════


class ChangeType(Enum):
    """نوع التغيير"""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


class Severity(Enum):
    """خطورة التغيير"""

    CRITICAL = "critical"  # تغييرات أمنية حرجة
    HIGH = "high"  # تغييرات مهمة
    MEDIUM = "medium"  # تغييرات متوسطة
    LOW = "low"  # تغييرات بسيطة
    INFO = "info"  # معلومات فقط


@dataclass
class Change:
    """تغيير واحد"""

    change_type: ChangeType
    category: str
    key: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    severity: Severity = Severity.INFO
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.change_type.value,
            "category": self.category,
            "key": self.key,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "severity": self.severity.value,
            "details": self.details,
        }


@dataclass
class DiffSummary:
    """ملخص المقارنة"""

    total_changes: int = 0
    added: int = 0
    removed: int = 0
    modified: int = 0

    by_category: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)

    critical_changes: List[Change] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_changes": self.total_changes,
            "added": self.added,
            "removed": self.removed,
            "modified": self.modified,
            "by_category": self.by_category,
            "by_severity": self.by_severity,
            "critical_count": len(self.critical_changes),
        }


# ═══════════════════════════════════════════════════════════
#                     Result Normalizer
# ═══════════════════════════════════════════════════════════


class ResultNormalizer:
    """
    تطبيع النتائج للمقارنة.

    يحول نتائج الفحص إلى صيغة موحدة قابلة للمقارنة.
    """

    # Fields to ignore when comparing
    IGNORE_FIELDS = {
        "timestamp",
        "scan_time",
        "duration",
        "scan_id",
        "job_id",
        "worker_id",
        "temp_file",
    }

    # Fields that identify a record
    KEY_FIELDS = {
        "subdomain": ["host", "subdomain", "domain"],
        "endpoint": ["url", "path", "endpoint"],
        "vulnerability": ["id", "name", "type", "cve"],
        "port": ["host", "port", "protocol"],
        "secret": ["file", "line", "type"],
    }

    def normalize(
        self,
        results: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        تطبيع النتائج.

        Returns:
            {category: {key: record}}
        """
        normalized: Dict[str, Dict[str, Any]] = defaultdict(dict)

        for record in results:
            category = self._detect_category(record)
            key = self._generate_key(record, category)
            clean_record = self._clean_record(record)

            normalized[category][key] = clean_record

        return dict(normalized)

    def _detect_category(self, record: Dict[str, Any]) -> str:
        """اكتشاف فئة السجل"""
        # Check for explicit category
        if "category" in record:
            return record["category"]

        # Detect by fields
        if any(k in record for k in ["cve", "severity", "vulnerability"]):
            return "vulnerability"

        if any(k in record for k in ["port", "service"]):
            return "port"

        if any(k in record for k in ["subdomain", "host"]):
            return "subdomain"

        if any(k in record for k in ["url", "endpoint", "path"]):
            return "endpoint"

        if any(k in record for k in ["secret", "password", "api_key"]):
            return "secret"

        return "other"

    def _generate_key(self, record: Dict[str, Any], category: str) -> str:
        """توليد مفتاح فريد للسجل"""
        key_fields = self.KEY_FIELDS.get(category, ["id", "name"])

        key_parts = []
        for fname in key_fields:
            if fname in record:
                key_parts.append(f"{fname}={record[fname]}")

        if not key_parts:
            # Fallback: hash of content
            import hashlib

            content = json.dumps(record, sort_keys=True)
            return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:12]

        return "|".join(key_parts)

    def _clean_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """تنظيف السجل من الحقول غير المهمة"""
        return {k: v for k, v in record.items() if k not in self.IGNORE_FIELDS}


# ═══════════════════════════════════════════════════════════
#                     Scan Diff
# ═══════════════════════════════════════════════════════════


class ScanDiff:
    """
    مقارنة نتائج الفحوصات.

    Example:
        >>> diff = ScanDiff()
        >>> changes = diff.compare(old_results, new_results)
        >>> summary = diff.summarize(changes)
        >>> report = diff.format_report(changes, summary)
    """

    # Severity rules based on category and change type
    SEVERITY_RULES = {
        ("vulnerability", ChangeType.ADDED): Severity.CRITICAL,
        ("vulnerability", ChangeType.REMOVED): Severity.MEDIUM,
        ("secret", ChangeType.ADDED): Severity.CRITICAL,
        ("port", ChangeType.ADDED): Severity.HIGH,
        ("subdomain", ChangeType.ADDED): Severity.MEDIUM,
        ("endpoint", ChangeType.ADDED): Severity.LOW,
    }

    def __init__(self, normalizer: Optional[ResultNormalizer] = None):
        self.normalizer = normalizer or ResultNormalizer()

    def compare(
        self,
        old_results: List[Dict[str, Any]],
        new_results: List[Dict[str, Any]],
    ) -> List[Change]:
        """
        مقارنة نتيجتين.

        Args:
            old_results: النتائج القديمة
            new_results: النتائج الجديدة

        Returns:
            قائمة التغييرات
        """
        # Normalize both results
        old_normalized = self.normalizer.normalize(old_results)
        new_normalized = self.normalizer.normalize(new_results)

        changes = []

        # Get all categories
        all_categories = set(old_normalized.keys()) | set(new_normalized.keys())

        for category in all_categories:
            old_cat = old_normalized.get(category, {})
            new_cat = new_normalized.get(category, {})

            # Find added
            for key in set(new_cat.keys()) - set(old_cat.keys()):
                changes.append(
                    Change(
                        change_type=ChangeType.ADDED,
                        category=category,
                        key=key,
                        new_value=new_cat[key],
                        severity=self._get_severity(category, ChangeType.ADDED),
                    )
                )

            # Find removed
            for key in set(old_cat.keys()) - set(new_cat.keys()):
                changes.append(
                    Change(
                        change_type=ChangeType.REMOVED,
                        category=category,
                        key=key,
                        old_value=old_cat[key],
                        severity=self._get_severity(category, ChangeType.REMOVED),
                    )
                )

            # Find modified
            for key in set(old_cat.keys()) & set(new_cat.keys()):
                if old_cat[key] != new_cat[key]:
                    field_changes = self._compare_records(old_cat[key], new_cat[key])
                    changes.append(
                        Change(
                            change_type=ChangeType.MODIFIED,
                            category=category,
                            key=key,
                            old_value=old_cat[key],
                            new_value=new_cat[key],
                            severity=self._get_severity(category, ChangeType.MODIFIED),
                            details={"field_changes": field_changes},
                        )
                    )

        return changes

    def _compare_records(
        self,
        old: Dict[str, Any],
        new: Dict[str, Any],
    ) -> Dict[str, Tuple[Any, Any]]:
        """مقارنة سجلين"""
        changes = {}
        all_keys = set(old.keys()) | set(new.keys())

        for key in all_keys:
            old_val = old.get(key)
            new_val = new.get(key)

            if old_val != new_val:
                changes[key] = (old_val, new_val)

        return changes

    def _get_severity(
        self,
        category: str,
        change_type: ChangeType,
    ) -> Severity:
        """تحديد خطورة التغيير"""
        return self.SEVERITY_RULES.get((category, change_type), Severity.INFO)

    def summarize(self, changes: List[Change]) -> DiffSummary:
        """ملخص التغييرات"""
        summary = DiffSummary()
        summary.total_changes = len(changes)

        for change in changes:
            # Count by type
            if change.change_type == ChangeType.ADDED:
                summary.added += 1
            elif change.change_type == ChangeType.REMOVED:
                summary.removed += 1
            elif change.change_type == ChangeType.MODIFIED:
                summary.modified += 1

            # Count by category
            cat = change.category
            summary.by_category[cat] = summary.by_category.get(cat, 0) + 1

            # Count by severity
            sev = change.severity.value
            summary.by_severity[sev] = summary.by_severity.get(sev, 0) + 1

            # Track critical
            if change.severity in (Severity.CRITICAL, Severity.HIGH):
                summary.critical_changes.append(change)

        return summary

    def format_report(
        self,
        changes: List[Change],
        summary: Optional[DiffSummary] = None,
    ) -> str:
        """تنسيق تقرير المقارنة"""
        if summary is None:
            summary = self.summarize(changes)

        lines = []
        lines.append("=" * 60)
        lines.append("           SCAN COMPARISON REPORT")
        lines.append("=" * 60)
        lines.append("")

        # Summary
        lines.append("📊 Summary")
        lines.append("-" * 40)
        lines.append(f"  Total Changes: {summary.total_changes}")
        lines.append(f"  ➕ Added:      {summary.added}")
        lines.append(f"  ➖ Removed:    {summary.removed}")
        lines.append(f"  📝 Modified:   {summary.modified}")
        lines.append("")

        # By category
        if summary.by_category:
            lines.append("📂 By Category")
            lines.append("-" * 40)
            for cat, count in sorted(summary.by_category.items()):
                lines.append(f"  {cat}: {count}")
            lines.append("")

        # Critical changes
        if summary.critical_changes:
            lines.append("🚨 CRITICAL CHANGES")
            lines.append("-" * 40)
            for change in summary.critical_changes:
                icon = "➕" if change.change_type == ChangeType.ADDED else "➖"
                lines.append(f"  {icon} [{change.category}] {change.key}")
            lines.append("")

        # Detailed changes by category
        lines.append("📋 Detailed Changes")
        lines.append("-" * 40)

        by_category = defaultdict(list)
        for change in changes:
            by_category[change.category].append(change)

        for category, cat_changes in sorted(by_category.items()):
            lines.append(f"\n  {category.upper()}")
            lines.append("  " + "-" * 30)

            for change in cat_changes[:10]:  # Limit per category
                icon = self._get_change_icon(change.change_type)
                sev = (
                    f"[{change.severity.value}]"
                    if change.severity != Severity.INFO
                    else ""
                )
                lines.append(f"    {icon} {change.key} {sev}")

            if len(cat_changes) > 10:
                lines.append(f"    ... and {len(cat_changes) - 10} more")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)

    def _get_change_icon(self, change_type: ChangeType) -> str:
        """أيقونة التغيير"""
        icons = {
            ChangeType.ADDED: "➕",
            ChangeType.REMOVED: "➖",
            ChangeType.MODIFIED: "📝",
            ChangeType.UNCHANGED: "⚪",
        }
        return icons.get(change_type, "•")


# ═══════════════════════════════════════════════════════════
#                     History Tracker
# ═══════════════════════════════════════════════════════════


@dataclass
class ScanSnapshot:
    """لقطة فحص"""

    scan_id: str
    timestamp: datetime
    target: str
    results_file: Path
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "target": self.target,
            "results_file": str(self.results_file),
            "summary": self.summary,
        }


class HistoryTracker:
    """
    تتبع تاريخ الفحوصات.

    يحفظ لقطات من الفحوصات للمقارنة المستقبلية.

    Example:
        >>> tracker = HistoryTracker(Path("./history"))
        >>> tracker.save_snapshot("scan-123", "example.com", results)
        >>>
        >>> # مقارنة مع آخر فحص
        >>> changes = tracker.compare_with_latest("example.com", new_results)
    """

    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self._index_file = self.storage_dir / "index.json"
        self._index: Dict[str, List[ScanSnapshot]] = self._load_index()

    def save_snapshot(
        self,
        scan_id: str,
        target: str,
        results: List[Dict[str, Any]],
    ) -> ScanSnapshot:
        """حفظ لقطة فحص"""
        timestamp = datetime.now()

        # Save results
        target_dir = self.storage_dir / self._safe_name(target)
        target_dir.mkdir(parents=True, exist_ok=True)

        results_file = target_dir / f"{scan_id}.json"
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # Create snapshot
        snapshot = ScanSnapshot(
            scan_id=scan_id,
            timestamp=timestamp,
            target=target,
            results_file=results_file,
            summary=self._summarize_results(results),
        )

        # Update index
        if target not in self._index:
            self._index[target] = []
        self._index[target].append(snapshot)
        self._save_index()

        logger.info("Saved snapshot: %s for %s", scan_id, target)
        return snapshot

    def get_snapshots(
        self,
        target: str,
        limit: Optional[int] = None,
    ) -> List[ScanSnapshot]:
        """الحصول على لقطات هدف"""
        snapshots = self._index.get(target, [])
        snapshots = sorted(snapshots, key=lambda s: s.timestamp, reverse=True)

        if limit:
            snapshots = snapshots[:limit]

        return snapshots

    def get_latest(self, target: str) -> Optional[ScanSnapshot]:
        """آخر لقطة لهدف"""
        snapshots = self.get_snapshots(target, limit=1)
        return snapshots[0] if snapshots else None

    def load_results(self, snapshot: ScanSnapshot) -> List[Dict[str, Any]]:
        """تحميل نتائج لقطة"""
        with open(snapshot.results_file, "r") as f:
            return json.load(f)

    def compare_with_latest(
        self,
        target: str,
        new_results: List[Dict[str, Any]],
    ) -> Optional[List[Change]]:
        """مقارنة مع آخر لقطة"""
        latest = self.get_latest(target)
        if not latest:
            return None

        old_results = self.load_results(latest)
        diff = ScanDiff()
        return diff.compare(old_results, new_results)

    def compare_snapshots(
        self,
        snapshot1: ScanSnapshot,
        snapshot2: ScanSnapshot,
    ) -> List[Change]:
        """مقارنة لقطتين"""
        results1 = self.load_results(snapshot1)
        results2 = self.load_results(snapshot2)

        diff = ScanDiff()
        return diff.compare(results1, results2)

    def get_trend(
        self,
        target: str,
        days: int = 30,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """اتجاهات التغيير"""
        snapshots = self.get_snapshots(target)

        # Filter by date
        cutoff = datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=days)

        snapshots = [s for s in snapshots if s.timestamp >= cutoff]

        if len(snapshots) < 2:
            return {"error": "Not enough snapshots for trend analysis"}

        # Calculate trends
        trends: Dict[str, Any] = {
            "dates": [],
            "total_findings": [],
            "by_category": defaultdict(list),
        }

        for snapshot in reversed(snapshots):  # Oldest first
            trends["dates"].append(snapshot.timestamp.isoformat())

            total = sum(snapshot.summary.values())
            trends["total_findings"].append(total)

            for cat, count in snapshot.summary.items():
                trends["by_category"][cat].append(count)

        return dict(trends)

    def cleanup(self, target: str, keep: int = 10) -> int:
        """تنظيف اللقطات القديمة"""
        snapshots = self._index.get(target, [])

        if len(snapshots) <= keep:
            return 0

        # Sort and remove old
        snapshots = sorted(snapshots, key=lambda s: s.timestamp, reverse=True)
        to_remove = snapshots[keep:]

        removed = 0
        for snapshot in to_remove:
            try:
                snapshot.results_file.unlink()
                removed += 1
            except Exception as e:
                logger.warning("Failed to remove %s: %s", snapshot.results_file, e)

        self._index[target] = snapshots[:keep]
        self._save_index()

        return removed

    def _safe_name(self, name: str) -> str:
        """اسم آمن للملف"""
        return "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)

    def _summarize_results(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """ملخص النتائج"""
        normalizer = ResultNormalizer()
        normalized = normalizer.normalize(results)

        return {cat: len(records) for cat, records in normalized.items()}

    def _load_index(self) -> Dict[str, List[ScanSnapshot]]:
        """تحميل الفهرس"""
        if not self._index_file.exists():
            return {}

        with open(self._index_file, "r") as f:
            data = json.load(f)

        index = {}
        for target, snapshots in data.items():
            index[target] = [
                ScanSnapshot(
                    scan_id=s["scan_id"],
                    timestamp=datetime.fromisoformat(s["timestamp"]),
                    target=s["target"],
                    results_file=Path(s["results_file"]),
                    summary=s.get("summary", {}),
                )
                for s in snapshots
            ]

        return index

    def _save_index(self) -> None:
        """حفظ الفهرس"""
        data = {
            target: [s.to_dict() for s in snapshots]
            for target, snapshots in self._index.items()
        }

        with open(self._index_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
