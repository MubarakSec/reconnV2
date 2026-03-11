"""
Config Migration Tool - أداة ترحيل الإعدادات

تحويل ملفات الإعدادات القديمة إلى الإصدار الجديد.

Example:
    >>> migrator = ConfigMigrator("old_config.yaml")
    >>> migrator.migrate()
    >>> migrator.save("new_config.yaml")
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     Migration Rules
# ═══════════════════════════════════════════════════════════

@dataclass
class MigrationRule:
    """قاعدة ترحيل واحدة"""
    from_version: str
    to_version: str
    description: str
    transform: Callable[[dict], dict]


@dataclass
class MigrationResult:
    """نتيجة الترحيل"""
    success: bool
    from_version: str
    to_version: str
    changes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════
#                     Migration Functions
# ═══════════════════════════════════════════════════════════

def migrate_v0_to_v1(config: dict) -> dict:
    """
    ترحيل من v0 (بدون version) إلى v1.0.0
    """
    changes = []
    
    # Add version
    config["version"] = "1.0.0"
    changes.append("Added version field")
    
    # Rename old keys
    key_mappings = {
        "concurrent": ("pipeline", "max_concurrent"),
        "timeout": ("pipeline", "stage_timeout"),
        "db_path": ("database", "path"),
        "api_port": ("api", "port"),
        "api_host": ("api", "host"),
        "log_level": ("logging", "level"),
        "log_file": ("logging", "file"),
    }
    
    for old_key, (section, new_key) in key_mappings.items():
        if old_key in config:
            if section not in config:
                config[section] = {}
            config[section][new_key] = config.pop(old_key)
            changes.append(f"Moved {old_key} → {section}.{new_key}")
    
    # Convert flat structure to nested
    if "dns_resolvers" in config:
        if "dns" not in config:
            config["dns"] = {}
        resolvers = config.pop("dns_resolvers")
        if isinstance(resolvers, str):
            resolvers = [r.strip() for r in resolvers.split(",")]
        config["dns"]["resolvers"] = resolvers
        changes.append("Converted dns_resolvers to dns.resolvers array")
    
    # Normalize boolean values
    bool_keys = [
        ("pipeline", "parallel_stages"),
        ("pipeline", "save_intermediate"),
        ("http", "verify_ssl"),
        ("http", "follow_redirects"),
        ("notifications", "enabled"),
        ("logging", "include_timestamps"),
    ]
    
    for section, key in bool_keys:
        if section in config and key in config[section]:
            value = config[section][key]
            if isinstance(value, str):
                config[section][key] = value.lower() in ("true", "yes", "1", "on")
                changes.append(f"Converted {section}.{key} to boolean")
    
    config["_migration_changes"] = changes
    return config


def migrate_v1_to_v1_1(config: dict) -> dict:
    """
    ترحيل من v1.0.0 إلى v1.1.0
    """
    changes = []
    
    config["version"] = "1.1.0"
    
    # Add new sections with defaults
    if "secrets" not in config:
        config["secrets"] = {
            "min_entropy": 3.5,
            "max_file_size": 10485760,
            "scan_extensions": [".js", ".json", ".yaml", ".env"],
        }
        changes.append("Added secrets configuration section")
    
    # Rename notifications.webhook to notifications.slack_webhook
    if "notifications" in config:
        notif = config["notifications"]
        if "webhook" in notif and "slack_webhook" not in notif:
            notif["slack_webhook"] = notif.pop("webhook")
            changes.append("Renamed notifications.webhook → slack_webhook")
    
    # Add jobs section if missing
    if "jobs" not in config:
        config["jobs"] = {
            "base_path": "jobs",
            "max_concurrent_jobs": 5,
            "cleanup_after_days": 30,
            "auto_cleanup": True,
        }
        changes.append("Added jobs configuration section")
    
    config["_migration_changes"] = changes
    return config


# ═══════════════════════════════════════════════════════════
#                     Migration Registry
# ═══════════════════════════════════════════════════════════

MIGRATIONS: List[MigrationRule] = [
    MigrationRule(
        from_version="0.0.0",
        to_version="1.0.0",
        description="Initial migration to structured config",
        transform=migrate_v0_to_v1,
    ),
    MigrationRule(
        from_version="1.0.0",
        to_version="1.1.0",
        description="Add secrets and jobs sections",
        transform=migrate_v1_to_v1_1,
    ),
]


# ═══════════════════════════════════════════════════════════
#                     Config Migrator
# ═══════════════════════════════════════════════════════════

class ConfigMigrator:
    """
    مُرحّل الإعدادات.
    
    Example:
        >>> migrator = ConfigMigrator("config/old.yaml")
        >>> result = migrator.migrate()
        >>> if result.success:
        ...     migrator.save("config/settings.yaml")
    """
    
    CURRENT_VERSION = "1.1.0"
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Args:
            config_path: مسار ملف الإعدادات
        """
        self.config_path = Path(config_path) if config_path else None
        self.config: dict = {}
        self.original_config: dict = {}
        self._result: Optional[MigrationResult] = None
        
        if self.config_path and self.config_path.exists():
            self.load(self.config_path)
    
    def load(self, path: Path) -> None:
        """تحميل الإعدادات"""
        import yaml
        
        self.config_path = Path(path)
        
        with open(path, "r", encoding="utf-8") as f:
            if path.suffix == ".json":
                self.config = json.load(f)
            else:
                self.config = yaml.safe_load(f) or {}
        
        # Keep original for backup
        self.original_config = self.config.copy()
    
    def get_version(self) -> str:
        """الحصول على إصدار الإعدادات"""
        return self.config.get("version", "0.0.0")
    
    def needs_migration(self) -> bool:
        """هل تحتاج الإعدادات للترحيل"""
        return self.get_version() != self.CURRENT_VERSION
    
    def _find_migration_path(
        self,
        from_version: str,
        to_version: str,
    ) -> List[MigrationRule]:
        """إيجاد مسار الترحيل"""
        path = []
        current = from_version
        
        while current != to_version:
            # Find next migration
            found = False
            for migration in MIGRATIONS:
                if migration.from_version == current:
                    path.append(migration)
                    current = migration.to_version
                    found = True
                    break
            
            if not found:
                break
        
        return path
    
    def migrate(self, target_version: Optional[str] = None) -> MigrationResult:
        """
        تنفيذ الترحيل.
        
        Args:
            target_version: الإصدار المستهدف (افتراضي: الأحدث)
            
        Returns:
            MigrationResult
        """
        target = target_version or self.CURRENT_VERSION
        current = self.get_version()
        
        if current == target:
            return MigrationResult(
                success=True,
                from_version=current,
                to_version=target,
                changes=["No migration needed"],
            )
        
        # Find migration path
        migrations = self._find_migration_path(current, target)
        
        if not migrations:
            return MigrationResult(
                success=False,
                from_version=current,
                to_version=target,
                errors=[f"No migration path found from {current} to {target}"],
            )
        
        # Execute migrations
        all_changes = []
        all_warnings = []
        
        for migration in migrations:
            logger.info(
                "Applying migration: %s → %s (%s)",
                migration.from_version,
                migration.to_version,
                migration.description,
            )
            
            try:
                self.config = migration.transform(self.config)
                
                # Extract changes
                changes = self.config.pop("_migration_changes", [])
                all_changes.extend(changes)
                
            except Exception as e:
                return MigrationResult(
                    success=False,
                    from_version=current,
                    to_version=target,
                    changes=all_changes,
                    errors=[f"Migration failed at {migration.from_version}: {e}"],
                )
        
        self._result = MigrationResult(
            success=True,
            from_version=current,
            to_version=target,
            changes=all_changes,
            warnings=all_warnings,
        )
        
        return self._result
    
    def save(
        self,
        path: Optional[Path] = None,
        backup: bool = True,
    ) -> Path:
        """
        حفظ الإعدادات المُرحّلة.
        
        Args:
            path: مسار الحفظ (افتراضي: المسار الأصلي)
            backup: إنشاء نسخة احتياطية
            
        Returns:
            مسار الملف المحفوظ
        """
        import yaml
        
        save_path = Path(path) if path else self.config_path
        
        if not save_path:
            raise ValueError("No save path specified")
        
        # Create backup
        if backup and save_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = save_path.with_suffix(f".backup_{timestamp}{save_path.suffix}")
            shutil.copy(save_path, backup_path)
            logger.info("Created backup: %s", backup_path)
        
        # Save
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(save_path, "w", encoding="utf-8") as f:
            if save_path.suffix == ".json":
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            else:
                yaml.dump(
                    self.config,
                    f,
                    default_flow_style=False,
                    allow_unicode=True,
                )
        
        logger.info("Saved migrated config to: %s", save_path)
        return save_path
    
    def validate(self) -> Tuple[bool, List[str]]:
        """
        التحقق من صحة الإعدادات.
        
        Returns:
            (is_valid, errors)
        """
        errors = []
        
        # Check required sections
        required_sections = ["pipeline", "http", "logging"]
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: {section}")
        
        # Validate types
        type_checks = [
            ("pipeline.max_concurrent", int),
            ("pipeline.stage_timeout", (int, float)),
            ("http.timeout", (int, float)),
            ("http.max_connections", int),
            ("logging.level", str),
        ]
        
        for key_path, expected_type in type_checks:
            parts = key_path.split(".")
            value = self.config
            
            try:
                for part in parts:
                    value = value[part]
                
                if not isinstance(value, expected_type):
                    errors.append(
                        f"{key_path} should be {expected_type.__name__}, "
                        f"got {type(value).__name__}"
                    )
            except KeyError:
                pass  # Optional field
        
        # Validate ranges
        range_checks = [
            ("pipeline.max_concurrent", 1, 500),
            ("http.max_connections", 10, 1000),
            ("api.port", 1024, 65535),
        ]
        
        for key_path, min_val, max_val in range_checks:
            parts = key_path.split(".")
            value = self.config
            
            try:
                for part in parts:
                    value = value[part]
                
                if isinstance(value, (int, float)):
                    if value < min_val or value > max_val:
                        errors.append(
                            f"{key_path} should be between {min_val} and {max_val}, "
                            f"got {value}"
                        )
            except KeyError:
                pass
        
        return len(errors) == 0, errors


# ═══════════════════════════════════════════════════════════
#                     CLI Interface
# ═══════════════════════════════════════════════════════════

def migrate_config(
    source: str,
    target: Optional[str] = None,
    backup: bool = True,
    dry_run: bool = False,
) -> bool:
    """
    واجهة الترحيل.
    
    Args:
        source: ملف الإعدادات المصدر
        target: ملف الإعدادات الهدف
        backup: إنشاء نسخة احتياطية
        dry_run: عرض التغييرات فقط بدون حفظ
        
    Returns:
        True if successful
    """
    migrator = ConfigMigrator(source)
    
    if not migrator.needs_migration():
        print(f"✅ Config is already at version {migrator.get_version()}")
        return True
    
    print(f"📦 Current version: {migrator.get_version()}")
    print(f"🎯 Target version: {ConfigMigrator.CURRENT_VERSION}")
    
    result = migrator.migrate()
    
    if not result.success:
        print("❌ Migration failed:")
        for error in result.errors:
            print(f"  • {error}")
        return False
    
    print("\n✅ Migration successful!")
    print("\n📝 Changes made:")
    for change in result.changes:
        print(f"  • {change}")
    
    if result.warnings:
        print("\n⚠️ Warnings:")
        for warning in result.warnings:
            print(f"  • {warning}")
    
    # Validate
    is_valid, validation_errors = migrator.validate()
    if not is_valid:
        print("\n⚠️ Validation warnings:")
        for error in validation_errors:
            print(f"  • {error}")
    
    if dry_run:
        print("\n🔍 Dry run mode - no changes saved")
        return True
    
    # Save
    save_path = migrator.save(target, backup=backup)
    print(f"\n💾 Saved to: {save_path}")
    
    return True


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python config_migrate.py <config_file> [--dry-run]")
        sys.exit(1)
    
    source = sys.argv[1]
    dry_run = "--dry-run" in sys.argv
    
    success = migrate_config(source, dry_run=dry_run)
    sys.exit(0 if success else 1)
