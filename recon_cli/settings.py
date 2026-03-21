"""
Unified Settings - إعدادات موحدة

نظام إعدادات مركزي باستخدام Pydantic للتحقق والتحميل.

Features:
- تحميل من environment variables
- تحميل من ملف .env
- تحميل من YAML/JSON
- تحقق تلقائي
- قيم افتراضية ذكية

Example:
    >>> from recon_cli.settings import settings
    >>> print(settings.max_concurrent)
    50
    >>> print(settings.api.port)
    8080
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Literal, Optional, Set, Union

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    SecretStr,
)

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    # Fallback for older pydantic
    from pydantic import BaseSettings

    SettingsConfigDict = None


# ═══════════════════════════════════════════════════════════
#                     Sub-Settings Models
# ═══════════════════════════════════════════════════════════


class DatabaseSettings(BaseModel):
    """إعدادات قاعدة البيانات"""

    path: Path = Field(default=Path("data/recon.db"), description="مسار ملف SQLite")
    pool_size: int = Field(default=5, ge=1, le=20, description="حجم connection pool")
    timeout: float = Field(
        default=30.0, ge=1.0, le=300.0, description="timeout للاستعلامات بالثواني"
    )
    wal_mode: bool = Field(default=True, description="استخدام WAL mode للأداء")

    @field_validator("path")
    @classmethod
    def ensure_parent_exists(cls, v: Path) -> Path:
        v.parent.mkdir(parents=True, exist_ok=True)
        return v


class APISettings(BaseModel):
    """إعدادات الـ API"""

    host: str = Field(default="127.0.0.1", description="عنوان الاستماع")
    port: int = Field(default=8080, ge=1024, le=65535, description="المنفذ")
    workers: int = Field(default=4, ge=1, le=32, description="عدد workers")
    cors_origins: List[str] = Field(default=["*"], description="CORS origins المسموحة")
    rate_limit: int = Field(
        default=100, ge=1, description="الحد الأقصى للطلبات في الدقيقة"
    )
    api_key: Optional[SecretStr] = Field(
        default=None, description="مفتاح API (اختياري)"
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        if v not in ("0.0.0.0", "127.0.0.1", "localhost") and not v.startswith( # nosec B104
            "192.168."
        ):
            # Allow any IP but warn about public binding
            pass
        return v


class PipelineSettings(BaseModel):
    """إعدادات الـ Pipeline"""

    max_concurrent: int = Field(
        default=50, ge=1, le=500, description="الحد الأقصى للعمليات المتزامنة"
    )
    stage_timeout: float = Field(
        default=3600.0, ge=60.0, description="timeout للمرحلة بالثواني"
    )
    retry_attempts: int = Field(
        default=3, ge=0, le=10, description="عدد محاولات الإعادة"
    )
    retry_delay: float = Field(default=5.0, ge=1.0, description="التأخير بين المحاولات")
    parallel_stages: bool = Field(
        default=True, description="تنفيذ المراحل المستقلة بالتوازي"
    )
    save_intermediate: bool = Field(default=True, description="حفظ النتائج الوسيطة")
    gc_between_stages: bool = Field(default=True, description="تشغيل GC بين المراحل")


class HTTPSettings(BaseModel):
    """إعدادات HTTP"""

    timeout: float = Field(
        default=30.0, ge=5.0, le=300.0, description="timeout للطلبات"
    )
    max_connections: int = Field(
        default=100, ge=10, le=1000, description="الحد الأقصى للاتصالات"
    )
    max_per_host: int = Field(
        default=10, ge=1, le=100, description="الحد الأقصى للاتصالات لكل host"
    )
    verify_ssl: bool = Field(default=True, description="التحقق من SSL")
    follow_redirects: bool = Field(default=True, description="متابعة redirects")
    max_redirects: int = Field(
        default=10, ge=0, le=50, description="الحد الأقصى للـ redirects"
    )
    user_agent: str = Field(default="recon-cli/1.0", description="User-Agent header")

    @model_validator(mode="after")
    def validate_connections(self) -> "HTTPSettings":
        if self.max_per_host > self.max_connections:
            self.max_per_host = self.max_connections
        return self


class DNSSettings(BaseModel):
    """إعدادات DNS"""

    resolvers: List[str] = Field(
        default=["8.8.8.8", "1.1.1.1", "9.9.9.9"], description="قائمة resolvers"
    )
    timeout: float = Field(
        default=5.0, ge=1.0, le=30.0, description="timeout للاستعلام"
    )
    retries: int = Field(default=2, ge=0, le=5, description="عدد المحاولات")
    cache_ttl: int = Field(
        default=300, ge=60, le=86400, description="TTL للـ cache بالثواني"
    )
    max_concurrent: int = Field(
        default=100, ge=10, le=500, description="استعلامات متزامنة"
    )


class ToolsSettings(BaseModel):
    """إعدادات الأدوات الخارجية"""

    path: Path = Field(default=Path("/usr/local/bin"), description="مسار الأدوات")
    timeout: float = Field(default=300.0, ge=30.0, description="timeout للأدوات")

    # أدوات محددة
    subfinder: Optional[Path] = None
    httpx: Optional[Path] = None
    nuclei: Optional[Path] = None
    naabu: Optional[Path] = None
    katana: Optional[Path] = None

    @model_validator(mode="after")
    def find_tools(self) -> "ToolsSettings":
        """البحث عن الأدوات تلقائياً"""
        import shutil

        tools = ["subfinder", "httpx", "nuclei", "naabu", "katana"]
        for tool in tools:
            if getattr(self, tool) is None:
                found = shutil.which(tool)
                if found:
                    setattr(self, tool, Path(found))
        return self


class SecretsSettings(BaseModel):
    """إعدادات فحص الأسرار"""

    min_entropy: float = Field(
        default=3.5, ge=2.0, le=5.0, description="الحد الأدنى للـ entropy"
    )
    max_file_size: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        ge=1024,
        description="الحد الأقصى لحجم الملف",
    )
    scan_extensions: Set[str] = Field(
        default={".js", ".json", ".xml", ".yaml", ".yml", ".env", ".config"},
        description="الامتدادات للفحص",
    )
    exclude_patterns: List[str] = Field(
        default=["node_modules", ".git", "__pycache__"], description="أنماط للاستبعاد"
    )


class NotificationSettings(BaseModel):
    """إعدادات الإشعارات"""

    enabled: bool = Field(default=False, description="تفعيل الإشعارات")

    # Slack
    slack_webhook: Optional[SecretStr] = None
    slack_channel: Optional[str] = None

    # Discord
    discord_webhook: Optional[SecretStr] = None

    # Telegram
    telegram_token: Optional[SecretStr] = None
    telegram_chat_id: Optional[str] = None

    # Email
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[SecretStr] = None
    email_to: Optional[str] = None

    # Alert thresholds
    alert_on_critical: bool = True
    alert_on_high: bool = True
    alert_on_medium: bool = False
    alert_on_error: bool = True


class LoggingSettings(BaseModel):
    """إعدادات التسجيل"""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="مستوى التسجيل"
    )
    format: Literal["text", "json"] = Field(default="text", description="تنسيق السجلات")
    file: Optional[Path] = Field(default=None, description="ملف السجلات")
    max_size: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="الحد الأقصى لحجم الملف",
    )
    backup_count: int = Field(
        default=5, ge=0, le=100, description="عدد النسخ الاحتياطية"
    )
    include_timestamps: bool = True
    include_trace_id: bool = True


class JobsSettings(BaseModel):
    """إعدادات الـ Jobs"""

    base_path: Path = Field(default=Path("jobs"), description="مسار الـ jobs")
    max_concurrent_jobs: int = Field(
        default=5, ge=1, le=20, description="الحد الأقصى للـ jobs المتزامنة"
    )
    cleanup_after_days: int = Field(
        default=30, ge=1, description="حذف الـ jobs القديمة بعد أيام"
    )
    auto_cleanup: bool = Field(default=True, description="تنظيف تلقائي")


# ═══════════════════════════════════════════════════════════
#                     Main Settings Class
# ═══════════════════════════════════════════════════════════


class Settings(BaseSettings):
    """
    الإعدادات الرئيسية للتطبيق.

    يمكن تحميلها من:
    - Environment variables (RECON_*)
    - ملف .env
    - ملف config.yaml

    Example:
        >>> settings = Settings()
        >>> settings.pipeline.max_concurrent
        50

        # أو مع environment variables
        >>> # RECON_PIPELINE__MAX_CONCURRENT=100
        >>> settings = Settings()
        >>> settings.pipeline.max_concurrent
        100
    """

    if SettingsConfigDict:
        model_config = SettingsConfigDict(
            env_prefix="RECON_",
            env_nested_delimiter="__",
            env_file=".env",
            env_file_encoding="utf-8",
            case_sensitive=False,
            extra="ignore",
        )

    # Application info
    app_name: str = "ReconnV2"
    version: str = "1.0.0"
    debug: bool = False

    # Sub-settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    api: APISettings = Field(default_factory=APISettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    http: HTTPSettings = Field(default_factory=HTTPSettings)
    dns: DNSSettings = Field(default_factory=DNSSettings)
    tools: ToolsSettings = Field(default_factory=ToolsSettings)
    secrets: SecretsSettings = Field(default_factory=SecretsSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    jobs: JobsSettings = Field(default_factory=JobsSettings)

    # Paths
    config_path: Path = Field(
        default=Path("config"), description="مسار ملفات الإعدادات"
    )
    data_path: Path = Field(default=Path("data"), description="مسار البيانات")

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "Settings":
        """
        تحميل الإعدادات من ملف YAML.

        Args:
            path: مسار الملف

        Returns:
            Settings instance
        """
        import yaml

        path = Path(path)
        if not path.exists():
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls(**data)

    @classmethod
    def from_json(cls, path: Union[str, Path]) -> "Settings":
        """
        تحميل الإعدادات من ملف JSON.

        Args:
            path: مسار الملف

        Returns:
            Settings instance
        """
        import json

        path = Path(path)
        if not path.exists():
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return cls(**data)

    def to_yaml(self, path: Union[str, Path]) -> None:
        """حفظ الإعدادات إلى YAML"""
        import yaml

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self.model_dump(mode="json", exclude_none=True)

        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    def to_json(self, path: Union[str, Path]) -> None:
        """حفظ الإعدادات إلى JSON"""
        import json

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self.model_dump(mode="json", exclude_none=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_nested(self, key: str, default: Any = None) -> Any:
        """
        الحصول على قيمة متداخلة.

        Args:
            key: المفتاح بتنسيق "section.key"
            default: القيمة الافتراضية

        Example:
            >>> settings.get_nested("pipeline.max_concurrent")
            50
        """
        parts = key.split(".")
        value = self

        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            elif isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default

        return value


# ═══════════════════════════════════════════════════════════
#                     Singleton Instance
# ═══════════════════════════════════════════════════════════

_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    الحصول على instance الإعدادات.

    Returns:
        Settings singleton
    """
    global _settings

    if _settings is None:
        # Try to load from config file
        config_file = Path("config/settings.yaml")
        if config_file.exists():
            _settings = Settings.from_yaml(config_file)
        else:
            _settings = Settings()

    return _settings


def reload_settings() -> Settings:
    """إعادة تحميل الإعدادات"""
    global _settings
    _settings = None
    return get_settings()


# Convenience alias
settings = get_settings()
