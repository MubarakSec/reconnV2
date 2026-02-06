from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Pattern
from urllib.parse import urlparse
import re

from recon_cli import config
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.jobs.results import ResultsTracker
from recon_cli.tools.executor import CommandExecutor
from recon_cli.utils import fs
from recon_cli.utils.logging import build_file_logger, silence_logger


@dataclass
class PipelineContext:
    record: Optional[JobRecord] = None
    manager: Optional[JobManager] = None
    force: bool = False
    runtime_config: Optional[config.RuntimeConfig] = None
    max_retries: Optional[int] = None
    logger_name: str = "recon.pipeline"
    job_id: Optional[str] = None
    targets: List[str] = field(default_factory=list)
    work_dir: Optional[Path] = None
    results_file: Optional[Path] = None
    concurrency: Optional[int] = None
    rate_limit: Optional[float] = None
    execution_profile: Optional[str] = field(init=False, default=None)
    _url_allow_pattern: Optional[Pattern[str]] = field(init=False, default=None)
    _delta_cache: Dict[str, Dict[str, str]] = field(init=False, default_factory=dict)
    _cache_path: Path = field(init=False)
    _cache_dirty: bool = field(init=False, default=False)
    _simple_mode: bool = field(init=False, default=False)
    _data_store: Dict[str, object] = field(init=False, default_factory=dict)
    _rate_limiters: Dict[str, object] = field(init=False, default_factory=dict)
    _auth_manager: object = field(init=False, default=None)

    def __post_init__(self) -> None:
        if self.record is None:
            self._simple_mode = True
            if self.job_id is None:
                self.job_id = "job"
            if self.work_dir is not None and self.results_file is None:
                self.results_file = self.work_dir / "results.jsonl"
            base_dir = self.work_dir or Path.cwd()
            self._cache_path = base_dir / "cache.json"
            return
        if self.manager is None:
            self.manager = JobManager()
        spec = self.record.spec
        overrides = getattr(spec, 'runtime_overrides', {}) or {}
        base_config = config.RuntimeConfig()
        if getattr(spec, "insecure", False):
            overrides = {**overrides, "verify_tls": False}
        if overrides:
            base_config = base_config.clone(**overrides)
        self.runtime_config = base_config
        self._cache_path = self.record.paths.root / "cache.json"
        raw_cache = fs.read_json(self._cache_path, default={})
        self._delta_cache = {}
        if isinstance(raw_cache, dict):
            for url, entry in raw_cache.items():
                if not isinstance(entry, dict):
                    continue
                cleaned = {}
                for key in ("etag", "last_modified", "body_md5"):
                    value = entry.get(key)
                    if value:
                        cleaned[key] = str(value)
                if cleaned:
                    self._delta_cache[str(url)] = cleaned
        self._cache_dirty = False
        if self.max_retries is None:
            self.max_retries = self.runtime_config.retry_count
        self.logger = build_file_logger(
            self.logger_name,
            self.record.paths.pipeline_log,
            level=config.LOG_LEVEL,
            log_format=config.LOG_FORMAT,
        )
        self.executor = CommandExecutor(self.logger)
        pattern = self.runtime_config.url_path_allow_regex
        self._url_allow_pattern = re.compile(pattern) if pattern else None
        try:
            from recon_cli.utils.auth import build_auth_manager

            self._auth_manager = build_auth_manager(
                self.runtime_config,
                logger=self.logger,
                record=self.record,
                manager=self.manager,
                default_host=spec.target,
            )
        except Exception:
            self._auth_manager = None

        def _allow_payload(payload: Dict[str, object]) -> bool:
            url_value = payload.get('url')
            if url_value:
                return self.url_allowed(url_value)
            return True

        self.results = ResultsTracker(self.record.paths.results_jsonl, allow=_allow_payload)
        self.stage_attempts: Dict[str, int] = dict(self.record.metadata.attempts)
        self.targets = [spec.target]
        self.execution_profile = getattr(spec, 'execution_profile', None)
        profile_stats = self.record.metadata.stats.setdefault('profiles', {})
        base_profile = spec.profile
        if self.execution_profile:
            profile_stats.setdefault('execution', self.execution_profile)
        else:
            profile_stats.setdefault('execution', base_profile)
        profile_stats.setdefault('base', base_profile)
        self.manager.update_metadata(self.record)

    def set_data(self, key: str, value: object) -> None:
        self._data_store[key] = value

    def get_data(self, key: str, default: object = None) -> object:
        return self._data_store.get(key, default)

    def get_rate_limiter(
        self,
        name: str,
        *,
        rps: float,
        per_host: float,
        burst: int | None = None,
        cooldown_429: float | None = None,
        cooldown_error: float | None = None,
    ):
        if rps <= 0 and per_host <= 0:
            return None
        existing = self._rate_limiters.get(name)
        if existing:
            return existing
        rps_value = float(rps) if rps > 0 else float(per_host)
        per_host_value = float(per_host) if per_host > 0 else rps_value
        if rps_value <= 0:
            rps_value = max(per_host_value, 1.0)
        if per_host_value <= 0:
            per_host_value = max(rps_value, 1.0)
        burst_size = int(burst) if burst and burst > 0 else max(1, int(max(rps_value, per_host_value) * 2))
        from recon_cli.utils.rate_limiter import RateLimitConfig, RateLimiter

        config = RateLimitConfig(
            requests_per_second=rps_value,
            per_host_limit=per_host_value,
            burst_size=burst_size,
        )
        if cooldown_429 is not None:
            config.cooldown_on_429 = float(cooldown_429)
        if cooldown_error is not None:
            config.cooldown_on_error = float(cooldown_error)
        limiter = RateLimiter(config)
        self._rate_limiters[name] = limiter
        return limiter

    def url_allowed(self, url: str) -> bool:
        if not url:
            return False
        if not self._url_allow_pattern:
            return True
        try:
            path = urlparse(url).path or ''
        except ValueError:
            return False
        return bool(self._url_allow_pattern.search(path))

    def auth_enabled(self) -> bool:
        return bool(self._auth_manager)

    def auth_headers(self, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        if self._auth_manager:
            try:
                return self._auth_manager.prepare_headers(base)
            except Exception:
                return base or {}
        return base or {}

    def auth_session(self, url: Optional[str] = None):
        if self._auth_manager:
            try:
                return self._auth_manager.get_session(url)
            except Exception:
                return None
        return None

    def auth_cookies(self, default_domain: Optional[str] = None) -> List[Dict[str, object]]:
        if self._auth_manager:
            try:
                return self._auth_manager.export_cookies(default_domain)
            except Exception:
                return []
        return []

    def auth_cookie_header(self) -> Optional[str]:
        if self._auth_manager:
            try:
                return self._auth_manager.cookie_header()
            except Exception:
                return None
        return None

    def get_cache_entry(self, url: str) -> Optional[Dict[str, str]]:
        return self._delta_cache.get(url)

    def should_skip_due_to_cache(self, url: str, *, etag: Optional[str] = None, last_modified: Optional[str] = None, body_md5: Optional[str] = None) -> bool:
        if self.force:
            return False
        previous = self._delta_cache.get(url)
        if not previous:
            return False
        comparisons = []
        for key, value in (("etag", etag), ("last_modified", last_modified), ("body_md5", body_md5)):
            if value:
                comparisons.append(previous.get(key) == value)
            elif previous.get(key):
                return False
        return bool(comparisons) and all(comparisons)

    def update_cache(self, url: str, *, etag: Optional[str] = None, last_modified: Optional[str] = None, body_md5: Optional[str] = None) -> None:
        entry = self._delta_cache.get(url, {}).copy()
        mutated = False
        for key, value in (("etag", etag), ("last_modified", last_modified), ("body_md5", body_md5)):
            if value:
                if entry.get(key) != value:
                    entry[key] = str(value)
                    mutated = True
        if entry:
            if self._delta_cache.get(url) != entry:
                self._delta_cache[url] = entry
                self._cache_dirty = True
        elif url in self._delta_cache and mutated:
            del self._delta_cache[url]
            self._cache_dirty = True

    def increment_attempt(self, stage: str) -> int:
        current = self.stage_attempts.get(stage, 0) + 1
        self.stage_attempts[stage] = current
        self.record.metadata.attempts[stage] = current
        self.manager.update_metadata(self.record)
        return current

    def checkpoint(self, stage: str) -> None:
        self.record.metadata.checkpoint(stage)
        self.manager.update_metadata(self.record)

    def mark_error(self, message: str) -> None:
        self.record.metadata.record_error(message)
        self.manager.update_metadata(self.record)

    def mark_started(self) -> None:
        self.record.metadata.mark_started()
        self.manager.update_metadata(self.record)

    def mark_finished(self, status: str = "finished") -> None:
        self.record.metadata.mark_finished(status=status)
        self.record.metadata.attempts = self.stage_attempts
        self.manager.update_metadata(self.record)

    def close(self) -> None:
        if self._cache_dirty:
            fs.write_json(self._cache_path, self._delta_cache)
        if self._auth_manager:
            try:
                self._auth_manager.close()
            except Exception:
                pass
        silence_logger(self.logger)
