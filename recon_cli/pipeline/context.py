from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from recon_cli.utils.event_bus import PipelineEventBus
import uuid
import re

from recon_cli import config
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.jobs.results import ResultsTracker
from recon_cli.tools.executor import CommandExecutor, CommandCache
from recon_cli.utils import fs, time as time_utils, validation
from recon_cli.utils.jsonl import iter_jsonl
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
    _host_errors: Dict[str, Dict[int, int]] = field(
        init=False, default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    _host_blocks: Dict[str, str] = field(init=False, default_factory=dict)
    _auth_manager: object = field(init=False, default=None)
    _stop_request_path: Optional[Path] = field(init=False, default=None)
    _global_limiter: Optional[object] = field(init=False, default=None)
    event_bus: "PipelineEventBus" = field(init=False)
    finished_stages: Set[str] = field(init=False, default_factory=set)
    trace_recorder: Optional[object] = field(init=False, default=None)

    def __post_init__(self) -> None:
        from recon_cli.utils.pipeline_trace import current_trace_recorder
        from recon_cli.utils.event_bus import PipelineEventBus

        self.trace_recorder = current_trace_recorder()
        self.event_bus = PipelineEventBus()

        # Initialize Global Rate Limiter
        from recon_cli.utils.rate_limiter import RateLimitConfig, RateLimiter

        global_rps = float(
            getattr(self.runtime_config, "global_rps", 50.0)
            if hasattr(self, "runtime_config")
            else 50.0
        )
        global_per_host = float(
            getattr(self.runtime_config, "global_per_host_rps", 10.0)
            if hasattr(self, "runtime_config")
            else 10.0
        )
        self._global_limiter = RateLimiter(
            RateLimitConfig(
                requests_per_second=global_rps,
                per_host_limit=global_per_host,
                burst_size=max(1, int(global_rps * 2)),
            )
        )

        if self.record is None:
            self._simple_mode = True
            if self.job_id is None:
                self.job_id = "job"
            if self.work_dir is not None and self.results_file is None:
                self.results_file = self.work_dir / "results.jsonl"
            base_dir = self.work_dir or Path.cwd()
            self._cache_path = base_dir / "cache.json"
            self._stop_request_path = None
            return
        if self.manager is None:
            self.manager = JobManager()
        spec = self.record.spec
        overrides = getattr(spec, "runtime_overrides", {}) or {}
        base_config = config.RuntimeConfig()
        if getattr(spec, "insecure", False):
            overrides = {**overrides, "verify_tls": False}
        if overrides:
            base_config = base_config.clone(**overrides)
        self.runtime_config = base_config
        self._cache_path = self.record.paths.root / "cache.json"
        self._stop_request_path = self.record.paths.root / "stop.request"
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
        cache = CommandCache(config.GLOBAL_CACHE_DIR)
        self.executor = CommandExecutor(self.logger, cache=cache)
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
            url_value = payload.get("url")
            if url_value:
                if not self.url_allowed(str(url_value)):
                    return False
                if not self.url_in_scope(str(url_value)):
                    return False
            host_value = payload.get("hostname")
            if host_value and not self.host_in_scope(str(host_value)):
                return False
            return True

        self.results = ResultsTracker(
            self.record.paths.results_jsonl,
            allow=_allow_payload,
            event_bus=self.event_bus,
        )
        self.stage_attempts: Dict[str, int] = dict(self.record.metadata.attempts)
        self.targets = [spec.target]
        self.execution_profile = getattr(spec, "execution_profile", None)
        profile_stats = self.record.metadata.stats.setdefault("profiles", {})
        base_profile = spec.profile
        if self.execution_profile:
            profile_stats.setdefault("execution", self.execution_profile)
        else:
            profile_stats.setdefault("execution", base_profile)
        profile_stats.setdefault("base", base_profile)
        self.manager.update_metadata(self.record)

    def set_data(self, key: str, value: object) -> None:
        self._data_store[key] = value

    def get_data(self, key: str, default: object = None) -> object:
        return self._data_store.get(key, default)

    def record_host_error(self, host: str, code: int) -> None:
        if not host:
            return
        self._host_errors[host][code] += 1

        # Check for block triggers (WAF detection)
        threshold = int(
            getattr(self.runtime_config, "host_circuit_breaker_threshold", 10)
        )
        if code == 429 and self._host_errors[host][code] >= threshold:
            if host not in self._host_blocks:
                self.logger.warning(
                    "Host circuit breaker OPEN for %s: Too many 429s (Rate Limited)",
                    host,
                )
                self._host_blocks[host] = "rate_limited"
        elif code == 403 and self._host_errors[host][code] >= threshold * 2:
            if host not in self._host_blocks:
                self.logger.warning(
                    "Host circuit breaker OPEN for %s: Too many 403s (WAF Blocked?)",
                    host,
                )
                self._host_blocks[host] = "waf_blocked"

    def is_host_blocked(self, host: str) -> bool:
        return host in self._host_blocks

    def get_host_block_reason(self, host: str) -> Optional[str]:
        return self._host_blocks.get(host)

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
        burst_size = (
            int(burst)
            if burst and burst > 0
            else max(1, int(max(rps_value, per_host_value) * 2))
        )
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
        limiter = RateLimiter(config, parent=self._global_limiter)
        self._rate_limiters[name] = limiter
        return limiter

    def url_allowed(self, url: str) -> bool:
        if not url:
            return False
        if not self._url_allow_pattern:
            return True
        try:
            path = urlparse(url).path or ""
        except ValueError:
            return False
        return bool(self._url_allow_pattern.search(path))

    def _normalize_scope_value(self, value: str) -> str:
        candidate = str(value or "").strip()
        if not candidate:
            return ""
        if candidate.startswith("*."):
            candidate = candidate[2:]
        parsed = None
        if "://" in candidate or any(ch in candidate for ch in ("/", "?", "#")):
            parsed = urlparse(
                candidate if "://" in candidate else f"https://{candidate}"
            )
        elif ":" in candidate and not validation.is_ip(candidate):
            parsed = urlparse(f"https://{candidate}")
        if parsed and parsed.hostname:
            candidate = parsed.hostname
        return str(candidate).strip().rstrip(".").lower()

    def scope_targets(self) -> List[str]:
        raw_targets: List[str] = []
        raw_targets.extend(str(value) for value in self.targets if value)
        if getattr(self, "record", None):
            spec = self.record.spec
            if getattr(spec, "target", None):
                raw_targets.append(str(spec.target))
            raw_targets.extend(
                str(value) for value in getattr(spec, "targets", []) if value
            )
        seen: set[str] = set()
        targets: List[str] = []
        for value in raw_targets:
            normalized = self._normalize_scope_value(value)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            targets.append(normalized)
        return targets

    def host_in_scope(self, host: str) -> bool:
        normalized_host = self._normalize_scope_value(host)
        if not normalized_host:
            return False
        targets = self.scope_targets()
        if not targets:
            return True
        for target in targets:
            if validation.is_ip(normalized_host) or validation.is_ip(target):
                if normalized_host == target:
                    return True
                continue
            if normalized_host == target or normalized_host.endswith(f".{target}"):
                return True
        return False

    def url_in_scope(self, url: str) -> bool:
        if not url:
            return False
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = parsed.hostname or self._normalize_scope_value(url)
        return self.host_in_scope(host)

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

    def auth_cookies(
        self, default_domain: Optional[str] = None
    ) -> List[Dict[str, object]]:
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

    def emit_signal(
        self,
        signal_type: str,
        target_type: str,
        target: str,
        *,
        confidence: float = 0.5,
        source: str = "pipeline",
        tags: Optional[List[str]] = None,
        evidence: Optional[Dict[str, object]] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> str:
        """Append a structured signal record and return its signal_id."""
        if not signal_type or not target_type or not target:
            return ""
        if target_type == "url":
            if not self.url_allowed(str(target)) or not self.url_in_scope(str(target)):
                return ""
        elif target_type in {"host", "hostname", "ip"} and not self.host_in_scope(
            str(target)
        ):
            return ""
        if not hasattr(self, "results") or self.results is None:
            return ""

        from recon_cli.db.schemas import SignalResult

        signal_id = f"sig_{uuid.uuid4().hex[:10]}"
        signal = SignalResult(
            signal_id=signal_id,
            signal_type=str(signal_type),
            target_type=str(target_type),
            target=str(target),
            confidence=float(confidence),
            source=str(source),
            tags=list(tags) if tags else [],
            evidence=evidence,
            metadata=metadata,
        )

        self.results.append(signal.model_dump(exclude_none=False))
        self._data_store.pop("_signals", None)
        self._data_store.pop("_signal_index", None)
        return signal_id

    def _signal_source_path(self) -> Optional[Path]:
        if getattr(self, "record", None):
            return self.record.paths.results_jsonl
        return getattr(self, "results_file", None)

    def _load_signals(self) -> List[Dict[str, object]]:
        cached = self._data_store.get("_signals")
        if isinstance(cached, list):
            return cached
        signals: List[Dict[str, object]] = []
        path = self._signal_source_path()
        if path and path.exists():
            records = iter_jsonl(path)
            if records is not None:
                for entry in records:
                    if isinstance(entry, dict) and entry.get("type") == "signal":
                        signals.append(entry)
        self._data_store["_signals"] = signals
        return signals

    def signal_index(self) -> Dict[str, Dict[str, set[str]]]:
        cached = self._data_store.get("_signal_index")
        if isinstance(cached, dict):
            return cached
        by_url: Dict[str, set[str]] = defaultdict(set)
        by_host: Dict[str, set[str]] = defaultdict(set)
        by_ip: Dict[str, set[str]] = defaultdict(set)
        for signal in self._load_signals():
            stype = signal.get("signal_type")
            ttype = signal.get("target_type")
            target = signal.get("target")
            if not stype or not target or not ttype:
                continue
            stype_value = str(stype)
            if ttype == "url":
                target_value = str(target)
                by_url[target_value].add(stype_value)
                try:
                    host = urlparse(target_value).hostname
                except ValueError:
                    host = None
                if host:
                    by_host[host].add(stype_value)
            elif ttype == "host":
                by_host[str(target)].add(stype_value)
            elif ttype == "ip":
                by_ip[str(target)].add(stype_value)
        index = {"by_url": by_url, "by_host": by_host, "by_ip": by_ip}
        self._data_store["_signal_index"] = index
        return index

    def get_cache_entry(self, url: str) -> Optional[Dict[str, str]]:
        return self._delta_cache.get(url)

    def should_skip_due_to_cache(
        self,
        url: str,
        *,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
        body_md5: Optional[str] = None,
    ) -> bool:
        if self.force:
            return False
        previous = self._delta_cache.get(url)
        if not previous:
            return False
        comparisons = []
        for key, value in (
            ("etag", etag),
            ("last_modified", last_modified),
            ("body_md5", body_md5),
        ):
            if value:
                comparisons.append(previous.get(key) == value)
            elif previous.get(key):
                return False
        return bool(comparisons) and all(comparisons)

    def update_cache(
        self,
        url: str,
        *,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
        body_md5: Optional[str] = None,
    ) -> None:
        entry = self._delta_cache.get(url, {}).copy()
        mutated = False
        for key, value in (
            ("etag", etag),
            ("last_modified", last_modified),
            ("body_md5", body_md5),
        ):
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

    def stop_requested(self) -> bool:
        if self._stop_request_path is None:
            return False
        try:
            return self._stop_request_path.exists()
        except Exception:
            return False

    def request_stop(self, reason: str = "user_request") -> bool:
        if self._stop_request_path is None:
            return False
        payload = {
            "requested_at": time_utils.iso_now(),
            "reason": reason,
        }
        try:
            fs.write_json(self._stop_request_path, payload)
        except Exception:
            return False
        return True

    def clear_stop_request(self) -> None:
        if self._stop_request_path is None:
            return
        try:
            self._stop_request_path.unlink(missing_ok=True)
        except Exception:
            pass

    def close(self) -> None:
        if self._cache_dirty:
            fs.write_json(self._cache_path, self._delta_cache)
        if self._auth_manager:
            try:
                self._auth_manager.close()
            except Exception:
                pass
        silence_logger(self.logger)
