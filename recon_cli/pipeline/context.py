from __future__ import annotations

import threading
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Set, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from recon_cli.utils.event_bus import PipelineEventBus
import uuid
import re

from recon_cli import config
from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.jobs.models import IdentityRecord
from recon_cli.jobs.results import ResultsTracker
from recon_cli.tools.executor import CommandExecutor, CommandCache
from recon_cli.utils import fs, time as time_utils, validation
from recon_cli.utils.auth import UnifiedAuthManager
from recon_cli.utils.jsonl import iter_jsonl
from recon_cli.utils.logging import build_file_logger, silence_logger
from recon_cli.engine.planner import Planner
from recon_cli.engine.executor import Executor
from recon_cli.engine.judge import Judge


class TargetGraph:
    """
    A persistent, queryable model of the target attack surface.
    Used for planning and cross-stage memory.
    """
    def __init__(self):
        from recon_cli.correlation.graph import Graph
        self._graph = Graph()
        self._lock = threading.Lock()

    def add_entity(self, entity_type: str, entity_id: str, **attrs) -> None:
        with self._lock:
            self._graph.add_node(entity_type, entity_id, **attrs)

    def add_relation(self, src_type: str, src_id: str, label: str, dst_type: str, dst_id: str, **attrs) -> None:
        with self._lock:
            self._graph.add_edge(src_type, src_id, label, dst_type, dst_id, **attrs)

    def get_related(self, entity_type: str, entity_id: str, relation_label: Optional[str] = None) -> List[Dict[str, Any]]:
        # Simplified query logic for now
        results = []
        key = (entity_type, entity_id)
        with self._lock:
            if key in self._graph._adjacency:
                for related_key in self._graph._adjacency[key]:
                    # Find the edge to check label
                    for edge in self._graph._edges.values():
                        if (edge.source == key and edge.target == related_key) or \
                           (edge.source == related_key and edge.target == key):
                            if relation_label and edge.label != relation_label:
                                continue
                            
                            node = self._graph._nodes[related_key]
                            results.append({
                                "type": node.type,
                                "id": node.id,
                                "attrs": node.attrs,
                                "relation": edge.label
                            })
        return results

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return self._graph.to_dict()


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
    _host_adaptive_jitter: Dict[str, float] = field(init=False, default_factory=dict)
    _host_force_proxy: Set[str] = field(init=False, default_factory=set)
    _any_stage_failed: bool = field(init=False, default=False)
    _auth_manager: UnifiedAuthManager = field(init=False, default=None)
    target_graph: TargetGraph = field(init=False, default=None)
    planner: Planner = field(init=False, default=None)
    executor_engine: Executor = field(init=False, default=None)
    judge: Judge = field(init=False, default=None)
    _stop_request_path: Optional[Path] = field(init=False, default=None)
    _global_limiter: Optional[object] = field(init=False, default=None)
    event_bus: "PipelineEventBus" = field(init=False)
    finished_stages: Set[str] = field(init=False, default_factory=set)
    trace_recorder: Optional[object] = field(init=False, default=None)
    stealth_manager: Optional[object] = field(init=False, default=None)
    scope_manager: "ScopeManager" = field(init=False)
    http_client: "AsyncHTTPClient" = field(init=False, default=None)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        from recon_cli.utils.pipeline_trace import current_trace_recorder
        from recon_cli.utils.event_bus import PipelineEventBus
        from recon_cli.utils.stealth import StealthConfig, StealthManager
        from recon_cli.utils.scope import ScopeManager
        from recon_cli.utils.async_http import AsyncHTTPClient

        self.trace_recorder = current_trace_recorder()
        self.event_bus = PipelineEventBus()
        self.http_client = AsyncHTTPClient(context=self)
        
        # 1. Initialize Runtime Config FIRST (critical for overrides)
        if self.record is not None:
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
        else:
            self._simple_mode = True
            if self.job_id is None:
                self.job_id = "job"
            if self.work_dir is not None and self.results_file is None:
                self.results_file = self.work_dir / "results.jsonl"
            base_dir = self.work_dir or Path.cwd()
            self._cache_path = base_dir / "cache.json"
            self._stop_request_path = None
            if not hasattr(self, "runtime_config") or self.runtime_config is None:
                self.runtime_config = config.RuntimeConfig()

        # 2. Initialize Scope Manager
        if self.record and self.record.spec.scope_file:
            self.scope_manager = ScopeManager.from_file(Path(self.record.spec.scope_file))
        else:
            include_patterns = self.scope_targets()
            self.scope_manager = ScopeManager(include_patterns=include_patterns)

        # 3. Initialize Stealth Manager (now uses correct runtime_config)
        proxies = getattr(self.runtime_config, "proxies", []) or []
        stealth_cfg = StealthConfig(
            proxies=list(proxies) if isinstance(proxies, list) else [],
            jitter_min=float(getattr(self.runtime_config, "stealth_jitter_min", 0.1)),
            jitter_max=float(getattr(self.runtime_config, "stealth_jitter_max", 0.0))
        )
        self.stealth_manager = StealthManager(stealth_cfg)

        # 4. Initialize Global Rate Limiter
        from recon_cli.utils.rate_limiter import RateLimitConfig, RateLimiter

        global_rps = float(getattr(self.runtime_config, "global_rps", 50.0))
        global_per_host = float(getattr(self.runtime_config, "global_per_host_rps", 10.0))
        self._global_limiter = RateLimiter(
            RateLimitConfig(
                requests_per_second=global_rps,
                per_host_limit=global_per_host,
                burst_size=max(1, int(global_rps * 2)),
            )
        )

        # 5. Initialize Unified Auth Manager
        self._auth_manager = UnifiedAuthManager(self)

        # 6. Initialize Target Graph
        self.target_graph = TargetGraph()

        # 7. Initialize Autonomy Engine (Phase 4)
        self.planner = Planner(self)
        self.executor_engine = Executor(self)
        self.judge = Judge()

        if self.record is None:
            return

        # 8. Rest of initialization
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

        def _allow_payload(payload: Dict[str, object]) -> bool:
            def _is_local(val: str) -> bool:
                val = str(val).lower()
                return "localhost" in val or "127.0.0.1" in val

            url_value = payload.get("url")
            if url_value:
                if not self.url_allowed(str(url_value)):
                    return False
                # Bypass strict scope checks for local testing
                if _is_local(str(url_value)):
                    return True
                if not self.url_in_scope(str(url_value)):
                    return False
            host_value = payload.get("hostname")
            if host_value:
                if _is_local(str(host_value)):
                    return True
                if not self.host_in_scope(str(host_value)):
                    return False
            return True

        self.results = ResultsTracker(
            self.record.paths.results_jsonl,
            allow=_allow_payload,
            event_bus=self.event_bus,
            on_finding=self.notify_finding
        )
        
        def _on_result_added(payload: Dict[str, Any]) -> None:
            ptype = payload.get("type")
            if not ptype: return
            
            # Populate TargetGraph dynamically (Phase 2)
            if ptype == "hostname":
                self.target_graph.add_entity("hostname", str(payload.get("hostname")), tags=payload.get("tags", []))
            elif ptype == "url":
                self.target_graph.add_entity("url", str(payload.get("url")), tags=payload.get("tags", []), status=payload.get("status_code"))
            elif ptype == "api":
                self.target_graph.add_entity("endpoint", str(payload.get("url")))
                host = str(payload.get("hostname"))
                if host and host != "None":
                    self.target_graph.add_entity("hostname", host)
                    self.target_graph.add_relation("hostname", host, "exposes", "endpoint", str(payload.get("url")))
            elif ptype == "parameter":
                self.target_graph.add_entity("parameter", str(payload.get("name")))
            elif ptype == "form":
                self.target_graph.add_entity("form", str(payload.get("action")))

        self.event_bus.subscribe("result_added", _on_result_added)
        
        self.stage_attempts: Dict[str, int] = dict(self.record.metadata.attempts)
        if not self.targets:
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

    def get_results(self, result_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Memory-efficient retrieval of results.
        If result_type is provided, only returns records of that type.
        """
        if result_type:
            return list(self.filter_results(result_type))
        return list(self.results.iter_results())

    def iter_results(self) -> Iterable[Dict[str, Any]]:
        """Stream results line-by-line from disk."""
        return self.results.iter_results()

    def filter_results(self, result_type: str) -> Iterable[Dict[str, Any]]:
        """Efficiently filter results by type without loading everything into memory."""
        for entry in self.results.iter_results():
            if entry.get("type") == result_type:
                yield entry

    def clear_results_cache(self) -> None:
        """Clear the results cache (no-op now)."""
        pass

    def record_host_error(self, host: str, code: int) -> None:
        if not host:
            return
        self._host_errors[host][code] += 1

        # Adaptive Rate Limiting (Dynamic Backoff)
        if code == 429:
            current_jitter = self._host_adaptive_jitter.get(host, 0.5)
            self._host_adaptive_jitter[host] = current_jitter * 1.5
            self.logger.debug("Adaptive Rate Limiting: increased jitter for %s to %.2fs", host, self._host_adaptive_jitter[host])

        # WAF Profiling
        if code == 403 and self._host_errors[host][code] >= 5:
            if host not in self._host_force_proxy:
                self.logger.info("WAF Profiling: Forcing proxy rotation for %s due to multiple 403s", host)
                self._host_force_proxy.add(host)

        # Check for block triggers (WAF detection / hard rate limits)
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
        limiter = RateLimiter(config, parent=self._global_limiter)  # type: ignore[arg-type]
        self._rate_limiters[name] = limiter
        return limiter

    def url_allowed(self, url: str) -> bool:
        if not url:
            return False
        
        # Check scope manager (host-level and wildcard scope)
        if not self.scope_manager.is_allowed(url):
            return False

        # If no path-level pattern is set, the host check is enough
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
        elif ":" in candidate:
            # Handle host:port even if it's an IP:port
            parsed = urlparse(f"https://{candidate}")

        if parsed and parsed.hostname:
            if parsed.port and parsed.port not in (80, 443):
                candidate = f"{parsed.hostname}:{parsed.port}"
            else:
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
            
        # Global bypass for local testing
        if "localhost" in normalized_host or "127.0.0.1" in normalized_host:
            return True
            
        targets = self.scope_targets()
        if not targets:
            return True

        def _strip_port(value: str) -> str:
            if ":" in value and not (value.startswith("[") and "]" in value):
                parts = value.rsplit(":", 1)
                if parts[1].isdigit():
                    return parts[0]
            return value

        host_no_port = _strip_port(normalized_host)

        for target in targets:
            target_no_port = _strip_port(target)

            if validation.is_ip(host_no_port) or validation.is_ip(target_no_port):
                if normalized_host == target or host_no_port == target_no_port:
                    return True
                continue

            if normalized_host == target or host_no_port == target_no_port or host_no_port.endswith(f".{target_no_port}"):
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

    def auth_headers(self, base: Optional[Dict[str, str]] = None, identity_id: Optional[str] = None) -> Dict[str, str]:
        """Get authentication headers for a specific identity or default, including stealth wrapping."""
        headers = base or {}
        if self._auth_manager:
            try:
                headers = self._auth_manager.get_auth_headers(identity_id=identity_id, base=headers)
            except Exception:
                pass
        
        if self.stealth_manager:
            return self.stealth_manager.wrap_headers(headers)
        return headers

    async def auth_session_async(self, url: Optional[str] = None):
        """Async version of auth_session that doesn't block the loop for jitter."""
        host = urlparse(url).hostname if url else None
        
        # Adaptive Jitter
        if self.stealth_manager:
            if host and host in self._host_adaptive_jitter:
                import asyncio
                await asyncio.sleep(self._host_adaptive_jitter[host])
            else:
                await self.stealth_manager.apply_jitter_async()
        
        # WAF Profiling / Proxy Force
        proxy = None
        if self.stealth_manager:
            if host and host in self._host_force_proxy:
                proxy = self.stealth_manager.get_proxy()
            elif getattr(self.runtime_config, "always_use_proxy", False):
                proxy = self.stealth_manager.get_proxy()

        session = None
        if self._auth_manager:
            try:
                if hasattr(self._auth_manager, "_legacy_manager") and self._auth_manager._legacy_manager:
                    session = self._auth_manager._legacy_manager.get_session(url)
                else:
                    import requests
                    session = requests.Session()
            except Exception:
                session = None
        
        if not session:
            import requests
            session = requests.Session()
            session.verify = getattr(self.runtime_config, "verify_tls", True)

        if proxy and hasattr(session, "proxies"):
            session.proxies.update(proxy)
            
        return session

    def auth_session(self, url: Optional[str] = None):
        host = urlparse(url).hostname if url else None
        
        # Adaptive Jitter
        if self.stealth_manager:
            if host and host in self._host_adaptive_jitter:
                import time
                time.sleep(self._host_adaptive_jitter[host])
            else:
                self.stealth_manager.apply_jitter()
        
        # WAF Profiling / Proxy Force
        proxy = None
        if self.stealth_manager:
            if host and host in self._host_force_proxy:
                proxy = self.stealth_manager.get_proxy()
            elif getattr(self.runtime_config, "always_use_proxy", False):
                proxy = self.stealth_manager.get_proxy()

        session = None
        if self._auth_manager:
            try:
                # UnifiedAuthManager doesn't have a direct get_session like legacy manager.
                # If we need a requests session, we should probably use the legacy manager's session
                # or create a new one. UnifiedAuthManager._legacy_manager is an AuthSessionManager.
                if hasattr(self._auth_manager, "_legacy_manager") and self._auth_manager._legacy_manager:
                    session = self._auth_manager._legacy_manager.get_session(url)
                else:
                    import requests
                    session = requests.Session()
            except Exception:
                session = None
        
        # If no auth session, provide a base requests session with stealth
        if not session:
            import requests
            session = requests.Session()
            session.verify = getattr(self.runtime_config, "verify_tls", True)

        if proxy and hasattr(session, "proxies"):
            session.proxies.update(proxy)
            
        return session

    def auth_cookies(
        self, default_domain: Optional[str] = None
    ) -> List[Dict[str, object]]:
        if self._auth_manager:
            try:
                # UnifiedAuthManager should expose cookies somehow.
                # Legacy manager has export_cookies.
                if hasattr(self._auth_manager, "_legacy_manager") and self._auth_manager._legacy_manager:
                    return self._auth_manager._legacy_manager.export_cookies(default_domain)
                return []
            except Exception:
                return []
        return []

    def auth_cookie_header(self, identity_id: Optional[str] = None) -> Optional[str]:
        """Get Cookie header for a specific identity or default."""
        if self._auth_manager:
            try:
                return self._auth_manager.get_cookie_header(identity_id=identity_id)
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

    def mark_stage_failed(self) -> None:
        self._any_stage_failed = True

    def update_stats(self, stage_name: str, **updates: Any) -> None:
        """Thread-safe update of job statistics."""
        if not self.record:
            return
        with self._lock:
            stats = self.record.metadata.stats.setdefault(stage_name, {})
            for key, value in updates.items():
                if isinstance(value, int) and key in stats and isinstance(stats[key], int):
                    stats[key] += value
                else:
                    stats[key] = value
            self.manager.update_metadata(self.record)

    def mark_finished(self, status: str = "finished") -> None:
        if self._any_stage_failed:
             if status == "finished":
                 status = "partial"
             if not self.record.metadata.error:
                 self.record.metadata.error = "Scan completed with partial failures in some stages"
        
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

    def notify_finding(self, finding: Dict[str, Any]) -> None:
        """Sends a notification for a high-value finding."""
        if not self.runtime_config: return
        
        severity = str(finding.get("severity", "low")).lower()
        if severity not in ["high", "critical"] and int(finding.get("score", 0)) < 80:
            return

        from recon_cli.utils import notify
        
        message = f"🚨 RECONN FINDING [{severity.upper()}]\n"
        message += f"Type: {finding.get('finding_type', 'unknown')}\n"
        message += f"Target: {finding.get('url') or finding.get('hostname')}\n"
        message += f"Desc: {finding.get('description')}\n"
        
        # Try Telegram
        token = getattr(self.runtime_config, "telegram_token", None)
        chat_id = getattr(self.runtime_config, "telegram_chat_id", None)
        if token and chat_id:
            notify.send_telegram_message(token, chat_id, message)
            
        # Try Discord/Slack webhooks if configured
        disc_webhook = getattr(self.runtime_config, "discord_webhook_url", None)
        if disc_webhook:
            notify.send_discord_message(disc_webhook, message)

    def close(self) -> None:
        if self._cache_dirty:
            fs.write_json(self._cache_path, self._delta_cache)
        if self._auth_manager:
            try:
                self._auth_manager.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        silence_logger(self.logger)
