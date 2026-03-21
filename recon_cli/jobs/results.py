from __future__ import annotations

import json
import asyncio
from collections import Counter
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, TYPE_CHECKING
from urllib.parse import parse_qsl, urlparse

if TYPE_CHECKING:
    from recon_cli.utils.event_bus import PipelineEventBus
    from recon_cli.jobs.manager import JobManager

from recon_cli.utils import time as time_utils
from recon_cli.utils.jsonl import JsonlWriter, iter_jsonl
from recon_cli.utils.reporting import (
    build_finding_fingerprint,
    confidence_to_score,
    is_finding,
    resolve_confidence_label,
)
from recon_cli.jobs.manager import JobManager


def dedupe_key(payload: Dict[str, object]) -> tuple:
    def _url_path_and_params(value: object) -> tuple[object, tuple]:
        if not isinstance(value, str) or not value:
            return None, ()
        try:
            parsed = urlparse(value)
        except ValueError:
            return None, ()
        path = parsed.path or ""
        params = tuple(
            sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        )
        return path, params

    def _parameter_hint(entry: Dict[str, object]) -> object:
        for key in ("parameter", "param", "name"):
            value = entry.get(key)
            if isinstance(value, str) and value:
                return value
        details = entry.get("details")
        if isinstance(details, dict):
            for key in ("parameter", "param", "name"):
                value = details.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    ptype = payload.get("type")
    if ptype == "hostname":
        return (ptype, payload.get("hostname"))
    if ptype == "asset":
        return (ptype, payload.get("hostname"), payload.get("ip"))
    if ptype == "url":
        return (ptype, payload.get("url"))
    if ptype == "api":
        return (ptype, payload.get("url"), payload.get("hostname"))
    if ptype == "api_spec":
        return (ptype, payload.get("url"), payload.get("hostname"))
    if ptype == "parameter":
        return (ptype, payload.get("name"), payload.get("source"))
    if ptype == "param_mutation":
        return (
            ptype,
            payload.get("name"),
            payload.get("category"),
            payload.get("source"),
        )
    if ptype == "form":
        return (ptype, payload.get("url"), payload.get("action"), payload.get("method"))
    if ptype == "auth_form":
        return (ptype, payload.get("url"), payload.get("action"), payload.get("method"))
    if ptype == "asset_enrichment":
        return (ptype, payload.get("hostname"), payload.get("ip"))
    if ptype == "finding":
        fingerprint = payload.get("finding_fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            return (ptype, fingerprint)
        url_value = payload.get("url") or payload.get("matched_at")
        path_fp, query_param_fp = _url_path_and_params(url_value)
        return (
            ptype,
            payload.get("finding_type"),
            payload.get("template_id")
            or payload.get("template")
            or payload.get("templateID"),
            url_value,
            path_fp,
            query_param_fp,
            payload.get("hostname"),
            payload.get("description") or payload.get("title"),
            _parameter_hint(payload),
        )
    if ptype == "cms":
        return (
            ptype,
            payload.get("hostname"),
            payload.get("cms"),
            payload.get("source"),
        )
    if ptype == "learning_prediction":
        return (ptype, payload.get("hostname"))
    if ptype == "screenshot":
        return (ptype, payload.get("screenshot_path"))
    if ptype == "runtime_crawl":
        return (ptype, payload.get("url"))
    if ptype == "runtime_crawl_profile":
        return (ptype, payload.get("url"), payload.get("auth_profile"))
    if ptype == "idor_suspect":
        return (ptype, payload.get("url"), payload.get("auth"), payload.get("source"))
    if ptype == "idor_candidate":
        return (ptype, payload.get("url"), payload.get("auth"), payload.get("source"))
    if ptype == "attack_path":
        return (
            ptype,
            payload.get("entry_url"),
            payload.get("sink_url"),
            payload.get("finding_type"),
            payload.get("hostname"),
        )
    if ptype == "signal":
        return (
            ptype,
            payload.get("signal_type"),
            payload.get("target_type"),
            payload.get("target"),
            payload.get("source"),
        )
    if ptype == "ip_prefix":
        return (ptype, payload.get("prefix"), payload.get("asn"), payload.get("source"))
    if ptype == "meta":
        return (ptype, payload.get("schema_version"))
    return (ptype, payload.get("source"))


@dataclass
class ResultsTracker:
    path: Path
    allow: Optional[Callable[[Dict[str, object]], bool]] = None
    event_bus: Optional["PipelineEventBus"] = None
    _writer: JsonlWriter = field(init=False)
    _lock: threading.RLock = field(init=False, default_factory=threading.RLock)
    _seen: set[tuple] = field(default_factory=set)
    stats: Counter = field(default_factory=Counter)

    # Permanently buffer critical types (findings, signals)
    _critical_records: Dict[tuple, Dict[str, object]] = field(
        init=False, default_factory=dict
    )
    # LRU buffer for other types (urls, etc) to allow merging without loading everything
    _lru_records: Dict[tuple, Dict[str, object]] = field(
        init=False, default_factory=dict
    )
    _order: list[tuple] = field(init=False, default_factory=list)
    MAX_LRU_SIZE = 10000

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = JsonlWriter(self.path)
        self._load_existing()
        self._ensure_schema_record()

    def _load_existing(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = dedupe_key(payload)
                if key in self._seen:
                    continue
                self._seen.add(key)

                ptype = payload.get("type")
                # All unique records must be in _order to be written to file
                self._order.append(key)

                # Permanently buffer critical types
                if ptype in {"finding", "signal", "attack_path", "meta"}:
                    self._critical_records[key] = payload
                else:
                    # Add to LRU for potential merging later
                    self._lru_records[key] = payload
                    if len(self._lru_records) > self.MAX_LRU_SIZE:
                        oldest_lru_key = next(iter(self._lru_records))
                        self._lru_records.pop(oldest_lru_key)

                self.stats["records_seen"] += 1
                self.stats["records_unique"] += 1
                if ptype:
                    self.stats[f"type:{ptype}"] += 1

    def append(self, payload: Dict[str, object]) -> bool:
        with self._lock:
            if self.allow and not self.allow(payload):
                return False

            # Redact sensitive data from proof and details
            from recon_cli.utils.sanitizer import redact_json_value

            payload = redact_json_value(payload)

            # Pydantic validation (optional, can be disabled for performance on large URL lists)
            ptype = str(payload.get("type") or "unknown")
            if ptype in {"finding", "signal", "attack_path"}:
                from recon_cli.db.schemas import validate_result

                try:
                    payload = validate_result(payload)
                except Exception:
                    self.stats[f"validation_failed:{ptype}"] += 1
                    pass

            if isinstance(payload, dict):
                payload = self._normalize_payload(payload)
            key = dedupe_key(payload)
            self.stats["records_seen"] += 1

            if key in self._seen:
                self.stats["records_duplicate"] += 1
                if ptype:
                    self.stats[f"duplicate:{ptype}"] += 1

                # Check critical buffer first, then LRU buffer
                buffer = (
                    self._critical_records
                    if key in self._critical_records
                    else self._lru_records
                )
                if key in buffer:
                    merged = self._merge_entries(buffer.get(key, {}), payload)
                    if merged != buffer.get(key):
                        buffer[key] = merged
                        self._rewrite_all()
                return True

            self._seen.add(key)
            self.stats["records_unique"] += 1
            payload.setdefault("timestamp", time_utils.iso_now())
            self._order.append(key)
            # Buffer only critical types
            if ptype in {"finding", "signal", "attack_path", "meta"}:
                self._critical_records[key] = payload
            else:
                self._lru_records[key] = payload
                if len(self._lru_records) > self.MAX_LRU_SIZE:
                    oldest_lru_key = next(iter(self._lru_records))
                    self._lru_records.pop(oldest_lru_key)

            # Publish to event bus if available
            if self.event_bus:
                try:
                    loop = asyncio.get_running_loop()
                    if loop.is_running():
                        # Use call_soon_threadsafe if we are in a thread, or just create task if in loop
                        # To keep it simple and robust, we'll try to publish
                        asyncio.run_coroutine_threadsafe(
                            self.event_bus.publish(ptype, payload), loop
                        )
                except RuntimeError:
                    # No loop running, skip publishing
                    pass

            # Always write to file

            with self._writer as writer:
                writer.write(payload)

            if ptype:
                self.stats[f"type:{ptype}"] += 1
            return True

    def extend(self, payloads: Iterable[Dict[str, object]]) -> int:
        added = 0
        for payload in payloads:
            if self.append(payload):
                added += 1
        return added

    def replace_all(self, payloads: Iterable[Dict[str, object]]) -> None:
        """Replace all tracked results with the provided payloads."""
        with self._lock:
            self._seen.clear()
            self._critical_records.clear()
            self._lru_records.clear()
            self._order.clear()
            self.stats = Counter()
            has_schema = False

            for payload in payloads:
                if not isinstance(payload, dict):
                    continue
                payload = self._normalize_payload(payload)
                key = dedupe_key(payload)
                ptype = payload.get("type")

                if key in self._seen:
                    buffer = (
                        self._critical_records
                        if key in self._critical_records
                        else self._lru_records
                    )
                    if key in buffer:
                        merged = self._merge_entries(buffer.get(key, {}), payload)
                        if merged != buffer.get(key):
                            buffer[key] = merged
                    continue

                self._seen.add(key)
                self._order.append(key)
                if ptype in {"finding", "signal", "attack_path", "meta"}:
                    self._critical_records[key] = payload
                else:
                    self._lru_records[key] = payload
                    if len(self._lru_records) > self.MAX_LRU_SIZE:
                        oldest_lru_key = next(iter(self._lru_records))
                        self._lru_records.pop(oldest_lru_key)

                self.stats["records_seen"] += 1
                self.stats["records_unique"] += 1
                if ptype:
                    self.stats[f"type:{ptype}"] += 1
                if ptype == "meta" and payload.get("schema_version"):
                    has_schema = True

            if not has_schema:
                schema_key = ("meta", "1.0.0")
                payload = {
                    "type": "meta",
                    "schema_version": "1.0.0",
                    "timestamp": time_utils.iso_now(),
                }
                self._seen.add(schema_key)
                self._critical_records[schema_key] = payload
                self._order.insert(0, schema_key)

            self._rewrite_all()

    def to_dict(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.stats)

    def _ensure_schema_record(self) -> None:
        schema_key = ("meta", "1.0.0")
        if schema_key in self._seen:
            return
        payload = {
            "type": "meta",
            "schema_version": "1.0.0",
            "timestamp": time_utils.iso_now(),
        }
        self._seen.add(schema_key)
        self._critical_records[schema_key] = payload  # type: ignore[assignment]
        self._order.insert(0, schema_key)
        with self._writer as writer:
            writer.write(payload)

    @staticmethod
    def _priority_rank(value: object) -> int:
        order = ["noise", "low", "medium", "high", "critical"]
        if isinstance(value, str):
            try:
                return order.index(value.lower())
            except ValueError:
                return -1
        return -1

    @staticmethod
    def _confidence_rank(value: object) -> int:
        order = ["low", "medium", "high", "verified"]
        if isinstance(value, str):
            try:
                return order.index(value.lower())
            except ValueError:
                return -1
        return -1

    @staticmethod
    def _normalize_payload(payload: Dict[str, object]) -> Dict[str, object]:
        normalized = dict(payload)
        if is_finding(normalized):
            label = resolve_confidence_label(normalized)
            if label:
                normalized["confidence_label"] = label
                normalized["confidence_score"] = confidence_to_score(label)
            normalized["finding_fingerprint"] = build_finding_fingerprint(normalized)
        return normalized

    def _merge_entries(
        self, existing: Dict[str, object], new: Dict[str, object]
    ) -> Dict[str, object]:
        merged = dict(existing)
        # Merge sources
        existing_sources = merged.get("sources") or []
        if isinstance(existing_sources, str):
            existing_sources = [existing_sources]
        if isinstance(existing_sources, list):
            existing_sources = list(existing_sources)
        else:
            existing_sources = []
        existing_source = merged.get("source")
        if existing_source and existing_source not in existing_sources:
            existing_sources.append(existing_source)
        new_source = new.get("source")
        if new_source and new_source not in existing_sources:
            existing_sources.append(new_source)
        new_sources = new.get("sources") or []
        if isinstance(new_sources, str):
            new_sources = [new_sources]
        if isinstance(new_sources, list):
            for src in new_sources:
                if src not in existing_sources:
                    existing_sources.append(src)
        if existing_sources:
            merged["sources"] = existing_sources
            if not merged.get("source"):
                merged["source"] = existing_sources[0]
        # Merge tags
        for key, value in new.items():
            if value is None:
                continue
            if key == "tags":
                current = merged.get("tags", [])
                current_set = set(current) if isinstance(current, list) else set()
                if isinstance(value, list):
                    current_set.update(value)
                merged["tags"] = (
                    sorted(current_set) if current_set else merged.get("tags", [])
                )
                continue
            if key == "score":
                try:
                    merged["score"] = max(int(merged.get("score", 0)), int(value))
                except (TypeError, ValueError):
                    merged["score"] = merged.get("score", value)
                continue
            if key == "priority":
                existing_rank = self._priority_rank(merged.get("priority"))
                new_rank = self._priority_rank(value)
                if new_rank > existing_rank:
                    merged["priority"] = value
                continue
            if key == "confidence":
                try:
                    merged_value = float(merged.get("confidence", 0.0))
                    new_value = float(value)
                    merged["confidence"] = max(merged_value, new_value)
                except (TypeError, ValueError):
                    merged["confidence"] = merged.get("confidence", value)
                continue
            if key == "confidence_label":
                existing_rank = self._confidence_rank(merged.get("confidence_label"))
                new_rank = self._confidence_rank(value)
                if new_rank > existing_rank:
                    merged["confidence_label"] = value
                continue
            if key == "confidence_score":
                try:
                    merged_value = float(merged.get("confidence_score", 0.0))
                    new_value = float(value)
                    merged["confidence_score"] = max(merged_value, new_value)
                except (TypeError, ValueError):
                    merged["confidence_score"] = merged.get("confidence_score", value)
                continue
            if key == "timestamp":
                continue
            if key not in merged or merged.get(key) in (None, "", []):
                merged[key] = value
        if is_finding(merged):
            merged["confidence_label"] = resolve_confidence_label(merged)
            merged["confidence_score"] = confidence_to_score(merged["confidence_label"])  # type: ignore[arg-type]
            merged["finding_fingerprint"] = build_finding_fingerprint(merged)
        return merged

    def _rewrite_all(self) -> None:
        with self.path.open("w", encoding="utf-8") as handle:
            for key in self._order:
                payload = self._critical_records.get(key) or self._lru_records.get(key)
                if not payload:
                    continue
                json.dump(payload, handle, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")

    def iter_results(self) -> Iterable[Dict[str, Any]]:
        """Iterate over all results currently tracked (disk + buffer)."""
        with self._lock:
            # We must use iter_jsonl for the full set because the buffer might be limited (LRU)
            # However, if we want to avoid disk IO, we could increase LRU size or cache everything.
            # For now, let's keep it simple and read from disk to ensure completeness,
            # but provide a centralized place for it.
            return iter_jsonl(self.path)

    def read_all(self) -> List[Dict[str, Any]]:
        """Read all results into a list."""
        return list(self.iter_results())


class JobResults:
    def __init__(self, manager: Optional[JobManager] = None) -> None:
        self.manager = manager or JobManager()

    def get_results(
        self,
        job_id: str,
        limit: int = 100,
        result_type: Optional[str] = None,
    ) -> Optional[list[Dict[str, object]]]:
        record = self.manager.load_job(job_id)
        if not record:
            return None
        results: list[Dict[str, object]] = []
        for item in iter_jsonl(record.paths.results_jsonl):
            if result_type and item.get("type") != result_type:
                continue
            results.append(item)
            if limit and len(results) >= limit:
                break
        return results
