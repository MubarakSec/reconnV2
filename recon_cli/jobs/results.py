from __future__ import annotations

import json
from collections import Counter
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional
from urllib.parse import parse_qsl, urlparse

from recon_cli.utils import time as time_utils
from recon_cli.utils.jsonl import JsonlWriter, read_jsonl
from recon_cli.utils.reporting import build_finding_fingerprint, confidence_to_score, is_finding, resolve_confidence_label
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
        params = tuple(sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)))
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
        return (ptype, payload.get("name"), payload.get("category"), payload.get("source"))
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
            payload.get("template_id") or payload.get("template") or payload.get("templateID"),
            url_value,
            path_fp,
            query_param_fp,
            payload.get("hostname"),
            payload.get("description") or payload.get("title"),
            _parameter_hint(payload),
        )
    if ptype == "cms":
        return (ptype, payload.get("hostname"), payload.get("cms"), payload.get("source"))
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
    _writer: JsonlWriter = field(init=False)
    _lock: threading.RLock = field(init=False, default_factory=threading.RLock)
    _seen: set[tuple] = field(default_factory=set)
    stats: Counter = field(default_factory=Counter)
    _records: Dict[tuple, Dict[str, object]] = field(init=False, default_factory=dict)
    _order: list[tuple] = field(init=False, default_factory=list)

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
                self._records[key] = payload
                self._order.append(key)
                self.stats["records_seen"] += 1
                self.stats["records_unique"] += 1
                ptype = payload.get("type")
                if ptype:
                    self.stats[f"type:{ptype}"] += 1

    def append(self, payload: Dict[str, object]) -> bool:
        with self._lock:
            if self.allow and not self.allow(payload):
                return False
            
            # Pydantic validation
            from recon_cli.db.schemas import validate_result
            try:
                payload = validate_result(payload)
            except Exception as e:
                # We log this to stats so it's visible in the job metadata
                ptype = payload.get("type") or "unknown"
                self.stats[f"validation_failed:{ptype}"] += 1
                # If it's a critical result type, we should probably still allow it 
                # but we've marked it as failed validation.
                # In a truly strict mode, we might return False here.
                pass

            if isinstance(payload, dict):
                payload = self._normalize_payload(payload)
            key = dedupe_key(payload)
            self.stats["records_seen"] += 1
            if key in self._seen:
                self.stats["records_duplicate"] += 1
                ptype = payload.get("type")
                if ptype:
                    self.stats[f"duplicate:{ptype}"] += 1
                merged = self._merge_entries(self._records.get(key, {}), payload)
                if merged != self._records.get(key):
                    self._records[key] = merged
                    self._rewrite_all()
                return True
            self._seen.add(key)
            self.stats["records_unique"] += 1
            payload.setdefault("timestamp", time_utils.iso_now())
            self._records[key] = payload
            self._order.append(key)
            with self._writer as writer:
                writer.write(payload)
            ptype = payload.get("type")
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
            self._records.clear()
            self._order.clear()
            self.stats = Counter()
            has_schema = False

            for payload in payloads:
                if not isinstance(payload, dict):
                    continue
                payload = self._normalize_payload(payload)
                key = dedupe_key(payload)
                if key in self._seen:
                    merged = self._merge_entries(self._records.get(key, {}), payload)
                    if merged != self._records.get(key):
                        self._records[key] = merged
                    continue
                self._seen.add(key)
                self._records[key] = payload
                self._order.append(key)
                self.stats["records_seen"] += 1
                self.stats["records_unique"] += 1
                ptype = payload.get("type")
                if ptype:
                    self.stats[f"type:{ptype}"] += 1
                if ptype == "meta" and payload.get("schema_version"):
                    has_schema = True

            if not has_schema:
                schema_key = ("meta", "1.0.0")
                payload = {"type": "meta", "schema_version": "1.0.0", "timestamp": time_utils.iso_now()}
                self._seen.add(schema_key)
                self._records[schema_key] = payload
                self._order.insert(0, schema_key)

            self._rewrite_all()

    def to_dict(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.stats)

    def _ensure_schema_record(self) -> None:
        schema_key = ("meta", "1.0.0")
        if schema_key in self._seen:
            return
        payload = {"type": "meta", "schema_version": "1.0.0", "timestamp": time_utils.iso_now()}
        self._seen.add(schema_key)
        self._records[schema_key] = payload
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

    def _merge_entries(self, existing: Dict[str, object], new: Dict[str, object]) -> Dict[str, object]:
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
                merged["tags"] = sorted(current_set) if current_set else merged.get("tags", [])
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
            merged["confidence_score"] = confidence_to_score(merged["confidence_label"])
            merged["finding_fingerprint"] = build_finding_fingerprint(merged)
        return merged

    def _rewrite_all(self) -> None:
        with self.path.open("w", encoding="utf-8") as handle:
            for key in self._order:
                payload = self._records.get(key)
                if not payload:
                    continue
                json.dump(payload, handle, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")


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
        for item in read_jsonl(record.paths.results_jsonl):
            if result_type and item.get("type") != result_type:
                continue
            results.append(item)
            if limit and len(results) >= limit:
                break
        return results
