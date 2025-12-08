from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional

from recon_cli.utils import time as time_utils
from recon_cli.utils.jsonl import JsonlWriter


def dedupe_key(payload: Dict[str, object]) -> tuple:
    ptype = payload.get("type")
    if ptype == "hostname":
        return (ptype, payload.get("hostname"))
    if ptype == "asset":
        return (ptype, payload.get("hostname"), payload.get("ip"))
    if ptype == "url":
        return (ptype, payload.get("url"))
    if ptype == "asset_enrichment":
        return (ptype, payload.get("hostname"), payload.get("ip"))
    if ptype == "finding":
        return (ptype, payload.get("description"), payload.get("hostname"))
    if ptype == "learning_prediction":
        return (ptype, payload.get("hostname"))
    if ptype == "screenshot":
        return (ptype, payload.get("screenshot_path"))
    if ptype == "runtime_crawl":
        return (ptype, payload.get("url"))
    return (ptype, payload.get("source"))


@dataclass
class ResultsTracker:
    path: Path
    allow: Optional[Callable[[Dict[str, object]], bool]] = None
    _writer: JsonlWriter = field(init=False)
    _seen: set[tuple] = field(default_factory=set)
    stats: Counter = field(default_factory=Counter)
    _records: Dict[tuple, Dict[str, object]] = field(init=False, default_factory=dict)
    _order: list[tuple] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = JsonlWriter(self.path)
        self._load_existing()

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
                ptype = payload.get("type")
                if ptype:
                    self.stats[f"type:{ptype}"] += 1

    def append(self, payload: Dict[str, object]) -> bool:
        if self.allow and not self.allow(payload):
            return False
        key = dedupe_key(payload)
        if key in self._seen:
            merged = self._merge_entries(self._records.get(key, {}), payload)
            if merged != self._records.get(key):
                self._records[key] = merged
                self._rewrite_all()
            return True
        self._seen.add(key)
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

    def to_dict(self) -> Dict[str, int]:
        return dict(self.stats)

    @staticmethod
    def _priority_rank(value: object) -> int:
        order = ["noise", "low", "medium", "high", "critical"]
        if isinstance(value, str):
            try:
                return order.index(value.lower())
            except ValueError:
                return -1
        return -1

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
            if key == "timestamp":
                continue
            if key not in merged or merged.get(key) in (None, "", []):
                merged[key] = value
        return merged

    def _rewrite_all(self) -> None:
        with self.path.open("w", encoding="utf-8") as handle:
            for key in self._order:
                payload = self._records.get(key)
                if not payload:
                    continue
                json.dump(payload, handle, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")
