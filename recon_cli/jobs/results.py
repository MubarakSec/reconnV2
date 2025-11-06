from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable

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
                self._seen.add(key)
                ptype = payload.get("type")
                if ptype:
                    self.stats[f"type:{ptype}"] += 1

    def append(self, payload: Dict[str, object]) -> bool:
        if self.allow and not self.allow(payload):
            return False
        key = dedupe_key(payload)
        if key in self._seen:
            return False
        self._seen.add(key)
        payload.setdefault("timestamp", time_utils.iso_now())
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
