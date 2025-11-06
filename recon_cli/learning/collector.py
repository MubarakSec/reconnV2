from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from recon_cli.utils import time as time_utils


DATASET_NAME = "dataset.jsonl"
MODEL_NAME = "model.json"


@dataclass
class HostFeatures:
    host: str
    features: Dict[str, float]
    label: Optional[int] = None

    def to_record(self, job_id: str) -> Dict[str, object]:
        return {
            "host": self.host,
            "features": self.features,
            "label": self.label,
            "job_id": job_id,
            "timestamp": time_utils.iso_now(),
        }


class DatasetStore:
    def __init__(self, learning_root: Path) -> None:
        self.learning_root = learning_root
        self.learning_root.mkdir(parents=True, exist_ok=True)
        self.dataset_path = self.learning_root / DATASET_NAME

    def append(self, records: List[Dict[str, object]]) -> None:
        with self.dataset_path.open("a", encoding="utf-8") as handle:
            for record in records:
                json.dump(record, handle, sort_keys=True)
                handle.write("\n")

    def load_labeled(self) -> List[Dict[str, object]]:
        if not self.dataset_path.exists():
            return []
        labeled: List[Dict[str, object]] = []
        with self.dataset_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("label") is not None:
                    labeled.append(record)
        return labeled

    def load_all(self) -> List[Dict[str, object]]:
        if not self.dataset_path.exists():
            return []
        with self.dataset_path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
