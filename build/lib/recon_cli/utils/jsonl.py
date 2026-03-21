from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, IO

from recon_cli.utils.sanitizer import redact


class JsonlWriter:
    """Append-only JSON Lines writer that keeps file handle open."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle: IO[str] | None = None

    def __enter__(self) -> "JsonlWriter":
        self._handle = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._handle:
            self._handle.close()
            self._handle = None

    def write(self, payload: Dict[str, Any]) -> None:
        if self._handle is None:
            with self:
                self.write(payload)
            return
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        redacted = redact(line) or ""
        self._handle.write(redacted + "\n")
        self._handle.flush()


def iter_jsonl(path: Path):
    """Yield JSON objects from a JSON Lines file without loading everything into memory."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))
