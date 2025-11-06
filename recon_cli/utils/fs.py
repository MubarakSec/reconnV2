from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from recon_cli.utils.sanitizer import redact


def read_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        text = json.dumps(payload, indent=2, sort_keys=True)
        redacted = redact(text) or ""
        handle.write(redacted)
        if not redacted.endswith("\n"):
            handle.write("\n")
    tmp_path.replace(path)


def safe_move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
