from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from recon_cli.utils.sanitizer import redact


def emit_metrics(payload: Dict[str, object], path: Path) -> None:
    """Write metrics JSON to path (opt-in via RECON_METRICS=1)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    redacted = json.loads(redact(json.dumps(payload)) or "{}")
    path.write_text(json.dumps(redacted, indent=2, sort_keys=True), encoding="utf-8")
