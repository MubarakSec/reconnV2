from __future__ import annotations

import json
from typing import List

from recon_cli.jobs.manager import JobRecord
from recon_cli.utils import fs


def validate_job(record: JobRecord) -> List[str]:
    issues: List[str] = []
    # Spec validation
    if not record.paths.spec_path.exists():
        issues.append("spec.json missing")
    else:
        spec = fs.read_json(record.paths.spec_path, default=None)
        if spec is None:
            issues.append("spec.json unreadable or invalid JSON")
    # Metadata validation
    if not record.paths.metadata_path.exists():
        issues.append("metadata.json missing")
    else:
        metadata = fs.read_json(record.paths.metadata_path, default=None)
        if metadata is None:
            issues.append("metadata.json unreadable or invalid JSON")
        else:
            schema = metadata.get("schema_version") if isinstance(metadata, dict) else None  # type: ignore
            if not schema:
                issues.append("metadata schema_version missing")
    # Results validation
    if not record.paths.results_jsonl.exists():
        issues.append("results.jsonl missing")
    else:
        bad_lines = 0
        with record.paths.results_jsonl.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)
                except json.JSONDecodeError:
                    bad_lines += 1
        if bad_lines:
            issues.append(f"results.jsonl contains {bad_lines} invalid lines")
    # Logs
    if not record.paths.pipeline_log.exists():
        issues.append("pipeline log missing")
    return issues
