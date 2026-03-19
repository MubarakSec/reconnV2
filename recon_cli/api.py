from __future__ import annotations

import json
from typing import Dict, Optional

from recon_cli.jobs.manager import JobManager
from recon_cli.jobs.models import JobSpec, JobMetadata


def schema() -> Dict[str, object]:
    """Return machine-consumable schema hints for automation clients."""
    return {
        "job_spec": JobSpec(
            job_id="string", target="string", profile="string"
        ).to_dict(),
        "job_metadata": JobMetadata(job_id="string", queued_at="timestamp").to_dict(),
        "results_meta": {"type": "meta", "schema_version": "1.0.0"},
    }


def schema_json() -> str:
    return json.dumps(schema(), indent=2, sort_keys=True)


def submit_job(payload: Dict[str, object]) -> Optional[str]:
    """Programmatic job submission helper (non-HTTP)."""
    manager = JobManager()
    try:
        spec = JobSpec.from_dict(payload)  # type: ignore[arg-type]
    except Exception:
        return None
    record = manager.create_job(
        target=spec.target,
        profile=spec.profile,
        project=getattr(spec, "project", None),
        inline=spec.inline,
        wordlist=spec.wordlist,
        targets_file=spec.targets_file,
        max_screenshots=spec.max_screenshots,
        force=spec.force,
        allow_ip=spec.allow_ip,
        active_modules=spec.active_modules,
        scanners=spec.scanners,
        execution_profile=spec.execution_profile,
        runtime_overrides=spec.runtime_overrides,
        insecure=spec.insecure,
        incremental_from=getattr(spec, "incremental_from", None),
    )
    return record.spec.job_id
