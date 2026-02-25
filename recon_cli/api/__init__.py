"""
ReconnV2 REST API
واجهة برمجة تطبيقات للتحكم في الأداة عن بعد
"""

import json

from .app import create_app, run_api
from recon_cli.jobs.models import JobMetadata, JobSpec


def schema() -> dict:
    """Return machine-consumable schema hints for automation clients."""
    return {
        "job_spec": JobSpec(job_id="string", target="string", profile="string").to_dict(),
        "job_metadata": JobMetadata(job_id="string", queued_at="timestamp").to_dict(),
        "results_meta": {"type": "meta", "schema_version": "1.0.0"},
    }


def schema_json() -> str:
    return json.dumps(schema(), indent=2, sort_keys=True)


__all__ = ["create_app", "run_api", "schema", "schema_json"]
