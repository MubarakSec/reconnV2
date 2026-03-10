"""
ReconnV2 REST API
واجهة برمجة تطبيقات للتحكم في الأداة عن بعد
"""

import json
from typing import Any, Dict, Optional

from recon_cli.utils.json_schema import normalize_json_schema

from .app import create_app, run_api
from . import app as api_app
from recon_cli.jobs.models import JobMetadata, JobSpec
from recon_cli.users import Permission


_API_AUTH_HINTS: Dict[str, Dict[str, Any]] = {
    "GET /api/status": {"x_api_key": "none", "permissions": []},
    "GET /api/health": {"x_api_key": "none", "permissions": []},
    "GET /api/version": {"x_api_key": "none", "permissions": []},
    "GET /api/stats": {"x_api_key": "none", "permissions": []},
    "GET /api/metrics": {"x_api_key": "none", "permissions": []},
    "GET /api/jobs": {"x_api_key": "optional", "permissions": []},
    "GET /api/jobs/{job_id}": {"x_api_key": "optional", "permissions": []},
    "GET /api/jobs/{job_id}/results": {"x_api_key": "optional", "permissions": []},
    "GET /api/jobs/{job_id}/summary": {"x_api_key": "optional", "permissions": []},
    "GET /api/jobs/{job_id}/logs": {"x_api_key": "optional", "permissions": []},
    "GET /api/jobs/{job_id}/report": {"x_api_key": "none", "permissions": []},
    "POST /api/scan": {
        "x_api_key": "required",
        "permissions": [Permission.API_ACCESS.value, Permission.JOBS_CREATE.value],
    },
    "POST /api/jobs": {
        "x_api_key": "required",
        "permissions": [Permission.API_ACCESS.value, Permission.JOBS_CREATE.value],
    },
    "POST /api/jobs/{job_id}/requeue": {
        "x_api_key": "required",
        "permissions": [Permission.API_ACCESS.value, Permission.JOBS_RUN.value],
    },
    "DELETE /api/jobs/{job_id}": {
        "x_api_key": "required",
        "permissions": [Permission.API_ACCESS.value, Permission.JOBS_DELETE.value],
    },
}


def _type_schema(model: type[Any]) -> Dict[str, Any]:
    try:
        from pydantic import TypeAdapter
    except Exception:
        return {}
    return normalize_json_schema(TypeAdapter(model).json_schema())


def _openapi_schema() -> Optional[Dict[str, Any]]:
    if not getattr(api_app, "FASTAPI_AVAILABLE", False):
        return None
    try:
        return create_app().openapi()
    except Exception:
        return None


def schema() -> dict:
    """Return machine-consumable schema hints for automation clients."""
    payload = {
        "schema_version": "2026-03-10",
        "job_spec": JobSpec(job_id="string", target="string", profile="string").to_dict(),
        "job_metadata": JobMetadata(job_id="string", queued_at="timestamp").to_dict(),
        "job_spec_schema": _type_schema(JobSpec),
        "job_metadata_schema": _type_schema(JobMetadata),
        "results_meta": {"type": "meta", "schema_version": "1.0.0"},
        "api_auth": _API_AUTH_HINTS,
    }
    openapi = _openapi_schema()
    if openapi:
        payload["openapi"] = openapi
    return payload


def schema_json() -> str:
    return json.dumps(schema(), indent=2, sort_keys=True)


__all__ = ["create_app", "run_api", "schema", "schema_json"]
