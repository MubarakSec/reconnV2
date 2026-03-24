from __future__ import annotations

import json
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_jwt_vuln import JWTVulnerabilityStage
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-jwt-vuln"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(
        job_id="job-jwt-vuln",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(
        job_id="job-jwt-vuln", queued_at="2020-01-01T00:00:00Z"
    )
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_jwt_finding(path: Path, token: str):
    payload = {
        "type": "js_secret",
        "url": "https://example.com/main.js",
        "evidence": {"type": "jwt_token", "value": token},
        "tags": ["secret", "jwt_token"]
    }
    with path.open("a", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")

def _write_url_finding(path: Path, url: str):
    payload = {
        "type": "url",
        "url": url,
        "source": "js-intel"
    }
    with path.open("a", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


@pytest.mark.asyncio
async def test_jwt_vuln_stage_detects_weak_secret(tmp_path: Path, monkeypatch):
    # JWT with secret "secret"
    # Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    # Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022} -> eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
    # Signature: XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
    
    record = _make_record(tmp_path, {"enable_jwt_vuln": True})
    _write_jwt_finding(record.paths.results_jsonl, token)
    _write_url_finding(record.paths.results_jsonl, "https://example.com/api/v1/user")
    
    context = PipelineContext(record=record, manager=DummyManager())
    
    # Mock AsyncHTTPClient
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.body = '{"id": 1, "user": "admin"}'
    mock_client_instance.get.return_value = mock_resp
    
    monkeypatch.setattr("recon_cli.pipeline.stage_jwt_vuln.AsyncHTTPClient", MagicMock(return_value=mock_client_instance))
    
    stage = JWTVulnerabilityStage()
    
    # We need to mock emit_signal to verify detection
    context.emit_signal = MagicMock()
    
    await stage.run_async(context)
    
    # Verify weak secret "secret" was detected
    calls = context.emit_signal.call_args_list
    weak_secret_detected = any(call.args[0] == "jwt_weak_secret" and call.kwargs["evidence"]["secret"] == "secret" for call in calls)
    assert weak_secret_detected

@pytest.mark.asyncio
async def test_jwt_vuln_stage_detects_alg_none(tmp_path: Path, monkeypatch):
    # Valid JWT
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
    
    record = _make_record(tmp_path, {"enable_jwt_vuln": True})
    _write_jwt_finding(record.paths.results_jsonl, token)
    _write_url_finding(record.paths.results_jsonl, "https://example.com/api/v1/user")
    
    context = PipelineContext(record=record, manager=DummyManager())
    
    # Mock AsyncHTTPClient
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    
    def side_effect(url, headers=None, **kwargs):
        auth = headers.get("Authorization", "")
        # Header {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
        if "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" in auth:
            resp = MagicMock()
            resp.status = 200
            resp.body = '{"id": 1, "user": "admin"}'
            return resp
        resp = MagicMock()
        resp.status = 401
        resp.body = "Unauthorized"
        return resp

    mock_client_instance.get.side_effect = side_effect
    
    monkeypatch.setattr("recon_cli.pipeline.stage_jwt_vuln.AsyncHTTPClient", MagicMock(return_value=mock_client_instance))
    
    stage = JWTVulnerabilityStage()
    context.emit_signal = MagicMock()
    
    await stage.run_async(context)
    
    # Verify alg:none was detected
    calls = context.emit_signal.call_args_list
    alg_none_detected = any(call.args[0] == "jwt_vulnerability" and call.kwargs["evidence"]["vuln"] == "alg:none" for call in calls)
    assert alg_none_detected
