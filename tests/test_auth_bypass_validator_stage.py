from __future__ import annotations

import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from urllib.parse import urlparse

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.validation.stage_auth_bypass_validator import AuthBypassValidatorStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.async_http import HTTPResponse


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-auth-bypass-validator"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-auth-bypass-validator",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(
        job_id="job-auth-bypass-validator", queued_at="2020-01-01T00:00:00Z"
    )
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_url(path: Path, url: str, score: int = 90, status_code: int = 403) -> None:
    payload = {
        "type": "url",
        "url": url,
        "hostname": "app.example.com",
        "score": score,
        "status_code": status_code,
        "source": "httpx",
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "", headers: dict | None = None):
        self.status = status_code
        self.body = text
        self.headers = headers or {}
        self.url = "http://example.com"

    def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_auth_bypass_validator_confirms_forced_browse(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_auth_bypass_validator": True,
            "auth_bypass_validator_enable_forced_browse": True,
            "auth_bypass_validator_enable_privilege_boundary": False,
            "auth_bypass_validator_max_urls": 5,
            "auth_bypass_validator_max_per_host": 5,
            "auth_bypass_validator_timeout": 1,
            "auth_bypass_validator_min_score": 20,
            "auth_bypass_validator_rps": 0,
            "auth_bypass_validator_per_host_rps": 0,
        },
    )
    _write_url(
        record.paths.results_jsonl,
        "https://app.example.com/admin/panel",
        score=80,
        status_code=403,
    )
    context = PipelineContext(record=record, manager=DummyManager())
    from recon_cli.utils.auth import UnifiedAuthManager
    from recon_cli.pipeline.context import TargetGraph
    context._auth_manager = UnifiedAuthManager(context)
    context.target_graph = TargetGraph()

    async def fake_request(method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        if headers.get("X-Original-URL"):
            return _FakeResponse(200, text="admin ok")
        return _FakeResponse(403, text="forbidden")

    with patch("recon_cli.utils.async_http.AsyncHTTPClient._request", side_effect=fake_request):
        stage = AuthBypassValidatorStage()
        await stage.run_async(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "auth_bypass_validator"
        and item.get("finding_type") == "auth_bypass"
    ]
    assert len(findings) == 1
    assert "forced_browse" in (findings[0].get("tags") or [])

    stats = record.metadata.stats.get("auth_bypass_validator", {})
    assert stats.get("confirmed") == 1


@pytest.mark.asyncio
async def test_auth_bypass_validator_confirms_privilege_boundary(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_auth_bypass_validator": True,
            "auth_bypass_validator_enable_forced_browse": False,
            "auth_bypass_validator_enable_privilege_boundary": True,
            "auth_bypass_validator_max_urls": 5,
            "auth_bypass_validator_max_per_host": 5,
            "auth_bypass_validator_timeout": 1,
            "auth_bypass_validator_min_score": 20,
            "auth_bypass_validator_rps": 0,
            "auth_bypass_validator_per_host_rps": 0,
        },
    )
    _write_url(
        record.paths.results_jsonl,
        "https://app.example.com/admin/users",
        score=75,
        status_code=403,
    )
    context = PipelineContext(record=record, manager=DummyManager())
    from recon_cli.utils.auth import UnifiedAuthManager
    from recon_cli.pipeline.context import TargetGraph
    context._auth_manager = UnifiedAuthManager(context)
    context.target_graph = TargetGraph()
    
    # Register identities in UnifiedAuthManager
    context._auth_manager.register_identity("token-a", "admin", {"bearer": "token-a"}, host="app.example.com")
    context._auth_manager.register_identity("token-b", "user", {"bearer": "token-b"}, host="app.example.com")

    async def fake_request(method, url, **kwargs):
        identity_id = kwargs.get("identity_id")
        if identity_id in {"token-a", "token-b"}:
            return _FakeResponse(200, text='{"users":[{"id":"1001","role":"admin"}]}')
        return _FakeResponse(403, text="forbidden")

    with patch("recon_cli.utils.async_http.AsyncHTTPClient._request", side_effect=fake_request):
        stage = AuthBypassValidatorStage()
        await stage.run_async(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "auth_bypass_validator"
        and item.get("finding_type") == "auth_bypass"
    ]
    assert len(findings) == 1
    assert (findings[0].get("details") or {}).get("reason") == "boundary_weakness_bypass"

    stats = record.metadata.stats.get("auth_bypass_validator", {})
    assert stats.get("confirmed") == 1


@pytest.mark.asyncio
async def test_auth_bypass_validator_handles_empty_candidates(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_auth_bypass_validator": True,
            "auth_bypass_validator_max_urls": 5,
            "auth_bypass_validator_max_per_host": 5,
            "auth_bypass_validator_timeout": 1,
            "auth_bypass_validator_min_score": 40,
        },
    )
    _write_url(
        record.paths.results_jsonl,
        "https://app.example.com/public/health",
        score=10,
        status_code=200,
    )
    context = PipelineContext(record=record, manager=DummyManager())
    from recon_cli.utils.auth import UnifiedAuthManager
    from recon_cli.pipeline.context import TargetGraph
    context._auth_manager = UnifiedAuthManager(context)
    context.target_graph = TargetGraph()

    stage = AuthBypassValidatorStage()
    await stage.run_async(context)

    stats = record.metadata.stats.get("auth_bypass_validator", {})
    assert stats.get("confirmed") == 0
