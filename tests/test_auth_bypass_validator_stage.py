from __future__ import annotations

import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_auth_bypass_validator import AuthBypassValidatorStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


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
    metadata = JobMetadata(job_id="job-auth-bypass-validator", queued_at="2020-01-01T00:00:00Z")
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
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def close(self) -> None:
        return None


def test_auth_bypass_validator_confirms_forced_browse(monkeypatch, tmp_path: Path):
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
    _write_url(record.paths.results_jsonl, "https://app.example.com/admin/panel", score=80, status_code=403)
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_request(_method, _url, **kwargs):
        headers = kwargs.get("headers") or {}
        if headers.get("X-Original-URL"):
            return _FakeResponse(200, text="admin ok")
        return _FakeResponse(403, text="forbidden")

    import requests

    monkeypatch.setattr(requests, "request", fake_request)

    stage = AuthBypassValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "auth-bypass-validator" and item.get("finding_type") == "auth_bypass"
    ]
    assert len(findings) == 1
    assert findings[0].get("confidence_label") == "verified"
    assert "forced-browse" in (findings[0].get("tags") or [])

    stats = record.metadata.stats.get("auth_bypass_validator", {})
    assert stats.get("confirmed_forced") == 1
    assert stats.get("confirmed") == 1
    artifact_path = record.paths.root / str(stats.get("artifact"))
    assert artifact_path.exists()


def test_auth_bypass_validator_confirms_privilege_boundary(monkeypatch, tmp_path: Path):
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
            "idor_token_a": "Bearer token-a",
            "idor_token_b": "Bearer token-b",
        },
    )
    _write_url(record.paths.results_jsonl, "https://app.example.com/admin/users", score=75, status_code=403)
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_request(_method, _url, **kwargs):
        headers = kwargs.get("headers") or {}
        auth = str(headers.get("Authorization") or "")
        if auth in {"Bearer token-a", "Bearer token-b"}:
            return _FakeResponse(200, text='{"users":[{"id":"1001","role":"admin"}]}')
        return _FakeResponse(403, text="forbidden")

    import requests

    monkeypatch.setattr(requests, "request", fake_request)

    stage = AuthBypassValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "auth-bypass-validator" and item.get("finding_type") == "auth_bypass"
    ]
    assert len(findings) == 1
    assert (findings[0].get("details") or {}).get("reason") == "token_boundary_indistinguishable"

    stats = record.metadata.stats.get("auth_bypass_validator", {})
    assert stats.get("confirmed_boundary") == 1
    assert stats.get("confirmed") == 1


def test_auth_bypass_validator_handles_empty_candidates(tmp_path: Path):
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
    _write_url(record.paths.results_jsonl, "https://app.example.com/public/health", score=10, status_code=200)
    context = PipelineContext(record=record, manager=DummyManager())

    stage = AuthBypassValidatorStage()
    stage.run(context)

    stats = record.metadata.stats.get("auth_bypass_validator", {})
    assert stats.get("attempted") == 0
    assert stats.get("confirmed") == 0
