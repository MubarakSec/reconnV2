from __future__ import annotations

import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_idor_validator import IDORValidatorStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-idor-validator"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-idor-validator",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-idor-validator", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_idor_suspect(path: Path, payload: dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


class _FakeResponse:
    def __init__(self, status_code: int, body: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")
        self.content = self.text.encode("utf-8")
        self.headers = {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body

    def close(self) -> None:
        return None


def test_idor_validator_confirms_subject_change(monkeypatch, tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_idor_validator": True,
            "idor_validator_max_candidates": 5,
            "idor_validator_max_per_host": 5,
            "idor_validator_timeout": 1,
            "idor_validator_min_score": 20,
            "idor_validator_rps": 0,
            "idor_validator_per_host_rps": 0,
            "idor_token_a": "Bearer token-a",
            "idor_token_b": "Bearer token-b",
        },
    )
    _write_idor_suspect(
        record.paths.results_jsonl,
        {
            "type": "idor_suspect",
            "source": "idor-stage",
            "url": "https://api.example.com/users/2",
            "auth": "token-a",
            "score": 88,
            "poc": "curl -k -H 'Authorization: Token-A' 'https://api.example.com/users/2'",
            "details": {
                "path_index": 1,
                "original": "1",
                "variant": "2",
                "reasons": ["subject_identifier_changed"],
            },
        },
    )
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(_self, url, **kwargs):
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        # Successful cross-user access simulation
        if url.endswith("/users/1"):
            # Both token-a and token-b can see users/1
            if auth in {"Bearer token-a", "Bearer token-b"}:
                return _FakeResponse(200, body={"id": "1", "email": "alice@example.com"})
            return _FakeResponse(403, text="forbidden")
        if url.endswith("/users/2"):
            if auth == "Bearer token-a":
                return _FakeResponse(200, body={"id": "2", "email": "bob@example.com"})
            return _FakeResponse(403, text="forbidden")
        return _FakeResponse(404, text="not found")

    import requests

    monkeypatch.setattr(requests.sessions.Session, "get", fake_get)

    stage = IDORValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "idor-validator" and item.get("finding_type") == "idor"
    ]
    assert len(findings) == 1
    reasons = (findings[0].get("details") or {}).get("reasons") or []
    assert "cross_user_access_confirmed" in reasons
    assert findings[0].get("confidence_label") == "verified"

    stats = record.metadata.stats.get("idor_validator", {})
    assert stats.get("confirmed") == 1
    artifact_path = record.paths.root / str(stats.get("artifact"))
    assert artifact_path.exists()


def test_idor_validator_skips_when_token_missing(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_idor_validator": True,
            "idor_validator_max_candidates": 5,
            "idor_validator_max_per_host": 5,
            "idor_validator_timeout": 1,
            "idor_validator_min_score": 20,
        },
    )
    _write_idor_suspect(
        record.paths.results_jsonl,
        {
            "type": "idor_suspect",
            "source": "idor-stage",
            "url": "https://api.example.com/users/2",
            "auth": "token-b",
            "score": 88,
            "details": {
                "path_index": 1,
                "original": "1",
                "variant": "2",
                "reasons": ["subject_identifier_changed"],
            },
        },
    )
    context = PipelineContext(record=record, manager=DummyManager())

    stage = IDORValidatorStage()
    stage.run(context)

    stats = record.metadata.stats.get("idor_validator", {})
    assert stats.get("confirmed") == 0
    assert stats.get("skipped") == 1


def test_idor_validator_handles_empty_candidates(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_idor_validator": True,
            "idor_validator_max_candidates": 5,
            "idor_validator_max_per_host": 5,
            "idor_validator_timeout": 1,
            "idor_validator_min_score": 60,
        },
    )
    _write_idor_suspect(
        record.paths.results_jsonl,
        {
            "type": "url",
            "url": "https://app.example.com/home",
            "score": 5,
        },
    )
    context = PipelineContext(record=record, manager=DummyManager())

    stage = IDORValidatorStage()
    stage.run(context)

    stats = record.metadata.stats.get("idor_validator", {})
    assert stats.get("attempted") == 0
    assert stats.get("confirmed") == 0
