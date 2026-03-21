from __future__ import annotations

import hashlib
import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_secret_exposure_validator import (
    SecretExposureValidatorStage,
)
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-secret-validator"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-secret-validator",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(
        job_id="job-secret-validator", queued_at="2020-01-01T00:00:00Z"
    )
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


def _write_secret_finding(
    path: Path, *, url: str, pattern: str, value: str, score: int = 85
) -> None:
    start_text = f'const sample = "{value}";'
    start = start_text.index(value)
    end = start + len(value)
    payload = {
        "type": "finding",
        "finding_type": "exposed_secret",
        "source": "secrets-static",
        "url": url,
        "hostname": "app.example.com",
        "score": score,
        "details": {
            "pattern": pattern,
            "value_hash": _hash_value(value),
            "length": len(value),
            "entropy": 4.2,
            "location": {"start": start, "end": end},
        },
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


class _FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.headers = {"Content-Type": "application/javascript"}

    def close(self) -> None:
        return None


def test_secret_validator_confirms_live_exposure(monkeypatch, tmp_path: Path):
    token = "AKIAQWERTYUIOPASDFGH"
    url = "https://app.example.com/app.js"
    record = _make_record(
        tmp_path,
        {
            "enable_secret_exposure_validator": True,
            "secret_exposure_validator_max_findings": 5,
            "secret_exposure_validator_min_score": 20,
            "secret_exposure_validator_timeout": 1,
            "secret_exposure_validator_rps": 0,
            "secret_exposure_validator_per_host_rps": 0,
        },
    )
    _write_secret_finding(
        record.paths.results_jsonl, url=url, pattern="aws_access_key", value=token
    )
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(_url, **_kwargs):
        return _FakeResponse(200, f'const sample = "{token}";')

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    stage = SecretExposureValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "secret-validator"
        and item.get("finding_type") == "exposed_secret"
    ]
    assert len(findings) == 1
    assert findings[0].get("confidence_label") == "verified"
    assert "live" in (findings[0].get("tags") or [])

    stats = record.metadata.stats.get("secret_exposure_validator", {})
    assert stats.get("confirmed") == 1
    assert stats.get("stale") == 0


def test_secret_validator_marks_stale_when_not_present(monkeypatch, tmp_path: Path):
    token = "AKIAQWERTYUIOPASDFGH"
    url = "https://app.example.com/app.js"
    record = _make_record(
        tmp_path,
        {
            "enable_secret_exposure_validator": True,
            "secret_exposure_validator_max_findings": 5,
            "secret_exposure_validator_min_score": 20,
            "secret_exposure_validator_timeout": 1,
        },
    )
    _write_secret_finding(
        record.paths.results_jsonl, url=url, pattern="aws_access_key", value=token
    )
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(_url, **_kwargs):
        return _FakeResponse(200, 'const sample = "SAFE_VALUE";')

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    stage = SecretExposureValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "secret-validator"
        and item.get("finding_type") == "exposed_secret"
    ]
    assert not findings
    stats = record.metadata.stats.get("secret_exposure_validator", {})
    assert stats.get("confirmed") == 0
    assert stats.get("stale") == 1


def test_secret_validator_filters_placeholder_tokens(monkeypatch, tmp_path: Path):
    value = "api_key='exampleexampleexampleexample'"
    url = "https://app.example.com/config.js"
    record = _make_record(
        tmp_path,
        {
            "enable_secret_exposure_validator": True,
            "secret_exposure_validator_max_findings": 5,
            "secret_exposure_validator_min_score": 20,
            "secret_exposure_validator_timeout": 1,
        },
    )
    _write_secret_finding(
        record.paths.results_jsonl, url=url, pattern="generic_secret", value=value
    )
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(_url, **_kwargs):
        return _FakeResponse(200, f'const sample = "{value}";')

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    stage = SecretExposureValidatorStage()
    stage.run(context)

    stats = record.metadata.stats.get("secret_exposure_validator", {})
    assert stats.get("confirmed") == 0
    assert stats.get("filtered_sanity") == 1
