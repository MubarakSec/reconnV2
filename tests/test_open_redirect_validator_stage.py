from __future__ import annotations

import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.validation.stage_open_redirect_validator import OpenRedirectValidatorStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-open-redirect"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-open-redirect",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-open-redirect", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_url(path: Path, url: str, score: int = 90) -> None:
    payload = {
        "type": "url",
        "url": url,
        "hostname": "app.example.com",
        "score": score,
        "source": "httpx",
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


class _FakeResponse:
    def __init__(self, status_code: int, location: str = ""):
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}

    def close(self) -> None:
        return None


def test_open_redirect_validator_confirms_and_writes_artifact(
    monkeypatch, tmp_path: Path
):
    record = _make_record(
        tmp_path,
        {
            "enable_open_redirect_validator": True,
            "open_redirect_validator_max_urls": 5,
            "open_redirect_validator_max_per_host": 5,
            "open_redirect_validator_timeout": 1,
            "open_redirect_validator_min_score": 20,
            "open_redirect_validator_rps": 0,
            "open_redirect_validator_per_host_rps": 0,
        },
    )
    _write_url(
        record.paths.results_jsonl, "https://app.example.com/login?next=/dashboard"
    )
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(url, **_kwargs):
        if "redirect-" in url:
            start = url.find("https%3A%2F%2F")
            if start == -1:
                start = url.find("%2F%2Fredirect-")
            if start != -1:
                encoded = url[start:].split("&", 1)[0]
                location = encoded.replace("https%3A%2F%2F", "https://").replace(
                    "%2F", "/"
                )
                return _FakeResponse(302, location=location)
        return _FakeResponse(302, location="/dashboard")

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    stage = OpenRedirectValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "open-redirect-validator"
        and item.get("finding_type") == "open_redirect"
    ]
    assert len(findings) == 1
    assert findings[0].get("confidence_label") == "verified"

    stats = record.metadata.stats.get("open_redirect_validator", {})
    assert stats.get("confirmed") == 1
    artifact_path = Path(stats.get("artifact"))
    assert artifact_path.exists()
    artifact_payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact_payload
    assert artifact_payload[0]["status_code"] == 302


def test_open_redirect_validator_skips_when_no_candidates(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_open_redirect_validator": True,
            "open_redirect_validator_max_urls": 5,
            "open_redirect_validator_max_per_host": 5,
            "open_redirect_validator_timeout": 1,
            "open_redirect_validator_min_score": 20,
        },
    )
    _write_url(record.paths.results_jsonl, "https://app.example.com/home")
    context = PipelineContext(record=record, manager=DummyManager())

    stage = OpenRedirectValidatorStage()
    stage.run(context)

    stats = record.metadata.stats.get("open_redirect_validator", {})
    assert stats.get("attempted") == 0
    assert stats.get("confirmed") == 0
