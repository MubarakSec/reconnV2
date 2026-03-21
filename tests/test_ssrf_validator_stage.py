from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_ssrf_validator import SSRFValidatorStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.oast import OastInteraction


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-ssrf-validator"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-ssrf-validator",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(
        job_id="job-ssrf-validator", queued_at="2020-01-01T00:00:00Z"
    )
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
    def __init__(self, status_code: int, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def close(self) -> None:
        return None


def test_ssrf_validator_confirms_via_oast(monkeypatch, tmp_path: Path):
    from recon_cli.pipeline import stage_ssrf_validator as stage_mod

    record = _make_record(
        tmp_path,
        {
            "enable_ssrf_validator": True,
            "ssrf_validator_enable_oast": True,
            "ssrf_validator_enable_internal": False,
            "ssrf_validator_max_urls": 5,
            "ssrf_validator_max_per_host": 5,
            "ssrf_validator_timeout": 1,
            "ssrf_validator_min_score": 20,
            "ssrf_validator_rps": 0,
            "ssrf_validator_per_host_rps": 0,
        },
    )
    _write_url(
        record.paths.results_jsonl,
        "https://app.example.com/fetch?url=https://example.net/",
    )
    context = PipelineContext(record=record, manager=DummyManager())

    class FakeSession:
        def __init__(self, *_args, **_kwargs):
            return None

        def start(self):
            return True

        def make_url(self, token: str) -> str:
            return f"http://{token}.oast.local"

        def collect_interactions(self, tokens):
            token = list(tokens)[0]
            return [
                OastInteraction(
                    token=token,
                    protocol="http",
                    raw={"token": token, "protocol": "http"},
                )
            ]

        def stop(self):
            return None

    monkeypatch.setattr(stage_mod, "InteractshSession", FakeSession)

    def fake_request(_method, _url, **_kwargs):
        return _FakeResponse(200, text="ok")

    import requests

    monkeypatch.setattr(requests, "request", fake_request)

    stage = SSRFValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "ssrf-validator" and item.get("finding_type") == "ssrf"
    ]
    assert findings
    assert any("oast" in item.get("tags", []) for item in findings)
    stats = record.metadata.stats.get("ssrf_validator", {})
    assert stats.get("confirmed_oast", 0) >= 1
    assert stats.get("confirmed", 0) >= 1


def test_ssrf_validator_confirms_via_internal_probe(monkeypatch, tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_ssrf_validator": True,
            "ssrf_validator_enable_oast": False,
            "ssrf_validator_enable_internal": True,
            "ssrf_validator_max_urls": 5,
            "ssrf_validator_max_per_host": 5,
            "ssrf_validator_timeout": 1,
            "ssrf_validator_min_score": 20,
            "ssrf_validator_rps": 0,
            "ssrf_validator_per_host_rps": 0,
            "retry_count": 0,
        },
    )
    _write_url(
        record.paths.results_jsonl,
        "https://app.example.com/render?url=https://example.net/",
    )
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_request(_method, url, **_kwargs):
        query = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        payload = query.get("url", "")
        if payload.startswith("http://127.0.0.1"):
            return _FakeResponse(
                500, text="dial tcp 127.0.0.1:80: connect: connection refused"
            )
        return _FakeResponse(200, text="ok baseline")

    import requests

    monkeypatch.setattr(requests, "request", fake_request)

    stage = SSRFValidatorStage()
    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "ssrf-validator" and item.get("finding_type") == "ssrf"
    ]
    assert findings
    assert any("internal" in item.get("tags", []) for item in findings)
    stats = record.metadata.stats.get("ssrf_validator", {})
    assert stats.get("confirmed_internal", 0) >= 1
