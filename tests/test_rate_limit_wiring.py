import json
import sys
import types
import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.vuln.stage_waf import WafProbeStage
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


class FakeLimiter:
    def __init__(self):
        self.wait_calls = 0
        self.response_calls = 0
        self.error_calls = 0

    async def wait_for_slot(self, _url, timeout=None):
        self.wait_calls += 1
        return True

    def on_response(self, _url, _status):
        self.response_calls += 1

    def on_error(self, _url):
        self.error_calls += 1


def make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-rate"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-rate",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-rate", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_url(path: Path, url: str, status_code: int = 200):
    payload = {
        "type": "url",
        "url": url,
        "hostname": "example.com",
        "status_code": status_code,
        "score": 10,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


# Test removed as APIReconStage now uses AsyncHTTPClient's built-in rate limiting


@pytest.mark.asyncio
async def test_rate_limiter_used_in_waf_probe(monkeypatch, tmp_path: Path):
    record = make_record(tmp_path, {"enable_waf_probe": True})
    _write_url(record.paths.results_jsonl, "http://example.com/", status_code=403)

    context = PipelineContext(record=record, manager=DummyManager())
    context.runtime_config.enable_waf_probe = True
    # Ensure the URL is allowed by scope logic
    monkeypatch.setattr(context, "url_allowed", lambda *_: True)

    # Force the context to return our seeded result
    seeded_result = {
        "type": "url",
        "url": "http://example.com/",
        "hostname": "example.com",
        "status_code": 403,
        "score": 10,
    }
    # Return an iterator
    monkeypatch.setattr(context, "iter_results", lambda: iter([seeded_result]))

    class DummyResponse:
        def __init__(self, status):
            self.status_code = status
            self.text = "ok"

    def _get(_url, **kwargs):
        headers = kwargs.get("headers") or {}
        if "Googlebot" in headers.get("User-Agent", ""):
            return DummyResponse(200)
        return DummyResponse(403)

    class FakeSession:
        def __init__(self):
            self.cookies = MagicMock()
            self.get = _get

    fake_requests = types.SimpleNamespace(get=_get, Session=FakeSession)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    limiter = FakeLimiter()
    monkeypatch.setattr(context, "get_rate_limiter", lambda *a, **k: limiter)

    stage = WafProbeStage()
    await stage.run_async(context)

    assert limiter.wait_calls > 0
    assert limiter.response_calls > 0
