from __future__ import annotations

import asyncio
import json
import pytest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.vuln.stage_second_order_injection import SecondOrderInjectionStage
from recon_cli.pipeline.stages.vuln.stage_advanced_idor import AdvancedIDORStage
from recon_cli.pipeline.stages.vuln.stage_timing_attacks import TimingAttackStage
from recon_cli.utils import fs
from recon_cli.utils.async_http import HTTPResponse

class DummyManager:
    def update_metadata(self, record) -> None: pass
    def update_spec(self, record) -> None: pass

def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-business-logic"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id="job-bl", target="example.com", profile="full", runtime_overrides=runtime_overrides)
    metadata = JobMetadata(job_id="job-bl", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)

@pytest.mark.asyncio
async def test_second_order_injection_detection(monkeypatch, tmp_path: Path):
    record = _make_record(tmp_path, {"enable_second_order": True})
    context = PipelineContext(record=record, manager=DummyManager())
    
    # Setup some results: a sink (form) and a source (url)
    context.results.append({
        "type": "form", "url": "https://example.com/profile/edit", "method": "POST",
        "inputs": [{"name": "display_name", "type": "text"}], "source": "test"
    })
    context.results.append({
        "type": "url", "url": "https://example.com/profile/view", "status_code": 200, "hostname": "example.com"
    })

    # Mock UUID to have a predictable canary
    mock_uuid = MagicMock()
    mock_uuid.hex = "12345678"
    monkeypatch.setattr("uuid.uuid4", MagicMock(return_value=mock_uuid))

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = HTTPResponse(url="...", status=200, headers={}, body="saved", elapsed=0.1)
    mock_client.get.return_value = HTTPResponse(url="...", status=200, headers={}, body="Hello recon_canary_12345678", elapsed=0.1)
    
    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_second_order_injection.AsyncHTTPClient", MagicMock(return_value=mock_client))
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    stage = SecondOrderInjectionStage()
    await stage.run_async(context)

    findings = [r for r in context.get_results() if r.get("finding_type") == "second_order_injection"]
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_advanced_idor_sequential_detection(monkeypatch, tmp_path: Path):
    record = _make_record(tmp_path, {"enable_advanced_idor": True})
    context = PipelineContext(record=record, manager=DummyManager())
    
    context.results.append({
        "type": "url", "url": "https://example.com/api/orders/1001", "status_code": 200, "hostname": "example.com"
    })

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = HTTPResponse(url="https://example.com/api/orders/1000", status=200, headers={}, body='{"id": 1000}', elapsed=0.1)
    
    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_advanced_idor.AsyncHTTPClient", MagicMock(return_value=mock_client))

    stage = AdvancedIDORStage()
    await stage.run_async(context)

    findings = [r for r in context.get_results() if r.get("finding_type") == "advanced_idor"]
    assert len(findings) > 0
    assert "predictable-id" in findings[0]["tags"]

@pytest.mark.asyncio
async def test_timing_attack_detection(monkeypatch, tmp_path: Path):
    # Setup accounts.json so stage has a "valid" user to test against
    accounts_file = tmp_path / "data" / "accounts.json"
    accounts_file.parent.mkdir(parents=True)
    accounts_file.write_text(json.dumps({"example.com": {"username": "admin", "password": "abc"}}))

    record = _make_record(tmp_path, {"enable_timing_attacks": True, "timing_iterations": 2})
    context = PipelineContext(record=record, manager=DummyManager())
    # Mock event_bus to avoid coroutine warnings
    context.event_bus = MagicMock()
    context.results.event_bus = None 
    
    context.results.append({
        "type": "form", "url": "https://example.com/login", "method": "POST",
        "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}], "source": "test"
    })

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = HTTPResponse(url="...", status=401, headers={}, body="fail", elapsed=0.1)
    
    # TimingAttackStage calls time.perf_counter() before and after request
    # iterations=2, 2 warm-ups (4 calls), 2 invalid (4 calls), 2 valid (4 calls)
    perf_values = [
        1.0, 1.1, # Warmup 1 (diff 0.1)
        1.2, 1.3, # Warmup 2 (diff 0.1)
        2.0, 2.05, # Invalid 1 (diff 0.05)
        2.1, 2.15, # Invalid 2 (diff 0.05) -> avg_invalid = 0.05, std=0
        3.0, 3.25, # Valid 1 (diff 0.25)
        3.3, 3.55, # Valid 2 (diff 0.25) -> avg_valid = 0.25, std=0
    ]
    it = iter(perf_values)
    def mock_perf():
        try:
            return next(it)
        except StopIteration:
            return 100.0

    monkeypatch.setattr("time.perf_counter", mock_perf)

    monkeypatch.setattr("asyncio.sleep", AsyncMock())
    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_timing_attacks.AsyncHTTPClient", MagicMock(return_value=mock_client))
    
    stage = TimingAttackStage()
    stage.ACCOUNTS_FILE = accounts_file
    await stage.run_async(context)

    findings = [r for r in context.get_results() if r.get("finding_type") == "user_enumeration_timing"]
    assert len(findings) > 0
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["valid_user"] == "admin"

