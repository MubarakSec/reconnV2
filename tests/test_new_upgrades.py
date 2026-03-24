from __future__ import annotations

import json
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_favicon_recon import FaviconReconStage
from recon_cli.pipeline.stage_quic_discovery import QuicDiscoveryStage
from recon_cli.pipeline.stage_proto_pollution import ProtoPollutionStage


class DummyManager:
    def update_metadata(self, record) -> None: return None
    def update_spec(self, record) -> None: return None


def _make_record(tmp_path: Path, job_id: str) -> JobRecord:
    root = tmp_path / job_id
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id=job_id, target="example.com", profile="full")
    metadata = JobMetadata(job_id=job_id, queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


@pytest.mark.asyncio
async def test_favicon_recon_stage(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path, "job-favicon")
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://example.com/"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Mock AsyncHTTPClient and fetch_favicon_hash
    monkeypatch.setattr("recon_cli.pipeline.stage_favicon_recon.AsyncHTTPClient", MagicMock())
    # Django hash: -1253869855
    monkeypatch.setattr("recon_cli.pipeline.stage_favicon_recon.fetch_favicon_hash", AsyncMock(return_value=-1253869855))
    
    stage = FaviconReconStage()
    await stage.run_async(context)
    
    assert any("Django" in r.get("description", "") for r in context.results.iter_results())


@pytest.mark.asyncio
async def test_quic_discovery_stage(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path, "job-quic")
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://example.com/"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Mock QUICDetector
    mock_detector = AsyncMock()
    mock_detector.check_quic.return_value = (True, "Found Alt-Svc")
    monkeypatch.setattr("recon_cli.pipeline.stage_quic_discovery.QUICDetector", MagicMock(return_value=mock_detector))
    
    stage = QuicDiscoveryStage()
    await stage.run_async(context)
    
    assert any("protocol:h3" in r.get("tags", []) for r in context.results.iter_results())


@pytest.mark.asyncio
async def test_proto_pollution_stage_server_side(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path, "job-pp")
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://example.com/api/v1"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Mock AsyncHTTPClient to return 'reconn_pp' in body (simulating reflection)
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_resp = MagicMock()
    mock_resp.body = '{"status": "ok", "reconn_pp": "polluted"}'
    mock_client_instance.post.return_value = mock_resp
    monkeypatch.setattr("recon_cli.pipeline.stage_proto_pollution.AsyncHTTPClient", MagicMock(return_value=mock_client_instance))
    
    # Disable playwright for this test
    monkeypatch.setattr("recon_cli.pipeline.stage_proto_pollution.ProtoPollutionStage._test_client_side", AsyncMock())
    
    stage = ProtoPollutionStage()
    await stage.run_async(context)
    
    results = list(context.results.iter_results())
    assert any("Server-side Prototype Pollution" in r.get("description", "") for r in results)
