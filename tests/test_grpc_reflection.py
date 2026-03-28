from __future__ import annotations

import json
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.discovery.stage_ws_grpc_discovery import WsGrpcDiscoveryStage


class DummyManager:
    def update_metadata(self, record) -> None: return None
    def update_spec(self, record) -> None: return None


def _make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job-grpc"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id="job-grpc", target="example.com", profile="full")
    metadata = JobMetadata(job_id="job-grpc", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


@pytest.mark.asyncio
async def test_grpc_reflection_detection(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path)
    # Mock finding a gRPC-like URL
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://api.example.com/grpc", "content_type": "application/grpc"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Mock GRPCFuzzer
    mock_grpc_fuzzer = AsyncMock()
    mock_grpc_fuzzer.check_reflection.return_value = (True, "Reflection enabled", [])
    mock_grpc_fuzzer.fuzz_methods.return_value = [{"service": "test.Service", "status": "0"}]
    
    monkeypatch.setattr("recon_cli.pipeline.stages.discovery.stage_ws_grpc_discovery.GRPCFuzzer", MagicMock(return_value=mock_grpc_fuzzer))
    
    # Mock WS part to avoid errors
    monkeypatch.setattr("recon_cli.pipeline.stages.discovery.stage_ws_grpc_discovery.AsyncHTTPClient", MagicMock())
    
    stage = WsGrpcDiscoveryStage()
    await stage.run_async(context)
    
    # Verify reflection was detected
    calls = context.emit_signal.call_args_list
    assert any(call.args[0] == "grpc_reflection_enabled" for call in calls)
    assert any(r.get("finding_type") == "grpc_reflection" for r in context.results.iter_results())
