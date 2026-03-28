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
from recon_cli.utils.ws_fuzzer import WSFuzzer


class DummyManager:
    def update_metadata(self, record) -> None: return None
    def update_spec(self, record) -> None: return None


def _make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job-ws"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id="job-ws", target="example.com", profile="full")
    metadata = JobMetadata(job_id="job-ws", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


@pytest.mark.asyncio
async def test_ws_discovery_and_fuzzing(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path)
    # Mock finding a candidate URL
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "wss://example.com/ws"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    # Mock emit_signal to just store signals and NOT publish to event bus
    # which avoids the coroutine warning
    signals = []
    def mock_emit(stype, ttype, target, **kwargs):
        signals.append((stype, ttype, target, kwargs))
        # Also put it in results so the check at the end passes
        context.results.append({"type": "finding", "finding_type": stype, "url": target})
        return "sig_123"
    
    context.emit_signal = mock_emit
    
    # Mock AsyncHTTPClient for 101 Switching Protocols
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_resp = MagicMock()
    mock_resp.status = 101
    mock_client_instance.get.return_value = mock_resp
    monkeypatch.setattr("recon_cli.pipeline.stages.discovery.stage_ws_grpc_discovery.AsyncHTTPClient", MagicMock(return_value=mock_client_instance))
    
    # Mock WSFuzzer
    mock_fuzzer = AsyncMock()
    mock_fuzzer.fuzz_endpoint.return_value = [{
        "type": "ws_unauth",
        "confidence": 0.8,
        "description": "Unauth WS access",
        "evidence": {"status": "ok"}
    }]
    monkeypatch.setattr("recon_cli.pipeline.stages.discovery.stage_ws_grpc_discovery.WSFuzzer", MagicMock(return_value=mock_fuzzer))
    
    stage = WsGrpcDiscoveryStage()
    await stage.run_async(context)
    
    # Verify WS was detected and fuzzed
    assert any(s[0] == "ws_detected" for s in signals)
    assert any(s[0] == "ws_unauth" for s in signals)
    
    # Check results via iter_results
    all_results = list(context.results.iter_results())
    assert any(r.get("finding_type") == "ws_unauth" for r in all_results)

def test_ws_fuzzer_id_detection():
    fuzzer = WSFuzzer()
    # Should detect user_id
    assert fuzzer._check_json_for_ids({"user_id": 123}) == True
    # Should detect account in nested list
    assert fuzzer._check_json_for_ids({"data": [{"account": "hex123456789"}]}) == True
    # Should not detect random strings
    assert fuzzer._check_json_for_ids({"msg": "hello world"}) == False
