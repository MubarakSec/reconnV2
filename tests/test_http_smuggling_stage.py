from __future__ import annotations

import json
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.vuln.stage_http_smuggling import HttpSmugglingStage


class DummyManager:
    def update_metadata(self, record) -> None: return None
    def update_spec(self, record) -> None: return None


def _make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job-smuggling"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id="job-smuggling", target="example.com", profile="full")
    metadata = JobMetadata(job_id="job-smuggling", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


@pytest.mark.asyncio
async def test_http_smuggling_stage_detects_h1_clte(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path)
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://example.com/"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Mock send_raw_http to return TIMEOUT for CL.TE but success for normal
    async def mock_send_raw(url, payload, timeout=5.0):
        if b"Content-Length: 4" in payload and b"Transfer-Encoding: chunked" in payload:
            return None, "TIMEOUT"
        # Normal request
        resp = MagicMock()
        resp.status = 200
        return resp, None

    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_http_smuggling.send_raw_http", mock_send_raw)
    
    # Disable H2 for this test
    mock_h2_detector = AsyncMock()
    mock_h2_detector.check_h2_support.return_value = False
    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_http_smuggling.H2SmugglingDetector", MagicMock(return_value=mock_h2_detector))
    
    stage = HttpSmugglingStage()
    await stage.run_async(context)
    
    # Verify CL.TE was detected
    context.emit_signal.assert_called()
    found_clte = any(call.args[0] == "http_smuggling_suspected" and call.kwargs["evidence"]["technique"] == "CL.TE" for call in context.emit_signal.call_args_list)
    assert found_clte


@pytest.mark.asyncio
async def test_http_smuggling_stage_detects_h2_cl(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path)
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://example.com/"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Disable H1.1 desync (no timeouts)
    async def mock_send_raw(url, payload, timeout=5.0):
        resp = MagicMock()
        resp.status = 200
        return resp, None
    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_http_smuggling.send_raw_http", mock_send_raw)
    
    # Mock H2 detector to return H2.CL vuln
    mock_h2_detector = AsyncMock()
    mock_h2_detector.check_h2_support.return_value = True
    mock_h2_detector.detect_h2_cl.return_value = (True, "H2.CL desync: Timeout")
    mock_h2_detector.detect_h2_te.return_value = (False, "")
    
    monkeypatch.setattr("recon_cli.pipeline.stages.vuln.stage_http_smuggling.H2SmugglingDetector", MagicMock(return_value=mock_h2_detector))
    
    stage = HttpSmugglingStage()
    await stage.run_async(context)
    
    # Verify H2.CL was detected
    found_h2cl = any(call.args[0] == "http_smuggling_suspected" and call.kwargs["evidence"]["technique"] == "H2.CL" for call in context.emit_signal.call_args_list)
    assert found_h2cl
