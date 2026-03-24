from __future__ import annotations

import asyncio
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_race_condition import RaceConditionStage
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None: return None
    def update_spec(self, record) -> None: return None


def _make_record(tmp_path: Path) -> JobRecord:
    root = tmp_path / "job-race"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    spec = JobSpec(job_id="job-race", target="example.com", profile="full")
    metadata = JobMetadata(job_id="job-race", queued_at="2020-01-01T00:00:00Z")
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


@pytest.mark.asyncio
async def test_race_condition_stage_detects_multiple_success(tmp_path: Path, monkeypatch):
    record = _make_record(tmp_path)
    # Write a candidate URL
    with record.paths.results_jsonl.open("w") as f:
        f.write(json.dumps({"type": "url", "url": "https://example.com/api/v1/transfer"}) + "\n")
    
    context = PipelineContext(record=record, manager=DummyManager())
    context.emit_signal = MagicMock()
    
    # Mock RaceBurstClient
    mock_client_instance = AsyncMock()
    
    # 20 results, 3 are 200 OK
    mock_results = []
    for i in range(20):
        status = 200 if i < 3 else 403
        resp = MagicMock()
        resp.status = status
        resp.elapsed = 0.01
        mock_results.append((resp, None))
        
    mock_client_instance.sync_burst.return_value = mock_results
    
    monkeypatch.setattr("recon_cli.pipeline.stage_race_condition.RaceBurstClient", MagicMock(return_value=mock_client_instance))
    
    stage = RaceConditionStage()
    await stage.run_async(context)
    
    # Check if signal was emitted
    context.emit_signal.assert_called()
    args, kwargs = context.emit_signal.call_args
    assert args[0] == "race_condition_suspect"
    assert kwargs["evidence"]["total_success"] == 3
    assert "last-byte-sync" in kwargs["tags"]

import json
