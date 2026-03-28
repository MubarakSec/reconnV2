from __future__ import annotations

import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.vuln.stage_takeover import TakeoverStage
from recon_cli.takeover.detector import TakeoverFinding
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-takeover-hardening"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-takeover-hardening",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(
        job_id="job-takeover-hardening", queued_at="2020-01-01T00:00:00Z"
    )
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_host(path: Path, hostname: str) -> None:
    payload = {"type": "url", "url": f"https://{hostname}/", "hostname": hostname}
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


def test_takeover_stage_marks_high_claimability_when_dns_and_fingerprint_align(
    monkeypatch, tmp_path: Path
):
    from recon_cli.pipeline import stage_takeover as stage_mod

    record = _make_record(
        tmp_path,
        {
            "enable_takeover": True,
            "takeover_max_hosts": 5,
            "takeover_timeout": 1,
            "takeover_dns_timeout": 1,
            "takeover_require_cname": True,
        },
    )
    _write_host(record.paths.results_jsonl, "files.example.com")
    context = PipelineContext(record=record, manager=DummyManager())
    stage = TakeoverStage()

    monkeypatch.setattr(stage_mod, "dns", object())
    monkeypatch.setattr(
        stage,
        "_resolve_cname_chain",
        lambda _host, _timeout: ["orphan.s3.amazonaws.com"],
    )
    monkeypatch.setattr(stage, "_target_has_address", lambda _host, _timeout: False)

    async def fake_check(_self, hostname: str, providers=None):
        assert providers == {"aws_s3"}
        return TakeoverFinding(
            hostname=hostname,
            provider="aws_s3",
            evidence="NoSuchBucket",
            status_code=404,
            matched_url=f"https://{hostname}",
        )

    monkeypatch.setattr(stage_mod.TakeoverDetector, "check_host", fake_check)
    monkeypatch.setattr(stage, "_has_wildcard_dns", lambda *_a, **_k: False)

    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "takeover-check"
        and item.get("finding_type") == "subdomain_takeover"
    ]
    assert len(findings) == 1
    claimability = (findings[0].get("details") or {}).get("claimability") or {}
    assert claimability.get("level") == "high"
    assert findings[0].get("confidence_label") == "verified"
    assert "claimability:high" in (findings[0].get("tags") or [])

    stats = record.metadata.stats.get("takeover", {})
    assert stats.get("findings") == 1
    assert stats.get("suppressed_low_confidence") == 0


def test_takeover_stage_suppresses_low_confidence_fingerprints(
    monkeypatch, tmp_path: Path
):
    from recon_cli.pipeline import stage_takeover as stage_mod

    record = _make_record(
        tmp_path,
        {
            "enable_takeover": True,
            "takeover_max_hosts": 5,
            "takeover_timeout": 1,
            "takeover_dns_timeout": 1,
            "takeover_require_cname": False,
        },
    )
    _write_host(record.paths.results_jsonl, "portal.example.com")
    context = PipelineContext(record=record, manager=DummyManager())
    stage = TakeoverStage()

    monkeypatch.setattr(stage_mod, "dns", object())
    monkeypatch.setattr(stage, "_resolve_cname_chain", lambda _host, _timeout: [])
    monkeypatch.setattr(stage, "_target_has_address", lambda _host, _timeout: True)

    async def fake_check(_self, hostname: str, providers=None):
        assert not providers
        return TakeoverFinding(
            hostname=hostname,
            provider="heroku",
            evidence="no such app",
            status_code=404,
            matched_url=f"https://{hostname}",
        )

    monkeypatch.setattr(stage_mod.TakeoverDetector, "check_host", fake_check)
    monkeypatch.setattr(stage, "_has_wildcard_dns", lambda *_a, **_k: False)

    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "takeover-check"
        and item.get("finding_type") == "subdomain_takeover"
    ]
    assert not findings
    stats = record.metadata.stats.get("takeover", {})
    assert stats.get("findings") == 0
    assert stats.get("suppressed_low_confidence") == 1


def test_takeover_stage_verifies_exploitability(monkeypatch, tmp_path: Path):
    from recon_cli.pipeline import stage_takeover as stage_mod

    record = _make_record(
        tmp_path,
        {
            "enable_takeover": True,
            "takeover_max_hosts": 5,
            "takeover_timeout": 1,
            "takeover_dns_timeout": 1,
            "takeover_require_cname": True,
        },
    )
    _write_host(record.paths.results_jsonl, "confirmed.example.com")
    context = PipelineContext(record=record, manager=DummyManager())
    stage = TakeoverStage()

    monkeypatch.setattr(stage_mod, "dns", object())
    monkeypatch.setattr(
        stage,
        "_resolve_cname_chain",
        lambda _host, _timeout: ["bucket.s3.amazonaws.com"],
    )
    monkeypatch.setattr(stage, "_target_has_address", lambda _host, _timeout: False)

    async def fake_check(_self, hostname, providers=None):
        return TakeoverFinding(
            hostname=hostname,
            provider="aws_s3",
            evidence="NoSuchBucket",
            status_code=404,
            matched_url=f"https://{hostname}",
        )

    async def fake_can_claim(_self, hostname, provider):
        assert provider == "aws_s3"
        return True

    monkeypatch.setattr(stage_mod.TakeoverDetector, "check_host", fake_check)
    monkeypatch.setattr(stage_mod.TakeoverDetector, "can_claim", fake_can_claim)
    monkeypatch.setattr(stage, "_has_wildcard_dns", lambda *_a, **_k: False)

    stage.run(context)

    findings = [
        item
        for item in read_jsonl(record.paths.results_jsonl)
        if item.get("source") == "takeover-check"
    ]
    assert len(findings) == 1
    assert findings[0].get("confidence_label") == "verified"
    assert findings[0].get("score") == 100
    assert "exploitable" in findings[0].get("tags")
    assert "confirmed" in findings[0].get("tags")
    assert findings[0]["details"]["exploitable"] is True
