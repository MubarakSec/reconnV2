import json
import sys
import types
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_security_headers import SecurityHeadersStage
from recon_cli.pipeline.stage_tls_hygiene import TLSHygieneStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-sec"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-sec",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-sec", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_url_entry(path: Path, url: str) -> None:
    payload = {
        "type": "url",
        "url": url,
        "hostname": "example.com",
        "status_code": 200,
        "score": 50,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


def test_security_headers_missing_creates_finding(monkeypatch, tmp_path: Path):
    record = make_record(
        tmp_path,
        {
            "enable_security_headers": True,
            "security_headers_max_urls": 1,
            "security_headers_timeout": 1,
            "retry_count": 0,
        },
    )
    _write_url_entry(record.paths.results_jsonl, "https://example.com/")
    context = PipelineContext(record=record, manager=DummyManager())

    class DummyResponse:
        status_code = 200
        headers = {"Server": "nginx"}
        text = "<html>ok</html>"

    def _get(*_args, **_kwargs):
        return DummyResponse()

    fake_requests = types.SimpleNamespace(get=_get)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    stage = SecurityHeadersStage()
    stage.run(context)

    records = read_jsonl(record.paths.results_jsonl)
    findings = [r for r in records if r.get("finding_type") == "security_headers"]
    assert len(findings) == 1
    assert "missing" in findings[0].get("details", {})
    stats = record.metadata.stats.get("security_headers", {})
    assert stats.get("findings") == 1


def test_tls_hygiene_flags_legacy_and_expiring(monkeypatch, tmp_path: Path):
    record = make_record(
        tmp_path,
        {
            "enable_tls_hygiene": True,
            "tls_hygiene_max_hosts": 1,
            "tls_hygiene_timeout": 1,
            "retry_count": 0,
        },
    )
    _write_url_entry(record.paths.results_jsonl, "https://example.com/")
    context = PipelineContext(record=record, manager=DummyManager())

    stage = TLSHygieneStage()

    def _probe_host(_host, _port, _timeout, _verify_tls):
        return {
            "protocol": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "legacy_protocols": ["TLSv1"],
            "cert_days_remaining": 10,
        }

    monkeypatch.setattr(stage, "_probe_host", _probe_host)
    stage.run(context)

    records = read_jsonl(record.paths.results_jsonl)
    findings = [r for r in records if r.get("finding_type") == "tls_hygiene"]
    assert len(findings) == 1
    details = findings[0].get("details", {})
    assert "legacy_protocols" in details
    stats = record.metadata.stats.get("tls_hygiene", {})
    assert stats.get("findings") == 1
