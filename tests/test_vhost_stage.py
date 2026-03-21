import json
from pathlib import Path

from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_vhost import VHostDiscoveryStage
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-vhost"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-vhost",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-vhost", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def _write_base_url(path: Path) -> None:
    payload = {
        "type": "url",
        "url": "https://www.example.com/",
        "hostname": "www.example.com",
        "status_code": 200,
        "score": 80,
        "source": "httpx",
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")


class _FakeResponse:
    def __init__(self, status_code: int, body: str, headers: dict | None = None):
        self.status_code = status_code
        self._body = body.encode("utf-8")
        self.headers = headers or {}
        self.encoding = "utf-8"

    def iter_content(self, chunk_size: int = 4096):
        for idx in range(0, len(self._body), chunk_size):
            yield self._body[idx : idx + chunk_size]

    def close(self) -> None:
        return None


def test_vhost_probe_cap_enforced(monkeypatch, tmp_path: Path):
    wordlist = tmp_path / "vhost.txt"
    wordlist.write_text("admin\ntest\ndev\nstage\nqa\n", encoding="utf-8")

    record = _make_record(
        tmp_path,
        {
            "enable_vhost": True,
            "vhost_wordlist": str(wordlist),
            "vhost_max_hosts": 1,
            "vhost_max_candidates": 5,
            "vhost_max_probes": 3,
            "vhost_progress_every": 1,
            "vhost_timeout": 1,
            "vhost_rps": 0,
            "vhost_per_host_rps": 0,
        },
    )
    _write_base_url(record.paths.results_jsonl)
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(
        url, timeout=None, allow_redirects=None, verify=None, headers=None, stream=None
    ):
        host_header = (headers or {}).get("Host")
        if not host_header:
            return _FakeResponse(
                200, "<html><title>Base</title></html>", {"Content-Length": "1000"}
            )
        if host_header == "admin.example.com":
            return _FakeResponse(
                200,
                "<html><title>Admin</title></html>",
                {"Content-Length": "1200", "Server": "nginx"},
            )
        return _FakeResponse(
            200, "<html><title>Base</title></html>", {"Content-Length": "1000"}
        )

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    stage = VHostDiscoveryStage()
    stage.run(context)

    stats = record.metadata.stats.get("vhost", {})
    assert stats.get("checked_hosts") == 1
    assert stats.get("tested_candidates") == 3
    assert stats.get("probe_cap") == 3
    assert stats.get("tested_candidates") <= stats.get("probe_cap")


def test_vhost_filters_wildcard_like_candidates(monkeypatch, tmp_path: Path):
    wordlist = tmp_path / "vhost.txt"
    wordlist.write_text("admin\ntest\ndev\n", encoding="utf-8")

    record = _make_record(
        tmp_path,
        {
            "enable_vhost": True,
            "vhost_wordlist": str(wordlist),
            "vhost_max_hosts": 1,
            "vhost_max_candidates": 3,
            "vhost_max_probes": 10,
            "vhost_progress_every": 1,
            "vhost_timeout": 1,
            "vhost_rps": 0,
            "vhost_per_host_rps": 0,
        },
    )
    _write_base_url(record.paths.results_jsonl)
    context = PipelineContext(record=record, manager=DummyManager())

    def fake_get(
        url, timeout=None, allow_redirects=None, verify=None, headers=None, stream=None
    ):
        host_header = (headers or {}).get("Host")
        if not host_header:
            return _FakeResponse(
                200, "<html><title>Base</title></html>", {"Content-Length": "1000"}
            )
        return _FakeResponse(
            200,
            "<html><title>Catch-All</title></html>",
            {"Content-Length": "2000", "Server": "nginx"},
        )

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    stage = VHostDiscoveryStage()
    stage.run(context)

    stats = record.metadata.stats.get("vhost", {})
    assert stats.get("tested_candidates") == 3
    assert stats.get("discovered") == 0
    assert stats.get("wildcard_filtered") == 3
