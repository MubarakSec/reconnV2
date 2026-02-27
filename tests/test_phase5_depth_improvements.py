from __future__ import annotations

import json
from pathlib import Path

from recon_cli.crawl.runtime import CrawlResult
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_api_recon import APIReconStage
from recon_cli.pipeline.stage_correlation import CorrelationStage
from recon_cli.pipeline.stage_js_intel import JSIntelligenceStage
from recon_cli.pipeline.stage_param_mining import ParamMiningStage
from recon_cli.pipeline.stages import RuntimeCrawlStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-phase5-depth"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-phase5-depth",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-phase5-depth", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "application/json"}

    def close(self) -> None:
        return None


def test_js_intel_extracts_dynamic_routes_and_hidden_params(monkeypatch, tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_js_intel": True,
            "js_intel_max_files": 5,
            "js_intel_max_urls": 30,
            "js_intel_timeout": 1,
            "js_intel_extract_dynamic_routes": True,
            "js_intel_extract_hidden_params": True,
            "js_intel_rps": 0,
            "js_intel_per_host_rps": 0,
        },
    )
    payload = {
        "type": "runtime_crawl",
        "source": "playwright",
        "url": "https://app.example.com/",
        "hostname": "app.example.com",
        "success": True,
        "javascript_files": ["https://cdn.example.com/app.js"],
    }
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")
    context = PipelineContext(record=record, manager=DummyManager())

    js_blob = """
    const userPath = `/api/v1/users/${userId}?account_id=${accountId}`;
    fetch('/graphql/v1');
    axios.get("/api/orders?tenant_id=42&debug=true");
    const opts = { params: { token: authToken, redirect_url: nextUrl } };
    """

    import requests

    monkeypatch.setattr(requests, "get", lambda *_args, **_kwargs: _FakeResponse(200, text=js_blob, headers={"Content-Type": "application/javascript"}))

    JSIntelligenceStage().run(context)
    urls = [entry.get("url") for entry in read_jsonl(record.paths.results_jsonl) if entry.get("source") == "js-intel"]
    assert any("/api/v1/users/1" in str(url) for url in urls)
    assert any("/graphql/v1" in str(url) for url in urls)
    hints = context.get_data("js_param_hints", []) or []
    assert "account_id" in hints
    assert "token" in hints
    assert "redirect_url" in hints


def test_param_mining_generates_mutation_catalog_from_js_hints(tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_param_mining": True,
            "param_mining_max_urls": 20,
            "param_mining_max_params": 20,
            "param_mining_generate_mutations": True,
            "param_mining_mutations_per_param": 6,
        },
    )
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump({"type": "url", "url": "https://app.example.com/search?q=test&limit=10"}, handle, separators=(",", ":"))
        handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    context.set_data("js_param_hints", ["redirect_url", "user_id"])
    ParamMiningStage().run(context)

    mutations = [entry for entry in read_jsonl(record.paths.results_jsonl) if entry.get("type") == "param_mutation"]
    assert mutations
    by_name = {entry.get("name"): entry for entry in mutations}
    assert by_name["redirect_url"]["category"] == "url"
    assert any("169.254.169.254" in value for value in by_name["redirect_url"]["values"])
    assert by_name["user_id"]["category"] == "identifier"

    stats = record.metadata.stats.get("param_mining", {})
    assert stats.get("mutation_params", 0) >= 2


def test_api_recon_enriches_probe_paths_from_js_endpoints(monkeypatch, tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_api_recon": True,
            "api_recon_max_hosts": 1,
            "api_recon_timeout": 1,
            "api_recon_enrich_from_js": True,
            "api_recon_max_enriched_paths": 10,
            "api_recon_rps": 0,
            "api_recon_per_host_rps": 0,
        },
    )
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump(
            {"type": "url", "url": "https://api.example.com/home", "hostname": "api.example.com", "score": 20},
            handle,
            separators=(",", ":"),
        )
        handle.write("\n")
    context = PipelineContext(record=record, manager=DummyManager())
    context.set_data(
        "js_endpoints",
        [
            "https://api.example.com/api/private/users",
            "https://api.example.com/graphql/v1",
        ],
    )
    called: list[str] = []

    def fake_get(url, **_kwargs):
        called.append(url)
        return _FakeResponse(404, text="not found", headers={"Content-Type": "application/json"})

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    APIReconStage().run(context)
    assert any("/graphql/v1" in url for url in called)
    assert any("/api/openapi.json" in url for url in called)
    stats = record.metadata.stats.get("api_recon", {})
    assert stats.get("enriched_probe_paths", 0) > 0


def test_runtime_crawl_role_aware_profiles_emit_profile_records(monkeypatch, tmp_path: Path):
    record = _make_record(
        tmp_path,
        {
            "enable_runtime_crawl": True,
            "runtime_crawl_max_urls": 1,
            "runtime_crawl_timeout": 1,
            "runtime_crawl_concurrency": 1,
            "runtime_crawl_role_aware": True,
            "runtime_crawl_max_auth_profiles": 3,
            "auth_profiles": [
                {"name": "analyst", "headers": {"X-Role": "analyst"}},
                {"name": "admin", "headers": {"X-Role": "admin"}},
            ],
        },
    )
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "type": "url",
                "url": "https://example.com/",
                "hostname": "example.com",
                "status_code": 200,
                "score": 30,
            },
            handle,
            separators=(",", ":"),
        )
        handle.write("\n")
    context = PipelineContext(record=record, manager=DummyManager())

    import recon_cli.pipeline.stages as stages_module

    monkeypatch.setattr(stages_module, "PLAYWRIGHT_AVAILABLE", True)

    def fake_crawl(urls, _timeout, _concurrency, headers=None, cookies=None):
        _ = cookies
        role = "default"
        if isinstance(headers, dict):
            role = str(headers.get("X-Role") or "default")
        url = urls[0]
        return {
            url: CrawlResult(
                url=url,
                success=True,
                network=[],
                javascript_files=[f"https://cdn.example.com/{role}.js"],
                errors=[],
                console_messages=[],
                dom_snapshot="<html></html>",
            )
        }

    monkeypatch.setattr(stages_module, "crawl_urls", fake_crawl)

    RuntimeCrawlStage().run(context)
    rows = read_jsonl(record.paths.results_jsonl)
    profile_rows = [row for row in rows if row.get("type") == "runtime_crawl_profile"]
    assert profile_rows
    assert any(row.get("auth_profile") == "admin" for row in profile_rows)
    stats = record.metadata.stats.get("runtime_crawl", {})
    assert "admin" in (stats.get("role_profiles") or [])
    assert stats.get("profiles", 0) >= 2


def test_correlation_builds_attack_paths_and_surface_benchmark(tmp_path: Path):
    record = _make_record(tmp_path, {"correlation_attack_path_limit": 5})
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        rows = [
            {
                "type": "url",
                "source": "probe",
                "url": "https://app.example.com/login",
                "hostname": "app.example.com",
                "tags": ["surface:login"],
                "score": 35,
            },
            {
                "type": "url",
                "source": "js-intel",
                "url": "https://app.example.com/api/admin/users",
                "hostname": "app.example.com",
                "tags": ["service:api", "surface:admin"],
                "score": 70,
            },
            {
                "type": "finding",
                "source": "idor-validator",
                "finding_type": "idor",
                "url": "https://app.example.com/api/admin/users?id=2",
                "hostname": "app.example.com",
                "severity": "high",
                "score": 92,
            },
        ]
        for row in rows:
            json.dump(row, handle, separators=(",", ":"))
            handle.write("\n")
    context = PipelineContext(record=record, manager=DummyManager())
    CorrelationStage().run(context)

    attack_path = record.paths.root / "artifacts" / "correlation" / "attack_paths.json"
    benchmark_path = record.paths.root / "artifacts" / "correlation" / "surface_benchmark.json"
    assert attack_path.exists()
    assert benchmark_path.exists()
    payload = json.loads(attack_path.read_text(encoding="utf-8"))
    assert payload
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    assert benchmark["final_unique_surfaces"] >= benchmark["baseline_unique_surfaces"]
    rows = read_jsonl(record.paths.results_jsonl)
    assert any(row.get("type") == "attack_path" for row in rows)
