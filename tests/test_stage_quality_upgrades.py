import json
from pathlib import Path

from recon_cli.jobs import summary as jobs_summary
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_api_schema_probe import ApiSchemaProbeStage
from recon_cli.pipeline.stage_auth_matrix import AuthMatrixStage, AuthRecord
from recon_cli.pipeline.stage_cloud_assets import CloudAssetDiscoveryStage
from recon_cli.pipeline.stage_extended_validation import ExtendedValidationStage
from recon_cli.pipeline.stage_graphql_exploit import GraphQLExploitStage
from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.pipeline.stage_js_intel import JSIntelligenceStage
from recon_cli.pipeline.stage_scoring import ScoringStage
from recon_cli.utils import fs
from recon_cli.utils.jsonl import read_jsonl


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


def _make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-quality"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-quality",
        target="example.com",
        profile="full",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-quality", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_idor_semantic_reasons_detect_meaningful_changes():
    stage = IDORStage()
    baseline = {
        "status": 200,
        "body_md5": "aaaa",
        "sensitive": {},
        "subject_ids": {"100"},
        "text_sample": "",
    }
    variant = {
        "status": 200,
        "body_md5": "bbbb",
        "sensitive": {"email": True},
        "subject_ids": {"101"},
        "text_sample": "",
    }
    reasons = stage._semantic_reasons(baseline, variant)
    assert "new_sensitive_fields" in reasons
    assert "subject_identifier_changed" in reasons
    assert "successful_response_changed" in reasons


def test_idor_candidate_selection_prioritizes_and_limits_per_host(tmp_path: Path):
    runtime_overrides = {
        "idor_max_targets": 2,
        "idor_max_per_host": 1,
    }
    record = _make_record(tmp_path, runtime_overrides)
    context = PipelineContext(record=record, manager=DummyManager())
    stage = IDORStage()

    items = [
        {"type": "url", "url": "https://api.example.com/assets/app.js?id=1", "score": 90},
        {"type": "url", "url": "https://api.example.com/api/v1/users?id=1", "score": 20, "tags": ["api"]},
        {"type": "url", "url": "https://api.example.com/profile?user_id=2", "score": 25},
        {"type": "url", "url": "https://billing.example.net/account/1", "score": 15},
    ]

    candidates = stage._collect_candidates(context, items)
    urls = [candidate.url for candidate in candidates]
    assert len(candidates) == 2
    assert "https://api.example.com/assets/app.js?id=1" not in urls
    assert any("/api/v1/users" in url for url in urls)
    assert sum(1 for candidate in candidates if (candidate.parsed.hostname or "").lower() == "api.example.com") == 1
    context.close()


def test_auth_matrix_detects_cross_token_subject_exposure():
    stage = AuthMatrixStage()
    url = "https://api.example.com/users/123"
    records = [
        AuthRecord(
            url=url,
            auth="token-a",
            status=200,
            body_md5="aaa",
            length=120,
            sensitive={"data.user_id": "123"},
            subject_ids={"123"},
            auth_error=False,
        ),
        AuthRecord(
            url=url,
            auth="token-b",
            status=200,
            body_md5="bbb",
            length=118,
            sensitive={"data.user_id": "123"},
            subject_ids={"123"},
            auth_error=False,
        ),
    ]
    findings = stage._detect_issues(url, records)
    reasons = {finding["reason"] for finding in findings}
    assert "token_b_subject_matches_token_a" in reasons


def test_auth_matrix_collect_urls_prioritizes_sensitive_and_spreads_hosts(tmp_path: Path):
    runtime_overrides = {
        "auth_matrix_max_targets": 2,
        "auth_matrix_max_per_host": 1,
    }
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for payload in [
            {"type": "url", "url": "https://api.example.com/static/app.js?user_id=1", "score": 99},
            {"type": "url", "url": "https://api.example.com/api/users/1", "score": 20, "tags": ["api"]},
            {"type": "url", "url": "https://shop.example.org/account?user_id=5", "score": 18},
            {"type": "url", "url": "https://api.example.com/health", "score": 50},
        ]:
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = AuthMatrixStage()
    urls = stage._collect_urls(context)
    assert len(urls) == 2
    assert any("/api/users/1" in url for url in urls)
    assert any("shop.example.org/account" in url for url in urls)
    assert all("/static/app.js" not in url for url in urls)
    context.close()


def test_graphql_sensitive_query_generation_uses_schema():
    stage = GraphQLExploitStage()
    payload = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {"name": "users", "type": {"kind": "OBJECT", "name": "User"}, "args": []},
                            {"name": "health", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
                        ],
                    },
                    {
                        "name": "User",
                        "fields": [
                            {"name": "id"},
                            {"name": "email"},
                            {"name": "role"},
                        ],
                    },
                ],
            }
        }
    }
    queries = stage._build_sensitive_queries(payload, max_queries=4)
    assert queries
    assert any("users" in query for query in queries)
    assert any("email" in query or "role" in query for query in queries)


def test_graphql_collect_endpoints_prioritizes_and_enforces_host_cap(tmp_path: Path):
    runtime_overrides = {
        "graphql_exploit_max_per_host": 1,
    }
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for payload in [
            {
                "type": "url",
                "url": "https://api.example.com/graphql",
                "tags": ["api:graphql"],
                "score": 30,
            },
            {
                "type": "url",
                "url": "https://api.example.com/health/graphql",
                "tags": ["api:graphql"],
                "score": 80,
            },
            {
                "type": "api",
                "url": "https://billing.example.net/api/graphql",
                "tags": ["api:graphql"],
                "score": 20,
            },
        ]:
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = GraphQLExploitStage()
    endpoints = stage._collect_endpoints(context)
    assert len(endpoints) == 2
    assert "https://api.example.com/graphql" in endpoints
    assert "https://billing.example.net/api/graphql" in endpoints
    assert "https://api.example.com/health/graphql" not in endpoints
    context.close()


def test_graphql_auth_profile_analysis_uses_user_scoped_heuristics():
    stage = GraphQLExploitStage()
    findings = stage._analyze_auth_profiles(
        url="https://api.example.com/graphql",
        query="query { me { id email } }",
        by_auth={
            "token-a": {
                "status": 200,
                "has_data": True,
                "data_hash": "abc",
                "sensitive_paths": ["me.email"],
                "subject_ids": ["123"],
                "blocked": False,
            },
            "token-b": {
                "status": 200,
                "has_data": True,
                "data_hash": "abc",
                "sensitive_paths": ["me.email"],
                "subject_ids": ["456"],
                "blocked": False,
            },
        },
        sensitive_schema={"user.email"},
    )
    reasons = {finding["reason"] for finding in findings}
    assert "token_b_matches_token_a_sensitive_response" in reasons


def test_graphql_detects_unauthenticated_sensitive_exposure():
    stage = GraphQLExploitStage()
    findings = stage._analyze_auth_profiles(
        url="https://api.example.com/graphql",
        query="query { me { id email role } }",
        by_auth={
            "anon": {
                "status": 200,
                "has_data": True,
                "data_hash": "anon-hash",
                "sensitive_paths": ["me.email", "me.role"],
                "subject_ids": ["123"],
                "blocked": False,
            },
            "token-a": {
                "status": 403,
                "has_data": False,
                "data_hash": "",
                "sensitive_paths": [],
                "subject_ids": [],
                "blocked": True,
            },
        },
        sensitive_schema={"user.email"},
    )
    reasons = {finding["reason"] for finding in findings}
    assert "unauthenticated_sensitive_data_exposure" in reasons


def test_api_schema_prioritization_prefers_auth_and_user_paths():
    stage = ApiSchemaProbeStage()
    endpoints = [
        {"path": "/health", "method": "get", "params": [], "body_fields": [], "requires_auth": False},
        {"path": "/users/{id}", "method": "get", "params": [{"name": "id", "in": "path"}], "body_fields": [], "requires_auth": True},
        {"path": "/metrics", "method": "get", "params": [], "body_fields": [], "requires_auth": False},
    ]
    prioritized = stage._prioritize_endpoints(endpoints)
    assert prioritized[0]["path"] == "/users/{id}"


def test_api_schema_probe_global_budget_and_safe_writes(monkeypatch, tmp_path: Path):
    runtime_overrides = {
        "enable_api_schema_probe": True,
        "api_schema_max_specs": 2,
        "api_schema_max_endpoints": 3,
        "api_schema_param_max": 20,
        "api_schema_probe_safe_writes": True,
        "api_schema_timeout": 1,
        "api_schema_rps": 0,
        "api_schema_per_host_rps": 0,
        "retry_count": 0,
    }
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for spec_url in ("https://spec.example.com/openapi-1.json", "https://spec.example.com/openapi-2.json"):
            json.dump({"type": "api_spec", "url": spec_url}, handle, separators=(",", ":"))
            handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = ApiSchemaProbeStage()

    spec_payload = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path"}],
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                },
            },
            "/projects": {
                "put": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        },
    }

    class _FakeResponse:
        def __init__(self, status_code: int, text: str, headers: dict | None = None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}

    called_methods: list[str] = []

    def fake_get(url, timeout=None, allow_redirects=None, headers=None, verify=None):
        if url.startswith("https://spec.example.com/openapi-"):
            return _FakeResponse(200, json.dumps(spec_payload), {"Content-Type": "application/json"})
        return _FakeResponse(404, "", {"Content-Type": "application/json"})

    def fake_request(method, url, timeout=None, allow_redirects=None, headers=None, verify=None, json=None, data=None):
        called_methods.append(str(method).upper())
        status_code = 200 if str(method).upper() in {"GET", "HEAD", "OPTIONS"} else 401
        return _FakeResponse(status_code, "{}", {"Content-Type": "application/json", "Content-Length": "2"})

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(requests, "request", fake_request)

    stage.run(context)

    stats = record.metadata.stats.get("api_schema_probe", {})
    assert stats.get("endpoints_budget_used") == 3
    assert stats.get("budget_exhausted") is True
    assert stats.get("mutating_probed", 0) >= 2
    assert "POST" in called_methods
    assert "PUT" in called_methods


def test_extended_validation_hard_probe_cap(monkeypatch, tmp_path: Path):
    runtime_overrides = {
        "enable_extended_validation": True,
        "enable_oast_validation": False,
        "enable_redirect_validation": True,
        "enable_lfi_validation": False,
        "enable_header_validation": False,
        "redirect_max_urls": 20,
        "extended_validation_max_duration": 7200,
        "extended_validation_max_probes": 3,
        "oast_timeout": 1,
        "oast_rps": 0,
        "oast_per_host_rps": 0,
        "retry_count": 0,
    }
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for idx in range(10):
            payload = {
                "type": "url",
                "url": f"https://app.example.com/cb?next=https://target.example/{idx}",
                "score": 60,
            }
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = ExtendedValidationStage()

    class _FakeResponse:
        status_code = 302
        text = ""
        headers = {"Location": "https://example.com/recon"}

    monkeypatch.setattr(stage, "_request_with_retries", lambda *args, **kwargs: _FakeResponse())

    stage.run(context)

    stats = record.metadata.stats.get("extended_validation", {})
    assert stats.get("probe_cap_hit") is True
    assert stats.get("probes") == 3
    assert stats.get("max_total_probes") == 3


def test_cloud_discovery_enforces_max_checks_when_no_assets(monkeypatch, tmp_path: Path):
    runtime_overrides = {
        "enable_cloud_discovery": True,
        "cloud_max_checks": 5,
        "cloud_timeout": 1,
        "cloud_max_duration": 1200,
        "cloud_rps": 0,
        "cloud_per_host_rps": 0,
    }
    record = _make_record(tmp_path, runtime_overrides)
    context = PipelineContext(record=record, manager=DummyManager())
    stage = CloudAssetDiscoveryStage()

    monkeypatch.setattr(stage, "_generate_candidates", lambda _: [f"bucket-{i}" for i in range(10)])

    class _FakeResponse:
        def __init__(self) -> None:
            self.status_code = 404
            self.text = ""

    import requests

    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: _FakeResponse())

    stage.run(context)

    stats = record.metadata.stats.get("cloud_assets", {})
    assert stats.get("checked") == 5
    assert stats.get("public") == 0


def test_js_intel_uses_runtime_crawl_javascript_files(monkeypatch, tmp_path: Path):
    runtime_overrides = {
        "enable_js_intel": True,
        "js_intel_max_files": 10,
        "js_intel_max_urls": 20,
        "js_intel_timeout": 2,
        "js_intel_rps": 0,
        "js_intel_per_host_rps": 0,
    }
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "type": "runtime_crawl",
                "source": "playwright",
                "url": "https://app.example.com/",
                "hostname": "app.example.com",
                "success": True,
                "javascript_files": ["https://cdn.example.com/app.js"],
            },
            handle,
            separators=(",", ":"),
        )
        handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = JSIntelligenceStage()

    class _FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    import requests

    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: _FakeResponse("const a='https://api.example.com/v1/users';"),
    )

    stage.run(context)

    stats = record.metadata.stats.get("js_intel", {})
    assert stats.get("files") == 1
    assert stats.get("endpoints", 0) >= 1

    urls = [entry.get("url") for entry in read_jsonl(record.paths.results_jsonl) if entry.get("source") == "js-intel"]
    assert "https://api.example.com/v1/users" in urls


def test_scoring_caps_generic_auth_challenge_noise(tmp_path: Path):
    runtime_overrides = {}
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "type": "url",
                "source": "probe",
                "url": "https://api.example.com/account/login",
                "hostname": "api.example.com",
                "status_code": 403,
                "tags": ["service:api", "surface:login", "surface:admin", "probe++"],
                "score": 0,
            },
            handle,
            separators=(",", ":"),
        )
        handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = ScoringStage()
    stage.run(context)

    rows = [entry for entry in read_jsonl(record.paths.results_jsonl) if entry.get("type") == "url"]
    assert len(rows) == 1
    row = rows[0]
    assert "auth:challenge" in row.get("tags", [])
    assert row.get("score", 0) <= 55
    assert row.get("priority") in {"medium", "high"}


def test_scoring_downranks_repetitive_auth_surface_clusters(tmp_path: Path):
    runtime_overrides = {}
    record = _make_record(tmp_path, runtime_overrides)
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        for idx in range(12):
            json.dump(
                {
                    "type": "url",
                    "source": "probe",
                    "url": f"https://h{idx}.example.com/account/login",
                    "hostname": f"h{idx}.example.com",
                    "status_code": 403,
                    "tags": ["service:api", "surface:login", "surface:admin", "probe++"],
                    "score": 0,
                },
                handle,
                separators=(",", ":"),
            )
            handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    stage = ScoringStage()
    stage.run(context)

    rows = [entry for entry in read_jsonl(record.paths.results_jsonl) if entry.get("type") == "url"]
    assert len(rows) == 12
    assert all("auth:repetitive" in row.get("tags", []) for row in rows)
    assert all(row.get("score", 0) <= 45 for row in rows)


def test_summary_prefers_confirmed_findings_in_top_section(tmp_path: Path):
    record = _make_record(tmp_path, {})
    with record.paths.results_jsonl.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "type": "finding",
                "description": "unconfirmed-high-score",
                "url": "https://app.example.com/unconfirmed",
                "score": 95,
                "priority": "critical",
                "tags": ["surface:login"],
            },
            handle,
            separators=(",", ":"),
        )
        handle.write("\n")
        json.dump(
            {
                "type": "finding",
                "description": "confirmed-lower-score",
                "url": "https://app.example.com/confirmed",
                "score": 70,
                "priority": "high",
                "tags": ["ssrf:confirmed"],
            },
            handle,
            separators=(",", ":"),
        )
        handle.write("\n")

    context = PipelineContext(record=record, manager=DummyManager())
    jobs_summary.generate_summary(context)

    text = record.paths.results_txt.read_text(encoding="utf-8")
    marker = "== Top Findings"
    idx = text.find(marker)
    assert idx != -1
    section = text[idx:].splitlines()
    first_entry = next((line for line in section if line.startswith("[")), "")
    assert "confirmed-lower-score" in first_entry


def test_summary_emits_quality_metrics(tmp_path: Path):
    record = _make_record(tmp_path, {})
    context = PipelineContext(record=record, manager=DummyManager())
    context.results.append(
        {
            "type": "url",
            "url": "https://example.com/noise",
            "hostname": "example.com",
            "tags": ["noise"],
            "score": 0,
        }
    )
    context.results.append(
        {
            "type": "url",
            "url": "https://example.com/noise",
            "hostname": "example.com",
            "tags": ["noise"],
            "score": 0,
        }
    )
    context.results.append(
        {
            "type": "finding",
            "description": "confirmed-issue",
            "url": "https://example.com/confirmed",
            "tags": ["ssrf:confirmed"],
            "score": 70,
            "priority": "high",
        }
    )
    jobs_summary.generate_summary(context)

    quality = record.metadata.stats.get("quality", {})
    assert quality.get("noise_ratio") == 1.0
    assert quality.get("verified_ratio") == 1.0
    assert round(quality.get("duplicate_ratio", 0.0), 2) == 0.33
    assert quality.get("duplicates") == 1
    assert quality.get("records_seen") == 3
    text = record.paths.results_txt.read_text(encoding="utf-8")
    assert "== Quality ==" in text
