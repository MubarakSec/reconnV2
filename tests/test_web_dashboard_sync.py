from __future__ import annotations

from pathlib import Path

import pytest


def _configure_test_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from recon_cli import config

    monkeypatch.setattr(config, "RECON_HOME", tmp_path)
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "JOBS_ROOT", tmp_path / "jobs")
    monkeypatch.setattr(config, "QUEUED_JOBS", config.JOBS_ROOT / "queued")
    monkeypatch.setattr(config, "RUNNING_JOBS", config.JOBS_ROOT / "running")
    monkeypatch.setattr(config, "FINISHED_JOBS", config.JOBS_ROOT / "finished")
    monkeypatch.setattr(config, "FAILED_JOBS", config.JOBS_ROOT / "failed")
    monkeypatch.setattr(config, "ARCHIVE_ROOT", tmp_path / "archive")
    monkeypatch.setattr(config, "DEFAULT_RESOLVERS", config.CONFIG_DIR / "resolvers.txt")
    monkeypatch.setattr(config, "DEFAULT_RESOLVERS_PARENT", config.DEFAULT_RESOLVERS.parent)
    monkeypatch.setattr(config, "DEFAULT_PROFILES", config.CONFIG_DIR / "profiles.json")
    config.ensure_base_directories(force=True)


def test_confirmed_finding_detection():
    from recon_cli.web.app import _is_confirmed_finding

    assert _is_confirmed_finding({"tags": ["confirmed"]}) is True
    assert _is_confirmed_finding({"tags": ["ssrf:confirmed"]}) is True
    assert _is_confirmed_finding({"source": "extended-validation"}) is True
    assert _is_confirmed_finding({"source": "exploit-validation"}) is True
    assert _is_confirmed_finding({"tags": ["info"]}) is False


def test_normalize_targets_dedupes_and_handles_strings():
    from recon_cli.web.app import _normalize_targets

    data = {
        "targets": "example.com\napi.example.com\nexample.com\n",
        "target": "extra.example.com",
    }
    normalized = _normalize_targets(data)
    assert normalized == ["example.com", "api.example.com", "extra.example.com"]


def test_stage_overrides_group_disables():
    from recon_cli.web.app import _stage_overrides

    overrides = _stage_overrides(["web"])
    assert overrides["enable_ct_pivot"] is False
    assert overrides["enable_asn_pivot"] is False
    assert overrides["enable_secrets"] is False
    assert overrides["enable_fuzz"] is False


def test_outputs_api_downloads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.jobs.manager import JobManager
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    manager = JobManager()
    record = manager.create_job(target="example.com", profile="passive")
    record.paths.results_txt.write_text("hello", encoding="utf-8")
    record.paths.results_jsonl.write_text("{}\n", encoding="utf-8")
    (record.paths.root / "results_bigger.txt").write_text("big", encoding="utf-8")
    (record.paths.root / "results_confirmed.txt").write_text("confirmed", encoding="utf-8")
    (record.paths.root / "results_trimmed.jsonl").write_text("{}\n", encoding="utf-8")

    client = TestClient(fastapi_app)
    resp = client.get(f"/api/jobs/{record.spec.job_id}/outputs/results")
    assert resp.status_code == 200
    assert resp.text == "hello"
    assert resp.headers["content-type"].startswith("text/plain")

    resp = client.get(f"/api/jobs/{record.spec.job_id}/outputs/results_bigger")
    assert resp.status_code == 200
    assert resp.text == "big"

    resp = client.get(f"/api/jobs/{record.spec.job_id}/outputs/results_confirmed")
    assert resp.status_code == 200
    assert resp.text == "confirmed"

    resp = client.get(f"/api/jobs/{record.spec.job_id}/outputs/results_jsonl")
    assert resp.status_code == 200
    assert resp.text.strip() == "{}"
    assert resp.headers["content-type"].startswith("application/x-ndjson")

    resp = client.get(f"/api/jobs/{record.spec.job_id}/outputs/unknown")
    assert resp.status_code == 404


def test_outputs_api_rejects_invalid_job_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.get("/api/jobs/%2E%2E/outputs/results")
    assert resp.status_code == 400


def test_scan_api_targets_and_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.jobs.manager import JobManager
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)

    payload = {
        "targets": ["example.com", "api.example.com"],
        "profile": "full",
        "stages": ["web", "vulnerabilities"],
        "threads": 42,
        "timeout": 25,
        "rate_limit": 120,
        "resolvers": "cloudflare",
        "scanMode": "queued",
    }
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200
    job_id = resp.json().get("job_id")
    assert job_id

    manager = JobManager()
    record = manager.load_job(job_id)
    assert record is not None
    assert record.spec.target == "example.com"
    assert record.spec.targets_file
    targets_file = Path(record.spec.targets_file)
    assert targets_file.exists()
    targets_content = targets_file.read_text(encoding="utf-8")
    assert "example.com" in targets_content
    assert "api.example.com" in targets_content

    overrides = record.spec.runtime_overrides
    assert overrides.get("httpx_threads") == 42
    assert overrides.get("timeout_http") == 25
    assert overrides.get("requests_per_second") == 120
    assert overrides.get("per_host_limit") == 30
    assert overrides.get("enable_ct_pivot") is False
    assert "resolvers_file" in overrides
    resolver_path = Path(overrides["resolvers_file"])
    assert resolver_path.exists()
    resolver_content = resolver_path.read_text(encoding="utf-8")
    assert "1.1.1.1" in resolver_content
    assert record.spec.stages == ["web", "vulnerabilities"]


def test_scan_api_rejects_invalid_scan_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post(
        "/api/scan",
        json={"target": "example.com", "profile": "passive", "scanMode": "invalid"},
    )
    assert resp.status_code == 400
    assert "Invalid scanMode" in resp.json().get("detail", "")


def test_save_settings_api_rejects_non_object_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post("/api/settings", json=["not", "an", "object"])
    assert resp.status_code == 400


def test_retry_api_rejects_invalid_job_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post("/api/jobs/%2E%2E/retry")
    assert resp.status_code == 400


def test_scan_api_rejects_unknown_payload_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post(
        "/api/scan",
        json={"target": "example.com", "profile": "passive", "scanMode": "queued", "evil": "value"},
    )
    assert resp.status_code == 400
    assert "Unsupported scan payload keys" in resp.json().get("detail", "")


def test_scan_api_rejects_invalid_stage_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post(
        "/api/scan",
        json={"target": "example.com", "profile": "passive", "scanMode": "queued", "stages": ["web", "oops"]},
    )
    assert resp.status_code == 400
    assert "Invalid stage" in resp.json().get("detail", "")


def test_save_settings_api_rejects_invalid_general_log_level(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post("/api/settings", json={"general": {"log_level": "verbose"}})
    assert resp.status_code == 400
    assert "general.log_level" in resp.json().get("detail", "")


def test_notification_api_rejects_missing_telegram_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from recon_cli.web.app import app as fastapi_app

    _configure_test_home(tmp_path, monkeypatch)
    client = TestClient(fastapi_app)
    resp = client.post("/api/test-notification", json={"channel": "telegram"})
    assert resp.status_code == 400
    assert "bot_token" in resp.json().get("detail", "")
