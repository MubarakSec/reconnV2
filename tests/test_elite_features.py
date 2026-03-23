from __future__ import annotations

import json
import os
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_active_auth import ActiveAuthStage
from recon_cli.pipeline.stage_api_reconstructor import ApiSchemaReconstructorStage
from recon_cli.pipeline.stage_api_logic_fuzzer import ApiLogicFuzzerStage
from recon_cli.pipeline.stage_correlation import CorrelationStage
from recon_cli.pipeline.stage_poc_generator import POCGeneratorStage
from recon_cli.pipeline.stage_headless_crawl import HeadlessCrawlStage
from recon_cli.pipeline.stage_ssrf_pivot import SSRFPivotStage
from recon_cli.pipeline.stage_cache_vuln import WebCacheVulnStage
from recon_cli.pipeline.stage_cloud_looter import CloudBucketLooterStage
from recon_cli.pipeline.stage_wordlist_miner import WordlistMinerStage
from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.pipeline.stage_idor_validator import IDORValidatorStage
from recon_cli.pipeline.stage_secrets import SecretsDetectionStage
from recon_cli.utils.stealth import StealthManager, StealthConfig
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPResponse


@pytest.fixture
def mock_context(temp_dir):
    mock = MagicMock()
    mock.record = MagicMock()
    mock.record.paths.results_jsonl = temp_dir / "results.jsonl"
    mock.record.paths.artifact = lambda x: temp_dir / x
    mock.record.paths.ensure_subdir = lambda x: (temp_dir / x).mkdir(exist_ok=True) or (temp_dir / x)
    mock.runtime_config = MagicMock()
    mock.runtime_config.verify_tls = False
    mock.runtime_config.enable_secrets = True
    mock.runtime_config.secrets_max_files = 10
    mock.runtime_config.secrets_timeout = 5
    mock.runtime_config.idor_rps = 0
    mock.runtime_config.idor_timeout = 5
    mock.runtime_config.idor_validator_rps = 0
    
    # Store results in a list we can actually inspect
    mock._results_list = []
    def mock_append(item):
        mock._results_list.append(item)
        return True
    mock.results.append.side_effect = mock_append
    
    def mock_get_results():
        return mock._results_list
    mock.get_results.side_effect = mock_get_results
    
    def mock_iter_results():
        return iter(mock._results_list)
    mock.iter_results.side_effect = mock_iter_results

    def mock_filter(res_type):
        return [r for r in mock._results_list if r.get("type") == res_type]
    mock.filter_results.side_effect = mock_filter
    
    mock.auth_headers = MagicMock(side_effect=lambda x: x)
    def mock_url_allowed(url):
        return True
    mock.url_allowed.side_effect = mock_url_allowed
    mock.logger = MagicMock()
    return mock


class TestEliteFeatures:

    @pytest.mark.asyncio
    async def test_active_auth_discovery(self, mock_context):
        stage = ActiveAuthStage()
        mock_context._results_list = [
            {"type": "auth_form", "url": "https://example.com/signup", "tags": ["surface:register"], "inputs": [{"name": "email"}]},
            {"type": "auth_form", "url": "https://example.com/login", "tags": ["surface:login"], "inputs": [{"name": "user"}]}
        ]
        mock_context.is_host_blocked.return_value = False
        
        with patch("recon_cli.utils.async_http.AsyncHTTPClient.get", new_callable=AsyncMock) as mock_get, \
             patch("recon_cli.utils.async_http.AsyncHTTPClient.post", new_callable=AsyncMock) as mock_post:
            
            mock_get.return_value = HTTPResponse(url="https://example.com/signup", status=200, headers={}, body='<html><input name="csrf" value="123"></html>', elapsed=0.1)
            mock_post.return_value = HTTPResponse(url="https://example.com/signup", status=200, headers={}, body="Success!", elapsed=0.1)
            
            await stage.run_async(mock_context)
            assert mock_get.called or mock_post.called

    def test_api_reconstructor(self, mock_context, temp_dir):
        stage = ApiSchemaReconstructorStage()
        mock_context._results_list = [
            {"type": "url", "url": "https://api.example.com/v1/users?id=123", "method": "get"}
        ]
        stage.execute(mock_context)
        artifact = temp_dir / "openapi_reconstructed_api.example.com.json"
        assert artifact.exists()
        schema = json.loads(artifact.read_text())
        assert "/v1/users" in schema["paths"]

    @pytest.mark.asyncio
    async def test_idor_harvest_and_replay(self, mock_context):
        probe = IDORStage()
        validator = IDORValidatorStage()
        
        import hashlib
        body = '{"id": 100, "email": "a@a.com"}'
        body_md5 = hashlib.md5(body.encode()).hexdigest()
        url = "https://api.example.com/profile?id=100"
        mock_context._results_list = [
            {
                "type": "idor_baseline",
                "url": url,
                "auth": "token-a",
                "status": 200,
                "body_md5": body_md5,
                "hostname": "api.example.com"
            },
            {
                "type": "idor_suspect",
                "url": "https://api.example.com/profile?id=200",
                "hostname": "api.example.com",
                "original": "100",
                "parameter": "id",
                "auth": "token-a",
                "score": 95,
                "details": {
                    "parameter": "id",
                    "original": "100",
                    "variant": "200",
                    "reasons": ["successful_response_changed"]
                },
                "baseline_url": url,
                "baseline_status": 200,
                "baseline_md5": body_md5
            }
        ]
        mock_context.runtime_config.idor_token_a = "Bearer token-a"
        mock_context.runtime_config.idor_token_b = "Bearer token-b"

        # Elite: Mock _resolve_token
        validator._resolve_token = lambda ctx, label, host, runtime: runtime.idor_token_a if label == "token-a" else runtime.idor_token_b

        # Elite: Mock _fetch_profile to always return matching success profiles
        async def mock_fetch_profile(*args, **kwargs):
            return {
                "status": 200,
                "body_md5": body_md5,
                "url": url,
                "auth": kwargs.get("auth_label", "unknown")
            }, "ok"
        
        with patch.object(IDORValidatorStage, "_fetch_profile", side_effect=mock_fetch_profile):
            await validator.run_async(mock_context)
            findings = [r for r in mock_context._results_list if r.get("finding_type") == "idor"]
            assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_entropy_secrets_detection(self, mock_context, temp_dir):
        stage = SecretsDetectionStage()
        url = "https://example.com/app.js"
        mock_context._results_list = [
            {"type": "url", "url": url, "score": 90}
        ]
        
        from recon_cli.secrets.detector import SecretMatch
        mock_match = SecretMatch(
            pattern="aws_access_key", value_hash="hash123", length=20,
            entropy=4.5, start=0, end=20
        )
        
        with patch("recon_cli.secrets.detector.SecretsDetector.scan_urls", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = {url: [mock_match]}
            await stage.run_async(mock_context)
            findings = [r for r in mock_context._results_list if r.get("finding_type") == "exposed_secret"]
            assert len(findings) > 0
            assert any("aws_access_key" in f["description"] for f in findings)

    @pytest.mark.asyncio
    async def test_ssrf_pivot(self, mock_context):
        stage = SSRFPivotStage()
        mock_context._results_list = [
            {"type": "finding", "finding_type": "ssrf", "url": "https://example.com/proxy?url=FUZZ", "confidence_label": "verified"}
        ]
        
        with patch("recon_cli.utils.async_http.AsyncHTTPClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = HTTPResponse(url="http://internal", status=200, body="ami-id: i-123456", headers={}, elapsed=0.1)
            await stage.run_async(mock_context)
            assert len([r for r in mock_context._results_list if r.get("finding_type") == "ssrf_internal_pivot"]) > 0

    @pytest.mark.asyncio
    async def test_wordlist_miner(self, mock_context, temp_dir):
        stage = WordlistMinerStage()
        mock_context._results_list = [
            {"type": "url", "url": "https://example.com/", "tags": []}
        ]
        with patch("recon_cli.utils.async_http.AsyncHTTPClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = HTTPResponse(url="https://example.com/", status=200, headers={}, body="<html><body>Welcome to Internal-Portal-Mubarak</body></html>", elapsed=0.1)
            await stage.run_async(mock_context)
            assert mock_context.set_data.called
            artifact = temp_dir / "custom_wordlist.txt"
            assert artifact.exists()
            assert "internal-portal-mubarak" in artifact.read_text().lower()

    def test_stealth_manager(self):
        cfg = StealthConfig(proxies=["http://proxy1:8080"], jitter_max=0.1)
        manager = StealthManager(cfg)
        assert manager.get_random_ua() != ""
        proxy = manager.get_proxy()
        assert proxy["http"] == "http://proxy1:8080"
        headers = manager.wrap_headers({"Content-Type": "application/json"})
        assert "User-Agent" in headers
