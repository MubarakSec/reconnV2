from __future__ import annotations

import json
import os
import httpx
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
from recon_cli.utils.stealth import StealthManager, StealthConfig


@pytest.fixture
def mock_context(temp_dir):
    mock = MagicMock(spec=PipelineContext)
    mock.record = MagicMock()
    mock.record.paths.results_jsonl = temp_dir / "results.jsonl"
    mock.record.paths.artifact = lambda x: temp_dir / x
    mock.record.paths.ensure_subdir = lambda x: (temp_dir / x).mkdir(exist_ok=True) or (temp_dir / x)
    mock.runtime_config = MagicMock()
    mock.runtime_config.verify_tls = False
    mock.get_results = MagicMock(return_value=[])
    
    # Mock filter_results to return what was set in get_results
    def mock_filter(res_type):
        return [r for r in mock.get_results() if r.get("type") == res_type]
    mock.filter_results.side_effect = mock_filter
    
    mock.results = MagicMock()
    mock.logger = MagicMock()
    return mock


class TestEliteFeatures:

    def test_active_auth_discovery(self, mock_context):
        stage = ActiveAuthStage()
        # Provide both register and login forms
        mock_context.get_results.return_value = [
            {"type": "auth_form", "url": "https://example.com/signup", "tags": ["surface:register"], "inputs": [{"name": "email"}]},
            {"type": "auth_form", "url": "https://example.com/login", "tags": ["surface:login"], "inputs": [{"name": "user"}]}
        ]
        mock_context.is_host_blocked.return_value = False
        
        with patch("requests.Session.get") as mock_get, patch("requests.Session.post") as mock_post:
            mock_get.return_value.status_code = 200
            mock_get.return_value.text = '<html><input name="csrf" value="123"></html>'
            mock_post.return_value.status_code = 200
            mock_post.return_value.text = "Success!"
            
            stage.execute(mock_context)
            # Should have at least attempted signup
            assert mock_get.called or mock_post.called

    def test_api_reconstructor(self, mock_context, temp_dir):
        stage = ApiSchemaReconstructorStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "https://api.example.com/v1/users?id=123", "method": "get"}
        ]
        stage.execute(mock_context)
        artifact = temp_dir / "openapi_reconstructed_api.example.com.json"
        assert artifact.exists()
        schema = json.loads(artifact.read_text())
        assert "/v1/users" in schema["paths"]

    def test_vulnerability_chaining(self, mock_context):
        stage = CorrelationStage()
        # Mock findings that should be chained
        findings = [
            {"type": "finding", "finding_type": "info_leak", "hostname": "internal.box", "id": "f1"},
            {"type": "finding", "finding_type": "ssrf", "hostname": "internal.box", "id": "f2"}
        ]
        chains = stage._chain_vulnerabilities(findings)
        assert len(chains) > 0
        assert chains[0]["type"] == "vulnerability_chain"
        assert "SSRF" in chains[0]["description"]

    def test_poc_generator(self, mock_context, temp_dir):
        stage = POCGeneratorStage()
        mock_context.get_results.return_value = [
            {"type": "finding", "finding_type": "ssrf", "url": "https://example.com/vuln", "confidence_label": "verified", "score": 90}
        ]
        stage.execute(mock_context)
        pocs_dir = temp_dir / "pocs"
        assert pocs_dir.exists()
        assert any(p.name.startswith("poc_ssrf") for p in pocs_dir.iterdir())

    @pytest.mark.asyncio
    async def test_ssrf_pivot(self, mock_context):
        stage = SSRFPivotStage()
        mock_context.get_results.return_value = [
            {"type": "finding", "finding_type": "ssrf", "url": "https://example.com/proxy?url=FUZZ", "confidence_label": "verified"}
        ]
        
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock(spec=httpx.Response)
            mock_resp.status_code = 200
            mock_resp.text = "ami-id: i-123456"
            mock_get.return_value = mock_resp
            
            await stage.run_async(mock_context)
            
            # The stage should have appended findings for responsive internal assets
            assert mock_get.called
            assert mock_context.results.append.called

    @pytest.mark.asyncio
    async def test_cloud_looter(self, mock_context):
        stage = CloudBucketLooterStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "https://my-bucket.s3.amazonaws.com/", "tags": ["cloud:s3"]}
        ]
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, text="<ListBucketResult><Contents><Key>backup.sql</Key></Contents></ListBucketResult>")
            await stage.run_async(mock_context)
            assert mock_context.results.append.called
            # Check if it found the leaked file
            last_finding = mock_context.results.append.call_args[0][0]
            assert "backup.sql" in last_finding["description"]

    def test_wordlist_miner(self, mock_context, temp_dir):
        stage = WordlistMinerStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "https://example.com/", "tags": []}
        ]
        with patch("requests.Session.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.text = "<html><body>Welcome to Mubarak-Internal portal</body></html>"
            stage.execute(mock_context)
            assert mock_context.set_data.called
            artifact = temp_dir / "custom_wordlist.txt"
            assert artifact.exists()
            assert "mubarak-internal" in artifact.read_text().lower()

    def test_stealth_manager(self):
        cfg = StealthConfig(proxies=["http://proxy1:8080"], jitter_max=0.1)
        manager = StealthManager(cfg)
        
        # Test UA rotation
        ua1 = manager.get_random_ua()
        ua2 = manager.get_random_ua()
        assert ua1 != ""
        
        # Test Proxy selection
        proxy = manager.get_proxy()
        assert proxy["http"] == "http://proxy1:8080"
        
        # Test headers wrapping
        headers = {"Content-Type": "application/json"}
        wrapped = manager.wrap_headers(headers)
        assert "User-Agent" in wrapped
        assert "Sec-Ch-Ua" in wrapped

    @pytest.mark.asyncio
    async def test_api_logic_fuzzer(self, mock_context, temp_dir):
        stage = ApiLogicFuzzerStage()
        
        # 1. Mock schema artifact
        host = "api.example.com"
        schema_path = temp_dir / f"openapi_reconstructed_{host}.json"
        schema = {"paths": {"/api/v1/user/123": {"get": {}}, "/api/v1/profile": {"post": {}}}}
        schema_path.write_text(json.dumps(schema))
        
        # 2. Mock multiple sessions
        sessions_path = temp_dir / f"sessions_{host}.json"
        sessions = [
            {"session_id": "user-a", "cookies": {"sid": "a"}},
            {"session_id": "user-b", "cookies": {"sid": "b"}}
        ]
        sessions_path.write_text(json.dumps(sessions))
        
        mock_context.record.paths.artifacts_dir = temp_dir
        
        with patch("httpx.AsyncClient.request") as mock_req:
            # Baseline (User A) succeeds, Test (User B) succeeds -> BOLA
            mock_req.return_value = MagicMock(status_code=200, text="Reflected Admin", content=b"data")
            
            await stage.run_async(mock_context)
            
            assert mock_req.called
            # Check if findings were added
            assert mock_context.results.append.called
            findings = [call[0][0] for call in mock_context.results.append.call_args_list]
            assert any(f["finding_type"] == "bola" for f in findings)
            assert any(f["finding_type"] == "mass_assignment" for f in findings)

    @pytest.mark.asyncio
    async def test_web_cache_vuln(self, mock_context):
        stage = WebCacheVulnStage()
        url = "https://example.com/api/me"
        mock_context.get_results.return_value = [{"type": "url", "url": url, "tags": ["auth"]}]
        
        with patch("httpx.AsyncClient.get") as mock_get:
            # 1. Mock Deception Success
            mock_get.return_value = MagicMock(status_code=200, text='{"email": "test@test.com"}', headers={"CF-Cache-Status": "HIT"})
            
            await stage.run_async(mock_context)
            assert mock_context.results.append.called
            
            findings = [call[0][0] for call in mock_context.results.append.call_args_list]
            assert any(f["finding_type"] == "cache_deception" for f in findings)
