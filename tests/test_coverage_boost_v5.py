import json
import asyncio
from typing import Any, Dict, List
from unittest.mock import MagicMock, AsyncMock, patch, ANY
import pytest
from pathlib import Path
import sys

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_active_intel import ActiveIntelligenceStage
from recon_cli.pipeline.stage_auth_discovery import AuthDiscoveryStage
from recon_cli.pipeline.stage_github_recon import GitHubReconStage
from recon_cli.pipeline.stage_html_forms import HTMLFormMiningStage
from recon_cli.active import modules as active_modules

# -----------------------------------------------------------------------------
# Fixtures and Helpers
# -----------------------------------------------------------------------------

@pytest.fixture
def mock_context(temp_dir):
    context = MagicMock(spec=PipelineContext)
    context.record = MagicMock()
    context.record.spec.active_modules = []
    context.record.metadata.stats = {}
    
    # Mock paths.ensure_subdir to return a mock that supports / operator
    active_dir_mock = MagicMock()
    active_file_mock = MagicMock()
    active_dir_mock.__truediv__.return_value = active_file_mock
    context.record.paths.ensure_subdir.return_value = active_dir_mock
    
    # Mock paths.artifact to return a mock
    artifact_file_mock = MagicMock()
    context.record.paths.artifact.return_value = artifact_file_mock
    
    context.runtime_config = MagicMock()
    # Default config values
    context.runtime_config.auto_active_modules = True
    context.runtime_config.verify_tls = False
    context.runtime_config.auth_apply_active_modules = False
    context.runtime_config.enable_auth_discovery = True
    context.runtime_config.auth_discovery_max_urls = 10
    context.runtime_config.auth_discovery_timeout = 1
    context.runtime_config.auth_discovery_max_forms = 10
    context.runtime_config.auth_discovery_rps = 0
    context.runtime_config.auth_discovery_per_host_rps = 0
    
    context.runtime_config.enable_github_recon = True
    context.runtime_config.github_token = "test_token"
    
    context.runtime_config.enable_html_form_mining = True
    context.runtime_config.html_form_max_urls = 10
    context.runtime_config.html_form_timeout = 1
    context.runtime_config.html_form_max_forms = 10
    context.runtime_config.html_form_rps = 0
    context.runtime_config.html_form_per_host_rps = 0
    context.runtime_config.html_form_max_params = 10

    context.results = MagicMock()
    context.results.extend.return_value = 0
    context.results.append.return_value = True
    
    context.logger = MagicMock()
    
    context.manager = MagicMock()
    
    context.auth_enabled.return_value = False
    context.auth_session.return_value = None
    context.auth_headers.return_value = {}
    
    context.get_rate_limiter.return_value = None
    context.emit_signal.return_value = "sig-123"
    context.url_allowed.return_value = True
    
    # Default get_results return value
    context.get_results.return_value = []

    return context

# -----------------------------------------------------------------------------
# ActiveIntelligenceStage Tests
# -----------------------------------------------------------------------------

class TestActiveIntelligenceStage:
    
    def test_is_enabled(self, mock_context):
        stage = ActiveIntelligenceStage()
        
        # Case 1: Modules in spec
        mock_context.record.spec.active_modules = ["wayback"]
        assert stage.is_enabled(mock_context) is True
        
        # Case 2: No modules in spec, auto enabled
        mock_context.record.spec.active_modules = []
        mock_context.runtime_config.auto_active_modules = True
        assert stage.is_enabled(mock_context) is True
        
        # Case 3: No modules, auto disabled
        mock_context.runtime_config.auto_active_modules = False
        assert stage.is_enabled(mock_context) is False

    @patch("recon_cli.active.modules.available_modules")
    def test_execute_no_modules(self, mock_avail, mock_context):
        stage = ActiveIntelligenceStage()
        mock_context.record.spec.active_modules = []
        mock_context.runtime_config.auto_active_modules = False
        
        stage.execute(mock_context)
        mock_context.logger.info.assert_called_with("No active modules requested")

    @patch("recon_cli.active.modules.available_modules")
    def test_execute_unknown_module(self, mock_avail, mock_context):
        stage = ActiveIntelligenceStage()
        mock_avail.return_value = ["wayback"]
        mock_context.record.spec.active_modules = ["unknown_mod"]
        
        stage.execute(mock_context)
        mock_context.logger.warning.assert_called_with("Unknown active module '%s'", "unknown_mod")
        mock_context.logger.info.assert_called_with("No valid active modules requested")

    @patch("recon_cli.active.modules.execute_module")
    @patch("recon_cli.active.modules.create_session")
    @patch("recon_cli.active.modules.available_modules")
    def test_execute_success(self, mock_avail, mock_create_session, mock_exec, mock_context):
        stage = ActiveIntelligenceStage()
        mock_avail.return_value = ["wayback"]
        mock_context.record.spec.active_modules = ["wayback"]
        
        # Mock results
        mock_context.get_results.return_value = [
            {"type": "url", "hostname": "example.com", "score": 10},
            {"type": "other"}
        ]
        
        # Mock module execution result
        result_mock = MagicMock()
        result_mock.payloads = [{"type": "finding"}]
        result_mock.artifact_data = {"key": "value"}
        result_mock.artifact_name = "wayback.json"
        mock_exec.return_value = result_mock
        
        stage.execute(mock_context)
        
        mock_exec.assert_called_once()
        mock_context.results.extend.assert_called()
        
        # Verify artifact write
        artifact_path = mock_context.record.paths.ensure_subdir.return_value / "wayback.json"
        artifact_path.write_text.assert_called()

    @patch("recon_cli.active.modules.execute_module")
    @patch("recon_cli.active.modules.create_session")
    @patch("recon_cli.active.modules.available_modules")
    def test_execute_exception(self, mock_avail, mock_create_session, mock_exec, mock_context):
        stage = ActiveIntelligenceStage()
        mock_avail.return_value = ["wayback"]
        mock_context.record.spec.active_modules = ["wayback"]
        mock_context.get_results.return_value = [{"type": "url", "hostname": "example.com"}]
        
        mock_exec.side_effect = Exception("Boom")
        
        stage.execute(mock_context)
        
        mock_context.logger.exception.assert_called()

    @patch("recon_cli.active.modules.execute_module")
    @patch("recon_cli.active.modules.create_session")
    @patch("recon_cli.active.modules.available_modules")
    def test_execute_with_auth(self, mock_avail, mock_create_session, mock_exec, mock_context):
        stage = ActiveIntelligenceStage()
        mock_avail.return_value = ["wayback"]
        mock_context.record.spec.active_modules = ["wayback"]
        mock_context.runtime_config.auth_apply_active_modules = True
        mock_context.auth_enabled.return_value = True
        
        mock_auth_session = MagicMock()
        mock_auth_session.cookies.get_dict.return_value = {"cookie": "yum"}
        mock_context.auth_session.return_value = mock_auth_session
        mock_context.auth_headers.return_value = {"Authorization": "Bearer token"}
        
        mock_context.get_results.return_value = [{"type": "url", "hostname": "example.com"}]
        mock_exec.return_value = MagicMock(payloads=[], artifact_data=None)
        
        stage.execute(mock_context)
        
        mock_create_session.assert_called_with(
            headers={"Authorization": "Bearer token"},
            cookies={"cookie": "yum"},
            verify_tls=False
        )

    @patch("recon_cli.active.modules.execute_module")
    @patch("recon_cli.active.modules.create_session")
    @patch("recon_cli.active.modules.available_modules")
    def test_execute_artifact_write_error(self, mock_avail, mock_create_session, mock_exec, mock_context):
        stage = ActiveIntelligenceStage()
        mock_avail.return_value = ["wayback"]
        mock_context.record.spec.active_modules = ["wayback"]
        mock_context.get_results.return_value = [{"type": "url", "hostname": "example.com", "score": 10}]
        
        result_mock = MagicMock()
        result_mock.payloads = []
        result_mock.artifact_data = {"key": "value"}
        result_mock.artifact_name = "wayback.json"
        mock_exec.return_value = result_mock
        
        # Mock file write to raise TypeError first time
        active_file_mock = mock_context.record.paths.ensure_subdir.return_value.__truediv__.return_value
        active_file_mock.write_text.side_effect = [TypeError("Boom"), None]
        
        stage.execute(mock_context)
        
        assert active_file_mock.write_text.call_count == 2

    @patch("recon_cli.active.modules.execute_module")
    @patch("recon_cli.active.modules.create_session")
    @patch("recon_cli.active.modules.available_modules")
    def test_execute_sorting(self, mock_avail, mock_create_session, mock_exec, mock_context):
        stage = ActiveIntelligenceStage()
        mock_avail.return_value = ["wayback"]
        mock_context.record.spec.active_modules = ["wayback"]
        
        # Multiple hosts with different scores
        mock_context.get_results.return_value = [
            {"type": "url", "hostname": "host1.com", "score": 10},
            {"type": "url", "hostname": "host2.com", "score": 20},
            {"type": "url", "hostname": "host3.com", "score": 5},
        ]
        
        mock_exec.return_value = MagicMock(payloads=[], artifact_data=None)
        
        stage.execute(mock_context)
        
        # Verify hosts passed to execute_module are sorted
        args = mock_exec.call_args
        assert args
        hosts = args[1]['hosts'] # keyword argument
        assert hosts == ["host2.com", "host1.com", "host3.com"]

# -----------------------------------------------------------------------------
# AuthDiscoveryStage Tests
# -----------------------------------------------------------------------------

class TestAuthDiscoveryStage:
    
    def test_is_enabled(self, mock_context):
        stage = AuthDiscoveryStage()
        mock_context.runtime_config.enable_auth_discovery = True
        assert stage.is_enabled(mock_context) is True
        mock_context.runtime_config.enable_auth_discovery = False
        assert stage.is_enabled(mock_context) is False

    def test_execute_rate_limit_wait(self, mock_context):
        stage = AuthDiscoveryStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "http://example.com/login", "status_code": 200, "tags": ["surface:login"]}
        ]
        
        limiter = MagicMock()
        limiter.wait_for_slot.return_value = False
        mock_context.get_rate_limiter.return_value = limiter
        
        stage.execute(mock_context)
        
        assert not mock_context.results.append.called

    def test_execute_missing_deps(self, mock_context):
        stage = AuthDiscoveryStage()
        # We need to simulate ImportError for requests
        with patch.dict("sys.modules", {"requests": None}):
             # We need to reload the module or simulate the import inside execute failing
             # Since execute does `import requests`, patching sys.modules should work if it's not cached in the function scope
             # But it IS a local import.
             stage.execute(mock_context)
             mock_context.logger.warning.assert_called_with("auth discovery requires requests; skipping")

    def test_execute_no_candidates(self, mock_context):
        stage = AuthDiscoveryStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "http://example.com", "status_code": 404}
        ]
        stage.execute(mock_context)
        mock_context.logger.info.assert_called_with("No auth candidates discovered")

    @patch("requests.get")
    def test_execute_with_candidates(self, mock_get, mock_context):
        stage = AuthDiscoveryStage()
        
        # Setup candidates
        mock_context.get_results.return_value = [
            {
                "type": "url", 
                "url": "http://example.com/login", 
                "status_code": 200, 
                "tags": ["surface:login"],
                "score": 10
            }
        ]
        
        # Setup response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = '<html><form action="/login_post" method="post"><input type="text" name="user"><input type="password" name="pass"><input type="hidden" name="csrf_token" value="123"><input type="submit"></form></html>'
        mock_get.return_value = mock_resp
        
        stage.execute(mock_context)
        
        # Verify results
        assert mock_context.results.append.called
        # Check call args
        # The append is called multiple times?
        # Let's check if any call matches
        found_auth_form = False
        for call in mock_context.results.append.call_args_list:
            arg = call[0][0]
            if arg.get("type") == "auth_form":
                found_auth_form = True
                assert "surface:login" in arg["tags"]
                assert "indicator:csrf" in arg["tags"]
        
        assert found_auth_form
        
        # Verify artifacts
        mock_context.record.paths.artifact.return_value.write_text.assert_called()

    @patch("requests.get")
    def test_execute_rate_limit_and_error(self, mock_get, mock_context):
        stage = AuthDiscoveryStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "http://example.com/login", "status_code": 200, "tags": ["surface:login"]}
        ]
        
        # Mock rate limiter
        limiter = MagicMock()
        limiter.wait_for_slot.return_value = True
        mock_context.get_rate_limiter.return_value = limiter
        
        # Mock request exception
        import requests
        mock_get.side_effect = requests.exceptions.RequestException("Error")
        
        stage.execute(mock_context)
        
        limiter.on_error.assert_called()
        
        # Should not append results
        mock_context.results.append.assert_not_called()

# -----------------------------------------------------------------------------
# GitHubReconStage Tests
# -----------------------------------------------------------------------------

class TestGitHubReconStage:
    
    def test_is_enabled(self, mock_context):
        stage = GitHubReconStage()
        mock_context.runtime_config.enable_github_recon = True
        assert stage.is_enabled(mock_context) is True

    @pytest.mark.asyncio
    async def test_search_github(self):
        stage = GitHubReconStage()
        
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            
            # Case 1: Success
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"items": [{"path": "secret.js"}]}
            mock_client.get.return_value = mock_resp
            
            items = await stage._search_github("query", "token")
            assert len(items) == 1
            assert items[0]["path"] == "secret.js"
            
            # Case 2: 403
            mock_resp.status_code = 403
            items = await stage._search_github("query", "token")
            assert items == []
            
            # Case 3: No token
            items = await stage._search_github("query", None)
            assert items == []
            
            # Case 4: Exception
            mock_client.get.side_effect = Exception("Network error")
            items = await stage._search_github("query", "token")
            assert items == []

    @pytest.mark.asyncio
    async def test_run_async(self, mock_context):
        stage = GitHubReconStage()
        mock_context.scope_targets.return_value = ["example.com"]
        
        with patch.object(stage, "_search_github") as mock_search:
            # _search_github is async, so return value should be awaitable or it should be an AsyncMock
            # But here we are patching the method on the instance? No, just the class method if unbound or bound?
            # Easiest is to make it an AsyncMock
            mock_search.side_effect = AsyncMock(return_value=[
                {
                    "repository": {"full_name": "user/repo"},
                    "html_url": "http://github.com/user/repo/blob/main/file.js",
                    "path": "file.js"
                }
            ])
            
            await stage.run_async(mock_context)
            
            mock_context.results.append.assert_called()
            call_args = mock_context.results.append.call_args[0][0]
            assert call_args["finding_type"] == "github_leak"
            assert call_args["hostname"] == "example.com"

    @pytest.mark.asyncio
    async def test_run_async_no_token(self, mock_context):
        stage = GitHubReconStage()
        mock_context.runtime_config.github_token = None
        
        await stage.run_async(mock_context)
        mock_context.logger.info.assert_called_with("GitHub token not configured; skipping GitHub recon")

    @pytest.mark.asyncio
    async def test_run_async_no_targets(self, mock_context):
        stage = GitHubReconStage()
        mock_context.scope_targets.return_value = []
        
        await stage.run_async(mock_context)
        
        # Verify no search called
        with patch.object(stage, "_search_github") as mock_search:
            assert not mock_search.called
            assert not mock_context.results.append.called

    def test_execute(self, mock_context):
        stage = GitHubReconStage()
        with patch("asyncio.run") as mock_run:
            stage.execute(mock_context)
            mock_run.assert_called()
            # Close the coroutine to avoid RuntimeWarning
            coro = mock_run.call_args[0][0]
            coro.close()

# -----------------------------------------------------------------------------
# HTMLFormMiningStage Tests
# -----------------------------------------------------------------------------

class TestHTMLFormMiningStage:
    
    def test_is_enabled(self, mock_context):
        stage = HTMLFormMiningStage()
        mock_context.runtime_config.enable_html_form_mining = True
        assert stage.is_enabled(mock_context) is True

    def test_execute_rate_limit_wait(self, mock_context):
        stage = HTMLFormMiningStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "http://example.com/form", "status_code": 200, "score": 10}
        ]
        
        limiter = MagicMock()
        limiter.wait_for_slot.return_value = False
        mock_context.get_rate_limiter.return_value = limiter
        
        stage.execute(mock_context)
        
        assert not mock_context.results.append.called

    def test_select_urls(self, mock_context):
        stage = HTMLFormMiningStage()
        mock_context.get_results.return_value = [
            {"type": "url", "url": "http://good.com", "status_code": 200, "score": 10},
            {"type": "url", "url": "http://bad.com", "status_code": 500},
            {"type": "other"}
        ]
        
        urls = stage._select_urls(mock_context, max_urls=10)
        assert "http://good.com" in urls
        assert "http://bad.com" not in urls
        
    @patch("requests.get")
    def test_execute_flow(self, mock_get, mock_context):
        stage = HTMLFormMiningStage()
        
        # Setup candidates
        mock_context.get_results.return_value = [
            {"type": "url", "url": "http://example.com/form", "status_code": 200, "score": 10}
        ]
        
        # Setup response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = '<html><form action="/submit" method="post"><input type="text" name="username"><input type="text" name="username"><!-- duplicate param test --><input type="email" name="email"></form></html>'
        mock_get.return_value = mock_resp
        
        stage.execute(mock_context)
        
        # Verify form found
        assert mock_context.results.append.call_count >= 1
        
        # Check form payload
        form_payload = None
        param_payload = None
        
        for call in mock_context.results.append.call_args_list:
            args = call[0][0]
            if args.get("type") == "form":
                form_payload = args
            if args.get("type") == "parameter":
                param_payload = args
                
        assert form_payload is not None
        assert form_payload["url"] == "http://example.com/form"
        assert len(form_payload["inputs"]) == 3
        
        assert param_payload is not None
        # Verify param stats
        if param_payload["name"] == "username":
            assert param_payload["count"] >= 1
            
        # Verify artifacts
        mock_context.record.paths.artifact.return_value.write_text.assert_called()

    @patch("requests.get")
    def test_execute_empty(self, mock_get, mock_context):
        stage = HTMLFormMiningStage()
        mock_context.get_results.return_value = [] # No candidates
        
        stage.execute(mock_context)
        mock_context.logger.info.assert_called_with("No HTML URLs found for form mining")

    def test_execute_missing_deps(self, mock_context):
        stage = HTMLFormMiningStage()
        with patch.dict("sys.modules", {"requests": None}):
            stage.execute(mock_context)
            mock_context.logger.warning.assert_called_with("html form mining requires requests; skipping")
