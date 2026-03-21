
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch, mock_open, call

import pytest

# --- Mocks for missing dependencies ---
sys.modules["playwright"] = MagicMock()
sys.modules["playwright.async_api"] = MagicMock()
sys.modules["sklearn"] = MagicMock()
sys.modules["sklearn.linear_model"] = MagicMock()
sys.modules["sklearn.preprocessing"] = MagicMock()
sys.modules["numpy"] = MagicMock()

# --- Imports after mocking ---
from recon_cli.active import modules
from recon_cli.crawl import runtime
from recon_cli.learning import collector, model
from recon_cli.pipeline import stage_passive
from recon_cli.pipeline.context import PipelineContext
from recon_cli.tools.executor import CommandError


# =============================================================================
# 1. recon_cli/active/modules.py
# =============================================================================

class TestActiveModules:
    @pytest.fixture
    def mock_session(self):
        session = MagicMock()
        session.headers = {}
        session.cookies = {}
        return session

    def test_create_session(self):
        s = modules.create_session(headers={"X-Test": "1"}, cookies={"c": "v"})
        assert s.headers["X-Test"] == "1"
        assert s.cookies["c"] == "v"
        assert s.verify is True

    def test_backup_hunt_hit(self, mock_session):
        # Setup
        url_entries = [{"url": "http://example.com/login", "score": 10}]
        
        # Mock response
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Length": "300", "Content-Type": "text/plain"}
        resp.encoding = "utf-8"
        resp.iter_content = MagicMock(return_value=[b"A" * 300])
        mock_session.get.return_value = resp
        
        # Execute
        result = modules.run_backup_hunt(url_entries, mock_session)
        
        # Verify
        assert len(result.payloads) > 0
        assert result.payloads[0]["type"] == "url"
        assert result.payloads[0]["tags"] == ["active", "backup", "high-risk"]
        assert len(result.artifact_data) > 0

    def test_backup_hunt_miss_small_file(self, mock_session):
        url_entries = [{"url": "http://example.com/login", "score": 10}]
        resp = MagicMock()
        resp.status_code = 200
        # Too small
        resp.headers = {"Content-Length": "10"} 
        resp.iter_content = MagicMock(return_value=[b"A" * 10])
        mock_session.get.return_value = resp
        
        result = modules.run_backup_hunt(url_entries, mock_session)
        assert len(result.payloads) == 0

    def test_backup_hunt_exception(self, mock_session):
        url_entries = [{"url": "http://example.com/login", "score": 10}]
        # Must use RequestException as that is what is caught
        from requests import RequestException
        mock_session.get.side_effect = RequestException("Network error")
        result = modules.run_backup_hunt(url_entries, mock_session)
        assert len(result.payloads) == 0

    def test_execute_module_dispatch(self, mock_session):
        # Test valid dispatch
        # We must patch the functions in the module AND update the registry
        # because execute_module checks "if handler in {run_backup_hunt, ...}"
        
        mock_backup = MagicMock()
        mock_cors = MagicMock()
        
        with patch("recon_cli.active.modules.run_backup_hunt", mock_backup), \
             patch("recon_cli.active.modules.run_cors_checks", mock_cors), \
             patch.dict(modules.MODULE_REGISTRY, {"backup": mock_backup, "cors": mock_cors}):
            
            modules.execute_module("backup", url_entries=[], hosts=[], session=mock_session)
            mock_backup.assert_called_once()
            
            modules.execute_module("cors", url_entries=[], hosts=[], session=mock_session)
            mock_cors.assert_called_once()
            
            # Test invalid
            with pytest.raises(ValueError, match="Unknown active module"):
                modules.execute_module("unknown", url_entries=[], hosts=[], session=mock_session)

# =============================================================================
# 2. recon_cli/crawl/runtime.py
# =============================================================================

class TestCrawlRuntime:
    @patch("recon_cli.crawl.runtime.async_playwright")
    def test_crawl_urls_success(self, mock_ap):
        # Mock the entire playwright chain
        mock_p = AsyncMock()
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        
        mock_ap.return_value.__aenter__.return_value = mock_p
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Avoid warnings about unawaited coroutines for page.on
        mock_page.on = MagicMock()
        
        # Mock page behavior
        mock_page.content.return_value = "<html></html>"
        
        # Run
        results = runtime.crawl_urls(["http://example.com"], timeout_seconds=1)
        
        assert "http://example.com" in results
        res = results["http://example.com"]
        assert res.success is True
        assert res.dom_snapshot == "<html></html>"
        
        # Verify calls
        mock_page.goto.assert_called_once()

    @patch("recon_cli.crawl.runtime.async_playwright")
    def test_crawl_events(self, mock_ap):
        mock_p = AsyncMock()
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        
        mock_ap.return_value.__aenter__.return_value = mock_p
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        # Capture callbacks to trigger them manually
        callbacks = {}
        def on_side_effect(event, cb):
            callbacks[event] = cb
            
        # IMPORTANT: page.on is synchronous, so we need a MagicMock, not AsyncMock
        mock_page.on = MagicMock(side_effect=on_side_effect)
        
        async def mock_goto(*args, **kwargs):
            # Trigger events while "navigating"
            
            # Request
            req = MagicMock()
            req.url = "http://example.com/style.css"
            req.method = "GET"
            req.resource_type = "stylesheet"
            if "request" in callbacks:
                callbacks["request"](req)
                
            # Response
            resp = MagicMock()
            resp.url = "http://example.com/style.css"
            resp.request = req
            resp.status = 200
            if "response" in callbacks:
                callbacks["response"](resp)
                
            # Request Failed
            req_fail = MagicMock()
            req_fail.url = "http://example.com/fail"
            req_fail.method = "GET"
            req_fail.failure = MagicMock()
            req_fail.failure.error_text = "Blocked"
            if "requestfailed" in callbacks:
                callbacks["requestfailed"](req_fail)
                
            # Console
            msg = MagicMock()
            msg.type = "log"
            msg.text = "Hello"
            if "console" in callbacks:
                callbacks["console"](msg)
                
            # Page Error
            if "pageerror" in callbacks:
                callbacks["pageerror"](Exception("Page Crashed"))

        mock_page.goto.side_effect = mock_goto
        mock_page.content.return_value = "<html></html>"

        results = runtime.crawl_urls(["http://example.com"], timeout_seconds=1)
        res = results["http://example.com"]
        
        assert len(res.network) >= 1
        assert len(res.console_messages) == 1
        assert any("Page Crashed" in e for e in res.errors)
        assert "request_failed:http://example.com/fail" in str(res.errors)

    def test_save_results(self):
        # Setup data
        res = runtime.CrawlResult(
            url="http://example.com",
            success=True,
            network=[],
            javascript_files=[],
            errors=[],
            console_messages=[],
            dom_snapshot="<html></html>"
        )
        results = {"http://example.com": res}
        
        tmp_path = MagicMock(spec=Path)
        
        # Execute
        runtime.save_results(results, tmp_path)
        
        # Verify
        # Should create dir
        tmp_path.mkdir.assert_called()
        # Should write DOM
        # Should write JSON
        assert tmp_path.__truediv__.call_count >= 2

# =============================================================================
# 3. recon_cli/learning/collector.py & model.py
# =============================================================================

class TestLearning:
    def test_dataset_store(self, tmp_path):
        store = collector.DatasetStore(tmp_path)
        
        # Append
        record = {"host": "example.com", "features": {}, "label": 1}
        store.append([record])
        
        # Load all
        all_recs = store.load_all()
        assert len(all_recs) == 1
        assert all_recs[0]["host"] == "example.com"
        
        # Load labeled
        labeled = store.load_labeled()
        assert len(labeled) == 1
        
        # Load labeled with no label
        record2 = {"host": "other.com", "features": {}, "label": None}
        store.append([record2])
        labeled = store.load_labeled()
        assert len(labeled) == 1  # Should still be 1
        
        all_recs = store.load_all()
        assert len(all_recs) == 2

    def test_host_features_dataclass(self):
        hf = collector.HostFeatures(host="a.com", features={"a": 1.0}, label=1)
        rec = hf.to_record("job1")
        assert rec["host"] == "a.com"
        assert rec["job_id"] == "job1"

    def test_model_lifecycle(self, tmp_path):
        # Mock sklearn availability logic in model.py by patching globals in that module
        # Note: We already mocked sys.modules["sklearn"] at top level
        
        # We need to ensure SKLEARN_AVAILABLE is True for the test
        with patch("recon_cli.learning.model.SKLEARN_AVAILABLE", True):
            # Also mock numpy and sklearn classes
            with patch("recon_cli.learning.model.np") as mock_np, \
                 patch("recon_cli.learning.model.StandardScaler") as mock_scaler, \
                 patch("recon_cli.learning.model.LogisticRegression") as mock_lr:
                
                # Setup mocks
                mock_model_instance = MagicMock()
                mock_lr.return_value = mock_model_instance
                mock_model_instance.coef_ = [0.1]
                mock_model_instance.intercept_ = [0.0]
                mock_model_instance.classes_ = [0, 1]
                
                mock_scaler_instance = MagicMock()
                mock_scaler.return_value = mock_scaler_instance
                mock_scaler_instance.mean_ = [0.0]
                mock_scaler_instance.scale_ = [1.0]
                
                mdl = model.LearningModel(tmp_path, ["f1"])
                
                # Test Train (not enough data)
                assert mdl.train([]) is False
                
                # Test Train (enough data)
                records = []
                for i in range(5):
                    records.append({"features": {"f1": 1.0}, "label": 1})
                for i in range(5):
                    records.append({"features": {"f1": 0.0}, "label": 0})
                    
                assert mdl.train(records) is True
                assert mock_model_instance.fit.called
                
                # Test Persist (called inside train)
                mock_np.savez.assert_called()
                
                # Test Load
                # First simulate file exists
                mock_path = MagicMock()
                mock_path.exists.return_value = True
                mdl.model_path = mock_path
                
                # Mock np.load result
                mock_np_data = {
                    "feature_keys": mock_np.array(["f1"]),
                    "scaler_mean_": [0.0],
                    "scaler_scale_": [1.0],
                    "coef_": [0.1],
                    "intercept_": [0.0],
                    "classes_": [0, 1]
                }
                mock_np.load.return_value = mock_np_data
                
                assert mdl.load() is True
                
                # Test Predict
                # Use a helper class to simulate numpy indexing [0, 1]
                class MockArray:
                    def __getitem__(self, item):
                        if item == (0, 1):
                            return 0.8
                        return 0.0
                        
                mock_model_instance.predict_proba.return_value = MockArray()
                
                hf = collector.HostFeatures("test.com", {"f1": 1.0})
                preds = mdl.predict([hf])
                assert "test.com" in preds
                assert preds["test.com"] == 0.8

# =============================================================================
# 4. recon_cli/pipeline/stage_passive.py
# =============================================================================

class TestPassiveEnumerationStage:
    @pytest.fixture
    def mock_context(self):
        ctx = MagicMock(spec=PipelineContext)
        ctx.logger = MagicMock()
        ctx.executor = MagicMock()
        ctx.runtime_config.tool_timeout = 10
        ctx.record.spec.profile = "passive"
        ctx.record.spec.allow_ip = False
        ctx.record.paths.artifact = MagicMock(return_value=MagicMock(spec=Path))
        ctx.results = MagicMock()
        ctx.results.append = MagicMock()
        ctx.url_allowed.return_value = True
        return ctx

    def test_is_enabled(self, mock_context):
        stage = stage_passive.PassiveEnumerationStage()
        assert stage.is_enabled(mock_context) is True
        
        mock_context.record.spec.profile = "active"
        assert stage.is_enabled(mock_context) is False

    def test_execute_flow(self, mock_context):
        stage = stage_passive.PassiveEnumerationStage()
        mock_context.targets = ["example.com"]
        
        # Mock subfinder
        mock_context.executor.available.return_value = True
        run_res = MagicMock()
        run_res.stdout = "sub.example.com\n"
        mock_context.executor.run.return_value = run_res
        
        # Execute
        stage.execute(mock_context)
        
        # Verify subfinder called
        mock_context.executor.run.assert_called()
        # Verify results appended
        # We expect calls for seeds, subfinder results, etc.
        assert mock_context.results.append.called

    def test_run_amass_parsing(self, mock_context):
        stage = stage_passive.PassiveEnumerationStage()
        
        mock_context.executor.available.return_value = True
        
        # Mock amass output file
        amass_out = MagicMock()
        amass_out.exists.return_value = True
        
        # Mock file content
        lines = [
            '{"name": "amass.example.com"}',
            'plain.example.com'
        ]
        amass_out.open.return_value.__enter__.return_value = lines
        
        hosts = stage._run_amass(mock_context, "targets.txt", 10, amass_out)
        
        assert "amass.example.com" in hosts
        assert "plain.example.com" in hosts

    def test_run_wayback_command(self, mock_context):
        stage = stage_passive.PassiveEnumerationStage()
        mock_context.executor.available.side_effect = lambda tool: tool == "waybackurls"
        
        # Mock temp file output
        wayback_tmp = MagicMock()
        wayback_tmp.exists.return_value = True
        wayback_tmp.open.return_value.__enter__.return_value = ["http://example.com/page"]
        
        mock_context.record.paths.artifact.side_effect = lambda name: wayback_tmp
        
        stage._run_wayback(mock_context, ["example.com"], 10, MagicMock())
        
        # Check executor call
        mock_context.executor.run_to_file.assert_called()
        # Check tracking
        calls = mock_context.results.append.call_args_list
        found = any(c[0][0]["url"] == "http://example.com/page" for c in calls)
        assert found

    @patch("recon_cli.pipeline.stage_passive.httpx")
    def test_run_wayback_api_fallback(self, mock_httpx, mock_context):
        stage = stage_passive.PassiveEnumerationStage()
        mock_context.executor.available.return_value = False # Force fallback
        
        # Mock API response
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            ["original", "mimetype"], # Header
            ["http://api.example.com/1", "text/html"]
        ]
        mock_httpx.get.return_value = mock_resp
        
        stage._run_wayback(mock_context, ["example.com"], 10, MagicMock())
        
        calls = mock_context.results.append.call_args_list
        found = any(c[0][0]["url"] == "http://api.example.com/1" for c in calls)
        assert found

    def test_ip_handling(self, mock_context):
        stage = stage_passive.PassiveEnumerationStage()
        mock_context.record.spec.allow_ip = True
        mock_context.targets = ["192.168.1.1"]
        
        # Subfinder/Amass usually skipped for IPs or handle them differently
        # The logic says: if all targets are IPs, skip passive subdomain discovery
        
        stage.execute(mock_context)
        
        # Verify warnings or skip logs
        mock_context.logger.info.assert_any_call("Skipping passive subdomain discovery (targets are all IPs)")

if __name__ == "__main__":
    unittest.main()
