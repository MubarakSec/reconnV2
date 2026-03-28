
import unittest
from unittest.mock import MagicMock, patch
from recon_cli.pipeline.stages.validation.stage_extended_validation import ExtendedValidationStage
from recon_cli.pipeline.context import PipelineContext
from urllib.parse import urlparse

class TestRepro(unittest.TestCase):
    def test_repro(self):
        context = MagicMock(spec=PipelineContext)
        context.logger = MagicMock()
        context.runtime_config = MagicMock()
        context.runtime_config.enable_extended_validation = True
        context.runtime_config.enable_redirect_validation = True
        context.runtime_config.redirect_max_urls = 40
        context.runtime_config.verify_tls = True
        from pathlib import Path
        import tempfile
        tmp_dir = Path(tempfile.gettempdir())
        context.record.paths.root = tmp_dir
        context.record.paths.ensure_subdir.return_value = tmp_dir
        context.record.metadata.stats = {}
        context.get_results.return_value = [
            {"type": "url", "url": "http://test.com?redirect=orig", "score": 50}
        ]
        context.url_allowed.return_value = True
        context.results = MagicMock()
        context.signal_index.return_value = {}
        
        # This is what I suspect is the issue: context.auth_session returns a MagicMock
        # which is truthy, so ExtendedValidationStage uses session.request instead of requests.request
        # context.auth_session.return_value = None 

        from recon_cli.pipeline.stages.validation.stage_extended_validation import ExtendedValidationStage
        
        # Monkeypatch to add logging
        original_execute = ExtendedValidationStage.execute
        def logged_execute(self, context):
            print("Starting execute")
            res = original_execute(self, context)
            print("Finished execute")
            return res
        ExtendedValidationStage.execute = logged_execute

        original_collect = ExtendedValidationStage._collect_candidates
        def logged_collect(self, context, signals):
            print("Starting collect")
            res = original_collect(self, context, signals)
            print(f"Collect finished, redirect candidates: {len(res['redirect'])}")
            return res
        ExtendedValidationStage._collect_candidates = logged_collect

        stage = ExtendedValidationStage()
        
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "https://example.com/testtoken"}
        
        with patch("requests.request", return_value=mock_resp):
            with patch.object(ExtendedValidationStage, "_token", return_value="testtoken"):
                stage.execute(context)
        
        print(f"context.results.append called: {context.results.append.called}")
        if not context.results.append.called:
            print("Trying with auth_session = None")
            context.auth_session.return_value = None
            with patch("requests.request", return_value=mock_resp):
                with patch.object(ExtendedValidationStage, "_token", return_value="testtoken"):
                    stage.execute(context)
            print(f"context.results.append called after fix: {context.results.append.called}")

if __name__ == "__main__":
    unittest.main()
