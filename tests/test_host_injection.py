from __future__ import annotations

import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from recon_cli.pipeline.stage_host_injection import HostInjectionStage
from recon_cli.utils.async_http import HTTPResponse
from recon_cli.utils.oast import OastInteraction


@pytest.fixture
def mock_context():
    mock = MagicMock()
    mock.runtime_config = MagicMock()
    mock.results = []
    mock.logger = MagicMock()
    
    def mock_filter(res_type):
        return [r for r in mock._results_list if r.get("type") == res_type]
    mock.filter_results.side_effect = mock_filter
    
    mock.is_host_blocked.return_value = False
    mock.record.paths.artifact.return_value = MagicMock()
    return mock


class TestHostInjection:

    @pytest.mark.asyncio
    async def test_host_injection_poisoning(self, mock_context):
        stage = HostInjectionStage()
        mock_context._results_list = [
            {
                "type": "auth_form", 
                "url": "https://example.com/forgot-password", 
                "tags": ["surface:password-reset"],
                "inputs": [{"name": "email"}]
            }
        ]
        
        with patch("recon_cli.pipeline.stage_host_injection.InteractshSession") as mock_oast_cls, \
             patch("recon_cli.utils.async_http.AsyncHTTPClient.get", new_callable=AsyncMock) as mock_get, \
             patch("recon_cli.utils.async_http.AsyncHTTPClient.post", new_callable=AsyncMock) as mock_post, \
             patch("asyncio.sleep", new_callable=AsyncMock): # Skip the 30s wait
            
            # Setup OAST Mock
            mock_oast = mock_oast_cls.return_value
            mock_oast.start.return_value = True
            mock_oast.base_domain = "oast.live"
            
            # Mock successful interaction
            mock_oast.collect_interactions.return_value = [
                OastInteraction(token="test", protocol="http", raw={"full-url": "http://random.oast.live/reset?token=123"})
            ]
            
            # Mock HTTP responses
            mock_get.return_value = HTTPResponse(url="https://example.com/forgot-password", status=200, headers={}, body='<html><input name="csrf" value="token123"></html>', elapsed=0.1)
            mock_post.return_value = HTTPResponse(url="https://example.com/forgot-password", status=200, headers={}, body="Email sent", elapsed=0.1)
            
            await stage.run_async(mock_context)
            
            # Check if finding was added
            findings = [r for r in mock_context.results if r.get("finding_type") == "host_header_injection"]
            assert len(findings) == 1
            assert findings[0]["severity"] == "high"
            
            # Verify poisoned headers were sent
            called_headers = [call.kwargs.get("headers", {}) for call in mock_post.call_args_list]
            assert any("oast.live" in h.get("Host", "") for h in called_headers)
            assert any("oast.live" in h.get("X-Forwarded-Host", "") for h in called_headers)
