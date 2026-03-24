from __future__ import annotations

import pytest
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from recon_cli.utils.captcha import CaptchaDetector, CaptchaSolver
from recon_cli.pipeline.stage_active_auth import ActiveAuthStage
from recon_cli.pipeline.stage_headless_crawl import HeadlessCrawlStage
from recon_cli.pipeline.context import PipelineContext
from recon_cli.utils.async_http import HTTPResponse


@pytest.fixture
def mock_context():
    mock = MagicMock(spec=PipelineContext)
    mock.runtime_config = MagicMock()
    mock.runtime_config.two_captcha_api_key = "test_key"
    mock.results = []
    mock.logger = MagicMock()
    
    def mock_filter(res_type):
        return [r for r in mock._results_list if r.get("type") == res_type]
    mock.filter_results.side_effect = mock_filter
    
    mock.is_host_blocked.return_value = False
    return mock


class TestCaptchaBypass:

    def test_captcha_detection(self):
        html_recaptcha = '<html><script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha" data-sitekey="site_key_123"></div></html>'
        html_hcaptcha = '<html><script src="https://hcaptcha.com/1/api.js"></script><div class="h-captcha" data-sitekey="site_key_456"></div></html>'
        html_turnstile = '<html><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script><div class="cf-turnstile" data-sitekey="site_key_789"></div></html>'
        
        assert CaptchaDetector.detect(html_recaptcha) == "recaptcha"
        assert CaptchaDetector.detect(html_hcaptcha) == "hcaptcha"
        assert CaptchaDetector.detect(html_turnstile) == "turnstile"
        
        assert CaptchaDetector.extract_site_key(html_recaptcha, "recaptcha") == "site_key_123"
        assert CaptchaDetector.extract_site_key(html_hcaptcha, "hcaptcha") == "site_key_456"
        assert CaptchaDetector.extract_site_key(html_turnstile, "turnstile") == "site_key_789"

    @pytest.mark.asyncio
    async def test_active_auth_with_captcha(self, mock_context):
        stage = ActiveAuthStage()
        # Mock ACCOUNTS_FILE to avoid writing to disk
        stage.ACCOUNTS_FILE = Path("data/test_accounts.json")
        
        mock_context._results_list = [
            {"type": "auth_form", "url": "https://example.com/signup", "tags": ["surface:register"], "inputs": [{"name": "email"}, {"name": "password"}]}
        ]
        html_with_captcha = '<html><input type="hidden" name="csrf" value="123"><div class="g-recaptcha" data-sitekey="site_key_123"></div></html>'

        with patch("recon_cli.utils.async_http.AsyncHTTPClient.get", new_callable=AsyncMock) as mock_get, \
             patch("recon_cli.utils.async_http.AsyncHTTPClient.post", new_callable=AsyncMock) as mock_post, \
             patch("recon_cli.utils.captcha.CaptchaSolver.solve_recaptcha", return_value="solved_token"), \
             patch.object(ActiveAuthStage, "_get_existing_credentials", return_value=None), \
             patch("recon_cli.utils.fs.write_json") as mock_write_json:

            mock_get.return_value = HTTPResponse(url="https://example.com/signup", status=200, headers={}, body=html_with_captcha, elapsed=0.1)
            mock_post.return_value = HTTPResponse(url="https://example.com/signup", status=200, headers={}, body="Success!", elapsed=0.1)

            await stage.run_async(mock_context)

            assert mock_post.called, "mock_post should have been called"
            args, kwargs = mock_post.call_args
            payload = kwargs.get("data", {})
            print(f"DEBUG: ActiveAuth payload: {payload}")
            assert payload.get("csrf") == "123"
            assert payload.get("g-recaptcha-response") == "solved_token"


    @pytest.mark.asyncio
    async def test_headless_crawl_with_captcha(self, mock_context):
        stage = HeadlessCrawlStage()
        mock_context._results_list = [
            {"type": "url", "url": "https://example.com/", "tags": ["auth"]}
        ]
        
        html_with_captcha = '<html><div class="cf-turnstile" data-sitekey="site_key_789"></div></html>'
        
        # We need to mock Playwright correctly for 'async with async_playwright() as p:'
        mock_p = AsyncMock()
        mock_browser = AsyncMock()
        mock_p.chromium.launch.return_value = mock_browser
        
        mock_page_context = AsyncMock()
        mock_browser.new_context.return_value = mock_page_context
        
        mock_page = AsyncMock()
        mock_page.on = MagicMock() # Playwright 'on' is sync
        mock_page_context.new_page.return_value = mock_page
        
        mock_page.content.return_value = html_with_captcha
        mock_page.goto.return_value = None
        mock_page.evaluate.return_value = []
        
        # Create a mock for async_playwright that returns mock_p when called
        # and mock_p should support __aenter__ and __aexit__
        mock_p.__aenter__.return_value = mock_p
        
        print("DEBUG: Starting headless crawl")
        with patch("playwright.async_api.async_playwright", return_value=mock_p), \
             patch("recon_cli.utils.captcha.CaptchaSolver.solve_turnstile", return_value="solved_turnstile_token"):
            
            # Mock select_targets to ensure our URL is picked
            with patch.object(HeadlessCrawlStage, "_select_targets", return_value=["https://example.com/"]):
                print("DEBUG: Calling run_async")
                await stage.run_async(mock_context)
                print(f"DEBUG: run_async finished")

                # Verify that _crawl_url was called
                print(f"DEBUG: page.on calls: {mock_page.on.call_count}")
                assert mock_page.on.called, "page.on should have been called if _crawl_url ran"

                # Verify that injection was attempted
                evaluate_calls = [str(call) for call in mock_page.evaluate.call_args_list]

            print(f"DEBUG: evaluate_calls: {evaluate_calls}")
            
            # Check if any call contains cf-turnstile-response
            found = False
            for call in evaluate_calls:
                if "cf-turnstile-response" in call:
                    found = True
                    break
            
            if not found:
                print("DEBUG: Injection not found in evaluate calls")
                # Let's check why by checking if solve_turnstile was called
                # Wait, I patched CaptchaSolver.solve_turnstile, but I didn't mock the solver instance
                # Actually patch on class method works
                
            assert found
