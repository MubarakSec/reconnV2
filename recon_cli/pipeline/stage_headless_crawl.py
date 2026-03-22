from __future__ import annotations

import asyncio
import json
from typing import Dict, List, Set, Any
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class HeadlessCrawlStage(Stage):
    """
    Advanced Headless Browser Crawler.
    Uses Playwright to render pages and capture dynamic endpoints/XHR traffic.
    Fixes the 'SPA Gap' in static analysis.
    """
    name = "headless_crawl"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_headless", True))

    async def run_async(self, context: PipelineContext) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            context.logger.warning("playwright not installed; skipping headless crawl")
            return

        targets = self._select_targets(context)
        if not targets:
            return

        context.logger.info("Starting headless crawl on %d dynamic targets", len(targets))
        
        async with async_playwright() as p:
            # We use chromium as the default engine
            browser = await p.chromium.launch(headless=True)
            
            # Process targets in small batches to avoid resource exhaustion
            batch_size = 3
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i+batch_size]
                tasks = [self._crawl_url(context, browser, url) for url in batch]
                await asyncio.gather(*tasks)
                
            await browser.close()

    async def _crawl_url(self, context: PipelineContext, browser: Any, url: str) -> None:
        page = await browser.new_page(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) recon-cli/2.0 Headless",
            viewport={"width": 1280, "height": 720}
        )
        
        captured_urls: Set[str] = set()
        
        # Listen for all network requests (XHR, Fetch, etc.)
        page.on("request", lambda request: self._handle_request(request, captured_urls, context))

        try:
            context.logger.debug("Rendering %s", url)
            await page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Extract links from the rendered DOM
            hrefs = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a')).map(a => a.href);
            }""")
            
            for href in hrefs:
                if href and href.startswith("http"):
                    captured_urls.add(href)
                    
            # Basic DOM-based XSS check hint
            # (We could add more complex logic here later)
            
        except Exception as e:
            context.logger.debug("Failed to headless crawl %s: %s", url, e)
        finally:
            await page.close()

        # Ingest results
        self._ingest_captured(context, url, captured_urls)

    def _handle_request(self, request: Any, captured_urls: Set[str], context: PipelineContext) -> None:
        if request.resource_type in ["fetch", "xhr"]:
            captured_urls.add(request.url)

    def _ingest_captured(self, context: PipelineContext, source_url: str, urls: Set[str]) -> None:
        new_count = 0
        for url in urls:
            if not context.url_allowed(url):
                continue
                
            payload = {
                "type": "url",
                "source": "headless-crawl",
                "url": url,
                "hostname": urlparse(url).hostname,
                "tags": ["dynamic", "js:rendered"],
                "score": 40
            }
            if context.results.append(payload):
                new_count += 1
        
        if new_count > 0:
            context.logger.info("Headless crawl of %s discovered %d new dynamic endpoints", source_url, new_count)

    def _select_targets(self, context: PipelineContext) -> List[str]:
        # Prioritize high-value pages like dashboards, profile, etc.
        results = context.get_results()
        dynamic_urls = []
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                # Heuristic: if it has 'app', 'dashboard', or is a root, it's a good candidate
                path = urlparse(url).path.lower()
                if not path or path == "/" or any(h in path for h in ["app", "dashboard", "console", "portal"]):
                    dynamic_urls.append(url)
        
        return list(dict.fromkeys(dynamic_urls))[:10] # Limit to top 10 for performance
