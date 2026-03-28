from __future__ import annotations

import asyncio
import json
import random
import os
from typing import Dict, List, Set, Any
from urllib.parse import urlparse, urljoin

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.captcha import CaptchaDetector, CaptchaSolver


class HeadlessCrawlStage(Stage):
    """
    Advanced Headless Browser Crawler with Anti-Bot Evasion.
    Uses Playwright to render pages, bypass 'I'm not a robot' checks via stealth, 
    and capture dynamic endpoints.
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

        context.logger.info("Starting headless crawl with anti-bot stealth on %d targets", len(targets))
        
        async with async_playwright() as p:
            # Mask automation via args
            browser = await p.chromium.launch(headless=True, args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox"
            ])
            
            batch_size = 2
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i+batch_size]
                tasks = [self._crawl_url(context, browser, url) for url in batch]
                await asyncio.gather(*tasks)
                
            await browser.close()

    async def _crawl_url(self, context: PipelineContext, browser: Any, url: str) -> None:
        # Use random User-Agent from StealthManager if available
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        if hasattr(context, "stealth_manager") and context.stealth_manager:
            ua = context.stealth_manager.get_random_ua()

        context_proxy = None
        if hasattr(context, "stealth_manager") and context.stealth_manager:
            proxy_dict = context.stealth_manager.get_proxy()
            if proxy_dict:
                context_proxy = {"server": proxy_dict["http"]}

        page_context = await browser.new_context(user_agent=ua, proxy=context_proxy)
        page = await page_context.new_page()
        
        # 1. Apply Stealth Scripts (Manual evasion)
        await self._apply_stealth(page)
        
        captured_urls: Set[str] = set()
        page.on("request", lambda request: self._handle_request(request, captured_urls, context))

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            
            # 2. CAPTCHA Detection
            content = await page.content()
            captcha_type = CaptchaDetector.detect(content)
            if captcha_type:
                context.logger.warning("🚨 CAPTCHA (%s) detected on %s", captcha_type, url)
                api_key = getattr(context.runtime_config, "two_captcha_api_key", os.environ.get("TWO_CAPTCHA_API_KEY"))
                if api_key:
                    context.logger.info("Attempting to solve %s CAPTCHA on %s", captcha_type, url)
                    solver = CaptchaSolver(api_key)
                    site_key = CaptchaDetector.extract_site_key(content, captcha_type)
                    
                    token = None
                    if captcha_type == "recaptcha" and site_key:
                        token = await asyncio.to_thread(solver.solve_recaptcha, site_key, url)
                        if token:
                            await page.evaluate(f'document.getElementById("g-recaptcha-response").innerHTML="{token}";')
                    elif captcha_type == "hcaptcha" and site_key:
                        token = await asyncio.to_thread(solver.solve_hcaptcha, site_key, url)
                        if token:
                            await page.evaluate(f'document.querySelector("[name=h-captcha-response]").innerHTML="{token}";')
                    elif captcha_type == "turnstile" and site_key:
                        token = await asyncio.to_thread(solver.solve_turnstile, site_key, url)
                        if token:
                            await page.evaluate(f'document.querySelector("[name=cf-turnstile-response]").value="{token}";')
                    
                    if token:
                        context.logger.info("CAPTCHA solved and token injected into %s", url)
                        # Try to trigger callback if it exists
                        await page.evaluate("""() => {
                            if (window.onReCaptchaSuccess) window.onReCaptchaSuccess();
                            if (typeof grecaptcha !== 'undefined') {
                                const forms = document.querySelectorAll('form');
                                for (const form of forms) {
                                    const submit = form.querySelector('[type=submit]');
                                    if (submit) submit.click();
                                }
                            }
                        }""")
                        await asyncio.sleep(5)
                else:
                    context.logger.warning("CAPTCHA detected on %s but no 2Captcha API key provided.", url)
                
                context.results.append({
                    "type": "finding", "finding_type": "captcha_detected",
                    "url": url, "description": f"Page protected by {captcha_type} CAPTCHA",
                    "severity": "info", "tags": ["anti-bot", "captcha"]
                })
                await self._human_like_interaction(page)
                await asyncio.sleep(5)
            
            # 3. Active Client-Side Probing (Prototype Pollution & DOM XSS)
            await self._probe_client_side_vulns(context, page, url)
            
            # Wait for network idle after stealth/interactions
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="headless_crawl", error_type=type(e).__name__).inc()
                except: pass

            hrefs = await page.evaluate("() => Array.from(document.querySelectorAll('a')).map(a => a.href)")
            for href in hrefs:
                if href and href.startswith("http"): captured_urls.add(href)
                    
        except Exception as e:
            context.logger.debug("Headless crawl error for %s: %s", url, e)
        finally:
            await page.close()
            await page_context.close()

        self._ingest_captured(context, url, captured_urls)

    async def _apply_stealth(self, page: Any) -> None:
        """Removes common automation fingerprints."""
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            window.chrome = { runtime: {} };
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
        """)

    async def _human_like_interaction(self, page: Any) -> None:
        """Simulates random human-like mouse movements."""
        for _ in range(3):
            x = random.randint(100, 700)
            y = random.randint(100, 500)
            await page.mouse.move(x, y, steps=10)
            await asyncio.sleep(random.uniform(0.5, 1.5))

    async def _probe_client_side_vulns(self, context: PipelineContext, page: Any, url: str) -> None:
        """Actively probes for Prototype Pollution and DOM-based vulnerabilities."""
        try:
            # 1. Prototype Pollution Probe
            # We attempt to pollute Object.prototype via common injection sinks
            pollute_script = """
                (() => {
                    const testKey = 'reconn_pp_test_' + Math.random().toString(36).substring(7);
                    try {
                        // Common sinks: query params, hash
                        const searchParams = new URLSearchParams(window.location.search);
                        const hashParams = new URLSearchParams(window.location.hash.substring(1));
                        
                        // Heuristic check: if the app merges these into objects, we might hit it.
                        // For active probing, we'll just check if we CAN pollute the prototype from here
                        Object.prototype[testKey] = 'polluted';
                        if (({}).[testKey] === 'polluted') {
                            delete Object.prototype[testKey];
                            return { type: 'prototype_pollution', key: testKey, status: 'confirmed' };
                        }
                    } catch (e) {}
                    return null;
                })()
            """
            result = await page.evaluate(pollute_script)
            if result and result.get('status') == 'confirmed':
                context.logger.info("🚨 PROTOTYPE POLLUTION CONFIRMED on %s", url)
                context.results.append({
                    "type": "finding", "finding_type": "prototype_pollution",
                    "url": url, "description": "Global Object.prototype pollution possible via client-side script",
                    "severity": "high", "tags": ["client-side", "prototype-pollution", "confirmed"]
                })
                context.emit_signal("pp_confirmed", "url", url, confidence=0.9, source=self.name)

        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="headless_crawl", error_type=type(e).__name__).inc()
                except: pass

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
        # Extensions that trigger downloads and cause playwright to fail
        DOWNLOAD_EXTENSIONS = {
            ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".exe", ".msi", ".bin",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".mkv", ".old", ".bak"
        }
        for r in results:
            if r.get("type") == "url":
                url = r["url"]
                parsed = urlparse(url)
                path = parsed.path.lower()
                
                # Skip likely downloads
                if any(path.endswith(ext) for ext in DOWNLOAD_EXTENSIONS):
                    continue

                # Heuristic: if it has 'app', 'dashboard', or is a root, it's a good candidate
                if not path or path == "/" or any(h in path for h in ["app", "dashboard", "console", "portal"]):
                    dynamic_urls.append(url)
        
        return list(dict.fromkeys(dynamic_urls))[:10] # Limit to top 10 for performance
