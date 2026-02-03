from __future__ import annotations

import json
from typing import Dict, List
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.utils.jsonl import read_jsonl


class ScreenshotStage(Stage):
    name = "screenshots"

    def is_enabled(self, context: PipelineContext) -> bool:
        spec = context.record.spec
        if not context.runtime_config.enable_screenshots and not spec.max_screenshots:
            return False
        if spec.profile != "full" and not spec.max_screenshots:
            return False
        return True

    def execute(self, context: PipelineContext) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            context.logger.warning("playwright not installed; skipping screenshots")
            note_missing_tool(context, "playwright")
            return
        max_shots = context.record.spec.max_screenshots or context.runtime_config.max_screenshots
        candidates = self._select_urls(context, max_shots)
        if not candidates:
            context.logger.info("No URLs eligible for screenshots")
            return
        screenshots_dir = context.record.paths.ensure_subdir("screenshots")
        hars_dir = context.record.paths.ensure_subdir("hars")
        manifest: List[Dict[str, object]] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context.logger.info("Capturing screenshots for %s URLs", len(candidates))
            for idx, entry in enumerate(candidates, start=1):
                url = entry["url"]
                screenshot_path = screenshots_dir / f"shot_{idx}.png"
                html_path = screenshots_dir / f"shot_{idx}.html"
                har_path = hars_dir / f"shot_{idx}.har"
                payload = None
                browser_context = None
                page = None
                try:
                    browser_context = browser.new_context(record_har_path=str(har_path))
                    page = browser_context.new_page()
                    page.goto(url, timeout=15000, wait_until="networkidle")
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    html_path.write_text(page.content(), encoding="utf-8")
                    hostname = urlparse(page.url).hostname or ""
                    payload = {
                        "type": "screenshot",
                        "source": "playwright",
                        "hostname": hostname,
                        "url": url,
                        "final_url": page.url,
                        "score": entry.get("score"),
                        "selection_source": entry.get("source"),
                        "selection_tags": entry.get("tags"),
                        "selection_reason": entry.get("reason"),
                        "screenshot_path": str(screenshot_path.relative_to(context.record.paths.root)),
                    }
                except Exception as exc:
                    if browser_context is None:
                        context.logger.warning("Failed to initialize browser context for %s: %s", url, exc)
                    else:
                        context.logger.warning("Failed to screenshot %s: %s", url, exc)
                finally:
                    if page is not None:
                        try:
                            page.close()
                        except Exception:
                            pass
                    if browser_context is not None:
                        try:
                            browser_context.close()
                        except Exception:
                            pass
                if payload:
                    if har_path.exists():
                        payload["har_path"] = str(har_path.relative_to(context.record.paths.root))
                    if html_path.exists():
                        payload["html_path"] = str(html_path.relative_to(context.record.paths.root))
                    context.results.append(payload)
                    manifest.append(payload)
            browser.close()
        if manifest:
            manifest_path = screenshots_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
            stats = context.record.metadata.stats.setdefault("screenshots", {})
            stats["count"] = len(manifest)
            stats["manifest"] = str(manifest_path.relative_to(context.record.paths.root))
            context.manager.update_metadata(context.record)

    def _select_urls(self, context: PipelineContext, limit: int) -> List[Dict[str, object]]:
        urls: List[Dict[str, object]] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            status = entry.get("status_code")
            if status not in {200, 302}:
                continue
            url = entry.get("url")
            if not url:
                continue
            score = int(entry.get("score", 0))
            urls.append(
                {
                    "url": url,
                    "score": score,
                    "source": entry.get("source"),
                    "tags": entry.get("tags", []),
                    "reason": f"score={score} source={entry.get('source')}",
                }
            )
        urls.sort(key=lambda item: item.get("score", 0), reverse=True)
        return urls[:limit]
