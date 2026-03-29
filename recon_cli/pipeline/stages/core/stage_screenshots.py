from __future__ import annotations

import json
import re
from typing import Dict, List, Set
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool


class ScreenshotStage(Stage):
    name = "screenshots"
    LOGIN_HINTS = (
        "login",
        "sign in",
        "signin",
        "log in",
        "auth",
        "password",
        "otp",
        "verify",
    )
    ADMIN_HINTS = (
        "admin",
        "dashboard",
        "console",
        "portal",
        "manage",
        "backend",
        "staff",
    )
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

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
        runtime = context.runtime_config
        ocr_enabled = bool(getattr(runtime, "enable_screenshot_ocr", False))
        ocr_max = int(getattr(runtime, "screenshot_ocr_max", 0))
        ocr_lang = str(getattr(runtime, "screenshot_ocr_lang", "eng") or "eng")
        ocr_ready = False
        if ocr_enabled and ocr_max:
            try:
                ocr_ready = True
            except Exception:
                context.logger.warning("pytesseract/PIL not available; skipping OCR")
                note_missing_tool(context, "pytesseract")
                ocr_ready = False
        max_shots = (
            context.record.spec.max_screenshots
            or context.runtime_config.max_screenshots
        )
        candidates = self._select_urls(context, max_shots)
        if not candidates:
            context.logger.info("No URLs eligible for screenshots")
            return
        screenshots_dir = context.record.paths.ensure_subdir("screenshots")
        hars_dir = context.record.paths.ensure_subdir("hars")
        manifest: List[Dict[str, object]] = []
        ocr_count = 0

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context.logger.info("Capturing screenshots for %s URLs", len(candidates))
            for idx, entry in enumerate(candidates, start=1):
                url = entry["url"]
                screenshot_path = screenshots_dir / f"shot_{idx}.png"
                html_path = screenshots_dir / f"shot_{idx}.html"
                ocr_path = screenshots_dir / f"shot_{idx}.txt"
                har_path = hars_dir / f"shot_{idx}.har"
                payload = None
                browser_context = None
                page = None
                try:
                    browser_context = browser.new_context(record_har_path=str(har_path))
                    page = browser_context.new_page()
                    page.goto(url, timeout=15000, wait_until="domcontentloaded")  # type: ignore[arg-type]
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    html_content = page.content()
                    html_path.write_text(html_content, encoding="utf-8")
                    page_title = page.title() or self._extract_title(html_content)
                    hostname = urlparse(page.url).hostname or ""
                    portal_tags = self._classify_portal(
                        page.url, page_title, html_content, ""
                    )
                    ocr_snippet = ""
                    if ocr_ready and ocr_count < ocr_max and screenshot_path.exists():
                        ocr_text = self._run_ocr(str(screenshot_path), ocr_lang)
                        if ocr_text:
                            ocr_count += 1
                            ocr_path.write_text(ocr_text, encoding="utf-8")
                            ocr_snippet = ocr_text[:500]
                            portal_tags.update(
                                self._classify_portal(
                                    page.url, page_title, html_content, ocr_text
                                )
                            )
                    portal_tags_list = sorted(portal_tags) if portal_tags else []
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
                        "screenshot_path": str(
                            screenshot_path.relative_to(context.record.paths.root)
                        ),
                        "title": page_title,
                    }
                    if portal_tags_list:
                        payload["tags"] = portal_tags_list
                        self._emit_portal_signals(
                            context, page.url, portal_tags_list, page_title
                        )
                    if ocr_snippet:
                        payload["ocr_snippet"] = ocr_snippet
                except Exception as exc:
                    if browser_context is None:
                        context.logger.warning(
                            "Failed to initialize browser context for %s: %s", url, exc
                        )
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
                        payload["har_path"] = str(
                            har_path.relative_to(context.record.paths.root)
                        )
                    if html_path.exists():
                        payload["html_path"] = str(
                            html_path.relative_to(context.record.paths.root)
                        )
                    if ocr_path.exists():
                        payload["ocr_path"] = str(
                            ocr_path.relative_to(context.record.paths.root)
                        )
                    context.results.append(payload)
                    manifest.append(payload)
            browser.close()
        if manifest:
            manifest_path = screenshots_dir / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
            )
            stats = context.record.metadata.stats.setdefault("screenshots", {})
            stats["count"] = len(manifest)
            stats["manifest"] = str(
                manifest_path.relative_to(context.record.paths.root)
            )
            context.manager.update_metadata(context.record)

    def _select_urls(
        self, context: PipelineContext, limit: int
    ) -> List[Dict[str, object]]:
        urls: List[Dict[str, object]] = []
        # Common extensions that trigger downloads and cause playwright to fail
        DOWNLOAD_EXTENSIONS = {
            ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".exe", ".msi", ".bin",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".mkv", ".old", ".bak"
        }
        for entry in context.get_results():
            if entry.get("type") != "url":
                continue
            status = entry.get("status_code")
            if status not in {200, 302}:
                continue
            url = entry.get("url")
            if not url:
                continue
            
            # Skip likely downloads
            path = urlparse(url).path.lower()
            if any(path.endswith(ext) for ext in DOWNLOAD_EXTENSIONS):
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
        urls.sort(key=lambda item: item.get("score", 0), reverse=True)  # type: ignore[arg-type, return-value]
        return urls[:limit]

    def _classify_portal(
        self, url: str, title: str, html: str, ocr_text: str
    ) -> Set[str]:
        tags: Set[str] = set()
        title_lower = (title or "").lower()
        url_lower = (url or "").lower()
        html_lower = (html or "").lower()
        ocr_lower = (ocr_text or "").lower()
        combined = " ".join(
            [title_lower, url_lower, html_lower[:2000], ocr_lower[:2000]]
        )
        if 'type="password"' in html_lower or "type='password'" in html_lower:
            tags.add("portal:login")
        if any(hint in combined for hint in self.LOGIN_HINTS):
            tags.add("portal:login")
        if any(hint in combined for hint in self.ADMIN_HINTS):
            tags.add("portal:admin")
        if "dashboard" in combined:
            tags.add("portal:dashboard")
        return tags

    def _emit_portal_signals(
        self, context: PipelineContext, url: str, tags: List[str], title: str
    ) -> None:
        if "portal:login" in tags:
            context.emit_signal(
                "portal_login",
                "url",
                url,
                confidence=0.5,
                source="screenshots",
                tags=["portal", "login"],
                evidence={"title": title},
            )
        if "portal:admin" in tags:
            context.emit_signal(
                "portal_admin",
                "url",
                url,
                confidence=0.5,
                source="screenshots",
                tags=["portal", "admin"],
                evidence={"title": title},
            )
        if "portal:dashboard" in tags:
            context.emit_signal(
                "portal_dashboard",
                "url",
                url,
                confidence=0.4,
                source="screenshots",
                tags=["portal", "dashboard"],
                evidence={"title": title},
            )

    def _extract_title(self, html: str) -> str:
        if not html:
            return ""
        match = self.TITLE_RE.search(html)
        if not match:
            return ""
        title = match.group(1)
        title = re.sub(r"\s+", " ", title).strip()
        return title[:120]

    @staticmethod
    def _run_ocr(image_path: str, lang: str) -> str:
        try:
            import pytesseract  # type: ignore
            from PIL import Image  # type: ignore
        except Exception:
            return ""
        try:
            img = Image.open(image_path)
            text = pytesseract.image_to_string(img, lang=lang)
            return text or ""
        except Exception:
            return ""
