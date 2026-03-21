from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover
    async_playwright = None  # type: ignore
    PlaywrightTimeoutError = Exception  # type: ignore


PLAYWRIGHT_AVAILABLE = async_playwright is not None


@dataclass
class NetworkEntry:
    url: str
    method: str
    resource_type: str
    status: Optional[int]
    failure: Optional[str] = None


@dataclass
class CrawlResult:
    url: str
    success: bool
    network: List[NetworkEntry]
    javascript_files: List[str]
    errors: List[str]
    console_messages: List[str]
    dom_snapshot: Optional[str] = None


def dom_artifact_name(url: str) -> str:
    digest = hashlib.sha1(url.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"dom_{digest}.html"


async def _crawl_single(context, url: str, timeout_ms: int) -> CrawlResult:
    page = await context.new_page()
    network_entries: List[NetworkEntry] = []
    request_lookup: Dict[int, NetworkEntry] = {}
    javascript_urls: set[str] = set()
    errors: List[str] = []
    console_messages: List[str] = []

    def on_request(req) -> None:
        entry = NetworkEntry(
            url=req.url,
            method=req.method,
            resource_type=req.resource_type or "",
            status=None,
        )
        network_entries.append(entry)
        request_lookup[id(req)] = entry

    def on_response(resp) -> None:
        req = resp.request
        entry = request_lookup.get(id(req))
        resource_type = req.resource_type or ""
        status = resp.status
        if entry:
            entry.resource_type = resource_type
            entry.status = status
        else:
            entry = NetworkEntry(
                url=resp.url,
                method=req.method,
                resource_type=resource_type,
                status=status,
            )
            network_entries.append(entry)
            request_lookup[id(req)] = entry
        if resource_type == "script" and status and status < 400:
            javascript_urls.add(resp.url)

    def on_request_failed(req) -> None:
        entry = request_lookup.get(id(req))
        failure_info = getattr(req, "failure", None)
        failure_text = None
        if failure_info:
            failure_text = getattr(failure_info, "error_text", None) or getattr(
                failure_info, "errorText", None
            )
            if not failure_text:
                failure_text = str(failure_info)
        if entry:
            entry.failure = failure_text
        message = f"request_failed:{req.url}"
        if failure_text:
            message = f"{message} ({failure_text})"
        errors.append(message)

    page.on("request", on_request)
    page.on("response", on_response)
    page.on("requestfailed", on_request_failed)
    page.on("console", lambda msg: console_messages.append(f"{msg.type}: {msg.text}"))
    page.on("pageerror", lambda exc: errors.append(f"page_error:{exc}"))

    dom = None
    try:
        await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
        dom = await page.content()
    except PlaywrightTimeoutError:
        errors.append("timeout")
    except Exception as exc:  # pragma: no cover
        errors.append(str(exc))
    finally:
        await page.close()

    return CrawlResult(
        url=url,
        success=dom is not None,
        network=network_entries,
        javascript_files=sorted(javascript_urls),
        errors=errors,
        console_messages=console_messages,
        dom_snapshot=dom,
    )


def crawl_urls(
    urls: List[str],
    timeout_seconds: int,
    max_concurrency: int = 1,
    *,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[List[Dict[str, object]]] = None,
) -> Dict[str, CrawlResult]:
    results: Dict[str, CrawlResult] = {}
    if async_playwright is None or not urls:  # pragma: no cover
        return results

    timeout_ms = max(int(timeout_seconds * 1000), 1000)
    concurrency = max(1, int(max_concurrency))

    async def runner() -> None:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context_kwargs: Dict[str, object] = {}
            if headers:
                context_kwargs["extra_http_headers"] = headers
            browser_ctx = await browser.new_context(**context_kwargs)  # type: ignore[arg-type]
            if cookies:
                try:
                    await browser_ctx.add_cookies(cookies)  # type: ignore[arg-type]
                except Exception:
                    pass
            semaphore = asyncio.Semaphore(concurrency)

            async def run_single(target: str) -> None:
                async with semaphore:
                    try:
                        results[target] = await _crawl_single(
                            browser_ctx, target, timeout_ms
                        )
                    except Exception as exc:  # pragma: no cover - defensive
                        results[target] = CrawlResult(
                            url=target,
                            success=False,
                            network=[],
                            javascript_files=[],
                            errors=[str(exc)],
                            console_messages=[],
                            dom_snapshot=None,
                        )

            await asyncio.gather(*(run_single(url) for url in urls))
            await browser_ctx.close()
            await browser.close()

    asyncio.run(runner())
    return results


def save_results(results: Dict[str, CrawlResult], artifact_dir: Path) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Dict[str, object]] = {}
    for url, result in results.items():
        dom_file = None
        if result.dom_snapshot:
            dom_file = dom_artifact_name(url)
            dom_path = artifact_dir / dom_file
            dom_path.write_text(result.dom_snapshot, encoding="utf-8")
            result.dom_snapshot = None
        payload[url] = {
            "success": result.success,
            "errors": result.errors,
            "console_messages": result.console_messages,
            "network": [entry.__dict__ for entry in result.network],
            "javascript_files": result.javascript_files,
            "dom_artifact": dom_file,
        }
    (artifact_dir / "runtime_crawl.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
