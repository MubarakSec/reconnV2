from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from recon_cli.crawl.runtime import PLAYWRIGHT_AVAILABLE, crawl_urls, dom_artifact_name, save_results as save_crawl_results
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.utils.jsonl import read_jsonl


class RuntimeCrawlStage(Stage):
    name = "runtime_crawl"
    optional = True

    def is_enabled(self, context: PipelineContext) -> bool:
        if not context.runtime_config.enable_runtime_crawl:
            return False
        max_urls = getattr(context.runtime_config, "runtime_crawl_max_urls", 0)
        return max_urls > 0

    @staticmethod
    def _dom_relpath(context: PipelineContext, artifact_dir: Path, url: str) -> Optional[str]:
        dom_name = dom_artifact_name(url)
        dom_path = artifact_dir / dom_name
        if not dom_path.exists():
            return None
        try:
            return str(dom_path.relative_to(context.record.paths.root))
        except ValueError:
            return str(dom_path)

    def execute(self, context: PipelineContext) -> None:
        logger = context.logger
        items = read_jsonl(context.record.paths.results_jsonl)
        if not items:
            logger.info("No results recorded; skipping runtime crawl stage")
            stats = context.record.metadata.stats.setdefault("runtime_crawl", {})
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "no_input",
                }
            )
            context.manager.update_metadata(context.record)
            return

        stats = context.record.metadata.stats.setdefault("runtime_crawl", {})
        max_urls = max(0, getattr(context.runtime_config, "runtime_crawl_max_urls", 0))
        per_host_limit = max(1, getattr(context.runtime_config, "runtime_crawl_per_host_limit", 3))
        timeout = max(1, getattr(context.runtime_config, "runtime_crawl_timeout", 15))
        concurrency = max(1, getattr(context.runtime_config, "runtime_crawl_concurrency", 2))

        if not PLAYWRIGHT_AVAILABLE:
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "playwright_missing",
                }
            )
            context.manager.update_metadata(context.record)
            logger.warning("playwright not installed; skipping runtime crawl stage")
            note_missing_tool(context, "playwright")
            return

        candidates: List[tuple[int, str, str]] = []
        score_map: Dict[str, int] = {}
        seen_urls: set[str] = set()
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if not context.url_allowed(url):
                continue
            if url in seen_urls:
                continue
            parsed = urlparse(url)
            host = entry.get("hostname") or parsed.hostname
            if not host:
                continue
            status = entry.get("status_code")
            if isinstance(status, int) and status >= 500:
                continue
            score = int(entry.get("score", 0))
            path_lower = (parsed.path or "").lower()
            content_type = str(entry.get("content_type") or "").lower()
            tags = entry.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            tags_lower = [str(tag).lower() for tag in tags]
            if path_lower.endswith(".js"):
                score += 60
            elif ".js" in path_lower:
                score += 25
            if "javascript" in content_type:
                score += 40
            if "api" in tags_lower:
                score += 10
            if "login" in tags_lower:
                score += 5
            if parsed.query:
                score += 5
            if score < 0:
                score = 0
            candidates.append((score, url, host))
            score_map[url] = score
            seen_urls.add(url)

        if not candidates:
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "no_candidates",
                }
            )
            context.manager.update_metadata(context.record)
            logger.info("Runtime crawl stage skipped; no eligible URL candidates")
            return

        candidates.sort(key=lambda item: item[0], reverse=True)

        selected_urls: List[str] = []
        host_counts: Dict[str, int] = defaultdict(int)
        for score, url, host in candidates:
            if host_counts[host] >= per_host_limit:
                continue
            selected_urls.append(url)
            host_counts[host] += 1
            if len(selected_urls) >= max_urls:
                break

        if not selected_urls:
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "host_limit_exhausted",
                }
            )
            context.manager.update_metadata(context.record)
            logger.info("Runtime crawl stage skipped; host limits filtered all candidates")
            return

        logger.info(
            "Runtime crawl targeting %s URLs (timeout=%ss, concurrency=%s)",
            len(selected_urls),
            timeout,
            concurrency,
        )

        try:
            results = crawl_urls(selected_urls, timeout, concurrency)
        except Exception as exc:
            message = str(exc)
            missing_browsers = "playwright install" in message.lower() or "executable doesn't exist" in message.lower()
            stats.update(
                {
                    "selected": len(selected_urls),
                    "crawled": 0,
                    "success": 0,
                    "failures": len(selected_urls),
                    "javascript_files": 0,
                    "status": "playwright_browsers_missing" if missing_browsers else "crawl_error",
                    "error": message,
                }
            )
            context.manager.update_metadata(context.record)
            if missing_browsers:
                logger.warning("Playwright browsers not installed; skipping runtime crawl stage")
                note_missing_tool(context, "playwright-browsers")
            else:
                logger.warning("Runtime crawl failed; skipping stage: %s", message)
            return
        if not results:
            stats.update(
                {
                    "selected": len(selected_urls),
                    "crawled": 0,
                    "success": 0,
                    "failures": len(selected_urls),
                    "javascript_files": 0,
                    "status": "crawl_failed",
                }
            )
            context.manager.update_metadata(context.record)
            logger.warning("Runtime crawl returned no results")
            return

        artifact_dir = context.record.paths.ensure_subdir("runtime_crawl")
        save_crawl_results(results, artifact_dir)

        success_count = sum(1 for result in results.values() if result.success)
        failure_count = len(results) - success_count
        javascript_total = sum(len(result.javascript_files) for result in results.values())

        stats.update(
            {
                "selected": len(selected_urls),
                "crawled": len(results),
                "success": success_count,
                "failures": failure_count,
                "javascript_files": javascript_total,
                "status": "completed",
            }
        )
        context.manager.update_metadata(context.record)

        appended = 0
        for url, result in results.items():
            if not context.url_allowed(url):
                continue
            artifact_rel = self._dom_relpath(context, artifact_dir, url)
            payload = {
                "type": "runtime_crawl",
                "source": "playwright",
                "url": url,
                "hostname": urlparse(url).hostname or "",
                "success": result.success,
                "javascript_files": result.javascript_files,
                "javascript_count": len(result.javascript_files),
                "errors": result.errors,
                "error_count": len(result.errors),
                "console_messages": result.console_messages,
                "console_count": len(result.console_messages),
                "network_requests": len(result.network),
                "score": score_map.get(url, 0),
            }
            if artifact_rel:
                payload["dom_artifact"] = artifact_rel
            if context.results.append(payload):
                appended += 1

        logger.info(
            "Runtime crawl completed: %s/%s successful, %s JS files discovered (%s new records)",
            success_count,
            len(results),
            javascript_total,
            appended,
        )
