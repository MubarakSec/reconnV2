from __future__ import annotations

import base64
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from recon_cli.crawl.runtime import (
    PLAYWRIGHT_AVAILABLE,
    CrawlResult,
    crawl_urls,
    dom_artifact_name,
    save_results as save_crawl_results,
)
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool


class RuntimeCrawlStage(Stage):
    name = "runtime_crawl"
    optional = True

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_runtime_crawl", False))

    @staticmethod
    def _dom_relpath(
        context: PipelineContext, artifact_dir: Path, url: str
    ) -> Optional[str]:
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
        items = context.get_results()
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
        per_host_limit = max(
            1, getattr(context.runtime_config, "runtime_crawl_per_host_limit", 3)
        )
        timeout = max(1, getattr(context.runtime_config, "runtime_crawl_timeout", 15))
        concurrency = max(
            1, getattr(context.runtime_config, "runtime_crawl_concurrency", 2)
        )

        available = bool(PLAYWRIGHT_AVAILABLE)
        crawl_func = crawl_urls
        try:
            from recon_cli.pipeline import stages as stages_module

            available = bool(getattr(stages_module, "PLAYWRIGHT_AVAILABLE", available))
            crawl_func = getattr(stages_module, "crawl_urls", crawl_func)
        except Exception:
            pass

        if not available:
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
            logger.info(
                "Runtime crawl stage skipped; host limits filtered all candidates"
            )
            return

        logger.info(
            "Runtime crawl targeting %s URLs (timeout=%ss, concurrency=%s)",
            len(selected_urls),
            timeout,
            concurrency,
        )

        default_domain = urlparse(selected_urls[0]).hostname if selected_urls else None
        auth_headers: Optional[Dict[str, str]] = None
        auth_cookies: Optional[List[Dict[str, object]]] = None
        if context.auth_enabled():
            context.auth_session(selected_urls[0] if selected_urls else None)
            auth_headers = context.auth_headers(
                {"User-Agent": "recon-cli runtime-crawl"}
            )
            auth_cookies = context.auth_cookies(default_domain)

        crawl_profiles: List[Dict[str, object]] = [
            {"name": "default", "headers": auth_headers, "cookies": auth_cookies}
        ]
        if bool(getattr(context.runtime_config, "runtime_crawl_role_aware", True)):
            crawl_profiles.extend(self._role_aware_profiles(context, default_domain))

        merged_results: Dict[str, CrawlResult] = {}
        per_profile_results: Dict[str, Dict[str, CrawlResult]] = {}
        role_profile_names: List[str] = []
        default_error: Optional[Exception] = None

        for profile in crawl_profiles:
            profile_name = str(profile.get("name") or "default")
            headers = profile.get("headers")
            cookies = profile.get("cookies")
            try:
                results = crawl_func(
                    selected_urls,
                    timeout,
                    concurrency,
                    headers=headers if isinstance(headers, dict) else None,
                    cookies=cookies if isinstance(cookies, list) else None,
                )
            except Exception as exc:
                if profile_name == "default":
                    default_error = exc
                    break
                logger.warning("Runtime crawl profile %s failed: %s", profile_name, exc)
                continue
            if not results:
                continue
            per_profile_results[profile_name] = results
            if profile_name != "default":
                role_profile_names.append(profile_name)
            for url, result in results.items():
                merged_results[url] = self._merge_result(
                    merged_results.get(url), result
                )

        if default_error is not None:
            message = str(default_error)
            missing_browsers = (
                "playwright install" in message.lower()
                or "executable doesn't exist" in message.lower()
            )
            stats.update(
                {
                    "selected": len(selected_urls),
                    "crawled": 0,
                    "success": 0,
                    "failures": len(selected_urls),
                    "javascript_files": 0,
                    "status": "playwright_browsers_missing"
                    if missing_browsers
                    else "crawl_error",
                    "error": message,
                }
            )
            context.manager.update_metadata(context.record)
            if missing_browsers:
                logger.warning(
                    "Playwright browsers not installed; skipping runtime crawl stage"
                )
                note_missing_tool(context, "playwright-browsers")
            else:
                logger.warning("Runtime crawl failed; skipping stage: %s", message)
            return

        if not merged_results:
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
        save_crawl_results(merged_results, artifact_dir)
        for profile_name, results in per_profile_results.items():
            if profile_name == "default":
                continue
            profile_dir = (
                artifact_dir / f"profile_{self._safe_profile_name(profile_name)}"
            )
            save_crawl_results(results, profile_dir)

        success_count = sum(1 for result in merged_results.values() if result.success)
        failure_count = len(merged_results) - success_count
        javascript_total = sum(
            len(result.javascript_files) for result in merged_results.values()
        )

        stats.update(
            {
                "selected": len(selected_urls),
                "crawled": len(merged_results),
                "success": success_count,
                "failures": failure_count,
                "javascript_files": javascript_total,
                "profiles": len(per_profile_results),
                "role_profiles": role_profile_names,
                "status": "completed",
            }
        )
        context.manager.update_metadata(context.record)

        appended = 0
        for url, result in merged_results.items():
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
            if role_profile_names:
                payload["auth_profiles"] = ["default", *role_profile_names]
            if artifact_rel:
                payload["dom_artifact"] = artifact_rel
            if context.results.append(payload):
                appended += 1
            for profile_name, profile_results in per_profile_results.items():
                if profile_name == "default":
                    continue
                profile_result = profile_results.get(url)
                if not profile_result:
                    continue
                context.results.append(
                    {
                        "type": "runtime_crawl_profile",
                        "source": "playwright",
                        "url": url,
                        "hostname": payload["hostname"],
                        "auth_profile": profile_name,
                        "success": profile_result.success,
                        "javascript_count": len(profile_result.javascript_files),
                        "error_count": len(profile_result.errors),
                        "score": score_map.get(url, 0),
                    }
                )

        logger.info(
            "Runtime crawl completed: %s/%s successful, %s JS files discovered (%s new records)",
            success_count,
            len(merged_results),
            javascript_total,
            appended,
        )

    def _role_aware_profiles(
        self, context: PipelineContext, default_domain: Optional[str]
    ) -> List[Dict[str, object]]:
        try:
            from recon_cli.utils.auth import build_profiles
        except Exception:
            return []
        profiles = build_profiles(context.runtime_config)
        if len(profiles) <= 1:
            return []
        max_profiles = max(
            1,
            int(getattr(context.runtime_config, "runtime_crawl_max_auth_profiles", 3)),
        )
        result: List[Dict[str, object]] = []
        for profile in profiles[:max_profiles]:
            name = str(getattr(profile, "name", "") or "")
            if not name or name == "default":
                continue
            headers = {"User-Agent": "recon-cli runtime-crawl"}
            headers.update(dict(getattr(profile, "headers", {}) or {}))
            bearer = str(getattr(profile, "bearer", "") or "")
            basic_user = str(getattr(profile, "basic_user", "") or "")
            basic_pass = str(getattr(profile, "basic_pass", "") or "")
            if bearer and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {bearer}"
            elif basic_user and basic_pass and "Authorization" not in headers:
                token = f"{basic_user}:{basic_pass}".encode("utf-8")
                headers["Authorization"] = (
                    f"Basic {base64.b64encode(token).decode('ascii')}"
                )
            cookies = self._cookies_from_profile(
                dict(getattr(profile, "cookies", {}) or {}), default_domain
            )
            result.append({"name": name, "headers": headers, "cookies": cookies})
        return result

    def _cookies_from_profile(
        self,
        cookies: Dict[str, str],
        default_domain: Optional[str],
    ) -> List[Dict[str, object]]:
        if not cookies or not default_domain:
            return []
        return [
            {
                "name": str(name),
                "value": str(value),
                "domain": default_domain,
                "path": "/",
            }
            for name, value in cookies.items()
        ]

    def _merge_result(
        self, existing: Optional[CrawlResult], new: CrawlResult
    ) -> CrawlResult:
        if existing is None:
            return new
        merged_network = existing.network + [
            entry for entry in new.network if entry not in existing.network
        ]
        merged_js = sorted(
            set(existing.javascript_files).union(set(new.javascript_files))
        )
        merged_errors = list(dict.fromkeys(existing.errors + new.errors))
        merged_console = list(
            dict.fromkeys(existing.console_messages + new.console_messages)
        )
        return CrawlResult(
            url=new.url,
            success=bool(existing.success or new.success),
            network=merged_network[:500],
            javascript_files=merged_js,
            errors=merged_errors[:120],
            console_messages=merged_console[:160],
            dom_snapshot=existing.dom_snapshot or new.dom_snapshot,
        )

    def _safe_profile_name(self, name: str) -> str:
        lowered = (name or "").lower().strip().replace(" ", "_")
        cleaned = "".join(ch for ch in lowered if ch.isalnum() or ch in {"_", "-"})
        return cleaned.strip("_-") or "profile"
