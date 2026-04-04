from __future__ import annotations

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
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool


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

    async def run_async(self, context: PipelineContext) -> None:
        logger = context.logger
        items = context.get_results()
        if not items:
            logger.info("No results recorded; skipping runtime crawl stage")
            context.update_stats(self.name, 
                selected=0, crawled=0, success=0, failures=0, 
                javascript_files=0, status="no_input"
            )
            return

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
        if not available:
            context.update_stats(self.name,
                selected=0, crawled=0, success=0, failures=0,
                javascript_files=0, status="playwright_missing"
            )
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
            context.update_stats(self.name,
                selected=0, crawled=0, success=0, failures=0,
                javascript_files=0, status="no_candidates"
            )
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
            context.update_stats(self.name,
                selected=0, crawled=0, success=0, failures=0,
                javascript_files=0, status="host_limit_exhausted"
            )
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
        
        # Identity-aware crawling (Phase 1)
        crawl_profiles: List[Dict[str, object]] = []
        
        # 1. Anonymous / Default
        crawl_profiles.append({"name": "anonymous", "headers": {"User-Agent": "recon-cli runtime-crawl"}, "cookies": []})
        configured_profile_limit = max(
            0, int(getattr(context.runtime_config, "runtime_crawl_max_auth_profiles", 3))
        )
        configured_profiles_added = 0
        profile_names: set[str] = {"anonymous"}
        
        # 2. Authenticated identities from UnifiedAuthManager
        if bool(getattr(context.runtime_config, "runtime_crawl_role_aware", True)):
            for identity in context._auth_manager.get_all_identities():
                if configured_profiles_added >= configured_profile_limit:
                    break
                material = identity.auth_material
                profile_name = str(identity.identity_id or "").strip()
                if not profile_name or profile_name in profile_names:
                    continue
                headers = {"User-Agent": "recon-cli runtime-crawl"}
                if "headers" in material and isinstance(material["headers"], dict):
                    headers.update(material["headers"])
                if "bearer" in material:
                    headers["Authorization"] = f"Bearer {material['bearer']}"
                if "token" in material:
                    headers["Authorization"] = f"Bearer {material['token']}"
                
                cookies = []
                if "cookies" in material and isinstance(material["cookies"], dict):
                    cookies = [
                        {"name": k, "value": v, "domain": default_domain or "", "path": "/"}
                        for k, v in material["cookies"].items()
                    ]
                
                crawl_profiles.append({
                    "name": profile_name,
                    "headers": headers,
                    "cookies": cookies
                })
                profile_names.add(profile_name)
                configured_profiles_added += 1

            runtime_profiles = getattr(context.runtime_config, "auth_profiles", [])
            if isinstance(runtime_profiles, list):
                for profile in runtime_profiles:
                    if configured_profiles_added >= configured_profile_limit:
                        break
                    if not isinstance(profile, dict):
                        continue
                    profile_name = str(profile.get("name") or "").strip()
                    if not profile_name or profile_name in profile_names:
                        continue
                    headers = {"User-Agent": "recon-cli runtime-crawl"}
                    profile_headers = profile.get("headers")
                    if isinstance(profile_headers, dict):
                        headers.update(
                            {
                                str(key): str(value)
                                for key, value in profile_headers.items()
                            }
                        )
                    profile_cookies = profile.get("cookies")
                    profile_cookie_list: List[Dict[str, str]] = []
                    if isinstance(profile_cookies, dict):
                        profile_cookie_list = [
                            {
                                "name": str(key),
                                "value": str(value),
                                "domain": default_domain or "",
                                "path": "/",
                            }
                            for key, value in profile_cookies.items()
                        ]
                    elif isinstance(profile_cookies, list):
                        profile_cookie_list = [
                            cookie for cookie in profile_cookies if isinstance(cookie, dict)
                        ]
                    crawl_profiles.append(
                        {
                            "name": profile_name,
                            "headers": headers,
                            "cookies": profile_cookie_list,
                        }
                    )
                    profile_names.add(profile_name)
                    configured_profiles_added += 1

        merged_results: Dict[str, CrawlResult] = {}
        per_profile_results: Dict[str, Dict[str, CrawlResult]] = {}
        role_profile_names: List[str] = []
        default_error: Optional[Exception] = None

        for profile in crawl_profiles:
            profile_name = str(profile.get("name") or "anonymous")
            profile_headers = profile.get("headers")
            profile_cookies = profile.get("cookies")
            try:
                # If crawl_func is sync, we'd use to_thread, but it's likely async-ready 
                # in the crawl/runtime.py
                import asyncio
                if asyncio.iscoroutinefunction(crawl_func):
                    results = await crawl_func(
                        selected_urls, timeout, concurrency,
                        headers=profile_headers if isinstance(profile_headers, dict) else None,
                        cookies=profile_cookies if isinstance(profile_cookies, list) else None,
                    )
                else:
                    results = await asyncio.to_thread(crawl_func,
                        selected_urls, timeout, concurrency,
                        headers=profile_headers if isinstance(profile_headers, dict) else None,
                        cookies=profile_cookies if isinstance(profile_cookies, list) else None,
                    )
            except Exception as exc:
                if profile_name == "anonymous":
                    default_error = exc
                    break
                logger.warning("Runtime crawl profile %s failed: %s", profile_name, exc)
                continue
            if not results:
                continue
            per_profile_results[profile_name] = results
            if profile_name != "anonymous":
                role_profile_names.append(profile_name)
            for url, result in results.items():
                merged_results[url] = self._merge_result(
                    merged_results.get(url), result
                )

        if default_error is not None:
            message = str(default_error)
            missing_browsers = "playwright install" in message.lower()
            status = "playwright_browsers_missing" if missing_browsers else "crawl_error"
            context.update_stats(self.name,
                selected=len(selected_urls), crawled=0, success=0, 
                failures=len(selected_urls), javascript_files=0, 
                status=status, error=message
            )
            if missing_browsers: note_missing_tool(context, "playwright-browsers")
            return

        if not merged_results:
            context.update_stats(self.name,
                selected=len(selected_urls), crawled=0, success=0,
                failures=len(selected_urls), javascript_files=0, status="crawl_failed"
            )
            return

        artifact_dir = context.record.paths.ensure_subdir("runtime_crawl")
        save_crawl_results(merged_results, artifact_dir)
        
        # Save per-profile results
        for p_name, p_res in per_profile_results.items():
            p_dir = artifact_dir / f"profile_{self._safe_profile_name(p_name)}"
            save_crawl_results(p_res, p_dir)

        success_count = sum(1 for result in merged_results.values() if result.success)
        javascript_total = sum(len(result.javascript_files) for result in merged_results.values())
        role_profiles = sorted(
            {name for name in role_profile_names if name and name != "anonymous"}
        )

        context.update_stats(self.name,
            selected=len(selected_urls), crawled=len(merged_results),
            success=success_count, failures=len(merged_results) - success_count,
            javascript_files=javascript_total, profiles=len(per_profile_results),
            role_profiles=role_profiles,
            status="completed"
        )

        appended = 0
        for url, result in merged_results.items():
            if not context.url_allowed(url): continue
            artifact_rel = self._dom_relpath(context, artifact_dir, url)
            payload = {
                "type": "runtime_crawl", "source": "playwright", "url": url,
                "hostname": urlparse(url).hostname or "",
                "success": result.success, "javascript_files": result.javascript_files,
                "javascript_count": len(result.javascript_files),
                "errors": result.errors, "error_count": len(result.errors),
                "score": score_map.get(url, 0),
            }
            if role_profile_names: payload["auth_profiles"] = ["anonymous", *role_profile_names]
            if artifact_rel: payload["dom_artifact"] = artifact_rel
            if context.results.append(payload): appended += 1
            
            for p_name, p_results in per_profile_results.items():
                if p_name == "anonymous": continue
                p_result = p_results.get(url)
                if not p_result: continue
                context.results.append({
                    "type": "runtime_crawl_profile", "source": "playwright",
                    "url": url, "hostname": payload["hostname"], "auth_profile": p_name,
                    "success": p_result.success, "score": score_map.get(url, 0),
                })

        logger.info(
            "Runtime crawl completed: %s/%s successful, %s JS files discovered",
            success_count, len(merged_results), javascript_total
        )

    def execute(self, context: PipelineContext) -> None:
        # Backward compatibility for old runner
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(self.run_async(context), loop).result()
        except RuntimeError:
            asyncio.run(self.run_async(context))

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
