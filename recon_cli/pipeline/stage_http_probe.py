from __future__ import annotations

import hashlib
import json
import time
import asyncio
from typing import List, Set, Dict

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.tools.executor import CommandError
from recon_cli.utils import enrich as enrich_utils
from recon_cli.utils import fs

try:
    from recon_cli.utils.rate_limiter import RateLimiter, RateLimitConfig

    RATE_LIMITER_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    RATE_LIMITER_AVAILABLE = False
    RateLimiter = None
    RateLimitConfig = None


class HttpProbeStage(Stage):
    name = "http_probe"
    requires = ["hostname"]
    provides = ["url"]

    PROBE_PATHS = [
        "/robots.txt",
        "/.well-known/security.txt",
        "/sitemap.xml",
        "/api/",
        "/login",
        "/signin",
        "/auth",
        "/account/login",
        "/user/login",
        "/register",
        "/signup",
        "/forgot",
        "/forgot-password",
        "/reset",
        "/password/reset",
        "/admin",
    ]
    HEADER_TAG_KEYS = [
        "server",
        "x-powered-by",
        "server-timing",
        "location",
        "access-control-allow-origin",
        "www-authenticate",
    ]

    def execute(self, context: PipelineContext) -> None:
        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts to probe")
            return
        with hosts_path.open("r", encoding="utf-8") as handle:
            hosts = [line.strip() for line in handle if line.strip()]
        if not hosts:
            context.logger.info("No hosts to probe")
            return
        httpx_input = context.record.paths.artifact("hosts_for_httpx.txt")
        httpx_output = context.record.paths.artifact("httpx_raw.json")
        fs.ensure_directory(httpx_input.parent)
        max_hosts = max(0, context.runtime_config.max_probe_hosts)
        httpx_host_limit = max(0, context.runtime_config.httpx_max_hosts)
        cap = max_hosts if max_hosts else len(hosts)
        if httpx_host_limit:
            cap = min(cap, httpx_host_limit)
        selected_hosts = hosts[:cap]
        if len(selected_hosts) < len(hosts):
            context.logger.info(
                "HTTP probe limiting hosts to %s of %s (max_probe_hosts/httpx_max_hosts)",
                len(selected_hosts),
                len(hosts),
            )
            stats = context.record.metadata.stats.setdefault("http_probe", {})
            stats["hosts_total"] = len(hosts)
            stats["hosts_capped"] = len(hosts) - len(selected_hosts)
            context.manager.update_metadata(context.record)
        httpx_input.write_text("\n".join(selected_hosts) + "\n", encoding="utf-8")
        hosts = selected_hosts
        if not hosts:
            context.logger.info("No hosts to probe after applying caps")
            return
        executor = context.executor
        tool_timeout = context.runtime_config.tool_timeout
        tracker = context.results
        seen_urls: Set[str] = set()
        used_httpx = False
        if executor.available("httpx"):
            cmd = [
                "httpx",
                "-l",
                str(httpx_input),
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-web-server",
                "-cdn",
                "-favicon",
                "-o",
                str(httpx_output),
                "-threads",
                str(context.runtime_config.httpx_threads),
                "-timeout",
                str(context.runtime_config.timeout_http),
                "-follow-redirects",
            ]
            try:
                executor.run(cmd, check=False, timeout=tool_timeout)
                used_httpx = True
            except CommandError:
                context.logger.warning(
                    "httpx execution failed; attempting fallback probe"
                )
        if used_httpx and httpx_output.exists():
            with httpx_output.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    status_code = payload.get("status-code") or payload.get(
                        "status_code"
                    )
                    host = payload.get("host") or payload.get("input")
                    if host and status_code:
                        context.record_host_error(str(host), int(status_code))

                    content_length = (
                        payload.get("content-length")
                        or payload.get("content_length")
                        or payload.get("content-length")
                    )
                    server = (
                        payload.get("webserver")
                        or payload.get("server")
                        or payload.get("web-server")
                    )
                    technologies = (
                        payload.get("tech") or payload.get("technologies") or []
                    )
                    title = payload.get("title")
                    cdn = payload.get("cdn")
                    entry = {
                        "type": "url",
                        "source": "httpx",
                        "url": payload.get("url"),
                        "hostname": payload.get("host") or payload.get("input"),
                        "ip": payload.get("a") or payload.get("ip"),
                        "status_code": status_code,
                        "title": title,
                        "server": server,
                        "tls": bool(payload.get("tls")),
                        "response_time_ms": payload.get("rtt"),
                        "content_length": content_length,
                        "cdn": cdn,
                        "technologies": technologies,
                    }
                    url_value = entry.get("url")
                    if url_value and not context.url_allowed(url_value):
                        continue
                    if url_value and url_value in seen_urls:
                        continue
                    tags = set(entry.get("tags", []))
                    if url_value:
                        tags.update(enrich_utils.infer_service_tags(url_value))
                    tags.update(
                        enrich_utils.infer_tech_tags(
                            technologies
                            if isinstance(technologies, list)
                            else [str(technologies)],
                            server,
                            title,
                        )
                    )
                    tags.update(enrich_utils.detect_waf_tags(server, cdn))
                    if tags:
                        entry["tags"] = sorted(tags)
                    appended = tracker.append(entry)
                    if appended and url_value:
                        seen_urls.add(url_value)
        else:
            self._fallback_probe(context, hosts, seen_urls)
        self._probe_additional_paths(context, hosts, seen_urls)
        self._probe_soft_404(context, hosts)
        context.record.metadata.stats["http_urls"] = context.results.stats.get(
            "type:url", 0
        )
        context.manager.update_metadata(context.record)

    async def _fallback_probe_async(
        self, context: PipelineContext, hosts: List[str], seen_urls: Set[str]
    ) -> None:
        try:
            from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
        except ImportError:
            return

        urls_to_check = []
        for host in hosts:
            if not host:
                continue
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}/"
                if context.url_allowed(url) and url not in seen_urls:
                    urls_to_check.append((host, url, scheme))

        if not urls_to_check:
            return

        config = HTTPClientConfig(
            max_concurrent=50,
            total_timeout=10,
            verify_ssl=context.runtime_config.verify_tls,
        )
        tracker = context.results

        async with AsyncHTTPClient(config) as client:
            tasks = []
            for _, url, _ in urls_to_check:
                headers = context.auth_headers({"User-Agent": "recon-cli"})
                cookie_header = context.auth_cookie_header()
                if cookie_header and "cookie" not in {k.lower() for k in headers}:
                    headers["Cookie"] = cookie_header

                cache_entry = context.get_cache_entry(url)
                if cache_entry and not context.force:
                    if cache_entry.get("etag"):
                        headers["If-None-Match"] = cache_entry["etag"]
                    if cache_entry.get("last_modified"):
                        headers["If-Modified-Since"] = cache_entry["last_modified"]
                tasks.append(client.get(url, headers=headers))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for (host, url, scheme), resp in zip(urls_to_check, responses):
                if isinstance(resp, Exception) or resp.status == 0:
                    continue

                if resp.status == 304 and not context.force:
                    continue

                body = resp.body[:2048] if resp.body else ""
                raw_headers = resp.headers
                headers_lower = {k.lower(): v for k, v in raw_headers.items()}
                etag = headers_lower.get("etag")
                last_modified = headers_lower.get("last-modified")
                body_md5 = hashlib.md5(body.encode("utf-8", "ignore"), usedforsecurity=False).hexdigest()

                if context.should_skip_due_to_cache(
                    url, etag=etag, last_modified=last_modified, body_md5=body_md5
                ):
                    context.update_cache(
                        url, etag=etag, last_modified=last_modified, body_md5=body_md5
                    )
                    continue

                # Check for set-cookie manually since aiohttp merges headers if not careful,
                # but we'll extract from standard headers dict for now.
                set_cookie_headers = [
                    v for k, v in raw_headers.items() if k.lower() == "set-cookie" and v
                ]
                header_values = [
                    v
                    for k, v in headers_lower.items()
                    if k in ("x-powered-by", "server") and v
                ]

                payload = {
                    "type": "url",
                    "source": "probe",
                    "url": url,
                    "hostname": host,
                    "status_code": resp.status,
                    "server": headers_lower.get("server"),
                    "tls": scheme == "https",
                    "content_type": headers_lower.get("content-type"),
                    "length": len(body),
                    "body_md5": body_md5,
                    "etag": etag,
                    "last_modified": last_modified,
                }

                tags = set(enrich_utils.infer_service_tags(url))
                if header_values:
                    tags.update(enrich_utils.infer_tech_tags(header_values))
                tags.update(enrich_utils.infer_cookie_tags(set_cookie_headers))
                tags.update(enrich_utils.detect_waf_tags(payload.get("server")))
                if tags:
                    payload["tags"] = sorted(tags)

                context.update_cache(
                    url, etag=etag, last_modified=last_modified, body_md5=body_md5
                )
                appended = tracker.append(payload)
                if appended:
                    seen_urls.add(url)

    def _fallback_probe(
        self, context: PipelineContext, hosts: List[str], seen_urls: Set[str]
    ) -> None:
        asyncio.run(self._fallback_probe_async(context, hosts, seen_urls))

    async def _probe_additional_paths_async(
        self, context: PipelineContext, hosts: List[str], seen_urls: Set[str]
    ) -> None:
        if not hosts:
            return
        runtime = context.runtime_config
        host_limit = runtime.max_global_concurrency or len(hosts)
        hosts_to_probe = hosts[:host_limit]

        try:
            from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
        except ImportError:
            return

        urls_to_check = []
        for host in hosts_to_probe:
            for path in self.PROBE_PATHS:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}{path}"
                    if context.url_allowed(url) and url not in seen_urls:
                        urls_to_check.append((host, url, scheme, path))

        if not urls_to_check:
            return

        config = HTTPClientConfig(
            max_concurrent=50,
            total_timeout=10,
            verify_ssl=context.runtime_config.verify_tls,
        )
        tracker = context.results
        total_added = 0

        async with AsyncHTTPClient(config) as client:
            tasks = []
            for _, url, _, _ in urls_to_check:
                headers = context.auth_headers({"User-Agent": "recon-cli probe++"})
                cookie_header = context.auth_cookie_header()
                if cookie_header and "cookie" not in {k.lower() for k in headers}:
                    headers["Cookie"] = cookie_header

                cache_entry = context.get_cache_entry(url)
                if cache_entry and not context.force:
                    if cache_entry.get("etag"):
                        headers["If-None-Match"] = cache_entry["etag"]
                    if cache_entry.get("last_modified"):
                        headers["If-Modified-Since"] = cache_entry["last_modified"]
                tasks.append(client.get(url, headers=headers))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for (host, url, scheme, path), resp in zip(urls_to_check, responses):
                if isinstance(resp, Exception) or resp.status == 0:
                    continue

                if resp.status == 304 and not context.force:
                    continue

                body = resp.body[:2048] if resp.body else ""
                raw_headers = resp.headers
                headers_lower = {k.lower(): v for k, v in raw_headers.items()}
                etag = headers_lower.get("etag")
                last_modified = headers_lower.get("last-modified")
                body_md5 = hashlib.md5(body.encode("utf-8", "ignore"), usedforsecurity=False).hexdigest()

                if context.should_skip_due_to_cache(
                    url, etag=etag, last_modified=last_modified, body_md5=body_md5
                ):
                    context.update_cache(
                        url, etag=etag, last_modified=last_modified, body_md5=body_md5
                    )
                    continue

                set_cookie_headers = [
                    v for k, v in raw_headers.items() if k.lower() == "set-cookie" and v
                ]
                header_values = [
                    v
                    for k, v in headers_lower.items()
                    if k in ("x-powered-by", "server") and v
                ]

                base_tags = ["probe++", f"path:{path.lstrip('/') or '/'}"]
                tags = list(base_tags)
                tags.extend(enrich_utils.infer_service_tags(url))
                if header_values:
                    tags.extend(enrich_utils.infer_tech_tags(header_values))
                tags.extend(enrich_utils.infer_cookie_tags(set_cookie_headers))
                tags.extend(enrich_utils.detect_waf_tags(headers_lower.get("server")))
                for header_name in self.HEADER_TAG_KEYS:
                    value = headers_lower.get(header_name)
                    if value:
                        tags.append(f"header:{header_name}={value.strip()[:80]}")

                payload = {
                    "type": "url",
                    "source": "probe",
                    "url": url,
                    "hostname": host,
                    "status_code": resp.status,
                    "content_type": headers_lower.get("content-type"),
                    "length": len(body),
                    "body_md5": body_md5,
                    "tags": sorted(set(tags)),
                    "tls": scheme == "https",
                    "response_time_ms": int(resp.elapsed * 1000)
                    if getattr(resp, "elapsed", None)
                    else 0,
                    "etag": etag,
                    "last_modified": last_modified,
                }
                location = headers_lower.get("location")
                if location:
                    payload["redirect_location"] = location

                context.update_cache(
                    url, etag=etag, last_modified=last_modified, body_md5=body_md5
                )
                appended = tracker.append(payload)
                if appended:
                    total_added += 1
                    seen_urls.add(url)

        if total_added:
            stats = context.record.metadata.stats.setdefault("http_probe", {})
            stats["extra"] = stats.get("extra", 0) + total_added
            context.manager.update_metadata(context.record)

    def _probe_additional_paths(
        self, context: PipelineContext, hosts: List[str], seen_urls: Set[str]
    ) -> None:
        asyncio.run(self._probe_additional_paths_async(context, hosts, seen_urls))

    async def _probe_soft_404_async(
        self, context: PipelineContext, hosts: List[str]
    ) -> None:
        runtime = context.runtime_config
        if not getattr(runtime, "soft_404_probe", True):
            return
        if not hosts:
            return
        try:
            from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
        except ImportError:
            return
        max_hosts = max(0, int(getattr(runtime, "soft_404_max_hosts", 25)))
        if max_hosts == 0:
            return
        max_paths = max(1, int(getattr(runtime, "soft_404_paths", 1)))
        timeout = max(1, int(getattr(runtime, "soft_404_timeout", 6)))

        urls_to_check = []
        for host in hosts[:max_hosts]:
            for scheme in ("https", "http"):
                for _ in range(max_paths):
                    random_path = f"/recon404-{int(time.time() * 1000)}-{hashlib.md5(host.encode(), usedforsecurity=False).hexdigest()[:6]}"
                    url = f"{scheme}://{host}{random_path}"
                    if context.url_allowed(url):
                        urls_to_check.append((host, url))

        if not urls_to_check:
            return

        config = HTTPClientConfig(
            max_concurrent=20,
            total_timeout=timeout,
            verify_ssl=context.runtime_config.verify_tls,
        )
        headers = {"User-Agent": "recon-cli soft-404"}
        soft_hosts: Dict[str, dict] = {}

        async with AsyncHTTPClient(config) as client:
            tasks = [
                client.get(url, headers=headers, follow_redirects=True)
                for _, url in urls_to_check
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for (host, url), resp in zip(urls_to_check, responses):
                if isinstance(resp, Exception) or resp.status == 0:
                    continue
                if host in soft_hosts:
                    continue
                body = resp.body or ""
                body_snippet = body[:2048]
                title = ""
                if "<title" in body_snippet.lower():
                    try:
                        import re as _re

                        match = _re.search(
                            r"<title[^>]*>(.*?)</title>",
                            body_snippet,
                            _re.IGNORECASE | _re.DOTALL,
                        )
                        if match:
                            title = match.group(1).strip()
                    except Exception:
                        pass
                if enrich_utils.looks_like_soft_404(resp.status, body_snippet, title):
                    soft_hosts[host] = enrich_utils.get_soft_404_fingerprint(
                        body, title
                    )
                    soft_hosts[host]["status_code"] = resp.status

        if soft_hosts:
            stats = context.record.metadata.stats.setdefault("soft_404", {})
            stats["hosts"] = sorted(soft_hosts.keys())
            stats["fingerprints"] = soft_hosts
            stats["count"] = len(soft_hosts)
            context.manager.update_metadata(context.record)

    def _probe_soft_404(self, context: PipelineContext, hosts: List[str]) -> None:
        asyncio.run(self._probe_soft_404_async(context, hosts))
