from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import List, Set

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
                context.logger.warning("httpx execution failed; attempting fallback probe")
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
                    status_code = payload.get("status-code") or payload.get("status_code")
                    content_length = (
                        payload.get("content-length")
                        or payload.get("content_length")
                        or payload.get("content-length")
                    )
                    server = payload.get("webserver") or payload.get("server") or payload.get("web-server")
                    technologies = payload.get("tech") or payload.get("technologies") or []
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
                            technologies if isinstance(technologies, list) else [str(technologies)],
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
            self._fallback_probe(context, hosts_path, seen_urls)
        self._probe_additional_paths(context, hosts, seen_urls)
        self._probe_soft_404(context, hosts)
        context.record.metadata.stats["http_urls"] = context.results.stats.get("type:url", 0)
        context.manager.update_metadata(context.record)

    def _fallback_probe(self, context: PipelineContext, hosts_path: Path, seen_urls: Set[str]) -> None:
        import http.client
        import ssl

        # Initialize rate limiter if available
        rate_limiter = None
        if RATE_LIMITER_AVAILABLE and RateLimiter:
            rate_limiter = RateLimiter(
                RateLimitConfig(
                    requests_per_second=context.runtime_config.requests_per_second
                    if hasattr(context.runtime_config, "requests_per_second")
                    else 10,
                    per_host_limit=context.runtime_config.per_host_limit
                    if hasattr(context.runtime_config, "per_host_limit")
                    else 5,
                )
            )

        tracker = context.results
        with hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if not host:
                    continue
                for scheme, port in (("http", 80), ("https", 443)):
                    url = f"{scheme}://{host}/"
                    if not context.url_allowed(url):
                        continue
                    if url in seen_urls:
                        continue

                    # Apply rate limiting
                    if rate_limiter:
                        rate_limiter.wait_for_slot(url)

                    conn = None
                    try:
                        if scheme == "https":
                            ssl_ctx = ssl.create_default_context()
                            conn = http.client.HTTPSConnection(host, port=port, timeout=5, context=ssl_ctx)
                        else:
                            conn = http.client.HTTPConnection(host, port=port, timeout=5)
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
                        conn.request("GET", "/", headers=headers)
                        resp = conn.getresponse()

                        # Report response to rate limiter
                        if rate_limiter:
                            rate_limiter.on_response(url, resp.status)

                        if resp.status == 304 and not context.force:
                            break
                        body = resp.read(2048) or b""
                        raw_headers = resp.getheaders()
                        headers_lower = {k.lower(): v for k, v in raw_headers}
                        etag = headers_lower.get("etag")
                        last_modified = headers_lower.get("last-modified")
                        body_md5 = hashlib.md5(body).hexdigest()
                        if context.should_skip_due_to_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5):
                            context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                            break
                        set_cookie_headers = [
                            value for key, value in raw_headers if key.lower() == "set-cookie" and value
                        ]
                        header_values = [
                            value for value in (headers_lower.get("x-powered-by"), headers_lower.get("server")) if value
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
                        context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                        appended = tracker.append(payload)
                        if appended:
                            seen_urls.add(url)
                    except Exception:
                        continue
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass

    def _probe_additional_paths(self, context: PipelineContext, hosts: List[str], seen_urls: Set[str]) -> None:
        if not hosts:
            return
        runtime = context.runtime_config
        host_limit = runtime.max_global_concurrency or len(hosts)
        total_added = 0
        for idx, host in enumerate(hosts):
            if idx >= host_limit:
                break
            total_added += self._probe_host_paths(context, host, seen_urls)
        if total_added:
            stats = context.record.metadata.stats.setdefault("http_probe", {})
            stats["extra"] = stats.get("extra", 0) + total_added
            context.manager.update_metadata(context.record)

    def _probe_soft_404(self, context: PipelineContext, hosts: List[str]) -> None:
        runtime = context.runtime_config
        if not getattr(runtime, "soft_404_probe", True):
            return
        if not hosts:
            return
        try:
            import requests
        except Exception:
            return
        max_hosts = max(0, int(getattr(runtime, "soft_404_max_hosts", 25)))
        if max_hosts == 0:
            return
        max_paths = max(1, int(getattr(runtime, "soft_404_paths", 1)))
        timeout = max(1, int(getattr(runtime, "soft_404_timeout", 6)))
        soft_hosts: set[str] = set()
        for host in hosts[:max_hosts]:
            for scheme in ("https", "http"):
                if host in soft_hosts:
                    break
                for _ in range(max_paths):
                    random_path = f"/recon404-{int(time.time() * 1000)}-{hashlib.md5(host.encode()).hexdigest()[:6]}"
                    url = f"{scheme}://{host}{random_path}"
                    if not context.url_allowed(url):
                        continue
                    try:
                        resp = requests.get(
                            url,
                            timeout=timeout,
                            allow_redirects=True,
                            verify=context.runtime_config.verify_tls,
                            headers={"User-Agent": "recon-cli soft-404"},
                        )
                    except Exception:
                        continue
                    body_snippet = (resp.text or "")[:2048]
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
                            title = ""
                    if enrich_utils.looks_like_soft_404(resp.status_code, body_snippet, title):
                        soft_hosts.add(host)
                        break
        if soft_hosts:
            stats = context.record.metadata.stats.setdefault("soft_404", {})
            stats["hosts"] = sorted(soft_hosts)
            stats["count"] = len(soft_hosts)
            context.manager.update_metadata(context.record)

    def _probe_host_paths(self, context: PipelineContext, host: str, seen_urls: Set[str]) -> int:
        import http.client
        import ssl

        added = 0
        paths = self.PROBE_PATHS
        for path in paths:
            base_tags = ["probe++", f"path:{path.lstrip('/') or '/'}"]
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}{path}"
                if not context.url_allowed(url):
                    continue
                if url in seen_urls:
                    continue
                conn = None
                try:
                    start = time.perf_counter()
                    if scheme == "https":
                        conn = http.client.HTTPSConnection(host, timeout=5, context=ssl.create_default_context())
                    else:
                        conn = http.client.HTTPConnection(host, timeout=5)
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
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    if resp.status == 304 and not context.force:
                        break
                    body = resp.read(2048) or b""
                    duration_ms = int((time.perf_counter() - start) * 1000)
                    raw_headers = resp.getheaders()
                    headers_lower = {k.lower(): v for k, v in raw_headers}
                    etag = headers_lower.get("etag")
                    last_modified = headers_lower.get("last-modified")
                    body_md5 = hashlib.md5(body).hexdigest()
                    if context.should_skip_due_to_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5):
                        context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                        continue
                    set_cookie_headers = [
                        value for key, value in raw_headers if key.lower() == "set-cookie" and value
                    ]
                    header_values = [
                        value for value in (headers_lower.get("x-powered-by"), headers_lower.get("server")) if value
                    ]
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
                    content_type = headers_lower.get("content-type")
                    payload = {
                        "type": "url",
                        "source": "probe",
                        "url": url,
                        "hostname": host,
                        "status_code": resp.status,
                        "content_type": content_type,
                        "length": len(body),
                        "body_md5": body_md5,
                        "tags": sorted(set(tags)),
                        "tls": scheme == "https",
                        "response_time_ms": duration_ms,
                        "etag": etag,
                        "last_modified": last_modified,
                    }
                    location = headers_lower.get("location")
                    if location:
                        payload["redirect_location"] = location
                    context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                    appended = context.results.append(payload)
                    if appended:
                        added += 1
                        seen_urls.add(url)
                    break
                except Exception:
                    continue
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
        return added
