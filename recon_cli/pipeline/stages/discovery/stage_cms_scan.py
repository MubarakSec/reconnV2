from __future__ import annotations

import hashlib
import json
import re
import asyncio
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError, CommandExecutor
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig

try:
    from recon_cli.scanners import integrations as scanner_integrations
except ImportError:
    scanner_integrations = None


class CMSScanStage(Stage):
    name = "cms_scan"

    DRUPAL_HINTS = ("/user/login", "/user/register", "/sites/", "/core/", "/modules/", "/themes/", "/node/")
    JOOMLA_HINTS = ("/administrator", "/components/", "/templates/", "option=com_")
    MAGENTO_HINTS = ("/static/", "/media/", "/customer/account", "/checkout", "/catalogsearch", "/index.php/admin", "/magento")
    DRUPAL_MODULE_RE = re.compile(r"/modules/(?:contrib/)?([^/\\s\"']+)", re.IGNORECASE)
    DRUPAL_LEGACY_RE = re.compile(r"/sites/(?:all|default)/modules/([^/\\s\"']+)", re.IGNORECASE)
    MAGENTO_THEME_RE = re.compile(r"/static/(?:version\\d+/)?frontend/([^/\\s\"']+/[^/\\s\"']+)", re.IGNORECASE)
    MAGENTO_ADMIN_THEME_RE = re.compile(r"/static/(?:version\\d+/)?adminhtml/([^/\\s\"']+/[^/\\s\"']+)", re.IGNORECASE)

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_cms_scan", False))

    async def run_async(self, context: PipelineContext) -> None:
        host_info = self._collect_hosts(context)
        if not host_info:
            context.logger.info("No hosts eligible for CMS scan")
            return

        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "cms_max_hosts", 50))
        timeout = int(getattr(runtime, "cms_timeout", 15))

        cms_targets: Dict[str, Set[str]] = defaultdict(set)
        for host, info in host_info.items():
            tags = info.get("tags", set())
            techs = info.get("technologies", set())
            urls = info.get("urls", [])
            if "cms:drupal" in tags or any("drupal" in str(t) for t in techs): cms_targets[host].add("drupal")
            if "cms:joomla" in tags or any("joomla" in str(t) for t in techs): cms_targets[host].add("joomla")
            if "cms:magento" in tags or any("magento" in str(t) for t in techs): cms_targets[host].add("magento")
            if not cms_targets[host]:
                for url in urls:
                    lower_url = str(url).lower()
                    if any(hint in lower_url for hint in self.DRUPAL_HINTS): cms_targets[host].add("drupal")
                    if any(hint in lower_url for hint in self.JOOMLA_HINTS): cms_targets[host].add("joomla")
                    if any(hint in lower_url for hint in self.MAGENTO_HINTS): cms_targets[host].add("magento")

        if not cms_targets:
            context.logger.info("No CMS detections for drupal/joomla/magento")
            return

        cms_dir = context.record.paths.ensure_subdir("cms")
        stats = context.record.metadata.stats.setdefault("cms_scan", {})
        scanned, findings = 0, 0
        tool_stats, cms_stats, module_stats = defaultdict(int), defaultdict(int), defaultdict(int)
        artifacts = []
        module_cache = {}

        config = HTTPClientConfig(max_concurrent=10, total_timeout=float(timeout), verify_ssl=bool(getattr(runtime, "verify_tls", True)))

        async with AsyncHTTPClient(config, context=context) as client:
            for host in list(cms_targets.keys())[:max_hosts]:
                info = host_info.get(host, {})
                urls = info.get("urls", [])
                base_url = str(urls[0]) if urls else f"https://{host}"
                if not context.url_allowed(base_url): continue

                for cms in sorted(cms_targets[host]):
                    # External tools still run via executor (sync/subprocess)
                    scan_result = await self._run_scan(context, cms, host, base_url, timeout, cms_dir)
                    if not scan_result: continue
                    
                    scanned += 1
                    tool_used = scan_result["tool"]
                    scan_output = str(scan_result.get("output", ""))
                    tool_stats[tool_used] += 1
                    cms_stats[cms] += 1
                    
                    signal_id = context.emit_signal(f"cms_{cms}", "host", host, confidence=0.6, source=self.name, tags=[f"cms:{cms}"], evidence={"url": base_url, "tool": tool_used})
                    
                    cms_payload = {"type": "cms", "source": "cms-scan", "hostname": host, "url": base_url, "cms": cms, "tool": tool_used, "tags": ["cms", f"cms:{cms}"], "score": 35, "evidence_id": signal_id or None}
                    if context.results.append(cms_payload): artifacts.append(cms_payload)

                    # ID modules asynchronously
                    modules = await self._discover_modules(context, client, cms, host, base_url, timeout, module_cache)
                    if modules:
                        module_stats[cms] += len(modules)
                        for module in modules:
                            context.results.append({"type": "cms_module", "source": "cms-scan", "hostname": host, "url": base_url, "cms": cms, "module": module, "tags": ["cms", f"cms:{cms}", "module"], "score": 20})

        stats.update({"scanned": scanned, "findings": findings, "by_tool": dict(tool_stats), "by_cms": dict(cms_stats), "modules": dict(module_stats)})
        context.manager.update_metadata(context.record)

    async def _discover_modules(self, context: PipelineContext, client: AsyncHTTPClient, cms: str, host: str, base_url: str, timeout: int, cache: Dict[str, Tuple[str, str]]) -> List[str]:
        if cms not in {"drupal", "magento"}: return []
        cache_key = f"{host}:{cms}"
        if cache_key in cache:
            html, final_url = cache[cache_key]
        else:
            headers = context.auth_headers({"User-Agent": "recon-cli cms-modules"})
            try:
                resp = await client.get(base_url, headers=headers, follow_redirects=True)
                if resp.status >= 400: return []
                html = resp.body
                final_url = base_url
                cache[cache_key] = (html, final_url)
            except Exception: return []

        modules: Set[str] = set()
        if cms == "drupal":
            modules.update(self.DRUPAL_MODULE_RE.findall(html))
            modules.update(self.DRUPAL_LEGACY_RE.findall(html))
        elif cms == "magento":
            modules.update(self.MAGENTO_THEME_RE.findall(html))
            modules.update(self.MAGENTO_ADMIN_THEME_RE.findall(html))

        max_modules = int(getattr(context.runtime_config, "cms_module_max", 60))
        return [m.strip().strip("/") for m in sorted(modules) if m.strip()][:max_modules]

    @staticmethod
    def _collect_hosts(context: PipelineContext) -> Dict[str, Dict[str, object]]:
        host_info = {}
        for entry in context.filter_results("url"):
            url_value = entry.get("url")
            host = entry.get("hostname") or (url_value and urlparse(str(url_value)).hostname)
            if not host: continue
            info = host_info.setdefault(host, {"urls": [], "tags": set(), "technologies": set()})
            if url_value: info["urls"].append(url_value)
            for tag in entry.get("tags", []): info["tags"].add(tag)
            techs = entry.get("technologies") or []
            if isinstance(techs, list): info["technologies"].update({str(t).lower() for t in techs if t})
        return host_info

    async def _run_scan(self, context: PipelineContext, cms: str, host: str, base_url: str, timeout: int, artifact_dir) -> Dict[str, Any]:
        executor = context.executor

        # We prefer Nuclei for CMS scanning as droopescan is outdated/broken on Python 3.12+
        if CommandExecutor.available("nuclei"):
            self.logger.info("Running nuclei CMS scan for %s on %s", cms, base_url)
            try:
                # Use specific CMS tags in nuclei
                tags = [cms]
                if cms == "wordpress": tags.extend(["wp-plugin", "wp-theme"])

                completed = await executor.run_async(
                    [
                        "nuclei",
                        "-u", base_url,
                        "-tags", ",".join(tags),
                        "-severity", "info,low,medium,high,critical",
                        "-silent",
                        "-jsonl"
                    ],
                    capture_output=True,
                    check=False,
                    timeout=timeout
                )
                return {"tool": "nuclei", "output": completed.stdout.strip(), "findings": []}
            except Exception as e:
                self.logger.error("Nuclei CMS scan failed: %s", e)
                return {}

        return {"tool": "none", "error": "No suitable CMS scanner available"}

