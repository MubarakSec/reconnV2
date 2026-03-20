from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError, CommandExecutor

try:
    from recon_cli.scanners import integrations as scanner_integrations
except ImportError:  # pragma: no cover - optional dependency
    scanner_integrations = None  # type: ignore


class CMSScanStage(Stage):
    name = "cms_scan"

    DRUPAL_HINTS = (
        "/user/login",
        "/user/register",
        "/sites/",
        "/core/",
        "/modules/",
        "/themes/",
        "/node/",
    )
    JOOMLA_HINTS = (
        "/administrator",
        "/components/",
        "/templates/",
        "option=com_",
    )
    MAGENTO_HINTS = (
        "/static/",
        "/media/",
        "/customer/account",
        "/checkout",
        "/catalogsearch",
        "/index.php/admin",
        "/magento",
    )
    DRUPAL_MODULE_RE = re.compile(r"/modules/(?:contrib/)?([^/\\s\"']+)", re.IGNORECASE)
    DRUPAL_LEGACY_RE = re.compile(
        r"/sites/(?:all|default)/modules/([^/\\s\"']+)", re.IGNORECASE
    )
    MAGENTO_THEME_RE = re.compile(
        r"/static/(?:version\\d+/)?frontend/([^/\\s\"']+/[^/\\s\"']+)", re.IGNORECASE
    )
    MAGENTO_ADMIN_THEME_RE = re.compile(
        r"/static/(?:version\\d+/)?adminhtml/([^/\\s\"']+/[^/\\s\"']+)", re.IGNORECASE
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_cms_scan", False))

    def execute(self, context: PipelineContext) -> None:
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return

        host_info = self._collect_hosts(context)
        if not host_info:
            context.logger.info("No hosts eligible for CMS scan")
            return

        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "cms_max_hosts", 50))
        timeout = int(getattr(runtime, "cms_timeout", runtime.scanner_timeout))
        limiter = context.get_rate_limiter(
            "cms_scan",
            rps=float(getattr(runtime, "cms_rps", 0)),
            per_host=float(getattr(runtime, "cms_per_host_rps", 0)),
        )

        cms_targets: Dict[str, Set[str]] = defaultdict(set)
        for host, info in host_info.items():
            tags = info.get("tags", set())
            techs = info.get("technologies", set())
            urls = info.get("urls", [])
            if "cms:drupal" in tags or any("drupal" in t for t in techs):
                cms_targets[host].add("drupal")
            if "cms:joomla" in tags or any("joomla" in t for t in techs):
                cms_targets[host].add("joomla")
            if "cms:magento" in tags or any("magento" in t for t in techs):
                cms_targets[host].add("magento")
            if not cms_targets[host]:
                for url in urls:
                    lower_url = url.lower()
                    if any(hint in lower_url for hint in self.DRUPAL_HINTS):
                        cms_targets[host].add("drupal")
                    if any(hint in lower_url for hint in self.JOOMLA_HINTS):
                        cms_targets[host].add("joomla")
                    if any(hint in lower_url for hint in self.MAGENTO_HINTS):
                        cms_targets[host].add("magento")
            if not cms_targets:
                context.logger.info("No CMS detections for drupal/joomla/magento")
                return

        cms_dir = context.record.paths.ensure_subdir("cms")
        stats = context.record.metadata.stats.setdefault("cms_scan", {})
        scanned = 0
        findings = 0
        tool_stats: Dict[str, int] = defaultdict(int)
        cms_stats: Dict[str, int] = defaultdict(int)
        module_stats: Dict[str, int] = defaultdict(int)
        artifacts: List[Dict[str, object]] = []
        module_cache: Dict[str, Tuple[str, str]] = {}

        for host in list(cms_targets.keys())[:max_hosts]:
            info = host_info.get(host, {})
            urls = info.get("urls", [])
            base_url = urls[0] if urls else f"https://{host}"
            if not context.url_allowed(base_url):
                continue
            for cms in sorted(cms_targets[host]):
                if limiter and not limiter.wait_for_slot(base_url, timeout=timeout):
                    continue
                scan_result = self._run_scan(
                    context, cms, host, base_url, timeout, cms_dir
                )
                if not scan_result:
                    continue
                tool_used = scan_result["tool"]
                scan_output = scan_result.get("output", "")
                artifact_path = scan_result.get("artifact_path")
                finding_payloads = scan_result.get("findings", [])
                scanned += 1
                tool_stats[tool_used] += 1
                cms_stats[cms] += 1
                signal_id = context.emit_signal(
                    f"cms_{cms}",
                    "host",
                    host,
                    confidence=0.6,
                    source="cms-scan",
                    tags=[f"cms:{cms}"],
                    evidence={"url": base_url, "tool": tool_used},
                )

                safe_host = host.replace(":", "_")
                hash_id = hashlib.md5(base_url.encode()).hexdigest()[:8]
                if artifact_path is None:
                    artifact_path = cms_dir / f"{cms}_{safe_host}_{hash_id}.txt"
                    artifact_path.write_text(scan_output, encoding="utf-8")
                artifact_rel = (
                    str(artifact_path.relative_to(context.record.paths.root))
                    if artifact_path
                    else ""
                )

                cms_payload = {
                    "type": "cms",
                    "source": "cms-scan",
                    "hostname": host,
                    "url": base_url,
                    "cms": cms,
                    "tool": tool_used,
                    "artifact": artifact_rel,
                    "tags": ["cms", f"cms:{cms}"],
                    "score": 35,
                    "evidence_id": signal_id or None,
                }
                if context.results.append(cms_payload):
                    artifacts.append(cms_payload)

                cves = set(
                    re.findall(r"CVE-\\d{4}-\\d{4,7}", scan_output, re.IGNORECASE)
                )
                for finding in finding_payloads:
                    if not isinstance(finding, dict):
                        continue
                    description = str(finding.get("description") or "")
                    details = (
                        finding.get("details")
                        if isinstance(finding.get("details"), dict)
                        else {}
                    )
                    template_id = str(details.get("template_id") or "")
                    matched = re.findall(
                        r"CVE-\\d{4}-\\d{4,7}",
                        f"{description} {template_id}",
                        re.IGNORECASE,
                    )
                    cves.update(matched)
                cves = sorted(cves)
                vuln_hit = (
                    bool(finding_payloads)
                    or bool(cves)
                    or re.search(r"vulnerab|exploit", scan_output, re.IGNORECASE)
                )
                if finding_payloads:
                    for finding in finding_payloads:
                        if isinstance(finding, dict):
                            context.results.append(finding)
                            findings += 1
                if vuln_hit and not finding_payloads:
                    severity = "high" if cves else "medium"
                    priority = "high" if cves else "medium"
                    score = 75 if cves else 55
                    finding_payload = {
                        "type": "finding",
                        "finding_type": "cms",
                        "source": f"cms-{tool_used}",
                        "hostname": host,
                        "url": base_url,
                        "description": f"Potential {cms} exposure detected",
                        "details": {
                            "cves": cves,
                            "output_snippet": scan_output[:1200],
                            "tool": tool_used,
                        },
                        "tags": ["cms", f"cms:{cms}", "scanner"],
                        "score": score,
                        "priority": priority,
                        "severity": severity,
                        "evidence_id": signal_id or None,
                    }
                    if context.results.append(finding_payload):
                        findings += 1

                modules = self._discover_modules(
                    context,
                    cms,
                    host,
                    base_url,
                    timeout,
                    limiter,
                    module_cache,
                )
                if modules:
                    module_stats[cms] += len(modules)
                    signal_id = context.emit_signal(
                        "cms_module_discovered",
                        "host",
                        host,
                        confidence=0.4,
                        source="cms-scan",
                        tags=[f"cms:{cms}", "module"],
                        evidence={"modules": modules[:10]},
                    )
                    for module in modules:
                        module_payload = {
                            "type": "cms_module",
                            "source": "cms-scan",
                            "hostname": host,
                            "url": base_url,
                            "cms": cms,
                            "module": module,
                            "tags": ["cms", f"cms:{cms}", "module"],
                            "score": 20,
                            "evidence_id": signal_id or None,
                        }
                        context.results.append(module_payload)

        if artifacts:
            manifest_path = cms_dir / "cms_manifest.json"
            manifest_path.write_text(
                json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8"
            )
            stats["manifest"] = str(
                manifest_path.relative_to(context.record.paths.root)
            )

        stats["scanned"] = scanned
        stats["findings"] = findings
        stats["by_tool"] = dict(tool_stats)
        stats["by_cms"] = dict(cms_stats)
        stats["modules"] = dict(module_stats)
        context.manager.update_metadata(context.record)

    @staticmethod
    def _collect_hosts(context: PipelineContext) -> Dict[str, Dict[str, object]]:
        host_info: Dict[str, Dict[str, object]] = {}
        for entry in context.get_results():
            if entry.get("type") != "url":
                continue
            url_value = entry.get("url")
            host = entry.get("hostname") or (url_value and urlparse(url_value).hostname)
            if not host:
                continue
            info = host_info.setdefault(
                host,
                {"urls": [], "tags": set(), "technologies": set()},
            )
            if url_value:
                info["urls"].append(url_value)
            for tag in entry.get("tags", []):
                if isinstance(tag, str):
                    info["tags"].add(tag)
            technologies = entry.get("technologies") or []
            if isinstance(technologies, list):
                info["technologies"].update(
                    {str(item).lower() for item in technologies if item}
                )
            elif technologies:
                info["technologies"].add(str(technologies).lower())
        return host_info

    def _run_scan(
        self,
        context: PipelineContext,
        cms: str,
        host: str,
        base_url: str,
        timeout: int,
        artifact_dir,
    ) -> Dict[str, object]:
        executor = context.executor
        if CommandExecutor.available("droopescan"):
            cmd = ["droopescan", "scan", cms, "-u", base_url]
            try:
                result = executor.run(
                    cmd, check=False, timeout=timeout, capture_output=True
                )
            except CommandError as exc:
                context.logger.warning("droopescan failed for %s: %s", host, exc)
                return {}
            output = (result.stdout or "") + "\n" + (result.stderr or "")
            return {
                "tool": "droopescan",
                "output": output.strip(),
                "findings": [],
                "artifact_path": None,
            }

        if scanner_integrations is not None and CommandExecutor.available("nuclei"):
            tags = [cms]
            runtime = context.runtime_config
            result = scanner_integrations.run_nuclei(
                context.executor,
                context.logger,
                host,
                base_url,
                artifact_dir,
                timeout,
                tags=tags,
                request_timeout=int(getattr(runtime, "nuclei_timeout", 10)),
                retries=int(getattr(runtime, "nuclei_retries", 1)),
            )
            findings = [finding.payload for finding in result.findings]
            artifact_path = result.artifact_path
            output = ""
            if findings:
                output = "\n".join(
                    f"{item.get('description', '')} {item.get('details', {}).get('template_id', '')}".strip()
                    for item in findings
                )
            return {
                "tool": "nuclei",
                "output": output,
                "findings": findings,
                "artifact_path": artifact_path,
            }

        context.logger.warning("CMS scan tool missing; skipping %s", host)
        note_missing_tool(context, "droopescan")
        if not CommandExecutor.available("nuclei"):
            note_missing_tool(context, "nuclei")
        return {}

    def _discover_modules(
        self,
        context: PipelineContext,
        cms: str,
        host: str,
        base_url: str,
        timeout: int,
        limiter,
        cache: Dict[str, Tuple[str, str]],
    ) -> List[str]:
        if cms not in {"drupal", "magento"}:
            return []
        cache_key = f"{host}:{cms}"
        if cache_key in cache:
            html, final_url = cache[cache_key]
        else:
            try:
                import requests
            except Exception:
                return []
            headers = context.auth_headers({"User-Agent": "recon-cli cms-modules"})
            if limiter and not limiter.wait_for_slot(base_url, timeout=timeout):
                return []
            session = context.auth_session(base_url)
            try:
                if session:
                    resp = session.get(
                        base_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
                else:
                    resp = requests.get(
                        base_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
            except requests.exceptions.RequestException:
                if limiter:
                    limiter.on_error(base_url)
                return []
            if limiter:
                limiter.on_response(base_url, resp.status_code)
            if resp.status_code >= 400:
                return []
            html = resp.text or ""
            final_url = str(getattr(resp, "url", "")) or base_url
            cache[cache_key] = (html, final_url)

        modules: Set[str] = set()
        if cms == "drupal":
            modules.update(self.DRUPAL_MODULE_RE.findall(html))
            modules.update(self.DRUPAL_LEGACY_RE.findall(html))
        elif cms == "magento":
            modules.update(self.MAGENTO_THEME_RE.findall(html))
            modules.update(self.MAGENTO_ADMIN_THEME_RE.findall(html))

        max_modules = int(getattr(context.runtime_config, "cms_module_max", 60))
        cleaned = []
        for module in sorted(modules):
            module = module.strip().strip("/")
            if not module:
                continue
            cleaned.append(module)
            if max_modules > 0 and len(cleaned) >= max_modules:
                break
        return cleaned
