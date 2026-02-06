from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class WafProbeStage(Stage):
    name = "waf_probe"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_probe", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("waf probe requires requests; skipping")
            return
        candidates: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url:
                continue
            status = entry.get("status_code") or 0
            tags = entry.get("tags", [])
            if status in {403, 429} or any(tag.startswith("waf:") or tag == "service:waf" for tag in tags):
                candidates.append(url)
        if not candidates:
            return
        max_urls = int(getattr(context.runtime_config, "waf_probe_max_urls", 25))
        timeout = int(getattr(context.runtime_config, "waf_probe_timeout", 8))
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "waf_probe",
            rps=float(getattr(runtime, "waf_probe_rps", 0)),
            per_host=float(getattr(runtime, "waf_probe_per_host_rps", 0)),
        )
        findings = 0
        for url in candidates[:max_urls]:
            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                resp_default = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers={"User-Agent": "recon-cli waf-probe"},
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp_default.status_code)
            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                resp_alt = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                        "X-Forwarded-For": "127.0.0.1",
                        "X-Originating-IP": "127.0.0.1",
                        "X-Real-IP": "127.0.0.1",
                    },
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp_alt.status_code)
            if resp_default.status_code in {403, 429} and resp_alt.status_code not in {403, 429}:
                finding = {
                    "type": "finding",
                    "source": "waf-probe",
                    "hostname": urlparse(url).hostname,
                    "description": "Potential WAF bypass via alternate headers",
                    "details": {
                        "url": url,
                        "baseline_status": resp_default.status_code,
                        "alternate_status": resp_alt.status_code,
                        "baseline_length": len(resp_default.text or ""),
                        "alternate_length": len(resp_alt.text or ""),
                    },
                    "tags": ["waf", "bypass-possible"],
                    "score": 60,
                    "priority": "medium",
                }
                if context.results.append(finding):
                    findings += 1
        if findings:
            stats = context.record.metadata.stats.setdefault("waf_probe", {})
            stats["findings"] = findings
            context.manager.update_metadata(context.record)
