from __future__ import annotations

from typing import Dict, List, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class SecurityHeadersStage(Stage):
    name = "security_headers"

    REQUIRED_HEADERS = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_security_headers", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("security headers check requires requests; skipping")
            return

        items = read_jsonl(context.record.paths.results_jsonl)
        if not items:
            return

        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "security_headers_max_urls", 40))
        timeout = int(getattr(runtime, "security_headers_timeout", 8))
        limiter = context.get_rate_limiter(
            "security_headers",
            rps=float(getattr(runtime, "security_headers_rps", 0)),
            per_host=float(getattr(runtime, "security_headers_per_host_rps", 0)),
        )

        best_by_host: Dict[str, Tuple[int, str, str]] = {}
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                continue
            score = int(entry.get("score", 0))
            current = best_by_host.get(host)
            if current is None:
                best_by_host[host] = (score, url, parsed.scheme or "")
                continue
            current_score, current_url, current_scheme = current
            if (parsed.scheme == "https" and current_scheme != "https") or score > current_score:
                best_by_host[host] = (score, url, parsed.scheme or "")

        candidates = sorted(best_by_host.values(), key=lambda item: item[0], reverse=True)
        candidates = candidates[:max_urls] if max_urls > 0 else candidates
        if not candidates:
            return

        findings = 0
        for score, url, scheme in candidates:
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers={"User-Agent": "recon-cli security-headers"},
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)
            if resp.status_code >= 500:
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}
            missing: List[str] = []
            present: List[str] = []

            for header in self.REQUIRED_HEADERS:
                if header in headers:
                    present.append(header)
                else:
                    missing.append(header)

            if scheme == "https":
                if "strict-transport-security" in headers:
                    present.append("strict-transport-security")
                else:
                    missing.append("strict-transport-security")

            if not missing:
                continue

            severity = "low"
            score_value = 35
            if "strict-transport-security" in missing and scheme == "https":
                severity = "medium"
                score_value = 55

            payload = {
                "type": "finding",
                "finding_type": "security_headers",
                "source": "security-headers",
                "hostname": urlparse(url).hostname,
                "url": url,
                "description": "Missing recommended security headers",
                "details": {
                    "missing": missing,
                    "present": present,
                },
                "tags": ["security-headers"] + [f"missing:{name}" for name in missing],
                "score": score_value,
                "priority": "medium" if severity == "medium" else "low",
                "severity": severity,
            }
            if context.results.append(payload):
                findings += 1

        if findings:
            stats = context.record.metadata.stats.setdefault("security_headers", {})
            stats["checked"] = len(candidates)
            stats["findings"] = findings
            context.manager.update_metadata(context.record)
