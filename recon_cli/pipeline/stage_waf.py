from __future__ import annotations

from typing import List, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit, quote_plus

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils import enrich as enrich_utils


class WafProbeStage(Stage):
    name = "waf_probe"
    BLOCK_STATUSES = {401, 403, 406, 429, 503, 520, 521, 522, 523, 524}
    BLOCK_KEYWORDS = (
        "access denied",
        "request blocked",
        "forbidden",
        "not allowed",
        "malicious",
        "firewall",
        "security policy",
        "incident id",
        "ray id",
        "cloudflare",
        "imperva",
        "akamai",
        "sucuri",
        "incapsula",
        "mod_security",
        "modsecurity",
        "waf",
    )
    ATTACK_PAYLOADS = [
        "' or '1'='1",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "${jndi:ldap://127.0.0.1/a}",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_probe", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("waf probe requires requests; skipping")
            return
        candidates: List[Tuple[int, str]] = []
        fallback: List[Tuple[int, str]] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url:
                continue
            if not context.url_allowed(url):
                continue
            status = entry.get("status_code") or 0
            tags = entry.get("tags", [])
            score = int(entry.get("score", 0))
            waf_tags = enrich_utils.detect_waf_tags(entry.get("server"), entry.get("cdn"))
            indicated = status in self.BLOCK_STATUSES or any(
                tag.startswith("waf:") or tag == "service:waf" for tag in tags
            )
            if waf_tags:
                indicated = True
            if indicated:
                candidates.append((score, url))
            else:
                fallback.append((score, url))
        if not candidates:
            candidates = []
        max_urls = int(getattr(context.runtime_config, "waf_probe_max_urls", 25))
        timeout = int(getattr(context.runtime_config, "waf_probe_timeout", 8))
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "waf_probe",
            rps=float(getattr(runtime, "waf_probe_rps", 0)),
            per_host=float(getattr(runtime, "waf_probe_per_host_rps", 0)),
        )
        seen = set()
        selected: List[str] = []
        for score, url in sorted(candidates, key=lambda item: item[0], reverse=True):
            if url in seen:
                continue
            seen.add(url)
            selected.append(url)
            if max_urls > 0 and len(selected) >= max_urls:
                break
        if max_urls > 0 and len(selected) < max_urls:
            for score, url in sorted(fallback, key=lambda item: item[0], reverse=True):
                if url in seen:
                    continue
                seen.add(url)
                selected.append(url)
                if len(selected) >= max_urls:
                    break
        if not selected:
            return

        findings = 0
        checked = 0
        for url in selected:
            checked += 1
            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                resp_default = self._fetch(
                    context,
                    url,
                    requests,
                    timeout=timeout,
                    headers={"User-Agent": "recon-cli waf-probe"},
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp_default[0].status_code)
            baseline_resp, baseline_snip = resp_default
            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                attack_url = self._build_attack_url(url)
                resp_attack = self._fetch(
                    context,
                    attack_url,
                    requests,
                    timeout=timeout,
                    headers={
                        "User-Agent": "recon-cli waf-probe",
                    },
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp_attack[0].status_code)
            attack_resp, attack_snip = resp_attack

            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                resp_alt = self._fetch(
                    context,
                    attack_url,
                    requests,
                    timeout=timeout,
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
                limiter.on_response(url, resp_alt[0].status_code)
            alt_resp, alt_snip = resp_alt

            baseline_blocked = self._looks_blocked(baseline_resp, baseline_snip)
            attack_blocked = self._looks_blocked(attack_resp, attack_snip)
            alt_blocked = self._looks_blocked(alt_resp, alt_snip)
            waf_tags = set()
            waf_tags.update(enrich_utils.detect_waf_tags(baseline_resp.headers.get("server"), baseline_resp.headers.get("via")))
            waf_tags.update(enrich_utils.infer_cookie_tags(self._cookie_headers(baseline_resp)))
            waf_tags.update(enrich_utils.detect_waf_tags(attack_resp.headers.get("server"), attack_resp.headers.get("via")))
            waf_tags.update(enrich_utils.infer_cookie_tags(self._cookie_headers(attack_resp)))
            waf_tags.update(enrich_utils.detect_waf_tags(alt_resp.headers.get("server"), alt_resp.headers.get("via")))
            waf_tags.update(enrich_utils.infer_cookie_tags(self._cookie_headers(alt_resp)))

            if (not baseline_blocked and attack_blocked) or waf_tags:
                signal_id = context.emit_signal(
                    "waf_detected",
                    "url",
                    url,
                    confidence=0.6,
                    source="waf-probe",
                    tags=sorted({"service:waf"} | waf_tags),
                    evidence={
                        "baseline_status": baseline_resp.status_code,
                        "attack_status": attack_resp.status_code,
                        "alternate_status": alt_resp.status_code,
                    },
                )
                finding = {
                    "type": "finding",
                    "source": "waf-probe",
                    "hostname": urlparse(url).hostname,
                    "finding_type": "waf_detected",
                    "description": "WAF behavior detected via probe request",
                    "details": {
                        "url": url,
                        "attack_url": attack_url,
                        "baseline_status": baseline_resp.status_code,
                        "attack_status": attack_resp.status_code,
                        "alternate_status": alt_resp.status_code,
                        "baseline_length": len(baseline_snip),
                        "attack_length": len(attack_snip),
                        "alternate_length": len(alt_snip),
                    },
                    "tags": sorted({"waf", "detected", "service:waf"} | waf_tags),
                    "score": 40,
                    "priority": "low",
                    "evidence_id": signal_id or None,
                }
                if context.results.append(finding):
                    findings += 1

            if (baseline_blocked and not alt_blocked) or (attack_blocked and not alt_blocked):
                signal_id = context.emit_signal(
                    "waf_bypass_possible",
                    "url",
                    url,
                    confidence=0.7,
                    source="waf-probe",
                    tags=sorted({"waf", "bypass-possible"} | waf_tags),
                    evidence={
                        "baseline_status": baseline_resp.status_code,
                        "attack_status": attack_resp.status_code,
                        "alternate_status": alt_resp.status_code,
                    },
                )
                finding = {
                    "type": "finding",
                    "source": "waf-probe",
                    "hostname": urlparse(url).hostname,
                    "description": "Potential WAF bypass via alternate headers",
                    "finding_type": "waf_bypass_possible",
                    "details": {
                        "url": url,
                        "attack_url": attack_url,
                        "baseline_status": baseline_resp.status_code,
                        "attack_status": attack_resp.status_code,
                        "alternate_status": alt_resp.status_code,
                        "baseline_length": len(baseline_snip),
                        "attack_length": len(attack_snip),
                        "alternate_length": len(alt_snip),
                    },
                    "tags": sorted({"waf", "bypass-possible"} | waf_tags),
                    "score": 65,
                    "priority": "medium",
                    "evidence_id": signal_id or None,
                }
                if context.results.append(finding):
                    findings += 1
        stats = context.record.metadata.stats.setdefault("waf_probe", {})
        stats["findings"] = findings
        stats["checked"] = checked
        context.manager.update_metadata(context.record)

    def _build_attack_url(self, url: str) -> str:
        payload = self.ATTACK_PAYLOADS[0]
        parts = urlsplit(url)
        query = parts.query
        probe = f"recon_probe={quote_plus(payload)}"
        new_query = f"{query}&{probe}" if query else probe
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def _fetch(self, context: PipelineContext, url: str, requests_mod, timeout: int, headers: dict) -> Tuple[object, str]:
        session = context.auth_session(url)
        if session:
            resp = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=context.runtime_config.verify_tls,
                headers=headers,
            )
        else:
            resp = requests_mod.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=context.runtime_config.verify_tls,
                headers=headers,
            )
        snippet = (resp.text or "")[:2000]
        return resp, snippet

    def _looks_blocked(self, resp, body_snippet: str) -> bool:
        try:
            status_code = int(resp.status_code)
        except Exception:
            status_code = 0
        if status_code in self.BLOCK_STATUSES:
            return True
        lowered = (body_snippet or "").lower()
        if any(keyword in lowered for keyword in self.BLOCK_KEYWORDS):
            return True
        return False

    @staticmethod
    def _cookie_headers(resp) -> List[str]:
        if resp is None:
            return []
        try:
            raw_headers = getattr(resp, "raw", None)
            if raw_headers and hasattr(raw_headers, "headers"):
                header_obj = raw_headers.headers
                if hasattr(header_obj, "getlist"):
                    return [h for h in header_obj.getlist("Set-Cookie") if h]
        except Exception:
            pass
        value = resp.headers.get("Set-Cookie")
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        return [str(value)]
