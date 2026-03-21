from __future__ import annotations

import re
import requests
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit, quote_plus

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
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
        "';WAITFOR DELAY '0:0:2'--",
    ]
    CHALLENGE_KEYWORDS = (
        "captcha",
        "turnstile",
        "challenge",
        "verify you are human",
        "bot detection",
        "please enable cookies",
        "just a moment",
    )
    HEADER_TAGS: Dict[str, str] = {
        "cf-ray": "waf:cloudflare",
        "cf-cache-status": "waf:cloudflare",
        "cf-chl-bypass": "waf:cloudflare",
        "x-sucuri-id": "waf:sucuri",
        "x-sucuri-block": "waf:sucuri",
        "x-sucuri-cache": "waf:sucuri",
        "x-akamai-transformed": "waf:akamai",
        "x-akamai-request-id": "waf:akamai",
        "x-incapsula": "waf:incapsula",
        "x-iinfo": "waf:imperva",
        "x-distil-cs": "waf:distil",
        "x-waf": "waf:generic",
        "x-firewall": "waf:generic",
        "x-cdn": "waf:cdn",
        "x-amzn-waf-blocked": "waf:aws",
        "x-amz-cf-id": "waf:cloudfront",
        "x-amz-cf-pop": "waf:cloudfront",
    }
    HEADER_VALUE_TAGS: Dict[str, Dict[str, str]] = {
        "server": {
            "cloudflare": "waf:cloudflare",
            "akamai": "waf:akamai",
            "imperva": "waf:imperva",
            "incapsula": "waf:incapsula",
            "sucuri": "waf:sucuri",
            "f5": "waf:f5",
            "barracuda": "waf:barracuda",
        },
        "via": {
            "cloudflare": "waf:cloudflare",
            "imperva": "waf:imperva",
            "akamai": "waf:akamai",
        },
        "x-powered-by": {
            "imperia": "waf:imperva",
            "mod_security": "waf:modsecurity",
        },
    }
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_probe", False))

    def execute(self, context: PipelineContext) -> None:
        candidates: List[Tuple[int, str]] = []
        fallback: List[Tuple[int, str]] = []
        context.logger.info("WAF Probe starting: iterating results")
        item_count = 0
        for entry in context.iter_results():
            item_count += 1
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
            waf_tags = enrich_utils.detect_waf_tags(
                entry.get("server"), entry.get("cdn")
            )
            indicated = status in self.BLOCK_STATUSES or any(
                tag.startswith("waf:") or tag == "service:waf" for tag in tags
            )
            if waf_tags:
                indicated = True
            if indicated:
                candidates.append((score, url))
            else:
                fallback.append((score, url))

        context.logger.info(
            "WAF Probe: processed %d items, found %d candidates",
            item_count,
            len(candidates),
        )
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

        context.logger.info(
            "WAF Probe: selected %d URLs for probing (max_urls=%d)",
            len(selected),
            max_urls,
        )
        if not selected:
            return

        findings = 0
        checked = 0
        context.logger.info(
            "WAF Probe: beginning probe loop for %d URLs", len(selected)
        )
        for url in selected:
            checked += 1
            context.logger.info("WAF Probe: checking URL %s", url)
            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    context.logger.info(
                        "WAF Probe: limiter slot wait failed for %s", url
                    )
                    continue
                resp_default = self._fetch(
                    context,
                    url,
                    requests,
                    timeout=timeout,
                    headers={"User-Agent": "recon-cli waf-probe"},
                )
            except Exception as exc:
                context.logger.info(
                    "WAF Probe: FAILED baseline fetch for %s: %s", url, exc
                )
                if limiter:
                    limiter.on_error(url)
                continue

            if limiter:
                limiter.on_response(url, resp_default[0].status_code)  # type: ignore[attr-defined]
            baseline_resp, baseline_snip = resp_default
            context.logger.info(
                "WAF Probe: baseline fetched for %s (status %d)",
                url,
                baseline_resp.status_code,  # type: ignore[attr-defined]
            )
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
            except Exception as exc:
                context.logger.debug("Failed to fetch baseline for %s: %s", url, exc)
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp_attack[0].status_code)  # type: ignore[attr-defined]
            attack_resp, attack_snip = resp_attack

            try:
                if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                    continue
                alt_path = urlsplit(url).path or "/"
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
                        "X-Original-URL": alt_path,
                        "X-Rewrite-URL": alt_path,
                    },
                )
            except Exception as exc:
                context.logger.debug("Failed to fetch baseline for %s: %s", url, exc)
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp_alt[0].status_code)  # type: ignore[attr-defined]
            alt_resp, alt_snip = resp_alt

            baseline_meta = self._response_meta(baseline_resp, baseline_snip)
            attack_meta = self._response_meta(attack_resp, attack_snip)
            alt_meta = self._response_meta(alt_resp, alt_snip)

            baseline_blocked = self._looks_blocked(baseline_resp, baseline_snip)
            attack_blocked = self._looks_blocked(attack_resp, attack_snip)
            alt_blocked = self._looks_blocked(alt_resp, alt_snip)

            waf_tags = set()
            waf_tags.update(self._header_tags(baseline_resp))
            waf_tags.update(
                enrich_utils.detect_waf_tags(
                    self._get_header(baseline_resp, "server"),
                    self._get_header(baseline_resp, "via"),
                )
            )
            waf_tags.update(
                enrich_utils.infer_cookie_tags(self._cookie_headers(baseline_resp))
            )
            waf_tags.update(self._header_tags(attack_resp))
            waf_tags.update(
                enrich_utils.detect_waf_tags(
                    self._get_header(attack_resp, "server"),
                    self._get_header(attack_resp, "via"),
                )
            )
            waf_tags.update(
                enrich_utils.infer_cookie_tags(self._cookie_headers(attack_resp))
            )
            waf_tags.update(self._header_tags(alt_resp))
            waf_tags.update(
                enrich_utils.detect_waf_tags(
                    self._get_header(alt_resp, "server"),
                    self._get_header(alt_resp, "via"),
                )
            )
            waf_tags.update(
                enrich_utils.infer_cookie_tags(self._cookie_headers(alt_resp))
            )

            blocked_delta = self._blocked_delta(baseline_meta, attack_meta)
            indicators = 0
            if blocked_delta:
                indicators += 1
            if waf_tags:
                indicators += 1
            if self._looks_challenge(attack_resp, attack_snip):
                indicators += 1
            if not baseline_blocked and attack_blocked:
                indicators += 1

            if indicators >= 2:
                signal_id = context.emit_signal(
                    "waf_detected",
                    "url",
                    url,
                    confidence=0.6,
                    source="waf-probe",
                    tags=sorted({"service:waf"} | waf_tags),
                    evidence={
                        "baseline_status": baseline_meta["status"],
                        "attack_status": attack_meta["status"],
                        "alternate_status": alt_meta["status"],
                        "baseline_title": baseline_meta["title"],
                        "attack_title": attack_meta["title"],
                        "alternate_title": alt_meta["title"],
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
                        "baseline_status": baseline_meta["status"],
                        "attack_status": attack_meta["status"],
                        "alternate_status": alt_meta["status"],
                        "baseline_length": baseline_meta["length"],
                        "attack_length": attack_meta["length"],
                        "alternate_length": alt_meta["length"],
                        "baseline_title": baseline_meta["title"],
                        "attack_title": attack_meta["title"],
                        "alternate_title": alt_meta["title"],
                    },
                    "tags": sorted({"waf", "detected", "service:waf"} | waf_tags),
                    "score": 40,
                    "priority": "low",
                    "evidence_id": signal_id or None,
                }
                if context.results.append(finding):
                    findings += 1

            if (baseline_blocked and not alt_blocked) or (
                attack_blocked and not alt_blocked
            ):
                signal_id = context.emit_signal(
                    "waf_bypass_possible",
                    "url",
                    url,
                    confidence=0.7,
                    source="waf-probe",
                    tags=sorted({"waf", "bypass-possible"} | waf_tags),
                    evidence={
                        "baseline_status": baseline_meta["status"],
                        "attack_status": attack_meta["status"],
                        "alternate_status": alt_meta["status"],
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
                        "baseline_status": baseline_meta["status"],
                        "attack_status": attack_meta["status"],
                        "alternate_status": alt_meta["status"],
                        "baseline_length": baseline_meta["length"],
                        "attack_length": attack_meta["length"],
                        "alternate_length": alt_meta["length"],
                        "baseline_title": baseline_meta["title"],
                        "attack_title": attack_meta["title"],
                        "alternate_title": alt_meta["title"],
                    },
                    "tags": sorted({"waf", "bypass-possible"} | waf_tags),
                    "score": 65,
                    "priority": "medium",
                    "evidence_id": signal_id or None,
                }
                if context.results.append(finding):
                    findings += 1
            if self._looks_challenge(attack_resp, attack_snip):
                context.emit_signal(
                    "waf_challenge",
                    "url",
                    url,
                    confidence=0.5,
                    source="waf-probe",
                    tags=sorted({"waf", "challenge"} | waf_tags),
                    evidence={
                        "attack_status": attack_meta["status"],
                        "attack_title": attack_meta["title"],
                    },
                )
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
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
        )

    def _fetch(
        self,
        context: PipelineContext,
        url: str,
        requests_mod,
        timeout: int,
        headers: dict,
    ) -> Tuple[object, str]:
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
        if any(keyword in lowered for keyword in self.CHALLENGE_KEYWORDS):
            return True
        return False

    def _looks_challenge(self, resp, body_snippet: str) -> bool:
        if not resp:
            return False
        lowered = (body_snippet or "").lower()
        if any(keyword in lowered for keyword in self.CHALLENGE_KEYWORDS):
            return True
        title = self._extract_title(body_snippet).lower()
        if "just a moment" in title or "attention required" in title:
            return True
        return False

    def _response_meta(self, resp, body_snippet: str) -> Dict[str, object]:
        status = int(getattr(resp, "status_code", 0) or 0)
        return {
            "status": status,
            "length": len(body_snippet or ""),
            "title": self._extract_title(body_snippet),
        }

    def _blocked_delta(
        self, baseline: Dict[str, object], attack: Dict[str, object]
    ) -> bool:
        try:
            baseline_status = int(baseline.get("status") or 0)  # type: ignore[call-overload]
        except Exception:
            baseline_status = 0
        try:
            attack_status = int(attack.get("status") or 0)  # type: ignore[call-overload]
        except Exception:
            attack_status = 0
        if (
            attack_status in self.BLOCK_STATUSES
            and baseline_status not in self.BLOCK_STATUSES
        ):
            return True
        base_len = int(baseline.get("length") or 0)  # type: ignore[call-overload]
        attack_len = int(attack.get("length") or 0)  # type: ignore[call-overload]
        if base_len > 0 and attack_len > 0 and attack_len < base_len * 0.4:
            return True
        base_title = str(baseline.get("title") or "")
        attack_title = str(attack.get("title") or "")
        if base_title and attack_title and base_title != attack_title:
            if any(
                keyword in attack_title.lower()
                for keyword in ("denied", "blocked", "forbidden")
            ):
                return True
        return False

    def _header_tags(self, resp) -> set[str]:
        if not resp:
            return set()
        raw_headers = getattr(resp, "headers", {}) or {}
        try:
            headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
        except Exception:
            headers = {}
        tags: set[str] = set()
        for key, tag in self.HEADER_TAGS.items():
            if key in headers:
                tags.add(tag)
        for header, mapping in self.HEADER_VALUE_TAGS.items():
            value = headers.get(header)
            if not value:
                continue
            lower_value = value.lower()
            for needle, tag in mapping.items():
                if needle in lower_value:
                    tags.add(tag)
        return tags

    def _extract_title(self, body_snippet: str) -> str:
        if not body_snippet:
            return ""
        match = self.TITLE_RE.search(body_snippet)
        if not match:
            return ""
        title = match.group(1)
        title = re.sub(r"\s+", " ", title).strip()
        return title[:120]

    @staticmethod
    def _get_header(resp, name: str) -> str | None:
        if resp is None:
            return None
        headers = getattr(resp, "headers", {}) or {}
        try:
            return headers.get(name)
        except Exception:
            return None

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
        headers = getattr(resp, "headers", {}) or {}
        value = headers.get("Set-Cookie") if isinstance(headers, dict) else None
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        return [str(value)]
