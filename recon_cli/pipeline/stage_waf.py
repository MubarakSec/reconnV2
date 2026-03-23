from __future__ import annotations

import re
import asyncio
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse, urlsplit, urlunsplit, quote_plus

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import enrich as enrich_utils
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig, HTTPResponse


class WafProbeStage(Stage):
    name = "waf_probe"
    BLOCK_STATUSES = {401, 403, 406, 429, 503, 520, 521, 522, 523, 524}
    BLOCK_KEYWORDS = (
        "access denied", "request blocked", "forbidden", "not allowed", "malicious",
        "firewall", "security policy", "incident id", "ray id", "cloudflare",
        "imperva", "akamai", "sucuri", "incapsula", "mod_security", "modsecurity", "waf",
    )
    ATTACK_PAYLOADS = [
        "' or '1'='1", "<script>alert(1)</script>", "../../etc/passwd",
        "${jndi:ldap://127.0.0.1/a}", "';WAITFOR DELAY '0:0:2'--",
    ]
    CHALLENGE_KEYWORDS = (
        "captcha", "turnstile", "challenge", "verify you are human", "bot detection",
        "please enable cookies", "just a moment",
    )
    HEADER_TAGS: Dict[str, str] = {
        "cf-ray": "waf:cloudflare", "cf-cache-status": "waf:cloudflare",
        "cf-chl-bypass": "waf:cloudflare", "x-sucuri-id": "waf:sucuri",
        "x-sucuri-block": "waf:sucuri", "x-sucuri-cache": "waf:sucuri",
        "x-akamai-transformed": "waf:akamai", "x-akamai-request-id": "waf:akamai",
        "x-incapsula": "waf:incapsula", "x-iinfo": "waf:imperva", "x-distil-cs": "waf:distil",
        "x-waf": "waf:generic", "x-firewall": "waf:generic", "x-cdn": "waf:cdn",
        "x-amzn-waf-blocked": "waf:aws", "x-amz-cf-id": "waf:cloudfront", "x-amz-cf-pop": "waf:cloudfront",
    }
    HEADER_VALUE_TAGS: Dict[str, Dict[str, str]] = {
        "server": {
            "cloudflare": "waf:cloudflare", "akamai": "waf:akamai", "imperva": "waf:imperva",
            "incapsula": "waf:incapsula", "sucuri": "waf:sucuri", "f5": "waf:f5", "barracuda": "waf:barracuda",
        },
        "via": {"cloudflare": "waf:cloudflare", "imperva": "waf:imperva", "akamai": "waf:akamai"},
        "x-powered-by": {"imperia": "waf:imperva", "mod_security": "waf:modsecurity"},
    }
    TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_probe", False))

    async def run_async(self, context: PipelineContext) -> None:
        candidates: List[Tuple[int, str]] = []
        fallback: List[Tuple[int, str]] = []
        
        for entry in context.iter_results():
            if entry.get("type") != "url": continue
            url = entry.get("url")
            if not url or not context.url_allowed(url): continue
            
            status = entry.get("status_code") or 0
            tags = entry.get("tags", [])
            score = int(entry.get("score", 0))
            waf_tags = enrich_utils.detect_waf_tags(entry.get("server"), entry.get("cdn"))
            indicated = status in self.BLOCK_STATUSES or any(t.startswith("waf:") or t == "service:waf" for t in tags) or bool(waf_tags)
            
            if indicated: candidates.append((score, url))
            else: fallback.append((score, url))

        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "waf_probe_max_urls", 25))
        timeout = int(getattr(runtime, "waf_probe_timeout", 8))
        
        seen = set()
        selected: List[str] = []
        for _, url in sorted(candidates, key=lambda x: x[0], reverse=True):
            if url not in seen:
                seen.add(url); selected.append(url)
                if len(selected) >= max_urls: break
        if len(selected) < max_urls:
            for _, url in sorted(fallback, key=lambda x: x[0], reverse=True):
                if url not in seen:
                    seen.add(url); selected.append(url)
                    if len(selected) >= max_urls: break

        if not selected: return

        config = HTTPClientConfig(
            max_concurrent=10,
            total_timeout=float(timeout),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=float(getattr(runtime, "waf_probe_rps", 15.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            findings, checked = 0, 0
            for url in selected:
                checked += 1
                try:
                    # 1. Baseline
                    resp_default = await self._fetch(client, url, {"User-Agent": "recon-cli waf-probe"})
                    if not resp_default: continue
                    b_meta = self._response_meta(resp_default)
                    
                    # 2. Attack
                    attack_url = self._build_attack_url(url)
                    resp_attack = await self._fetch(client, attack_url, {"User-Agent": "recon-cli waf-probe"})
                    if not resp_attack: continue
                    a_meta = self._response_meta(resp_attack)
                    
                    # 3. Alternate Headers
                    alt_path = urlsplit(url).path or "/"
                    headers_alt = {
                        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                        "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
                        "X-Original-URL": alt_path, "X-Rewrite-URL": alt_path,
                    }
                    resp_alt = await self._fetch(client, attack_url, headers_alt)
                    if not resp_alt: continue
                    alt_meta = self._response_meta(resp_alt)

                    # Analysis
                    b_blocked = self._looks_blocked(resp_default)
                    a_blocked = self._looks_blocked(resp_attack)
                    alt_blocked = self._looks_blocked(resp_alt)

                    waf_tags = self._collect_waf_tags(resp_default, resp_attack, resp_alt)
                    blocked_delta = self._blocked_delta(b_meta, a_meta)
                    
                    indicators = sum([bool(blocked_delta), bool(waf_tags), self._looks_challenge(resp_attack), (not b_blocked and a_blocked)])

                    if indicators >= 2:
                        signal_id = context.emit_signal("waf_detected", "url", url, confidence=0.6, source=self.name, tags=sorted({"service:waf"} | waf_tags), evidence={"baseline_status": b_meta["status"], "attack_status": a_meta["status"], "alternate_status": alt_meta["status"]})
                        finding = {
                            "type": "finding", "source": self.name, "hostname": urlparse(url).hostname, "finding_type": "waf_detected",
                            "description": "WAF behavior detected via probe request",
                            "details": {"url": url, "attack_url": attack_url, "baseline_status": b_meta["status"], "attack_status": a_meta["status"], "alternate_status": alt_meta["status"], "baseline_length": b_meta["length"], "attack_length": a_meta["length"], "baseline_title": b_meta["title"], "attack_title": a_meta["title"]},
                            "tags": sorted({"waf", "detected", "service:waf"} | waf_tags), "score": 40, "priority": "low", "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding): findings += 1

                    if (b_blocked and not alt_blocked) or (a_blocked and not alt_blocked):
                        signal_id = context.emit_signal("waf_bypass_possible", "url", url, confidence=0.7, source=self.name, tags=sorted({"waf", "bypass-possible"} | waf_tags), evidence={"baseline_status": b_meta["status"], "attack_status": a_meta["status"], "alternate_status": alt_meta["status"]})
                        finding = {
                            "type": "finding", "source": self.name, "hostname": urlparse(url).hostname, "description": "Potential WAF bypass via alternate headers", "finding_type": "waf_bypass_possible",
                            "details": {"url": url, "attack_url": attack_url, "baseline_status": b_meta["status"], "attack_status": a_meta["status"], "alternate_status": alt_meta["status"], "baseline_length": b_meta["length"], "attack_length": a_meta["length"]},
                            "tags": sorted({"waf", "bypass-possible"} | waf_tags), "score": 65, "priority": "medium", "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding): findings += 1
                except Exception: continue

        stats = context.record.metadata.stats.setdefault("waf_probe", {})
        stats.update({"findings": findings, "checked": checked})
        context.manager.update_metadata(context.record)

    def _build_attack_url(self, url: str) -> str:
        parts = urlsplit(url)
        probe = f"recon_probe={quote_plus(self.ATTACK_PAYLOADS[0])}"
        new_query = f"{parts.query}&{probe}" if parts.query else probe
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    async def _fetch(self, client: AsyncHTTPClient, url: str, headers: dict) -> Optional[HTTPResponse]:
        try:
            return await client.get(url, headers=headers, follow_redirects=True)
        except Exception: return None

    def _looks_blocked(self, resp: HTTPResponse) -> bool:
        if resp.status in self.BLOCK_STATUSES: return True
        body = resp.body.lower()
        return any(k in body for k in self.BLOCK_KEYWORDS) or any(k in body for k in self.CHALLENGE_KEYWORDS)

    def _looks_challenge(self, resp: HTTPResponse) -> bool:
        body = resp.body.lower()
        if any(k in body for k in self.CHALLENGE_KEYWORDS): return True
        title = self._extract_title(resp.body).lower()
        return "just a moment" in title or "attention required" in title

    def _response_meta(self, resp: HTTPResponse) -> Dict[str, Any]:
        return {"status": resp.status, "length": len(resp.body), "title": self._extract_title(resp.body)}

    def _blocked_delta(self, baseline: Dict[str, Any], attack: Dict[str, Any]) -> bool:
        b_status, a_status = baseline["status"], attack["status"]
        if a_status in self.BLOCK_STATUSES and b_status not in self.BLOCK_STATUSES: return True
        b_len, a_len = baseline["length"], attack["length"]
        if b_len > 0 and a_len > 0 and a_len < b_len * 0.4: return True
        b_title, a_title = baseline["title"], attack["title"]
        if b_title and a_title and b_title != a_title and any(k in a_title.lower() for k in ("denied", "blocked", "forbidden")): return True
        return False

    def _collect_waf_tags(self, *resps: HTTPResponse) -> Set[str]:
        tags = set()
        for resp in resps:
            tags.update(self._header_tags(resp))
            tags.update(enrich_utils.detect_waf_tags(resp.headers.get("server"), resp.headers.get("via")))
            tags.update(enrich_utils.infer_cookie_tags([c.name for c in resp.cookies]))
        return tags

    def _header_tags(self, resp: HTTPResponse) -> Set[str]:
        headers = {k.lower(): str(v) for k, v in resp.headers.items()}
        tags = {self.HEADER_TAGS[k] for k in self.HEADER_TAGS if k in headers}
        for h, mapping in self.HEADER_VALUE_TAGS.items():
            val = headers.get(h, "").lower()
            if val: tags.update({tag for needle, tag in mapping.items() if needle in val})
        return tags

    def _extract_title(self, body: str) -> str:
        if not body: return ""
        match = self.TITLE_RE.search(body)
        return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
