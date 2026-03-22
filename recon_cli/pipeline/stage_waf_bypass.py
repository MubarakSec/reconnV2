from __future__ import annotations

import requests
import random
import string
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse, urlunparse, quote

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class WafBypassStage(Stage):
    """
    Advanced WAF Bypass Stage.
    Attempts to bypass detected WAFs using various header and encoding techniques.
    """
    name = "waf_bypass"

    BYPASS_HEADERS = [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Host", "X-Custom-IP-Authorization",
        "X-Original-URL", "X-Rewrite-URL", "X-Originating-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Client-IP", "Forwarded"
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_bypass", True))

    def execute(self, context: PipelineContext) -> None:
        signals = context.signal_index()
        waf_hosts = signals.get("by_host", {})
        
        # Collect verified origin IPs from findings
        origin_ips = {} # hostname -> ip
        for res in context.get_results():
            if res.get("finding_type") == "origin_ip_leak":
                host = res.get("hostname")
                ip = res.get("details", {}).get("ip")
                if host and ip:
                    origin_ips[host] = ip

        targets = []
        for host, host_signals in waf_hosts.items():
            if "waf_detected" in host_signals and "waf_bypass_possible" not in host_signals:
                targets.append(host)

        if not targets:
            context.logger.info("No hosts with detected WAFs requiring bypass attempts")
            return

        session = requests.Session()
        session.verify = getattr(context.runtime_config, "verify_tls", True)

        for host in targets:
            # Find a representative URL for this host
            url = f"https://{host}/"
            # Try to find a real URL from results if available
            for res in context.get_results():
                if res.get("hostname") == host and res.get("type") == "url":
                    url = res["url"]
                    break
            
            self._attempt_bypasses(context, session, url, origin_ips.get(host))

    def _attempt_bypasses(self, context: PipelineContext, session: requests.Session, url: str, origin_ip: str | None) -> None:
        # Attack payload that normally triggers the WAF
        payload = "<script>alert(1)</script>"
        parsed = urlparse(url)
        
        # 0. Direct Origin IP Bypass (The "Pro" Standard)
        if origin_ip:
            origin_url = f"{parsed.scheme}://{origin_ip}{parsed.path}"
            headers = {"Host": parsed.hostname, "User-Agent": "Mozilla/5.0"}
            if self._check_bypass(context, session, origin_url, payload, headers, "origin:direct-ip"):
                return

        # 1. Header Smuggling / Spoofing
        for header in self.BYPASS_HEADERS:
            headers = {header: "127.0.0.1", "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}
            if self._check_bypass(context, session, url, payload, headers, f"header:{header}"):
                return

        # 2. Double Encoding Bypass
        double_payload = quote(quote(payload))
        if self._check_bypass(context, session, url, double_payload, {}, "encoding:double"):
            return

        # 3. Path Obfuscation (e.g., /path/;/attack)
        obfuscated_path = f"{parsed.path};/{payload}" if parsed.path else f"/;/{payload}"
        test_url = urlunparse(parsed._replace(path=obfuscated_path))
        if self._check_bypass(context, session, test_url, "", {}, "path:obfuscation"):
            return

    def _check_bypass(self, context: PipelineContext, session: requests.Session, url: str, payload: str, headers: Dict[str, str], technique: str) -> bool:
        test_url = url
        if payload:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}bypass_test={payload}"
        
        try:
            resp = session.get(test_url, headers=headers, timeout=10, allow_redirects=False)
            # If we get a 200 or 404 instead of a WAF block (usually 403/406), it's a potential bypass
            if resp.status_code in [200, 404]:
                context.emit_signal(
                    "waf_bypass_confirmed", "url", url,
                    confidence=0.8, source=self.name,
                    tags=["waf", "bypass", technique],
                    evidence={"technique": technique, "status": resp.status_code}
                )
                context.results.append({
                    "type": "finding",
                    "finding_type": "waf_bypass",
                    "url": url,
                    "description": f"WAF bypass confirmed using technique: {technique}",
                    "severity": "medium",
                    "tags": ["waf", "bypass", "confirmed"]
                })
                return True
        except Exception: pass
        return False
