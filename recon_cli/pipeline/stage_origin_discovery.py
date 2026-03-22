from __future__ import annotations

import re
import socket
import asyncio
import dns.resolver
import httpx
import hashlib
import mmh3
import base64
from typing import List, Set, Dict, Any
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.enrich import classify_provider


class OriginDiscoveryStage(Stage):
    """
    Advanced Origin IP Discovery Stage.
    Attempts to bypass CDNs/WAFs using:
    1. Censys SSL/TLS Certificate Search.
    2. Favicon Hashing & Shodan Search.
    3. DNS History (SPF, MX, TXT).
    4. Direct IP verification via Host header.
    """
    name = "origin_discovery"

    async def run_async(self, context: PipelineContext) -> None:
        root_domains = self._collect_root_domains(context)
        if not root_domains:
            return

        context.logger.info("Starting origin discovery for %d root domains", len(root_domains))
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        for domain in root_domains:
            potential_ips: Dict[str, str] = {} # ip -> method

            # 1. Censys SSL Search (Pro technique)
            await self._probe_censys(context, domain, potential_ips)

            # 2. Favicon Hashing (Pro technique)
            await self._probe_favicon_hash(context, domain, potential_ips)

            # 3. DNS History / Records
            self._probe_dns_records(domain, resolver, potential_ips)

            # 4. Verify Origin IPs
            await self._verify_origins(context, domain, potential_ips)

    def _collect_root_domains(self, context: PipelineContext) -> Set[str]:
        results = context.get_results()
        domains = set()
        for r in results:
            host = r.get("hostname")
            if host:
                parts = host.split(".")
                if len(parts) >= 2:
                    domains.add(".".join(parts[-2:]))
        return domains

    async def _probe_censys(self, context: PipelineContext, domain: str, potential_ips: Dict[str, str]) -> None:
        api_id = os.environ.get("CENSYS_API_ID")
        api_secret = os.environ.get("CENSYS_API_SECRET")
        if not (api_id and api_secret): return

        try:
            url = "https://search.censys.io/api/v2/hosts/search"
            query = f"services.tls.certificates.leaf_data.names: {domain}"
            async with httpx.AsyncClient(auth=(api_id, api_secret), timeout=15) as client:
                resp = await client.get(url, params={"q": query})
                if resp.status_code == 200:
                    data = resp.json()
                    for hit in data.get("result", {}).get("hits", []):
                        ip = hit.get("ip")
                        if ip:
                            potential_ips[ip] = "Censys SSL Search"
        except Exception as e:
            context.logger.debug("Censys probe failed for %s: %s", domain, e)

    async def _probe_favicon_hash(self, context: PipelineContext, domain: str, potential_ips: Dict[str, str]) -> None:
        shodan_key = os.environ.get("SHODAN_API_KEY")
        if not shodan_key: return

        try:
            # 1. Fetch favicon
            target_url = f"https://{domain}/favicon.ico"
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(target_url)
                if resp.status_code == 200:
                    # 2. Calculate mmh3 hash (Shodan style)
                    favicon_b64 = base64.encodebytes(resp.content).decode()
                    f_hash = mmh3.hash(favicon_b64)
                    
                    # 3. Search Shodan
                    search_url = f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{f_hash}"
                    s_resp = await client.get(search_url)
                    if s_resp.status_code == 200:
                        s_data = s_resp.json()
                        for match in s_data.get("matches", []):
                            ip = match.get("ip_str")
                            if ip:
                                potential_ips[ip] = f"Favicon Hash ({f_hash})"
        except Exception: pass

    def _probe_dns_records(self, domain: str, resolver: dns.resolver.Resolver, potential_ips: Dict[str, str]) -> None:
        # SPF Records
        try:
            for rdata in resolver.resolve(domain, "TXT"):
                txt = rdata.to_text().lower()
                if "v=spf1" in txt:
                    for ip in re.findall(r"ip4:([0-9.]+)", txt):
                        potential_ips[ip] = "SPF Record"
        except Exception: pass

        # MX Records
        try:
            for rdata in resolver.resolve(domain, "MX"):
                mx_host = str(rdata.exchange).rstrip(".")
                try:
                    ips = [str(i) for i in resolver.resolve(mx_host, "A")]
                    for ip in ips:
                        potential_ips[ip] = f"MX Record ({mx_host})"
                except Exception: pass
        except Exception: pass

    async def _verify_origins(self, context: PipelineContext, domain: str, potential_ips: Dict[str, str]) -> None:
        for ip, method in potential_ips.items():
            # Filter CDN IPs
            _, is_cdn, _ = classify_provider(ip)
            if is_cdn: continue

            if await self._probe_origin_via_host_header(ip, domain):
                finding = {
                    "type": "finding",
                    "finding_type": "origin_ip_leak",
                    "source": self.name,
                    "hostname": domain,
                    "description": f"Verified Origin IP found via {method}: {ip}",
                    "severity": "high",
                    "details": {"ip": ip, "method": method},
                    "tags": ["origin", "bypass", "confirmed"]
                }
                context.results.append(finding)
                context.emit_signal("origin_found", "host", domain, confidence=1.0, source=self.name, evidence={"ip": ip, "method": method})

    async def _probe_origin_via_host_header(self, ip: str, domain: str) -> bool:
        """Connect directly to IP with Host header and check if it matches target."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                # Try HTTPS first
                resp = await client.get(f"https://{ip}/", headers={"Host": domain})
                # If we get a valid response that isn't a 403 WAF block, it's likely origin
                if resp.status_code < 400 or resp.status_code == 404:
                    return True
        except Exception: pass
        return False
import os # Ensure os is imported
