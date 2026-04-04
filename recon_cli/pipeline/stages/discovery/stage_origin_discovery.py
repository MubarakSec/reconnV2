from __future__ import annotations

import re
import socket
import asyncio
import logging
import ipaddress
import dns.resolver
import httpx
import hashlib
import mmh3
import base64
import os
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.enrich import classify_provider


class OriginDiscoveryStage(Stage):
    """
    State-of-the-Art Origin IP Discovery Stage.
    Attempts to bypass CDNs/WAFs using:
    1. Censys SSL/TLS Certificate Search.
    2. Favicon Hashing & Shodan Search.
    3. DNS History (SPF, MX, TXT, AAAA).
    4. Pro Verification: Body Hash Matching & Host Header Testing.
    """
    name = "origin_discovery"
    _KNOWN_MULTI_LABEL_SUFFIXES = {
        "ac.uk",
        "co.uk",
        "gov.uk",
        "org.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "co.kr",
        "com.br",
        "com.mx",
        "com.sa",
        "com.sg",
        "com.tr",
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_origin_discovery", False))

    def execute(self, context: PipelineContext) -> None:
        import asyncio
        asyncio.run(self.run_async(context))

    async def run_async(self, context: PipelineContext) -> None:
        root_domains = self._collect_root_domains(context)
        if not root_domains:
            return

        context.logger.info("Starting God-Mode origin discovery for %d root domains", len(root_domains))
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        for domain in root_domains:
            potential_ips: Dict[str, str] = {} # ip -> method

            # 0. Get Baseline Body Hash (Elite Verification Prerequisite)
            baseline_hash = await self._get_baseline_asset_hash(context, domain)

            # 1. Censys SSL Search
            await self._probe_censys(context, domain, potential_ips)

            # 2. Favicon Hashing
            await self._probe_favicon_hash(context, domain, potential_ips)

            # 3. DNS History & IPv6
            self._probe_dns_records(domain, resolver, potential_ips)

            # 4. Verify Origin IPs with Body Hash Match
            await self._verify_origins(context, domain, potential_ips, baseline_hash)

    def _collect_root_domains(self, context: PipelineContext) -> Set[str]:
        results: List[Dict[str, Any]] = []
        get_results = getattr(context, "get_results", None)
        if callable(get_results):
            try:
                fetched = get_results()
                if isinstance(fetched, list):
                    results = [entry for entry in fetched if isinstance(entry, dict)]
            except Exception:
                results = []

        if not results:
            fallback_results = getattr(context, "results", None)
            if isinstance(fallback_results, list):
                results = [entry for entry in fallback_results if isinstance(entry, dict)]

        domains = set()
        for r in results:
            host = str(r.get("hostname") or r.get("host") or "").strip().lower()
            if not host:
                url = str(r.get("url") or "").strip()
                if url:
                    try:
                        host = str(urlparse(url).hostname or "").strip().lower()
                    except ValueError:
                        host = ""
            domain = self._registrable_domain(host)
            if domain:
                domains.add(domain)

        if domains:
            return domains

        domains.update(self._collect_domains_from_legacy_artifact(context))
        return domains

    def _collect_domains_from_legacy_artifact(self, context: PipelineContext) -> Set[str]:
        """Fallback for older pipelines/tests that seed deduped hosts on disk."""
        record = getattr(context, "record", None)
        if record is None or not hasattr(record, "paths"):
            return set()

        try:
            hosts_path = record.paths.artifact("dedupe_hosts.txt")
        except Exception:
            return set()

        if not hosts_path.exists():
            return set()

        domains: Set[str] = set()
        try:
            for raw_line in hosts_path.read_text(encoding="utf-8").splitlines():
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                host = raw_line.split()[0].strip().lower()
                domain = self._registrable_domain(host)
                if domain:
                    domains.add(domain)
        except OSError:
            return set()
        return domains

    def _registrable_domain(self, host: str) -> Optional[str]:
        if not host:
            return None

        normalized = host.strip().strip(".").lower()
        if not normalized:
            return None

        # Ignore direct IPs: origin discovery expects a domain seed.
        try:
            ipaddress.ip_address(normalized)
            return None
        except ValueError:
            pass

        parts = normalized.split(".")
        if len(parts) < 2:
            return None

        suffix_two = ".".join(parts[-2:])
        if len(parts) >= 3 and suffix_two in self._KNOWN_MULTI_LABEL_SUFFIXES:
            return ".".join(parts[-3:])
        return suffix_two

    @staticmethod
    def _tls_verify(context: PipelineContext) -> bool:
        runtime_config = getattr(context, "runtime_config", None)
        return bool(getattr(runtime_config, "verify_tls", True))

    async def _get_baseline_asset_hash(self, context: PipelineContext, domain: str) -> Optional[str]:
        """Fetch favicon from public target and return its MD5 hash."""
        url = f"https://{domain}/favicon.ico"
        try:
            async with httpx.AsyncClient(verify=self._tls_verify(context), timeout=10) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and resp.content:
                    return hashlib.md5(resp.content).hexdigest()
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass
        return None

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
                        if ip: potential_ips[ip] = "Censys SSL Search"
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass

    async def _probe_favicon_hash(self, context: PipelineContext, domain: str, potential_ips: Dict[str, str]) -> None:
        shodan_key = os.environ.get("SHODAN_API_KEY")
        if not shodan_key: return

        try:
            target_url = f"https://{domain}/favicon.ico"
            async with httpx.AsyncClient(verify=self._tls_verify(context), timeout=10) as client:
                resp = await client.get(target_url)
                if resp.status_code == 200:
                    favicon_b64 = base64.encodebytes(resp.content).decode()
                    f_hash = mmh3.hash(favicon_b64)
                    search_url = f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{f_hash}"
                    s_resp = await client.get(search_url)
                    if s_resp.status_code == 200:
                        for match in s_resp.json().get("matches", []):
                            ip = match.get("ip_str")
                            if ip: potential_ips[ip] = f"Favicon Hash ({f_hash})"
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass

    def _probe_dns_records(self, domain: str, resolver: dns.resolver.Resolver, potential_ips: Dict[str, str]) -> None:
        # 1. SPF/TXT
        try:
            for rdata in resolver.resolve(domain, "TXT"):
                txt = rdata.to_text().lower()
                if "v=spf1" in txt:
                    for ip in re.findall(r"ip4:([0-9.]+)", txt):
                        potential_ips[ip] = "SPF Record"
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass

        # 4. Common direct-origin hostnames
        for candidate in (f"direct.{domain}", f"origin.{domain}"):
            resolved = False
            try:
                for rdata in resolver.resolve(candidate, "A"):
                    potential_ips[str(rdata)] = f"A Record ({candidate})"
                    resolved = True
            except Exception:
                resolved = False

            if resolved:
                continue

            try:
                _, _, ips = socket.gethostbyname_ex(candidate)
                for ip in ips:
                    potential_ips[ip] = f"DNS Lookup ({candidate})"
            except Exception:
                continue

        # 2. IPv6 (AAAA) - Common misconfig
        try:
            for rdata in resolver.resolve(domain, "AAAA"):
                potential_ips[str(rdata)] = "IPv6 Record (AAAA)"
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass

        # 3. MX Records
        try:
            for rdata in resolver.resolve(domain, "MX"):
                mx_host = str(rdata.exchange).rstrip(".")
                try:
                    ips = [str(i) for i in resolver.resolve(mx_host, "A")]
                    for ip in ips: potential_ips[ip] = f"MX Record ({mx_host})"
                except Exception as e:
                    logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                    try:
                        from recon_cli.utils.metrics import metrics
                        metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                    except Exception:
                        pass
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass

    async def _verify_origins(self, context: PipelineContext, domain: str, potential_ips: Dict[str, str], baseline_hash: Optional[str]) -> None:
        for ip, method in potential_ips.items():
            # Skip CDNs
            _, is_cdn, _ = classify_provider(ip)
            if is_cdn: continue

            # Elite Verification: Check Host Header AND Body Hash
            verification_results = await self._probe_origin_elite(context, ip, domain, baseline_hash)
            
            if verification_results["verified"]:
                conf = 1.0 if verification_results["hash_match"] else 0.8
                finding = {
                    "type": "finding",
                    "finding_type": "origin_ip_leak",
                    "source": self.name,
                    "hostname": domain,
                    "description": f"Verified Origin IP found via {method}: {ip} (HashMatch: {verification_results['hash_match']})",
                    "severity": "high",
                    "details": {"ip": ip, "method": method, "elite_verification": verification_results},
                    "tags": ["origin", "bypass", "confirmed", "elite-verified"]
                }
                context.results.append(finding)
                context.emit_signal("origin_found", "host", domain, confidence=conf, source=self.name, evidence=verification_results)

    async def _probe_origin_elite(
        self,
        context: PipelineContext,
        ip: str,
        domain: str,
        baseline_hash: Optional[str],
    ) -> Dict[str, Any]:
        """Pro-grade verification: Connect to IP, send Host header, compare Body Hash."""
        results = {"verified": False, "hash_match": False, "ip": ip}
        try:
            async with httpx.AsyncClient(verify=self._tls_verify(context), timeout=10) as client:
                # 1. Host Header Test
                resp = await client.get(f"https://{ip}/", headers={"Host": domain})
                if resp.status_code < 400 or resp.status_code == 404:
                    results["verified"] = True
                    results["status_code"] = resp.status_code
                    
                    # 2. Body Hash Test (Favicon Match)
                    if baseline_hash:
                        favicon_resp = await client.get(f"https://{ip}/favicon.ico", headers={"Host": domain})
                        if favicon_resp.status_code == 200:
                            current_hash = hashlib.md5(favicon_resp.content).hexdigest()
                            if current_hash == baseline_hash:
                                results["hash_match"] = True
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="origin_discovery", error_type=type(e).__name__).inc()
                except Exception:
                    pass
        return results
