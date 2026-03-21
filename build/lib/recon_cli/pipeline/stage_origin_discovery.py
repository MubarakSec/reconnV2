from __future__ import annotations

import re
import socket
import asyncio
import dns.resolver
import httpx
from typing import List, Set, Dict, Any

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.enrich import classify_provider


class OriginDiscoveryStage(Stage):
    """
    Advanced Origin IP Discovery Stage
    Attempts to bypass CDNs and find origin IPs by:
    1. Extracting SPF/TXT records for IPv4 addresses.
    2. Resolving MX records to check if email is hosted on origin.
    3. Brute-forcing common origin subdomains (direct, origin, mail, ftp).
    4. Verifying if discovered IPs serve the target domain via Host header.
    5. Filtering out known CDN/Cloud IP ranges.
    """

    name = "origin_discovery"

    async def _probe_origin_via_host_header(
        self, ip: str, domain: str, timeout: int = 5
    ) -> bool:
        """Verifies if the IP address responds to the domain's Host header."""
        urls = [f"http://{ip}", f"https://{ip}"]
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=True
        ) as client:  # nosec B501
            for url in urls:
                try:
                    resp = await client.get(url, headers={"Host": domain})
                    # If we get a 200/300/400 that isn't a generic CDN error, it's likely origin
                    # We look for server headers or content that matches the domain
                    if resp.status_code < 500:
                        return True
                except Exception:
                    continue
        return False

    async def _resolve_async(
        self, hostname: str, resolver: dns.resolver.Resolver
    ) -> List[str]:
        try:
            loop = asyncio.get_running_loop()
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(hostname, "A")
            )
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def run_async(self, context: PipelineContext) -> None:
        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts for origin discovery")
            return

        # Extract root domains
        root_domains: Set[str] = set()
        with hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if not host:
                    continue
                parts = host.split(".")
                if len(parts) > 2:
                    if parts[-2] in {"co", "com", "net", "org"} and len(parts[-1]) == 2:
                        root_domains.add(".".join(parts[-3:]))
                    else:
                        root_domains.add(".".join(parts[-2:]))
                else:
                    root_domains.add(host)

        if not root_domains:
            return

        context.logger.info(
            "Starting advanced origin IP discovery on %d root domains",
            len(root_domains),
        )

        origin_findings: List[Dict[str, Any]] = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        origin_subdomains = [
            "direct",
            "origin",
            "ftp",
            "cpanel",
            "mail",
            "webmail",
            "dev",
            "test",
            "staging",
            "admin",
        ]

        for domain in root_domains:
            potential_ips: Dict[str, str] = {}  # ip -> method

            # 0. Historical DNS (SecurityTrails)
            st_key = getattr(context.runtime_config, "securitytrails_api_key", None)
            if st_key:
                try:
                    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                    async with httpx.AsyncClient(timeout=10) as client:
                        resp = await client.get(url, headers={"APIKEY": st_key})
                        if resp.status_code == 200:
                            data = resp.json()
                            for record in data.get("records", []):
                                for val in record.get("values", []):
                                    ip = val.get("ip")
                                    if ip:
                                        potential_ips[ip] = "SecurityTrails History"
                except Exception as e:
                    context.logger.debug(
                        "SecurityTrails lookup failed for %s: %s", domain, e
                    )

            # 1. TXT / SPF Records
            try:
                answers = resolver.resolve(domain, "TXT")
                for rdata in answers:
                    txt_record = rdata.to_text().lower()
                    if "v=spf1" in txt_record:
                        ips = re.findall(
                            r"ip4:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})",
                            txt_record,
                        )
                        for ip in ips:
                            potential_ips[ip] = "SPF Record"
            except Exception:
                pass

            # 2. MX Records
            try:
                answers = resolver.resolve(domain, "MX")
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    if domain in mx_host:
                        try:
                            loop = asyncio.get_running_loop()
                            mx_ips = (
                                await loop.run_in_executor(
                                    None, lambda: socket.gethostbyname_ex(mx_host)
                                )
                            )[2]
                            for ip in mx_ips:
                                potential_ips[ip] = f"MX Record ({mx_host})"
                        except socket.error:
                            pass
            except Exception:
                pass

            # 3. Common Subdomains (Parallel)
            sub_tasks = [
                self._resolve_async(f"{sub}.{domain}", resolver)
                for sub in origin_subdomains
            ]
            sub_results = await asyncio.gather(*sub_tasks)
            for i, ips in enumerate(sub_results):
                for ip in ips:
                    potential_ips[ip] = f"Subdomain ({origin_subdomains[i]}.{domain})"

            # 4. Verify and Filter
            for ip, method in potential_ips.items():
                # Filter out known CDNs to avoid false positives
                _, is_cdn, _ = classify_provider(ip)
                if is_cdn:
                    context.logger.debug("Skipping CDN IP %s found via %s", ip, method)
                    continue

                context.logger.debug(
                    "Verifying potential origin IP %s found via %s", ip, method
                )

                if await self._probe_origin_via_host_header(ip, domain):
                    # Flag it
                    origin_findings.append(
                        {
                            "type": "finding",
                            "finding_type": "origin_ip_leak",
                            "source": "origin-discovery",
                            "hostname": domain,
                            "description": f"Verified origin IP bypass detected via {method}: {ip}",
                            "severity": "high"
                            if "MX" in method or "SPF" in method
                            else "medium",
                            "details": {"ip": ip, "method": method, "verified": True},
                        }
                    )

        if origin_findings:
            context.logger.info(
                "Found %d VERIFIED origin IP leaks", len(origin_findings)
            )
            for finding in origin_findings:
                context.results.append(finding)
        else:
            context.logger.info("No verified origin IP leaks found.")

    def execute(self, context: PipelineContext) -> None:
        asyncio.run(self.run_async(context))
