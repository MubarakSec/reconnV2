from __future__ import annotations

import re
import socket
import dns.resolver
from typing import List, Set, Dict, Any

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage

class OriginDiscoveryStage(Stage):
    """
    Advanced Origin IP Discovery Stage
    Attempts to bypass CDNs and find origin IPs by:
    1. Extracting SPF/TXT records for IPv4 addresses.
    2. Resolving MX records to check if email is hosted on origin.
    3. Brute-forcing common origin subdomains (direct, origin, mail, ftp).
    """
    name = "origin_discovery"

    def execute(self, context: PipelineContext) -> None:
        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts for origin discovery")
            return

        # Extract root domains to avoid repeating lookups on every subdomain
        root_domains: Set[str] = set()
        with hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if not host:
                    continue
                parts = host.split(".")
                # Rough heuristic for root domains (e.g. example.com, example.co.uk)
                if len(parts) > 2:
                    if parts[-2] in {"co", "com", "net", "org"} and len(parts[-1]) == 2:
                        root_domains.add(".".join(parts[-3:]))
                    else:
                        root_domains.add(".".join(parts[-2:]))
                else:
                    root_domains.add(host)

        if not root_domains:
            return

        context.logger.info("Starting advanced origin IP discovery on %d root domains", len(root_domains))
        
        origin_findings: List[Dict[str, Any]] = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        # Common subdomains that often bypass CDN
        origin_subdomains = ["direct", "origin", "ftp", "cpanel", "mail", "webmail", "dev", "test", "staging", "admin"]

        for domain in root_domains:
            # 1. TXT / SPF Records
            try:
                answers = resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt_record = rdata.to_text().lower()
                    if "v=spf1" in txt_record:
                        # Extract ip4 mechanisms
                        ips = re.findall(r"ip4:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", txt_record)
                        for ip in ips:
                            origin_findings.append({
                                "type": "finding",
                                "finding_type": "origin_ip_leak",
                                "source": "origin-discovery",
                                "hostname": domain,
                                "description": f"Potential origin IP leaked in SPF record: {ip}",
                                "severity": "medium",
                                "details": {"ip": ip, "method": "SPF Record", "record": txt_record}
                            })
            except Exception as e:
                context.logger.debug(f"TXT resolution failed for {domain}: {e}")

            # 2. MX Records
            try:
                answers = resolver.resolve(domain, 'MX')
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    # Only care if the MX record is a subdomain of the target (self-hosted)
                    if domain in mx_host:
                        try:
                            mx_ips = socket.gethostbyname_ex(mx_host)[2]
                            for ip in mx_ips:
                                origin_findings.append({
                                    "type": "finding",
                                    "finding_type": "origin_ip_leak",
                                    "source": "origin-discovery",
                                    "hostname": mx_host,
                                    "description": f"Potential origin IP leaked via self-hosted MX record: {ip}",
                                    "severity": "high",
                                    "details": {"ip": ip, "method": "MX Record"}
                                })
                        except socket.error:
                            pass
            except Exception as e:
                context.logger.debug(f"MX resolution failed for {domain}: {e}")

            # 3. Common Origin Subdomains Brute-Force
            for sub in origin_subdomains:
                target_sub = f"{sub}.{domain}"
                try:
                    ips = socket.gethostbyname_ex(target_sub)[2]
                    for ip in ips:
                        origin_findings.append({
                            "type": "finding",
                            "finding_type": "origin_ip_leak",
                            "source": "origin-discovery",
                            "hostname": target_sub,
                            "description": f"Potential origin IP exposed via direct subdomain: {ip}",
                            "severity": "medium",
                            "details": {"ip": ip, "method": "Common Subdomain"}
                        })
                except socket.error:
                    pass

        if origin_findings:
            context.logger.info("Found %d potential origin IP leaks", len(origin_findings))
            for finding in origin_findings:
                context.results.append(finding)
        else:
            context.logger.info("No origin IP leaks found.")
