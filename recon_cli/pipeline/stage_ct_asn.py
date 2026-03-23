from __future__ import annotations

import json
import asyncio
import socket
from typing import List, Set, Dict, Any, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import validation
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class CTPivotStage(Stage):
    name = "ct_asn_pivot"

    def is_enabled(self, context: PipelineContext) -> bool:
        runtime = context.runtime_config
        return bool(getattr(runtime, "enable_ct_pivot", False)) or \
               bool(getattr(runtime, "enable_asn_pivot", False)) or \
               bool(getattr(runtime, "enable_reverse_whois", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        ct_enabled = bool(getattr(runtime, "enable_ct_pivot", False))
        asn_enabled = bool(getattr(runtime, "enable_asn_pivot", False))
        whois_enabled = bool(getattr(runtime, "enable_reverse_whois", False))

        if not any([ct_enabled, asn_enabled, whois_enabled]): return

        config = HTTPClientConfig(
            max_concurrent=10,
            total_timeout=15.0,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=5.0
        )

        async with AsyncHTTPClient(config) as client:
            tasks = []
            if ct_enabled: tasks.append(self._run_ct_pivot(context, client))
            if asn_enabled: tasks.append(self._run_asn_pivot(context, client))
            if whois_enabled: tasks.append(self._run_reverse_whois(context, client))
            
            if tasks: await asyncio.gather(*tasks)

        # Always run bulk ASN for any new IPs found (socket-based)
        await self._run_bulk_asn_lookup(context)

    async def _run_reverse_whois(self, context: PipelineContext, client: AsyncHTTPClient) -> None:
        api_key = getattr(context.runtime_config, "viewdns_api_key", None)
        if not api_key: return

        roots = self._root_domains(context)
        for root in roots:
            url = f"https://viewdns.info/reversewhois/?q={root}&apikey={api_key}&output=json"
            try:
                resp = await client.get(url)
                if resp.status == 200: pass # Placeholder for future expansion
            except Exception: pass

    async def _run_bulk_asn_lookup(self, context: PipelineContext) -> None:
        ips = {r.get("ip") for r in context.filter_results("hostname") if r.get("ip") and validation.is_ip(r["ip"])}
        if not ips: return

        context.logger.info("Performing bulk ASN lookup for %d IPs", len(ips))
        loop = asyncio.get_event_loop()
        try:
            # Run socket operation in thread to avoid blocking loop
            response = await loop.run_in_executor(None, self._sync_socket_whois, list(ips))
            if not response: return

            for line in response.splitlines():
                if "|" not in line or line.startswith("AS"): continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    context.results.append({
                        "type": "asset_enrichment", "source": "team-cymru",
                        "ip": parts[1], "asn": parts[0], "bgp_prefix": parts[2],
                        "tags": ["asn", f"asn:{parts[0]}"],
                    })
        except Exception: pass

    def _sync_socket_whois(self, ips: List[str]) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(("whois.cymru.com", 43))
                s.sendall(b"begin\nverbose\n" + "\n".join(ips).encode() + b"\nend\n")
                res = b""
                while True:
                    data = s.recv(4096)
                    if not data: break
                    res += data
                return res.decode()
        except Exception: return ""

    async def _run_ct_pivot(self, context: PipelineContext, client: AsyncHTTPClient) -> None:
        runtime = context.runtime_config
        max_domains = int(getattr(runtime, "ct_max_domains", 15))
        max_names = int(getattr(runtime, "ct_max_names", 200))
        roots = self._root_domains(context)
        if not roots: return

        discovered: Set[str] = set()
        for root in roots[:max_domains]:
            url = f"https://crt.sh/?q=%25.{root}&output=json"
            try:
                resp = await client.get(url, headers={"User-Agent": "recon-cli ct-pivot"})
                if resp.status >= 400: continue
                entries = json.loads(resp.body)
                if not isinstance(entries, list): continue
                for entry in entries:
                    nv = entry.get("name_value") if isinstance(entry, dict) else None
                    if not isinstance(nv, str): continue
                    for rn in nv.splitlines():
                        cand = rn.strip().lstrip("*.").lower()
                        if cand and cand.endswith(root):
                            try:
                                discovered.add(validation.normalize_hostname(cand))
                            except ValueError: continue
                    if len(discovered) >= max_names: break
            except Exception: continue
            if len(discovered) >= max_names: break

        added = 0
        for host in sorted(discovered):
            signal_id = context.emit_signal("ct_discovery", "host", host, confidence=0.4, source=self.name, tags=["ct"])
            if context.results.append({"type": "hostname", "source": "ct", "hostname": host, "score": 20, "tags": ["ct"], "evidence_id": signal_id or None}):
                added += 1

        stats = context.record.metadata.stats.setdefault("ct_pivot", {})
        stats.update({"roots": min(len(roots), max_domains), "discovered": len(discovered), "added": added})

    async def _run_asn_pivot(self, context: PipelineContext, client: AsyncHTTPClient) -> None:
        runtime = context.runtime_config
        max_asn, max_prefixes = int(getattr(runtime, "asn_max", 10)), int(getattr(runtime, "asn_prefix_max", 120))
        asns = self._collect_asns(context)
        if not asns: return

        prefixes_added, prefixes_total = 0, 0
        for asn in asns[:max_asn]:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            try:
                resp = await client.get(url, headers={"User-Agent": "recon-cli asn-pivot"})
                if resp.status >= 400: continue
                data = json.loads(resp.body)
                prefixes = []
                if isinstance(data, dict):
                    pl = data.get("data") if isinstance(data.get("data"), dict) else {}
                    v4, v6 = pl.get("ipv4_prefixes") or [], pl.get("ipv6_prefixes") or []
                    prefixes.extend(v4 if isinstance(v4, list) else [])
                    prefixes.extend(v6 if isinstance(v6, list) else [])
                
                for item in prefixes:
                    prefix = item.get("prefix") if isinstance(item, dict) else None
                    if not prefix: continue
                    prefixes_total += 1
                    signal_id = context.emit_signal("asn_prefix", "ip_prefix", prefix, confidence=0.3, source=self.name, tags=[f"asn:{asn}"])
                    if context.results.append({"type": "ip_prefix", "source": "asn-pivot", "prefix": prefix, "asn": asn, "tags": ["asn", f"asn:{asn}"], "evidence_id": signal_id or None}):
                        prefixes_added += 1
                    if max_prefixes > 0 and prefixes_added >= max_prefixes: break
            except Exception: continue
            if max_prefixes > 0 and prefixes_added >= max_prefixes: break

        stats = context.record.metadata.stats.setdefault("asn_pivot", {})
        stats.update({"asns": min(len(asns), max_asn), "prefixes": prefixes_total, "added": prefixes_added})

    def _root_domains(self, context: PipelineContext) -> List[str]:
        roots: Set[str] = set()
        for r in context.filter_results("hostname"):
            h = r.get("hostname") or (r.get("url") and urlparse(r["url"]).hostname)
            if h: roots.add(self._root_domain(h))
        return sorted(list(roots))

    def _collect_asns(self, context: PipelineContext) -> List[str]:
        asns: Set[str] = set()
        enrichment = context.record.paths.artifact("ip_enrichment.json")
        if enrichment.exists():
            try:
                data = json.loads(enrichment.read_text(encoding="utf-8"))
                for entries in data.values():
                    for entry in entries:
                        if entry.get("asn"): asns.add(str(entry["asn"]).replace("AS", ""))
            except Exception: pass
        return sorted(list(asns))

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
