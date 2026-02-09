from __future__ import annotations

import json
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import validation
from recon_cli.utils.jsonl import read_jsonl


class CTPivotStage(Stage):
    name = "ct_asn_pivot"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_ct_pivot", False)) or bool(
            getattr(context.runtime_config, "enable_asn_pivot", False)
        )

    def execute(self, context: PipelineContext) -> None:
        ct_enabled = bool(getattr(context.runtime_config, "enable_ct_pivot", False))
        asn_enabled = bool(getattr(context.runtime_config, "enable_asn_pivot", False))

        if not ct_enabled and not asn_enabled:
            return

        try:
            import requests
        except Exception:
            context.logger.warning("ct/asn pivot requires requests; skipping")
            return

        if ct_enabled:
            self._run_ct_pivot(context, requests)
        if asn_enabled:
            self._run_asn_pivot(context, requests)

    def _run_ct_pivot(self, context: PipelineContext, requests_mod) -> None:
        runtime = context.runtime_config
        max_domains = int(getattr(runtime, "ct_max_domains", 15))
        max_names = int(getattr(runtime, "ct_max_names", 200))
        timeout = int(getattr(runtime, "ct_timeout", 10))
        limiter = context.get_rate_limiter(
            "ct_pivot",
            rps=float(getattr(runtime, "ct_rps", 0)),
            per_host=float(getattr(runtime, "ct_per_host_rps", 0)),
        )

        roots = self._root_domains(context)
        if not roots:
            context.logger.info("No domains available for CT pivot")
            return

        discovered: Set[str] = set()
        for root in roots[:max_domains]:
            url = f"https://crt.sh/?q=%25.{root}&output=json"
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            try:
                resp = requests_mod.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "recon-cli ct-pivot"},
                    verify=context.runtime_config.verify_tls,
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)
            if resp.status_code >= 400:
                continue
            try:
                entries = resp.json()
            except json.JSONDecodeError:
                continue
            if not isinstance(entries, list):
                continue
            for entry in entries:
                name_value = entry.get("name_value") if isinstance(entry, dict) else None
                if not isinstance(name_value, str):
                    continue
                for raw_name in name_value.splitlines():
                    candidate = raw_name.strip().lstrip("*.").lower()
                    if not candidate or not candidate.endswith(root):
                        continue
                    try:
                        normalized = validation.normalize_hostname(candidate)
                    except ValueError:
                        continue
                    discovered.add(normalized)
                    if len(discovered) >= max_names:
                        break
                if len(discovered) >= max_names:
                    break
            if len(discovered) >= max_names:
                break

        added = 0
        for host in sorted(discovered):
            signal_id = context.emit_signal(
                "ct_discovery",
                "host",
                host,
                confidence=0.4,
                source="ct-pivot",
                tags=["ct"],
            )
            payload = {
                "type": "hostname",
                "source": "ct",
                "hostname": host,
                "score": 20,
                "tags": ["ct"],
                "evidence_id": signal_id or None,
            }
            if context.results.append(payload):
                added += 1

        stats = context.record.metadata.stats.setdefault("ct_pivot", {})
        stats["roots"] = min(len(roots), max_domains)
        stats["discovered"] = len(discovered)
        stats["added"] = added
        context.manager.update_metadata(context.record)

    def _run_asn_pivot(self, context: PipelineContext, requests_mod) -> None:
        runtime = context.runtime_config
        max_asn = int(getattr(runtime, "asn_max", 10))
        max_prefixes = int(getattr(runtime, "asn_prefix_max", 120))
        timeout = int(getattr(runtime, "asn_timeout", 10))
        limiter = context.get_rate_limiter(
            "asn_pivot",
            rps=float(getattr(runtime, "asn_rps", 0)),
            per_host=float(getattr(runtime, "asn_per_host_rps", 0)),
        )

        asns = self._collect_asns(context)
        if not asns:
            context.logger.info("No ASN data available for pivot")
            return

        prefixes_added = 0
        prefixes_total = 0
        for asn in asns[:max_asn]:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            try:
                resp = requests_mod.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "recon-cli asn-pivot"},
                    verify=context.runtime_config.verify_tls,
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)
            if resp.status_code >= 400:
                continue
            data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
            prefixes = []
            if isinstance(data, dict):
                payload = data.get("data") if isinstance(data.get("data"), dict) else {}
                v4 = payload.get("ipv4_prefixes") or []
                v6 = payload.get("ipv6_prefixes") or []
                if isinstance(v4, list):
                    prefixes.extend(v4)
                if isinstance(v6, list):
                    prefixes.extend(v6)
            for item in prefixes:
                prefix = item.get("prefix") if isinstance(item, dict) else None
                if not prefix:
                    continue
                prefixes_total += 1
                signal_id = context.emit_signal(
                    "asn_prefix",
                    "ip_prefix",
                    prefix,
                    confidence=0.3,
                    source="asn-pivot",
                    tags=[f"asn:{asn}"],
                )
                payload = {
                    "type": "ip_prefix",
                    "source": "asn-pivot",
                    "prefix": prefix,
                    "asn": asn,
                    "tags": ["asn", f"asn:{asn}"],
                    "evidence_id": signal_id or None,
                }
                if context.results.append(payload):
                    prefixes_added += 1
                if max_prefixes > 0 and prefixes_added >= max_prefixes:
                    break
            if max_prefixes > 0 and prefixes_added >= max_prefixes:
                break

        stats = context.record.metadata.stats.setdefault("asn_pivot", {})
        stats["asns"] = min(len(asns), max_asn)
        stats["prefixes"] = prefixes_total
        stats["added"] = prefixes_added
        context.manager.update_metadata(context.record)

    def _root_domains(self, context: PipelineContext) -> List[str]:
        roots: Set[str] = set()
        for entry in read_jsonl(context.record.paths.results_jsonl):
            etype = entry.get("type")
            if etype == "hostname":
                host = entry.get("hostname")
            elif etype == "url":
                url = entry.get("url")
                if isinstance(url, str):
                    host = urlparse(url).hostname
                else:
                    host = None
            else:
                host = None
            if not isinstance(host, str) or not host:
                continue
            root = self._root_domain(host)
            if root:
                roots.add(root)
        return sorted(roots)

    def _collect_asns(self, context: PipelineContext) -> List[str]:
        asns: Set[str] = set()
        enrichment = context.record.paths.artifact("ip_enrichment.json")
        if enrichment.exists():
            try:
                data = json.loads(enrichment.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                for entries in data.values():
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        asn = entry.get("asn")
                        if asn:
                            asns.add(str(asn).replace("AS", ""))
        return sorted(asns)

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
