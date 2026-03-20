from __future__ import annotations

from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.takeover import TakeoverDetector
from recon_cli.takeover.detector import TAKEOVER_FINGERPRINTS
from recon_cli.utils import validation
from recon_cli.utils.jsonl import iter_jsonl

try:
    import dns.resolver
except Exception:  # pragma: no cover - optional dependency
    dns = None


class TakeoverStage(Stage):
    name = "takeover_check"
    MAX_CNAME_DEPTH = 5

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_takeover", False))

    async def run_async(self, context: PipelineContext) -> None:
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return

        max_hosts = int(getattr(context.runtime_config, "takeover_max_hosts", 50))
        if max_hosts <= 0:
            return

        timeout = int(getattr(context.runtime_config, "takeover_timeout", 6))
        require_cname = bool(
            getattr(context.runtime_config, "takeover_require_cname", False)
        )
        dns_timeout = max(
            1, int(getattr(context.runtime_config, "takeover_dns_timeout", timeout))
        )
        verify_tls = bool(getattr(context.runtime_config, "verify_tls", True))
        detector = TakeoverDetector(timeout=timeout, verify_tls=verify_tls)

        hosts: List[str] = []
        seen = set()
        for entry in iter_jsonl(results_path):
            hostname = entry.get("hostname") or entry.get("host")
            if not hostname:
                url_value = entry.get("url")
                if isinstance(url_value, str):
                    try:
                        hostname = urlparse(url_value).hostname
                    except ValueError:
                        hostname = None
            if not hostname:
                continue
            try:
                normalized = validation.normalize_hostname(str(hostname))
            except ValueError:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            hosts.append(normalized)

        if not hosts:
            return

        # Wildcard DNS detection
        root_domains = {".".join(h.split(".")[-2:]) for h in hosts[:max_hosts]}
        wildcard_domains = {
            d for d in root_domains if self._has_wildcard_dns(d, dns_timeout)
        }
        if wildcard_domains:
            context.logger.warning("Wildcard DNS detected for: %s", wildcard_domains)
            hosts = [
                h for h in hosts if ".".join(h.split(".")[-2:]) not in wildcard_domains
            ]

        if not hosts:
            return

        checked = 0
        findings = 0
        skipped_no_cname = 0
        cname_matches = 0
        suppressed_low_confidence = 0
        if require_cname and dns is None:
            context.logger.warning(
                "dnspython not available; skipping takeover checks (require_cname enabled)"
            )
            note_missing_tool(context, "dnspython")
            stats = context.record.metadata.stats.setdefault("takeover", {})
            stats["checked"] = 0
            stats["findings"] = 0
            stats["max_hosts"] = max_hosts
            stats["skipped_no_dns"] = min(len(hosts), max_hosts)
            context.manager.update_metadata(context.record)
            return

        for host in hosts[:max_hosts]:
            checked += 1
            cname_chain = (
                self._resolve_cname_chain(host, dns_timeout) if dns is not None else []
            )
            if require_cname and not cname_chain:
                skipped_no_cname += 1
                continue
            dns_state = self._evaluate_dns_state(host, cname_chain, dns_timeout)
            providers = self._match_providers(cname_chain)
            if providers:
                cname_matches += 1
            
            try:
                finding = await detector.check_host(
                    host, providers=providers if providers else None
                )
            except Exception as e:
                context.logger.debug("Takeover check failed for %s: %s", host, e)
                continue

            if not finding:
                continue
            claimability = self._assess_claimability(
                finding.provider, providers, dns_state
            )
            if claimability["level"] == "low" and finding.finding_type == "subdomain_takeover":
                suppressed_low_confidence += 1
                continue
            payload = {
                "type": "finding",
                "finding_type": finding.finding_type,
                "source": "takeover-check",
                "hostname": finding.hostname,
                "description": f"Potential {finding.finding_type.replace('_', ' ')} detected ({claimability['level']} claimability)" if finding.finding_type == "subdomain_takeover" else "Parked domain / Domain for sale detected",
                "details": {
                    "provider": finding.provider,
                    "evidence": finding.evidence,
                    "cname_chain": cname_chain,
                    "status_code": int(getattr(finding, "status_code", 0) or 0),
                    "matched_url": str(getattr(finding, "matched_url", "") or ""),
                    "dns_state": dns_state,
                    "claimability": claimability,
                },
                "tags": [
                    "takeover",
                    "subdomain",
                    f"provider:{finding.provider}",
                    f"claimability:{claimability['level']}",
                ],
                "score": int(claimability["score"]),
                "priority": str(claimability["priority"]),
                "severity": str(claimability["severity"]),
                "confidence_label": str(claimability["confidence"]),
            }
            if finding.finding_type == "parking_page":
                payload["tags"].append("parking")
                payload["score"] = 30
                payload["priority"] = "low"
                payload["severity"] = "low"

            if claimability["level"] == "high":
                payload["tags"].append("confirmed")
            if context.results.append(payload):
                findings += 1

        stats = context.record.metadata.stats.setdefault("takeover", {})
        stats["checked"] = checked
        stats["findings"] = findings
        stats["max_hosts"] = max_hosts
        stats["suppressed_low_confidence"] = suppressed_low_confidence
        if require_cname:
            stats["skipped_no_cname"] = skipped_no_cname
        if cname_matches:
            stats["cname_matches"] = cname_matches
        context.manager.update_metadata(context.record)

    def execute(self, context: PipelineContext) -> None:
        import asyncio
        asyncio.run(self.run_async(context))

    def _resolve_cname_chain(self, hostname: str, timeout: int) -> List[str]:
        if dns is None:
            return []
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        chain: List[str] = []
        current = hostname
        seen = set()
        for _ in range(self.MAX_CNAME_DEPTH):
            try:
                answers = resolver.resolve(current, "CNAME")
            except Exception:
                break
            next_name: Optional[str] = None
            for rdata in answers:
                cname = str(rdata).rstrip(".").lower()
                if cname in seen:
                    continue
                next_name = cname
                chain.append(cname)
                seen.add(cname)
                break
            if not next_name:
                break
            current = next_name
        return chain

    def _evaluate_dns_state(
        self, hostname: str, cname_chain: List[str], timeout: int
    ) -> Dict[str, object]:
        if dns is None:
            return {"state": "unknown", "dangling": False, "target": hostname}
        target = cname_chain[-1] if cname_chain else hostname
        resolved = self._target_has_address(target, timeout)
        if cname_chain:
            state = "cname_resolved" if resolved else "cname_unresolved"
        else:
            state = "resolved" if resolved else "unresolved"
        return {"state": state, "dangling": not resolved, "target": target}

    def _target_has_address(self, hostname: str, timeout: int) -> bool:
        if dns is None:
            return False
        try:
            resolver = dns.resolver.Resolver()
        except Exception:
            return False
        if hasattr(resolver, "timeout"):
            resolver.timeout = timeout
        if hasattr(resolver, "lifetime"):
            resolver.lifetime = timeout
        if not hasattr(resolver, "resolve"):
            return False
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname, record_type)
            except Exception:
                continue
            for _ in answers:
                return True
        return False

    def _assess_claimability(
        self, provider: str, providers: Set[str], dns_state: Dict[str, object]
    ) -> Dict[str, object]:
        dns_provider_match = bool(providers and provider in providers)
        dns_dangling = bool(dns_state.get("dangling"))
        if dns_provider_match and dns_dangling:
            return {
                "level": "high",
                "confidence": "verified",
                "score": 95,
                "priority": "critical",
                "severity": "critical",
            }
        if dns_provider_match or dns_dangling:
            return {
                "level": "medium",
                "confidence": "high",
                "score": 86,
                "priority": "high",
                "severity": "high",
            }
        return {
            "level": "low",
            "confidence": "medium",
            "score": 70,
            "priority": "medium",
            "severity": "medium",
        }

    @staticmethod
    def _cname_matches_pattern(cname: str, pattern: str) -> bool:
        """Match cname as a subdomain/exact match of pattern, not arbitrary substring."""
        cname = cname.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        return cname == pattern or cname.endswith("." + pattern)

    def _has_wildcard_dns(self, domain: str, timeout: int) -> bool:
        """Detect wildcard DNS by resolving a random nonexistent subdomain."""
        import uuid
        test_host = f"{uuid.uuid4().hex[:8]}.{domain}"
        return self._target_has_address(test_host, timeout)

    def _match_providers(self, cname_chain: List[str]) -> Set[str]:
        providers: Set[str] = set()
        if not cname_chain:
            return providers
        for fp in TAKEOVER_FINGERPRINTS:
            patterns = fp.get("cname") or []
            for pattern in patterns:
                for cname in cname_chain:
                    if self._cname_matches_pattern(cname, pattern):
                        providers.add(fp.get("provider", ""))
                        break
        providers.discard("")
        return providers
