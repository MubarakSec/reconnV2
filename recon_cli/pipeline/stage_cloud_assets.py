from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


@dataclass
class CloudCheck:
    provider: str
    url: str
    bucket: str
    exists: bool
    public: bool
    status: int
    reason: str


class CloudAssetDiscoveryStage(Stage):
    name = "cloud_asset_discovery"

    PUBLIC_STATUSES = {200, 206}
    EXISTS_STATUSES = {200, 206, 301, 302, 307, 308, 401, 403}
    NOT_FOUND_STATUSES = {400, 404}
    S3_KEYWORDS = ("NoSuchBucket", "AccessDenied", "AllAccessDisabled", "ListBucketResult")
    GCS_KEYWORDS = ("NoSuchBucket", "AccessDenied", "Bucket", "ListBucketResult")
    AZURE_KEYWORDS = ("ResourceNotFound", "AuthenticationFailed", "Container", "Blob")

    ORG_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_cloud_discovery", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("cloud discovery requires requests; skipping")
            return

        runtime = context.runtime_config
        max_checks = int(getattr(runtime, "cloud_max_checks", 400))
        timeout = int(getattr(runtime, "cloud_timeout", 8))
        max_duration = max(0, int(getattr(runtime, "cloud_max_duration", 1200)))
        progress_every = max(1, int(getattr(runtime, "cloud_progress_every", 50)))
        limiter = context.get_rate_limiter(
            "cloud_asset",
            rps=float(getattr(runtime, "cloud_rps", 0)),
            per_host=float(getattr(runtime, "cloud_per_host_rps", 0)),
        )

        buckets = self._generate_candidates(context)
        if not buckets:
            context.logger.info("No cloud asset candidates generated")
            return
        checks_plan = self._build_checks(buckets)
        planned_checks = len(checks_plan)
        if max_checks > 0:
            planned_checks = min(planned_checks, max_checks)

        checks: List[CloudCheck] = []
        public_findings = 0
        exists_only = 0
        checked = 0
        duration_cap_hit = False
        stage_started = time.monotonic()

        context.logger.info(
            "Cloud asset discovery checks=%s duration_cap=%ss progress_every=%d",
            planned_checks if max_checks > 0 else "unlimited",
            max_duration if max_duration else "unlimited",
            progress_every,
        )

        for provider, url, bucket in checks_plan:
            if max_checks > 0 and checked >= max_checks:
                break
            elapsed = time.monotonic() - stage_started
            if max_duration and elapsed >= max_duration:
                duration_cap_hit = True
                context.logger.warning("Cloud discovery duration cap reached (%ss); stopping stage", max_duration)
                break
            checked += 1
            if checked % progress_every == 0:
                context.logger.info(
                    "Cloud discovery progress: checked=%d public=%d exists_only=%d elapsed=%.1fs",
                    checked,
                    public_findings,
                    exists_only,
                    elapsed,
                )
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers={"User-Agent": "recon-cli cloud-discovery"},
                )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)
            status = int(resp.status_code or 0)
            body = (resp.text or "")[:1200]

            exists, public, reason = self._classify(provider, status, body)
            if not exists:
                continue
            checks.append(CloudCheck(provider, url, bucket, exists, public, status, reason))

            tags = [f"cloud:{provider}", "cloud-asset"]
            if public:
                tags.append("public")
                tags.append("exposed")
                signal_id = context.emit_signal(
                    "cloud_asset_public",
                    "url",
                    url,
                    confidence=0.7,
                    source="cloud-discovery",
                    tags=tags,
                    evidence={"status": status, "reason": reason, "bucket": bucket},
                )
                finding = {
                    "type": "finding",
                    "source": "cloud-discovery",
                    "finding_type": "cloud_asset_public",
                    "description": f"Public cloud asset detected ({provider})",
                    "url": url,
                    "details": {"bucket": bucket, "provider": provider, "status": status, "reason": reason},
                    "tags": tags,
                    "score": 80,
                    "priority": "high",
                    "evidence_id": signal_id or None,
                }
                if context.results.append(finding):
                    public_findings += 1
            else:
                context.emit_signal(
                    "cloud_asset_exists",
                    "url",
                    url,
                    confidence=0.4,
                    source="cloud-discovery",
                    tags=tags,
                    evidence={"status": status, "reason": reason, "bucket": bucket},
                )
                exists_only += 1

        stats = context.record.metadata.stats.setdefault("cloud_assets", {})
        stats.update(
            {
                "checked": checked,
                "public": public_findings,
                "exists_only": exists_only,
                "duration_cap_seconds": max_duration,
                "duration_cap_hit": duration_cap_hit,
            }
        )
        context.manager.update_metadata(context.record)

    def _generate_candidates(self, context: PipelineContext) -> List[str]:
        hosts: Set[str] = set()
        org_tokens: Set[str] = set()
        enrichment_artifact = context.record.paths.artifact("ip_enrichment.json")
        if enrichment_artifact.exists():
            try:
                import json as _json

                enrichment_map = _json.loads(enrichment_artifact.read_text(encoding="utf-8"))
            except Exception:
                enrichment_map = {}
            for entries in enrichment_map.values():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    org = entry.get("org")
                    if isinstance(org, str):
                        org_tokens.update(self._extract_tokens(org))
        for entry in read_jsonl(context.record.paths.results_jsonl):
            etype = entry.get("type")
            if etype == "hostname":
                host = entry.get("hostname")
            elif etype == "url":
                url = entry.get("url")
                host = urlparse(url).hostname if isinstance(url, str) else None
            else:
                host = None
            if isinstance(host, str) and host:
                hosts.add(host.lower())

        candidates: Set[str] = set()
        for host in hosts:
            root = self._root_domain(host)
            candidates.update(self._host_variants(host, root))
        for token in org_tokens:
            candidates.add(token)
            candidates.add(token.replace(" ", "-"))
        return sorted(candidates)

    def _build_checks(self, buckets: List[str]) -> List[Tuple[str, str, str]]:
        checks: List[Tuple[str, str, str]] = []
        for bucket in buckets:
            if not bucket or len(bucket) < 3:
                continue
            safe = bucket.lower()
            checks.append(("s3", f"https://{safe}.s3.amazonaws.com/", safe))
            checks.append(("gcs", f"https://storage.googleapis.com/{safe}", safe))
            checks.append(("gcs", f"https://{safe}.storage.googleapis.com/", safe))
            checks.append(("azure", f"https://{safe}.blob.core.windows.net/", safe))
        return checks

    def _classify(self, provider: str, status: int, body: str) -> Tuple[bool, bool, str]:
        if status in self.NOT_FOUND_STATUSES:
            return False, False, "not_found"
        keywords = self._keywords_for(provider)
        if status in self.PUBLIC_STATUSES:
            if any(keyword.lower() in body.lower() for keyword in keywords):
                return True, True, "public_listing"
            return True, True, "public_response"
        if status in self.EXISTS_STATUSES:
            if any(keyword.lower() in body.lower() for keyword in keywords):
                return True, False, "access_denied"
            return True, False, "exists"
        return False, False, "unknown"

    @staticmethod
    def _keywords_for(provider: str) -> Sequence[str]:
        if provider == "s3":
            return CloudAssetDiscoveryStage.S3_KEYWORDS
        if provider == "gcs":
            return CloudAssetDiscoveryStage.GCS_KEYWORDS
        if provider == "azure":
            return CloudAssetDiscoveryStage.AZURE_KEYWORDS
        return ()

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    def _host_variants(self, host: str, root: str) -> Set[str]:
        variants: Set[str] = set()
        root_dash = root.replace(".", "-")
        root_label = root.split(".")[0]
        sub = host.split(".")[0]
        for item in {root, root_dash, root_label, host.replace(".", "-"), sub, f"{sub}-{root_label}"}:
            if item:
                variants.add(item)
        return variants

    def _extract_tokens(self, org: str) -> Set[str]:
        tokens = set()
        lowered = org.lower()
        for match in self.ORG_TOKEN_RE.findall(lowered):
            if len(match) >= 3:
                tokens.add(match)
        return tokens
