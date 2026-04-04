from __future__ import annotations

import re
import asyncio
import time
import json
from dataclasses import dataclass
from typing import List, Sequence, Set, Tuple, Dict, Any, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig, HTTPResponse


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
    S3_KEYWORDS = (
        "NoSuchBucket",
        "AccessDenied",
        "AllAccessDisabled",
        "ListBucketResult",
    )
    GCS_KEYWORDS = ("NoSuchBucket", "AccessDenied", "Bucket", "ListBucketResult")
    AZURE_KEYWORDS = ("ResourceNotFound", "AuthenticationFailed", "Container", "Blob")

    ORG_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_cloud_discovery", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_checks = int(getattr(runtime, "cloud_max_checks", 400))
        timeout = int(getattr(runtime, "cloud_timeout", 8))
        max_duration = max(0, int(getattr(runtime, "cloud_max_duration", 1200)))
        
        buckets = self._generate_candidates(context)
        if not buckets:
            context.logger.info("No cloud asset candidates generated")
            return
        checks_plan = self._build_checks(buckets)
        if max_checks > 0:
            checks_plan = checks_plan[:max_checks]

        context.logger.info("Starting async cloud discovery on %d targets", len(checks_plan))
        
        
        # Calculate a more realistic total timeout
        estimated_time = (len(checks_plan) / getattr(runtime, "cloud_rps", 50.0)) + timeout
        total_timeout = min(max(estimated_time, timeout * 5), max_duration or 1200)

        config = HTTPClientConfig(
            max_concurrent=30,
            total_timeout=total_timeout,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=float(getattr(runtime, "cloud_rps", 50.0))
        )

        public_findings, exists_only, checked = 0, 0, 0
        stage_started = time.monotonic()

        async with AsyncHTTPClient(config, context=context) as client:
            # Group into smaller batches for gather to avoid hitting local limits
            batch_size = 50
            for i in range(0, len(checks_plan), batch_size):
                if max_duration and (time.monotonic() - stage_started) >= max_duration:
                    break
                
                batch = checks_plan[i:i+batch_size]
                tasks = [client.get(url, headers={"User-Agent": "recon-cli cloud-discovery"}, follow_redirects=True) for _, url, _ in batch]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                for (provider, url, bucket), resp in zip(batch, responses):
                    checked += 1
                    if isinstance(resp, Exception): continue
                    
                    status = resp.status
                    body = resp.body[:1200]
                    headers = {k.lower(): str(v) for k, v in resp.headers.items()}

                    exists, public, reason = self._classify(provider, status, body, headers)
                    if not exists: continue

                    tags = [f"cloud:{provider}", "cloud-asset"]
                    if public:
                        tags.extend(["public", "exposed"])
                        signal_id = context.emit_signal("cloud_asset_public", "url", url, confidence=0.7, source=self.name, tags=tags, evidence={"status": status, "reason": reason, "bucket": bucket})
                        finding = {
                            "type": "finding", "source": self.name, "hostname": urlparse(url).hostname, "finding_type": "cloud_asset_public",
                            "description": f"Public cloud asset detected ({provider})", "url": url,
                            "details": {"bucket": bucket, "provider": provider, "status": status, "reason": reason},
                            "tags": tags, "score": 80, "priority": "high", "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding): public_findings += 1
                    else:
                        context.emit_signal("cloud_asset_exists", "url", url, confidence=0.4, source=self.name, tags=tags, evidence={"status": status, "reason": reason, "bucket": bucket})
                        exists_only += 1

        stats = context.record.metadata.stats.setdefault("cloud_assets", {})
        stats.update({"checked": checked, "public": public_findings, "exists_only": exists_only})
        context.manager.update_metadata(context.record)

    def _generate_candidates(self, context: PipelineContext) -> List[str]:
        hosts: Set[str] = set()
        org_tokens: Set[str] = set()
        
        # Collect from enrichment
        enrichment_artifact = context.record.paths.artifact("ip_enrichment.json")
        if enrichment_artifact.exists():
            try:
                enrichment_map = json.loads(enrichment_artifact.read_text(encoding="utf-8"))
                for entries in enrichment_map.values():
                    for entry in entries:
                        org = entry.get("org")
                        if isinstance(org, str): org_tokens.update(self._extract_tokens(org))
            except Exception as e:
                context.logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="cloud_asset_discovery", error_type=type(e).__name__).inc()
                except: pass

        for entry in context.iter_results():
            etype = entry.get("type")
            host = entry.get("hostname") if etype == "hostname" else (urlparse(entry.get("url", "")).hostname if etype == "url" else None)
            if host: hosts.add(host.lower())

        candidates: Set[str] = set()
        for host in hosts:
            root = self._root_domain(host)
            candidates.update(self._host_variants(host, root))
        for token in org_tokens:
            candidates.add(token); candidates.add(token.replace(" ", "-"))
        return sorted(list(candidates))

    def _build_checks(self, buckets: List[str]) -> List[Tuple[str, str, str]]:
        checks: List[Tuple[str, str, str]] = []
        for b in buckets:
            if not b or len(b) < 3: continue
            safe = b.lower()
            checks.append(("s3", f"https://{safe}.s3.amazonaws.com/", safe))
            checks.append(("gcs", f"https://storage.googleapis.com/{safe}", safe))
            checks.append(("azure", f"https://{safe}.blob.core.windows.net/", safe))
        return checks

    def _classify(self, provider: str, status: int, body: str, headers: Dict[str, str]) -> Tuple[bool, bool, str]:
        if status in self.NOT_FOUND_STATUSES: return False, False, "not_found"
        server = headers.get("server", "")
        is_genuine = (provider == "s3" and ("amazons3" in server or "x-amz-request-id" in headers)) or \
                     (provider == "gcs" and ("uploadserver" in server or "x-guploader-uploadid" in headers)) or \
                     (provider == "azure" and ("windows-azure-blob" in server or "x-ms-request-id" in headers))
        if not is_genuine: return False, False, "not_genuine_cloud"
        
        keywords = self._keywords_for(provider)
        if status in self.PUBLIC_STATUSES:
            return True, True, "public_listing" if any(k.lower() in body.lower() for k in keywords) else "public_response"
        if status in self.EXISTS_STATUSES:
            return True, False, "access_denied" if any(k.lower() in body.lower() for k in keywords) else "exists"
        return False, False, "unknown"

    @staticmethod
    def _keywords_for(provider: str) -> Sequence[str]:
        if provider == "s3": return CloudAssetDiscoveryStage.S3_KEYWORDS
        if provider == "gcs": return CloudAssetDiscoveryStage.GCS_KEYWORDS
        if provider == "azure": return CloudAssetDiscoveryStage.AZURE_KEYWORDS
        return ()

    @staticmethod
    def _root_domain(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _host_variants(self, host: str, root: str) -> Set[str]:
        variants = {root, root.replace(".", "-"), root.split(".")[0], host.replace(".", "-"), host.split(".")[0]}
        if "-" in host: variants.add(host.split("-")[0])
        return {v for v in variants if v}

    def _extract_tokens(self, org: str) -> Set[str]:
        return {m.lower() for m in self.ORG_TOKEN_RE.findall(org) if len(m) >= 3}
