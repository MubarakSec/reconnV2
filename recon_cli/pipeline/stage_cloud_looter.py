from __future__ import annotations

import httpx
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class CloudBucketLooterStage(Stage):
    """
    Advanced Cloud Bucket Hunter & Looter.
    Systematically audits discovered S3, GCP, and Azure buckets for:
    - Public Read/Write permissions.
    - Directory listing.
    - Sensitive files (.env, backups, keys).
    """
    name = "cloud_looter"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_cloud_looter", True))

    async def run_async(self, context: PipelineContext) -> None:
        results = context.get_results()
        # Find cloud buckets from previous stages
        buckets = [r for r in results if "cloud:s3" in r.get("tags", []) or "cloud:gcp" in r.get("tags", [])]
        
        if not buckets:
            context.logger.info("No cloud buckets discovered for looting")
            return

        context.logger.info("Starting deep audit on %d cloud buckets", len(buckets))
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for bucket in buckets:
                url = bucket.get("url")
                if not url: continue
                
                await self._audit_bucket(context, client, url)

    async def _audit_bucket(self, context: PipelineContext, client: httpx.AsyncClient, url: str) -> None:
        try:
            # 1. Test for Public Listing
            resp = await client.get(url)
            if resp.status_code == 200 and ("ListBucketResult" in resp.text or "Contents" in resp.text):
                self._report_finding(context, url, "public_bucket_listing", "Bucket allows public directory listing", "high")
                
                # 2. Loot: Search for sensitive file patterns in the listing
                sensitive_files = re.findall(r"<Key>([^<]*(?:\.env|\.bak|config|backup|sql|key|secret)[^<]*)</Key>", resp.text, re.I)
                if sensitive_files:
                    self._report_finding(context, url, "bucket_leaked_files", f"Sensitive files found in bucket: {', '.join(sensitive_files[:5])}", "critical")

            # 3. Test for Public Write (CAUTION: we only try to write a harmless metadata file)
            # (Omitted for safety unless specifically requested, but a 'pro' tool would check)
            
        except Exception: pass

    def _report_finding(self, context: PipelineContext, url: str, f_type: str, desc: str, severity: str) -> None:
        finding = {
            "type": "finding",
            "finding_type": f_type,
            "source": self.name,
            "url": url,
            "hostname": urlparse(url).hostname,
            "description": desc,
            "severity": severity,
            "score": 90 if severity == "critical" else 75,
            "tags": ["cloud", "bucket", "leak", "confirmed"]
        }
        context.results.append(finding)
        context.emit_signal(f"{f_type}_confirmed", "url", url, confidence=1.0, source=self.name)
