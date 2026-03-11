from __future__ import annotations

import json
import asyncio
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl

try:
    from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig
except ImportError:
    AsyncHTTPClient = None

class UploadProbeStage(Stage):
    name = "upload_probe"

    PATH_HINTS = (
        "/upload", "/uploads", "/file", "/files", "/media",
        "/attachments", "/avatar", "/profile", "/images", "/userfiles",
    )
    DIR_PROBE_PATHS = (
        "/uploads/", "/upload/", "/files/", "/media/",
        "/attachments/", "/images/", "/assets/uploads/", "/static/uploads/",
    )
    DIR_LISTING_MARKERS = ("Index of /", "Directory listing", "Parent Directory")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_upload_probe", False))

    async def run_async(self, context: PipelineContext) -> bool:
        if not self.is_enabled(context):
            return False
        
        if not AsyncHTTPClient:
            context.logger.warning("AsyncHTTPClient unavailable. Skipping async upload probe.")
            return False

        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "upload_max_hosts", 60))
        max_urls = int(getattr(runtime, "upload_max_urls", 120))
        timeout = int(getattr(runtime, "upload_timeout", 8))
        
        candidates = self._collect_candidates(context)
        if max_urls > 0:
            candidates = candidates[:max_urls]

        hosts = self._collect_hosts(context)
        if max_hosts > 0:
            hosts = hosts[:max_hosts]

        probe_urls = set()
        for host in hosts:
            base = f"https://{host}"
            for path in self.DIR_PROBE_PATHS:
                url = urljoin(base, path)
                if context.url_allowed(url):
                    probe_urls.add(url)
                    
        all_urls_to_check = set(candidates) | set(probe_urls)
        if not all_urls_to_check:
            return True

        checked = 0
        surfaced = 0
        dir_exposed = 0
        artifacts: List[Dict[str, object]] = []
        
        config = HTTPClientConfig(
            max_concurrent=int(getattr(runtime, "upload_concurrency", 20)),
            total_timeout=timeout,
            verify_ssl=context.runtime_config.verify_tls,
        )
        
        headers = context.auth_headers({"User-Agent": "recon-cli upload-probe"})

        async with AsyncHTTPClient(config) as client:
            tasks = [
                client.get(url, headers=headers, follow_redirects=True)
                for url in all_urls_to_check
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for url, resp in zip(all_urls_to_check, responses):
                if isinstance(resp, Exception) or resp.status == 0:
                    continue
                checked += 1
                
                # Check candidate URLs
                if url in candidates and resp.status in {200, 401, 403, 405, 302}:
                    surfaced += 1
                    tags = ["surface:upload", "service:upload"]
                    context.results.append({
                        "type": "url",
                        "source": "upload-probe",
                        "url": url,
                        "hostname": urlparse(url).hostname,
                        "tags": tags,
                        "score": 40,
                    })
                    context.emit_signal(
                        "upload_surface", "url", url,
                        confidence=0.5, source="upload-probe",
                        tags=tags, evidence={"status_code": resp.status},
                    )
                    artifacts.append({"url": url, "status": resp.status})
                
                # Check directory listing
                if url in probe_urls and resp.status == 200 and self._looks_like_dir_listing(resp.body):
                    dir_exposed += 1
                    tags = ["upload", "exposed", "directory"]
                    host = urlparse(url).hostname
                    signal_id = context.emit_signal(
                        "upload_dir_exposed", "url", url,
                        confidence=0.7, source="upload-probe",
                        tags=tags, evidence={"status_code": resp.status},
                    )
                    context.results.append({
                        "type": "finding",
                        "source": "upload-probe",
                        "finding_type": "upload_directory_listing",
                        "hostname": host,
                        "url": url,
                        "description": "Upload directory listing exposed",
                        "tags": tags,
                        "score": 80,
                        "priority": "high",
                        "evidence_id": signal_id or None,
                    })
                    artifacts.append({"url": url, "status": resp.status, "directory_listing": True})

        if artifacts:
            artifact_path = context.record.paths.artifact("upload_probe.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("upload_probe", {})
        stats.update({
            "candidates": len(candidates),
            "checked": checked,
            "surface": surfaced,
            "dir_exposed": dir_exposed,
        })
        context.manager.update_metadata(context.record)
        return True

    def execute(self, context: PipelineContext) -> None:
        # Wrapper for synchronous execution if runner isn't fully async
        import asyncio
        asyncio.run(self.run_async(context))

    def _collect_candidates(self, context: PipelineContext) -> List[str]:
        candidates: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            etype = entry.get("type")
            if etype in {"form", "auth_form"}:
                action = entry.get("action") or entry.get("url")
                if isinstance(action, str) and action:
                    inputs = entry.get("inputs") or []
                    if self._form_has_upload(inputs, action):
                        candidates.append(action)
            elif etype == "url":
                url = entry.get("url")
                if isinstance(url, str) and self._url_looks_like_upload(url):
                    candidates.append(url)
        return list(dict.fromkeys(candidates))

    def _collect_hosts(self, context: PipelineContext) -> List[str]:
        hosts: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") == "hostname":
                h = entry.get("hostname")
                if h:
                    hosts.append(h)
        return list(dict.fromkeys(hosts))

    def _form_has_upload(self, inputs: List[Dict], action: str) -> bool:
        if self._url_looks_like_upload(action):
            return True
        for inp in inputs:
            if isinstance(inp, dict):
                itype = str(inp.get("type") or "").lower()
                name = str(inp.get("name") or "").lower()
                if itype == "file" or "upload" in name or "file" in name:
                    return True
        return False

    def _url_looks_like_upload(self, url: str) -> bool:
        lower_url = url.lower()
        return any(hint in lower_url for hint in self.PATH_HINTS)

    def _looks_like_dir_listing(self, body: str) -> bool:
        for marker in self.DIR_LISTING_MARKERS:
            if marker in body:
                return True
        return False