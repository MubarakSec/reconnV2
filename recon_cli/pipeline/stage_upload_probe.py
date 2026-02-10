from __future__ import annotations

import json
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class UploadProbeStage(Stage):
    name = "upload_probe"

    PATH_HINTS = (
        "/upload",
        "/uploads",
        "/file",
        "/files",
        "/media",
        "/attachments",
        "/avatar",
        "/profile",
        "/images",
        "/userfiles",
    )
    DIR_PROBE_PATHS = (
        "/uploads/",
        "/upload/",
        "/files/",
        "/media/",
        "/attachments/",
        "/images/",
        "/assets/uploads/",
        "/static/uploads/",
    )
    DIR_LISTING_MARKERS = ("Index of /", "Directory listing", "Parent Directory")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_upload_probe", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("upload probe requires requests; skipping")
            return

        runtime = context.runtime_config
        max_hosts = int(getattr(runtime, "upload_max_hosts", 60))
        max_urls = int(getattr(runtime, "upload_max_urls", 120))
        timeout = int(getattr(runtime, "upload_timeout", 8))
        limiter = context.get_rate_limiter(
            "upload_probe",
            rps=float(getattr(runtime, "upload_rps", 0)),
            per_host=float(getattr(runtime, "upload_per_host_rps", 0)),
        )

        candidates = self._collect_candidates(context)
        if max_urls > 0:
            candidates = candidates[:max_urls]

        checked = 0
        surfaced = 0
        dir_exposed = 0
        artifacts: List[Dict[str, object]] = []

        for url in candidates:
            if not context.url_allowed(url):
                continue
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            session = context.auth_session(url)
            headers = context.auth_headers({"User-Agent": "recon-cli upload-probe"})
            try:
                if session:
                    resp = session.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
                else:
                    resp = requests.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers=headers,
                        verify=context.runtime_config.verify_tls,
                    )
            except Exception:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)
            checked += 1
            if resp.status_code in {200, 401, 403, 405, 302}:
                surfaced += 1
                tags = ["surface:upload", "service:upload"]
                context.results.append(
                    {
                        "type": "url",
                        "source": "upload-probe",
                        "url": url,
                        "hostname": urlparse(url).hostname,
                        "tags": tags,
                        "score": 40,
                    }
                )
                context.emit_signal(
                    "upload_surface",
                    "url",
                    url,
                    confidence=0.5,
                    source="upload-probe",
                    tags=tags,
                    evidence={"status_code": resp.status_code},
                )
            artifacts.append({"url": url, "status": resp.status_code})

        hosts = self._collect_hosts(context)
        if max_hosts > 0:
            hosts = hosts[:max_hosts]
        for host in hosts:
            base = f"https://{host}"
            for path in self.DIR_PROBE_PATHS:
                probe_url = urljoin(base, path)
                if not context.url_allowed(probe_url):
                    continue
                if limiter and not limiter.wait_for_slot(probe_url, timeout=timeout):
                    continue
                session = context.auth_session(probe_url)
                headers = context.auth_headers({"User-Agent": "recon-cli upload-probe"})
                try:
                    if session:
                        resp = session.get(
                            probe_url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers=headers,
                            verify=context.runtime_config.verify_tls,
                        )
                    else:
                        resp = requests.get(
                            probe_url,
                            timeout=timeout,
                            allow_redirects=True,
                            headers=headers,
                            verify=context.runtime_config.verify_tls,
                        )
                except Exception:
                    if limiter:
                        limiter.on_error(probe_url)
                    continue
                if limiter:
                    limiter.on_response(probe_url, resp.status_code)
                if resp.status_code == 200 and self._looks_like_dir_listing(resp.text or ""):
                    dir_exposed += 1
                    tags = ["upload", "exposed", "directory"]
                    signal_id = context.emit_signal(
                        "upload_dir_exposed",
                        "url",
                        probe_url,
                        confidence=0.7,
                        source="upload-probe",
                        tags=tags,
                        evidence={"status_code": resp.status_code},
                    )
                    finding = {
                        "type": "finding",
                        "source": "upload-probe",
                        "finding_type": "upload_directory_listing",
                        "hostname": host,
                        "url": probe_url,
                        "description": "Upload directory listing exposed",
                        "tags": tags,
                        "score": 80,
                        "priority": "high",
                        "evidence_id": signal_id or None,
                    }
                    context.results.append(finding)
                    artifacts.append({"url": probe_url, "status": resp.status_code, "directory_listing": True})

        if artifacts:
            artifact_path = context.record.paths.artifact("upload_probe.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("upload_probe", {})
        stats.update(
            {
                "candidates": len(candidates),
                "checked": checked,
                "surface": surfaced,
                "dir_exposed": dir_exposed,
            }
        )
        context.manager.update_metadata(context.record)

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
                if isinstance(url, str) and url and self._has_hint(url):
                    candidates.append(url)
        return list(dict.fromkeys(candidates))

    def _collect_hosts(self, context: PipelineContext) -> List[str]:
        hosts: List[str] = []
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
                hosts.append(host)
        return list(dict.fromkeys(hosts))

    def _form_has_upload(self, inputs: object, action: str) -> bool:
        if any(hint in action.lower() for hint in self.PATH_HINTS):
            return True
        if not isinstance(inputs, list):
            return False
        for item in inputs:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").lower()
            input_type = str(item.get("type") or "").lower()
            if input_type == "file":
                return True
            if any(token in name for token in ("file", "upload", "avatar", "image")):
                return True
        return False

    def _has_hint(self, url: str) -> bool:
        lower = url.lower()
        return any(hint in lower for hint in self.PATH_HINTS)

    def _looks_like_dir_listing(self, text: str) -> bool:
        lower = text.lower()
        return any(marker.lower() in lower for marker in self.DIR_LISTING_MARKERS)
