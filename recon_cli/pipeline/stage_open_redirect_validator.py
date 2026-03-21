from __future__ import annotations

import json
import uuid
from collections import defaultdict
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import time as time_utils


class OpenRedirectValidatorStage(Stage):
    name = "open_redirect_validator"
    REDIRECT_STATUS = {301, 302, 303, 307, 308}
    REDIRECT_PARAMS = {
        "next",
        "redirect",
        "return",
        "url",
        "dest",
        "callback",
        "continue",
        "to",
        "target",
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(
            getattr(context.runtime_config, "enable_open_redirect_validator", True)
        )

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning(
                "open redirect validator requires requests; skipping"
            )
            return

        runtime = context.runtime_config
        max_urls = max(1, int(getattr(runtime, "open_redirect_validator_max_urls", 30)))
        max_per_host = max(
            1, int(getattr(runtime, "open_redirect_validator_max_per_host", 6))
        )
        min_score = int(getattr(runtime, "open_redirect_validator_min_score", 40))
        timeout = max(1, int(getattr(runtime, "open_redirect_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        limiter = context.get_rate_limiter(
            "open_redirect_validator",
            rps=float(getattr(runtime, "open_redirect_validator_rps", 0)),
            per_host=float(getattr(runtime, "open_redirect_validator_per_host_rps", 0)),
        )

        candidates = self._collect_candidates(
            context, min_score=min_score, max_urls=max_urls, max_per_host=max_per_host
        )
        if not candidates:
            stats = context.record.metadata.stats.setdefault(
                "open_redirect_validator", {}
            )
            stats.update({"attempted": 0, "confirmed": 0, "failed": 0, "skipped": 0})
            context.manager.update_metadata(context.record)
            context.logger.info("No open redirect candidates found")
            return

        attempted = 0
        confirmed = 0
        failed = 0
        skipped = 0
        artifacts: List[Dict[str, object]] = []

        for candidate in candidates:
            url = candidate["url"]
            param = candidate["param"]
            payloads = self._payloads()
            validated = False
            for payload in payloads:
                attempted += 1
                test_url = self._inject_param(url, param, payload)  # type: ignore[arg-type]
                if not context.url_allowed(test_url):
                    skipped += 1
                    continue
                if limiter and not limiter.wait_for_slot(test_url, timeout=timeout):
                    skipped += 1
                    continue
                headers = context.auth_headers(
                    {"User-Agent": "recon-cli open-redirect-validator"}
                )
                session = context.auth_session(test_url)
                try:
                    if session:
                        resp = session.get(
                            test_url,
                            headers=headers,
                            timeout=timeout,
                            allow_redirects=False,
                            verify=verify_tls,
                            stream=True,
                        )
                    else:
                        resp = requests.get(
                            test_url,
                            headers=headers,
                            timeout=timeout,
                            allow_redirects=False,
                            verify=verify_tls,
                            stream=True,
                        )
                except requests.exceptions.RequestException:
                    if limiter:
                        limiter.on_error(test_url)
                    failed += 1
                    continue

                status_code = int(getattr(resp, "status_code", 0) or 0)
                location = str(resp.headers.get("Location") or "")
                resp.close()
                if limiter:
                    limiter.on_response(test_url, status_code)

                if status_code in self.REDIRECT_STATUS and self._is_external_redirect(
                    url, location, payload  # type: ignore[arg-type]
                ):
                    signal_id = context.emit_signal(
                        "open_redirect_confirmed",
                        "url",
                        test_url,
                        confidence=1.0,
                        source="open-redirect-validator",
                        evidence={
                            "status_code": status_code,
                            "location": location,
                            "parameter": param,
                        },
                        tags=["redirect", "confirmed"],
                    )
                    finding = {
                        "type": "finding",
                        "finding_type": "open_redirect",
                        "source": "open-redirect-validator",
                        "severity": "high",
                        "url": test_url,
                        "description": "Open redirect confirmed by dedicated validator",
                        "title": "Open redirect confirmed",
                        "parameter": param,
                        "proof": location,
                        "status_code": status_code,
                        "tags": ["redirect", "confirmed", "validator:open-redirect"],
                        "confidence_label": "verified",
                        "score": max(85, int(candidate.get("score", 0) or 0)),  # type: ignore[call-overload]
                        "signal_id": signal_id or None,
                    }
                    if context.results.append(finding):
                        confirmed += 1
                        validated = True
                        artifacts.append(
                            {
                                "timestamp": time_utils.iso_now(),
                                "url": url,
                                "parameter": param,
                                "test_url": test_url,
                                "status_code": status_code,
                                "location": location,
                                "payload": payload,
                            }
                        )
                    break
            if validated:
                continue

        artifact_path = context.record.paths.artifact("open_redirect_validator.json")
        artifact_path.write_text(
            json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8"
        )
        stats = context.record.metadata.stats.setdefault("open_redirect_validator", {})
        stats.update(
            {
                "attempted": attempted,
                "confirmed": confirmed,
                "failed": failed,
                "skipped": skipped,
                "candidates": len(candidates),
                "artifact": str(artifact_path),
            }
        )
        context.manager.update_metadata(context.record)

    def _collect_candidates(
        self,
        context: PipelineContext,
        *,
        min_score: int,
        max_urls: int,
        max_per_host: int,
    ) -> List[Dict[str, object]]:
        grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        seen: set[Tuple[str, str]] = set()
        for entry in context.iter_results():
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or "").strip()
            if not url:
                continue
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            if not parsed.scheme or not parsed.netloc:
                continue
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            score = int(entry.get("score", 0) or 0)
            if score < min_score:
                continue
            for key, _value in params:
                name = str(key).strip().lower()
                if name not in self.REDIRECT_PARAMS:
                    continue
                item_key = (url, name)
                if item_key in seen:
                    continue
                seen.add(item_key)
                grouped[parsed.hostname or ""].append(
                    {
                        "url": url,
                        "param": name,
                        "score": score,
                    }
                )

        selected: List[Dict[str, object]] = []
        for _host, items in grouped.items():
            items.sort(key=lambda item: int(item.get("score", 0)), reverse=True)  # type: ignore[call-overload]
            selected.extend(items[:max_per_host])
        selected.sort(key=lambda item: int(item.get("score", 0)), reverse=True)  # type: ignore[call-overload]
        return selected[:max_urls]

    @staticmethod
    def _payloads() -> List[str]:
        token = uuid.uuid4().hex[:10]
        host = f"redirect-{token}.example.org"
        return [
            f"https://{host}/cb",
            f"//{host}/cb",
        ]

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated: List[Tuple[str, str]] = []
        replaced = False
        for key, current in params:
            if key == param and not replaced:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, current))
        if not replaced:
            updated.append((param, value))
        query = urlencode(updated, doseq=True)
        return urlunparse(parsed._replace(query=query))

    @staticmethod
    def _is_external_redirect(original_url: str, location: str, payload: str) -> bool:
        if not location:
            return False
        token = payload.rsplit("/", 2)[0]
        if payload not in location and token not in location:
            return False
        try:
            original = urlparse(original_url)
            location_value = location.strip()
            if location_value.startswith("//"):
                location_value = f"{original.scheme}:{location_value}"
            target = urlparse(location_value)
        except ValueError:
            return False
        if not target.scheme or not target.netloc:
            return False
        if not original.hostname or not target.hostname:
            return False
        return original.hostname.lower() != target.hostname.lower()
