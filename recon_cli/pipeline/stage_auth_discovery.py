from __future__ import annotations

import json
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


class AuthDiscoveryStage(Stage):
    name = "auth_discovery"

    AUTH_HINTS = ("login", "signin", "signup", "register", "forgot", "reset", "password", "auth")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_auth_discovery", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
            from html.parser import HTMLParser
        except Exception:
            context.logger.warning("auth discovery requires requests; skipping")
            return

        class FormParser(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.forms: List[Dict[str, object]] = []
                self._current: Optional[Dict[str, object]] = None

            def handle_starttag(self, tag, attrs):
                attrs_dict = {key.lower(): value for key, value in attrs if key}
                if tag == "form":
                    self._current = {
                        "action": attrs_dict.get("action") or "",
                        "method": (attrs_dict.get("method") or "get").lower(),
                        "inputs": [],
                    }
                elif tag in {"input", "textarea", "select"} and self._current is not None:
                    name = attrs_dict.get("name") or attrs_dict.get("id") or ""
                    input_type = attrs_dict.get("type") or tag
                    if name:
                        self._current["inputs"].append({"name": name, "type": input_type})

            def handle_endtag(self, tag):
                if tag == "form" and self._current is not None:
                    self.forms.append(self._current)
                    self._current = None

        candidates: List[Dict[str, object]] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            status = entry.get("status_code")
            if status not in {200, 302}:
                continue
            url = entry.get("url")
            if not url:
                continue
            tags = set(entry.get("tags", []))
            path = urlparse(url).path.lower()
            has_hint = any(hint in path for hint in self.AUTH_HINTS)
            if tags.intersection({"surface:login", "surface:register", "surface:password-reset", "surface:admin"}) or has_hint:
                candidates.append(
                    {
                        "url": url,
                        "score": int(entry.get("score", 0)),
                        "tags": list(tags),
                    }
                )
        if not candidates:
            context.logger.info("No auth candidates discovered")
            return
        candidates.sort(key=lambda item: item.get("score", 0), reverse=True)
        max_urls = int(getattr(context.runtime_config, "auth_discovery_max_urls", 40))
        timeout = int(getattr(context.runtime_config, "auth_discovery_timeout", 10))
        max_forms = int(getattr(context.runtime_config, "auth_discovery_max_forms", 80))
        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "auth_discovery",
            rps=float(getattr(runtime, "auth_discovery_rps", 0)),
            per_host=float(getattr(runtime, "auth_discovery_per_host_rps", 0)),
        )
        forms_found = 0
        artifacts: List[Dict[str, object]] = []
        for candidate in candidates[:max_urls]:
            if forms_found >= max_forms:
                break
            url = candidate["url"]
            session = context.auth_session(url)
            headers = context.auth_headers({"User-Agent": "recon-cli auth-discovery"})
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
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
            except requests.exceptions.RequestException:
                if limiter:
                    limiter.on_error(url)
                continue
            if limiter:
                limiter.on_response(url, resp.status_code)
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "<form" not in (resp.text or "").lower():
                continue
            parser = FormParser()
            parser.feed(resp.text or "")
            for form in parser.forms:
                if forms_found >= max_forms:
                    break
                action = form.get("action") or ""
                action_url = urljoin(url, action) if action else url
                inputs = form.get("inputs") or []
                tags = set(candidate.get("tags", []))
                input_names = [item.get("name") for item in inputs if isinstance(item, dict)]
                lower_action = str(action_url).lower()
                if any(item.get("type") == "password" for item in inputs if isinstance(item, dict)):
                    tags.add("surface:login")
                if "reset" in lower_action or "forgot" in lower_action:
                    tags.add("surface:password-reset")
                if "register" in lower_action or "signup" in lower_action:
                    tags.add("surface:register")
                if any(name for name in input_names if name and "csrf" in name.lower()):
                    tags.add("indicator:csrf")
                payload = {
                    "type": "auth_form",
                    "source": "form-discovery",
                    "hostname": urlparse(url).hostname,
                    "url": url,
                    "action": action_url,
                    "method": form.get("method"),
                    "inputs": inputs,
                    "tags": sorted(tags),
                    "score": 40 if "surface:login" in tags else 20,
                }
                signal_id = context.emit_signal(
                    "auth_surface",
                    "url",
                    url,
                    confidence=0.5,
                    source="auth-discovery",
                    tags=sorted(tags),
                    evidence={"action": action_url, "method": form.get("method")},
                )
                if signal_id:
                    payload["evidence_id"] = signal_id
                if context.results.append(payload):
                    forms_found += 1
                    artifacts.append(payload)
        if artifacts:
            artifact_path = context.record.paths.artifact("auth_forms.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")
            stats = context.record.metadata.stats.setdefault("auth_discovery", {})
            stats["forms"] = forms_found
            context.manager.update_metadata(context.record)
