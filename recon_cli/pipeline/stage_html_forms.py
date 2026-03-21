from __future__ import annotations

import json
from collections import defaultdict
from typing import Dict, List, Optional
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class HTMLFormMiningStage(Stage):
    name = "html_form_mining"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_html_form_mining", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
            from html.parser import HTMLParser
        except Exception:
            context.logger.warning("html form mining requires requests; skipping")
            return

        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "html_form_max_urls", 50))
        timeout = int(getattr(runtime, "html_form_timeout", 10))
        max_forms = int(getattr(runtime, "html_form_max_forms", 200))
        limiter = context.get_rate_limiter(
            "html_form_mining",
            rps=float(getattr(runtime, "html_form_rps", 0)),
            per_host=float(getattr(runtime, "html_form_per_host_rps", 0)),
        )

        candidates = self._select_urls(context, max_urls)
        if not candidates:
            context.logger.info("No HTML URLs found for form mining")
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
                elif (
                    tag in {"input", "textarea", "select"} and self._current is not None
                ):
                    name = attrs_dict.get("name") or attrs_dict.get("id") or ""
                    input_type = attrs_dict.get("type") or tag
                    if name:
                        self._current["inputs"].append(
                            {"name": name, "type": input_type}
                        )

            def handle_endtag(self, tag):
                if tag == "form" and self._current is not None:
                    self.forms.append(self._current)
                    self._current = None

        params: Dict[str, int] = defaultdict(int)
        examples: Dict[str, List[str]] = defaultdict(list)
        forms_saved = 0
        artifacts: List[Dict[str, object]] = []

        for url in candidates:
            if limiter and not limiter.wait_for_slot(url, timeout=timeout):
                continue
            session = context.auth_session(url)
            headers = context.auth_headers({"User-Agent": "recon-cli form-mining"})
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
            if resp.status_code >= 400:
                continue
            content_type = resp.headers.get("Content-Type", "")
            if (
                "text/html" not in content_type
                and "<form" not in (resp.text or "").lower()
            ):
                continue

            parser = FormParser()
            parser.feed(resp.text or "")
            if not parser.forms:
                continue
            for form in parser.forms:
                if forms_saved >= max_forms:
                    break
                inputs = form.get("inputs") or []
                input_names = []
                for item in inputs:  # type: ignore[attr-defined]
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    if not name:
                        continue
                    name = str(name)
                    params[name] += 1
                    input_names.append(name)
                    if len(examples[name]) < 3:
                        examples[name].append(url)
                if not input_names:
                    continue
                signal_id = context.emit_signal(
                    "form_discovered",
                    "url",
                    url,
                    confidence=0.4,
                    source="form-mining",
                    tags=["form"],
                    evidence={"inputs": input_names[:10]},
                )
                payload = {
                    "type": "form",
                    "source": "html-form-mining",
                    "hostname": urlparse(url).hostname,
                    "url": url,
                    "action": form.get("action"),
                    "method": form.get("method"),
                    "inputs": inputs,
                    "score": 25,
                    "tags": ["form"],
                    "evidence_id": signal_id or None,
                }
                if context.results.append(payload):
                    forms_saved += 1
                    artifacts.append(payload)

        max_params = int(getattr(runtime, "html_form_max_params", 80))
        for name, count in sorted(
            params.items(), key=lambda item: item[1], reverse=True
        )[:max_params]:
            payload = {
                "type": "parameter",
                "source": "form-mining",
                "name": name,
                "count": count,
                "examples": examples.get(name, []),
                "score": min(45, 10 + count),
                "tags": ["param", "form"],
            }
            context.results.append(payload)

        if artifacts:
            artifact_path = context.record.paths.artifact("html_forms.json")
            artifact_path.write_text(
                json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8"
            )

        stats = context.record.metadata.stats.setdefault("html_form_mining", {})
        stats["forms"] = forms_saved
        stats["params"] = min(len(params), max_params)
        context.manager.update_metadata(context.record)

    def _select_urls(self, context: PipelineContext, max_urls: int) -> List[str]:
        candidates: Dict[str, int] = {}
        for entry in context.get_results():
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            status = int(entry.get("status_code") or 0)
            if status not in {200, 301, 302, 401, 403}:
                continue
            if not context.url_allowed(url):
                continue
            score = int(entry.get("score", 0))
            candidates[url] = max(candidates.get(url, 0), score)
        ranked = sorted(candidates.items(), key=lambda item: item[1], reverse=True)
        urls = [url for url, _ in ranked]
        if max_urls > 0:
            urls = urls[:max_urls]
        return urls
