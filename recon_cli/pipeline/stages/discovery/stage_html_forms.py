from __future__ import annotations

import json
import asyncio
from collections import defaultdict
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class HTMLFormMiningStage(Stage):
    name = "html_form_mining"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_html_form_mining", False))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "html_form_max_urls", 50))
        timeout = int(getattr(runtime, "html_form_timeout", 10))
        max_forms = int(getattr(runtime, "html_form_max_forms", 200))
        concurrency = int(getattr(runtime, "html_form_concurrency", 15))

        candidates = self._select_urls(context, max_urls)
        if not candidates:
            context.logger.info("No HTML URLs found for form mining")
            return

        class FormParser(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.forms: List[Dict[str, Any]] = []
                self._current: Optional[Dict[str, Any]] = None

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
                    itype = attrs_dict.get("type") or tag
                    if name: self._current["inputs"].append({"name": name, "type": itype})

            def handle_endtag(self, tag):
                if tag == "form" and self._current is not None:
                    self.forms.append(self._current)
                    self._current = None

        config = HTTPClientConfig(
            max_concurrent=concurrency,
            total_timeout=float(timeout),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=float(getattr(runtime, "html_form_rps", 20.0))
        )

        params: Dict[str, int] = defaultdict(int)
        examples: Dict[str, List[str]] = defaultdict(list)
        forms_saved = 0
        artifacts: List[Dict[str, object]] = []

        async with AsyncHTTPClient(config, context=context) as client:
            context.logger.info("Starting async HTML form mining on %d targets", len(candidates))
            
            tasks = [client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli form-mining"}), follow_redirects=True) for url in candidates]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for url, resp in zip(candidates, responses):
                if isinstance(resp, Exception) or resp.status >= 400: continue
                
                content_type = resp.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type and "<form" not in resp.body.lower():
                    continue

                parser = FormParser()
                parser.feed(resp.body)
                
                if not parser.forms: continue
                
                for form in parser.forms:
                    if forms_saved >= max_forms: break
                    inputs = form.get("inputs") or []
                    input_names = [i.get("name") for i in inputs if isinstance(i, dict) and i.get("name")]
                    
                    if not input_names: continue
                    
                    for name in input_names:
                        params[name] += 1
                        if len(examples[name]) < 3: examples[name].append(url)

                    payload = {
                        "type": "form", "source": "html-form-mining", "hostname": urlparse(url).hostname,
                        "url": url, "action": form.get("action"), "method": form.get("method"),
                        "inputs": inputs, "score": 25, "tags": ["form"],
                    }
                    if context.results.append(payload):
                        forms_saved += 1
                        artifacts.append(payload)

        # Post-process parameters
        max_params = int(getattr(runtime, "html_form_max_params", 80))
        for name, count in sorted(params.items(), key=lambda x: x[1], reverse=True)[:max_params]:
            context.results.append({
                "type": "parameter", "source": "form-mining", "name": name, "count": count,
                "examples": examples.get(name, []), "score": min(45, 10 + count), "tags": ["param", "form"],
            })

        if artifacts:
            context.record.paths.artifact("html_forms.json").write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("html_form_mining", {})
        stats.update({"forms": forms_saved, "params": min(len(params), max_params)})
        context.manager.update_metadata(context.record)

    def _select_urls(self, context: PipelineContext, max_urls: int) -> List[str]:
        candidates: Dict[str, int] = {}
        for entry in context.iter_results():
            if entry.get("type") != "url": continue
            url = entry.get("url")
            if not isinstance(url, str) or not url or not context.url_allowed(url): continue
            status = int(entry.get("status_code") or 0)
            if status not in {200, 301, 302, 401, 403}: continue
            score = int(entry.get("score", 0))
            candidates[url] = max(candidates.get(url, 0), score)
        
        ranked = sorted(candidates.items(), key=lambda item: item[1], reverse=True)
        return [url for url, _ in ranked][:max_urls] if max_urls > 0 else [url for url, _ in ranked]
