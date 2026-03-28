from __future__ import annotations

import json
from typing import Dict, List, Optional, Iterable, Any
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class AuthDiscoveryStage(Stage):
    name = "auth_discovery"

    AUTH_HINTS = (
        "login", "signin", "signup", "register", "forgot", "reset", "password", "auth",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_auth_discovery", False))

    async def run_async(self, context: PipelineContext) -> None:
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

        candidates = []
        for entry in context.iter_results():
            if entry.get("type") != "url": continue
            if entry.get("status_code") not in {200, 302}: continue
            url = entry.get("url")
            if not url: continue
            
            tags = set(entry.get("tags", []))
            path = urlparse(url).path.lower()
            if tags.intersection({"surface:login", "surface:register", "surface:password-reset", "surface:admin"}) or any(h in path for h in self.AUTH_HINTS):
                candidates.append({"url": url, "score": int(entry.get("score", 0)), "tags": list(tags)})

        if not candidates:
            context.logger.info("No auth candidates discovered")
            return

        candidates.sort(key=lambda x: x["score"], reverse=True)
        runtime = context.runtime_config
        max_urls = int(getattr(runtime, "auth_discovery_max_urls", 40))
        max_forms = int(getattr(runtime, "auth_discovery_max_forms", 80))
        
        config = HTTPClientConfig(
            max_concurrent=15,
            total_timeout=float(getattr(runtime, "auth_discovery_timeout", 10)),
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
            requests_per_second=float(getattr(runtime, "auth_discovery_rps", 20.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            forms_found = 0
            artifacts = []
            for candidate in candidates[:max_urls]:
                if forms_found >= max_forms: break
                url = candidate["url"]
                
                try:
                    resp = await client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli auth-discovery"}), follow_redirects=True)
                    if "text/html" not in resp.headers.get("Content-Type", "").lower() and "<form" not in resp.body.lower():
                        continue
                    
                    parser = FormParser()
                    parser.feed(resp.body)
                    for form in parser.forms:
                        if forms_found >= max_forms: break
                        action_url = urljoin(url, form.get("action") or "")
                        inputs = form.get("inputs") or []
                        tags = set(candidate.get("tags", []))
                        
                        if any(i.get("type") == "password" for i in inputs): tags.add("surface:login")
                        if any(h in str(action_url).lower() for h in ["reset", "forgot"]): tags.add("surface:password-reset")
                        if any(h in str(action_url).lower() for h in ["register", "signup"]): tags.add("surface:register")
                        if any("csrf" in str(i.get("name", "")).lower() for i in inputs): tags.add("indicator:csrf")
                        
                        payload = {
                            "type": "auth_form", "source": "form-discovery", "hostname": urlparse(url).hostname,
                            "url": url, "action": action_url, "method": form.get("method"), "inputs": inputs,
                            "tags": sorted(tags), "score": 40 if "surface:login" in tags else 20,
                        }
                        context.emit_signal("auth_surface", "url", url, confidence=0.5, source=self.name, tags=sorted(tags), evidence={"action": action_url, "method": form.get("method")})
                        if context.results.append(payload):
                            forms_found += 1; artifacts.append(payload)
                except Exception: continue

        if artifacts:
            artifact_path = context.record.paths.artifact("auth_forms.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")
            stats = context.record.metadata.stats.setdefault("auth_discovery", {})
            stats["forms"] = forms_found
            context.manager.update_metadata(context.record)
