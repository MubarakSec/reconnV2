from __future__ import annotations

import asyncio
import re
import uuid
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig

class AdvancedIDORStage(Stage):
    name = "advanced_idor"
    optional = True

    # Keywords for non-obvious identifiers
    NON_OBVIOUS_KEYWORDS = {
        "order", "invoice", "payment", "job", "export", "report", "doc", "file",
        "booking", "ticket", "msg", "chat", "contract", "license", "oid", "inv",
        "jid", "eid", "rid", "tid", "mid",
    }

    SEQUENTIAL_RE = re.compile(r"(\d+)")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_advanced_idor", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        items = context.get_results()
        
        candidates = self._collect_candidates(context, items)
        if not candidates:
            return

        timeout = float(getattr(runtime, "idor_timeout", 10.0))
        concurrency = int(getattr(runtime, "idor_concurrency", 10))
        
        config = HTTPClientConfig(
            max_concurrent=concurrency,
            total_timeout=timeout,
            verify_ssl=bool(getattr(runtime, "verify_tls", True)),
        )

        tokens: List[Tuple[str, Optional[str]]] = [("anon", None)]
        if getattr(runtime, "idor_token_a", None):
            tokens.append(("token-a", runtime.idor_token_a))
        if getattr(runtime, "idor_token_b", None):
            tokens.append(("token-b", runtime.idor_token_b))

        async with AsyncHTTPClient(config, context=context) as client:
            for url, original_id, location_type, key in candidates:
                variants = self._generate_sequential_variants(original_id)
                for variant_id in variants:
                    variant_url = self._replace_id(url, original_id, variant_id, location_type, key)
                    
                    # Test with available tokens
                    for label, token in tokens:
                        headers = context.auth_headers({"User-Agent": "recon-cli advanced-idor"})
                        if token:
                            headers["Authorization"] = token
                        
                        try:
                            resp = await client.get(variant_url, headers=headers)
                            if resp.status == 200:
                                # Successful access to a predicted ID!
                                finding = {
                                    "type": "finding",
                                    "finding_type": "advanced_idor",
                                    "confidence": "medium",
                                    "url": variant_url,
                                    "original_url": url,
                                    "auth": label,
                                    "severity": "high",
                                    "description": f"Predictable identifier access detected on '{key}'. Accessed {variant_id} based on {original_id}.",
                                    "tags": ["business-logic", "idor", "predictable-id"],
                                    "evidence": {
                                        "identifier": key,
                                        "original_id": original_id,
                                        "variant_id": variant_id,
                                        "location": location_type,
                                        "status_code": resp.status
                                    }
                                }
                                context.results.append(finding)
                                context.logger.info("ADVANCED IDOR DETECTED: %s (%s)", variant_url, label)
                                break # Move to next candidate if found
                        except Exception:
                            continue

    def _collect_candidates(self, context: PipelineContext, items: List[Dict[str, Any]]) -> List[Tuple[str, str, str, str]]:
        candidates = []
        seen_patterns = set()

        for entry in items:
            if entry.get("type") != "url": continue
            url = entry["url"]
            parsed = urlparse(url)
            
            # Check path segments
            path_parts = parsed.path.split("/")
            for i, part in enumerate(path_parts):
                if self.SEQUENTIAL_RE.search(part):
                    # Check if previous segment is a keyword
                    prev = path_parts[i-1].lower() if i > 0 else ""
                    if any(kw in prev for kw in self.NON_OBVIOUS_KEYWORDS) or any(kw in part.lower() for kw in self.NON_OBVIOUS_KEYWORDS):
                        pattern = f"path:{prev}:{i}"
                        if pattern not in seen_patterns:
                            candidates.append((url, part, "path", str(i)))
                            seen_patterns.add(pattern)

            # Check query params
            params = parse_qsl(parsed.query)
            for key, value in params:
                if self.SEQUENTIAL_RE.search(value):
                    if any(kw in key.lower() for kw in self.NON_OBVIOUS_KEYWORDS):
                        pattern = f"query:{key}"
                        if pattern not in seen_patterns:
                            candidates.append((url, value, "query", key))
                            seen_patterns.add(pattern)
        
        return candidates[:20] # Limit to 20 unique patterns

    def _generate_sequential_variants(self, original_id: str) -> List[str]:
        match = self.SEQUENTIAL_RE.search(original_id)
        if not match: return []
        
        num_str = match.group(1)
        num = int(num_str)
        
        variants = []
        # Try nearby IDs
        for delta in [-1, 1, -2, 2]:
            new_num = num + delta
            if new_num >= 0:
                # Keep padding if original was padded
                if num_str.startswith("0") and len(num_str) > 1:
                    new_val = str(new_num).zfill(len(num_str))
                else:
                    new_val = str(new_num)
                variants.append(original_id.replace(num_str, new_val))
        
        return list(dict.fromkeys(variants))

    def _replace_id(self, url: str, old_id: str, new_id: str, location_type: str, key: str) -> str:
        parsed = urlparse(url)
        if location_type == "path":
            path_parts = parsed.path.split("/")
            idx = int(key)
            path_parts[idx] = new_id
            return urlunparse(parsed._replace(path="/".join(path_parts)))
        else: # query
            params = parse_qsl(parsed.query)
            new_params = []
            for k, v in params:
                if k == key:
                    new_params.append((k, new_id))
                else:
                    new_params.append((k, v))
            return urlunparse(parsed._replace(query=urlencode(new_params)))
