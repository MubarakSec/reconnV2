from __future__ import annotations

import hashlib
import re
import uuid
import asyncio
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple, Any
from urllib.parse import ParseResult, urlencode, urlparse, urlunparse, parse_qsl

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


@dataclass
class Candidate:
    entry: Dict[str, object]
    url: str
    parsed: ParseResult
    params: List[Tuple[str, str]]
    path_parts: List[str]
    matched_params: List[str]
    matched_path_indexes: List[int]


class IDORStage(Stage):
    name = "idor_probe"
    optional = True

    PARAM_KEYWORDS = {
        "id", "user", "uid", "account", "acct", "org", "tenant", "project",
    }
    SENSITIVE_KEYS = {
        "email", "role", "roles", "balance", "owner_id", "user_id", "account_id",
    }
    SUBJECT_KEYS = {
        "id", "user_id", "owner_id", "account_id", "uid", "tenant_id", "org_id", "project_id",
    }
    AUTH_ERROR_HINTS = (
        "unauthorized", "forbidden", "access denied", "permission", "login required",
    )
    MAX_TARGETS = 40
    MAX_PER_HOST = 6
    MAX_VARIANTS_PER_PARAM = 7
    PATH_HINTS = (
        "user", "users", "account", "accounts", "profile", "tenant", "org", "project",
        "order", "invoice", "payment", "admin",
    )
    STATIC_EXTENSIONS = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".map", ".pdf", ".zip", ".gz", ".mp4", ".mp3", ".webp",
    )

    def is_enabled(self, context: PipelineContext) -> bool:
        return True

    async def run_async(self, context: PipelineContext) -> None:
        items = context.get_results()
        candidates = self._collect_candidates(context, items)
        if not candidates:
            context.logger.info("IDOR stage: no suitable endpoints found")
            return

        runtime = context.runtime_config
        timeout = getattr(runtime, "idor_timeout", 10)
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        
        # Configure Async Client
        config = HTTPClientConfig(
            max_concurrent=20,
            total_timeout=float(timeout),
            verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "idor_rps", 20.0))
        )

        async with AsyncHTTPClient(config, context=context) as client:
            # Determine host-specific Soft-404 Fingerprint
            host = urlparse(candidates[0].url).hostname or ""
            soft_404_fingerprint = await self._get_soft_404_fingerprint(context, client, host, timeout)

            tokens: List[Tuple[str, Optional[str]]] = [("anon", None)]
            if getattr(runtime, "idor_token_a", None):
                tokens.append(("token-a", runtime.idor_token_a))
            if getattr(runtime, "idor_token_b", None):
                tokens.append(("token-b", runtime.idor_token_b))

            stats = context.record.metadata.stats.setdefault("idor", {"tests": 0, "suspects": 0, "harvested_ids": 0})
            other_id = getattr(runtime, "idor_other_identifier", None)

            # ELITE: Pass 1 - Harvest real IDs using Token-A
            token_a = tokens[1][1] if len(tokens) > 1 else None
            identity_map: Dict[str, Set[str]] = defaultdict(set)
            if token_a:
                context.logger.info("Starting ID harvesting pass with Token-A...")
                harvest_tasks = [self._fetch(client, context, c.url, "token-a", token_a) for c in candidates[:20]]
                harvest_results = await asyncio.gather(*harvest_tasks)
                for res in harvest_results:
                    if res and res.get("subject_ids"):
                        for sid in res["subject_ids"]:
                            identity_map[urlparse(res["url"]).hostname or ""].add(sid)
                stats["harvested_ids"] = sum(len(ids) for ids in identity_map.values())
                context.logger.info("Harvested %d unique IDs for logic-aware testing", stats["harvested_ids"])

            for candidate in candidates:
                # Add harvested IDs to variants for this host
                host = candidate.parsed.hostname or ""
                host_harvested = list(identity_map.get(host, set()))
                
                variants = self._generate_variants(candidate, other_id, harvested=host_harvested)
                if not variants:
                    continue

                for variant_url, variant_meta in variants:
                    # 1. Test with Token A (legitimate user)
                    data_a = await self._fetch(
                        client, context, variant_url, "token-a",
                        tokens[1][1] if len(tokens) > 1 else None,
                    )
                    if not data_a or data_a["status"] >= 400:
                        continue
                    
                    # Soft-404 Destroyer
                    if soft_404_fingerprint:
                        if data_a["status"] == soft_404_fingerprint["status"] and data_a["body_md5"] == soft_404_fingerprint["body_md5"]:
                            continue

                    # 2. Test with Token B or Anon
                    token_b = tokens[2][1] if len(tokens) > 2 else None
                    auth_label = "token-b" if token_b else "anon"
                    
                    data_b = await self._fetch(client, context, variant_url, auth_label, token_b)
                    if not data_b:
                        continue

                    reasons = self._semantic_reasons(data_a, data_b)
                    is_confirmed = (
                        data_b["status"] == data_a["status"]
                        and data_b["body_md5"] == data_a["body_md5"]
                    )

                    if is_confirmed or reasons:
                        stats["tests"] += 1
                        finding = self._assemble_finding(
                            candidate, variant_url, variant_meta, auth_label, token_b, data_a, data_b,
                            reasons if reasons else ["unauthorized_access_confirmed"],
                        )
                        if is_confirmed:
                            finding["type"] = "finding"
                            finding["finding_type"] = "idor"
                            finding["confidence"] = "high"
                            finding.setdefault("tags", []).append("confirmed")

                        if context.results.append(finding):
                            stats["suspects"] += 1
            
            context.manager.update_metadata(context.record)

    async def _get_soft_404_fingerprint(self, context: PipelineContext, client: AsyncHTTPClient, host: str, timeout: int) -> Optional[Dict[str, Any]]:
        if not host: return None
        random_path = f"/this-does-not-exist-{uuid.uuid4().hex[:10]}"
        url = f"https://{host}{random_path}"
        if not context.url_allowed(url):
            url = f"http://{host}{random_path}"
        try:
            resp = await client.get(url)
            return {
                "status": resp.status,
                "body_md5": hashlib.md5(resp.body.encode(), usedforsecurity=False).hexdigest()
            }
        except Exception: return None

    async def _fetch(
        self,
        client: AsyncHTTPClient,
        context: PipelineContext,
        url: str,
        auth_label: str,
        token: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        if not context.url_allowed(url):
            return None
        headers = {"User-Agent": "recon-cli idor"}
        if token:
            headers["Authorization"] = token
        
        try:
            resp = await client.get(url, headers=headers)
        except Exception as exc:
            context.logger.debug("IDOR request failed for %s (%s): %s", url, auth_label, exc)
            return None

        body = resp.body
        body_md5 = hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()
        
        # Simple JSON helper
        data_json = {}
        try:
            data_json = json.loads(body)
        except Exception: pass

        return {
            "status": resp.status,
            "body_md5": body_md5,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "sensitive": self._extract_sensitive(data_json, body[:4000]),
            "subject_ids": self._extract_subject_ids(data_json, body[:4000]),
            "text_sample": body[:4000],
            "url": url,
            "auth": auth_label,
        }

    def _collect_candidates(
        self, context: PipelineContext, items: Iterable[Dict[str, object]]
    ) -> List[Candidate]:
        max_targets = max(1, int(getattr(context.runtime_config, "idor_max_targets", self.MAX_TARGETS)))
        max_per_host = max(1, int(getattr(context.runtime_config, "idor_max_per_host", self.MAX_PER_HOST)))
        scored: List[Tuple[int, Candidate]] = []
        for entry in items:
            if entry.get("type") != "url": continue
            url = entry.get("url")
            if not isinstance(url, str) or not url or not context.url_allowed(url): continue
            parsed = urlparse(url)
            if self._is_static_asset(parsed.path): continue
            
            params = parse_qsl(parsed.query, keep_blank_values=True)
            matched_params: List[str] = []
            for key, value in params:
                if any(keyword in key.lower() for keyword in self.PARAM_KEYWORDS) or self._looks_like_identifier(value):
                    matched_params.append(key)
            
            path_parts = [part for part in parsed.path.split("/") if part]
            matched_path_indexes = [idx for idx, part in enumerate(path_parts) if self._looks_like_identifier(part) or any(keyword in part.lower() for keyword in self.PARAM_KEYWORDS)]
            
            if not matched_params and not matched_path_indexes: continue
            
            candidate = Candidate(entry=entry, url=url, parsed=parsed, params=params, path_parts=path_parts, matched_params=matched_params, matched_path_indexes=matched_path_indexes)
            scored.append((self._candidate_priority(candidate), candidate))

        if not scored: return []
        scored.sort(key=lambda item: item[0], reverse=True)
        selected: List[Candidate] = []
        host_counts: Dict[str, int] = {}
        for _, candidate in scored:
            host = (candidate.parsed.hostname or "").lower()
            if host and host_counts.get(host, 0) >= max_per_host: continue
            selected.append(candidate)
            if host: host_counts[host] = host_counts.get(host, 0) + 1
            if len(selected) >= max_targets: break
        return selected

    @staticmethod
    def _looks_like_identifier(value: str) -> bool:
        if not value: return False
        if value.isdigit() or UUID_RE.fullmatch(value): return True
        return any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)

    def _is_static_asset(self, path: str) -> bool:
        lower = (path or "").lower()
        return any(lower.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _candidate_priority(self, candidate: Candidate) -> int:
        score = int(candidate.entry.get("score") or 0)
        path = (candidate.parsed.path or "").lower()
        if path.startswith("/api") or "/api/" in path: score += 30
        if any(hint in path for hint in self.PATH_HINTS): score += 20
        if candidate.matched_params: score += 20 + min(10, len(candidate.matched_params) * 3)
        if candidate.matched_path_indexes: score += 15 + min(10, len(candidate.matched_path_indexes) * 3)
        if "logout" in candidate.url.lower(): score -= 40
        return score

    def _generate_variants(self, candidate: Candidate, other_id: Optional[str], harvested: Optional[List[str]] = None) -> List[Tuple[str, Dict[str, object]]]:
        variants = []
        parsed = candidate.parsed
        for key in candidate.matched_params:
            originals = [value for k, value in candidate.params if k == key]
            if not originals: continue
            for variant_value in self._value_variants(originals[0], other_id, harvested=harvested):
                if variant_value == originals[0]: continue
                new_params = []
                replaced = False
                for name, value in candidate.params:
                    if name == key and not replaced:
                        new_params.append((name, variant_value)); replaced = True
                    else: new_params.append((name, value))
                new_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                variants.append((new_url, {"parameter": key, "original": originals[0], "variant": variant_value}))
        
        for idx in candidate.matched_path_indexes:
            base_value = candidate.path_parts[idx]
            for variant_value in self._value_variants(base_value, other_id, harvested=harvested):
                if variant_value == base_value: continue
                new_parts = [str(p) for p in candidate.path_parts]
                new_parts[idx] = str(variant_value)
                new_url = urlunparse(parsed._replace(path="/" + "/".join(new_parts)))
                variants.append((new_url, {"path_index": idx, "original": base_value, "variant": variant_value}))
        
        seen = set()
        unique = []
        for u, m in variants:
            if u not in seen:
                seen.add(u); unique.append((u, m))
                if len(unique) >= 50: break
        return unique

    def _value_variants(self, value: str, other_id: Optional[str], harvested: Optional[List[str]] = None) -> List[str]:
        variants = []
        # 1. Numeric Sweep (Elite: wider range)
        try:
            num = int(value)
            for i in [-1, 1, -2, 2, 10, -10]:
                variants.append(str(num + i))
            variants.extend(["0", "1", "999999"])
        except ValueError: pass

        # 2. UUID Randomization
        if UUID_RE.fullmatch(value):
            import uuid
            for _ in range(3):
                variants.append(str(uuid.uuid4()))
            variants.append(ZERO_UUID)

        # 3. ELITE: Harvested ID Replay
        if harvested:
            variants.extend(harvested[:5])

        # 4. Base64 Manipulation
        if self._looks_like_base64(value):
            manipulated = self._manipulate_base64(value)
            if manipulated: variants.extend(manipulated)

        # 4. Standard Fuzz
        variants.extend(["null", "true", "false", "undefined"])
        if value and len(value) < 50: variants.append("x" + value)
        
        if other_id: variants.append(other_id)
        
        # Dedupe and limit
        return list(dict.fromkeys(variants))[:self.MAX_VARIANTS_PER_PARAM]

    def _looks_like_base64(self, value: str) -> bool:
        if len(value) < 8 or len(value) % 4 != 0: return False
        return bool(re.match(r"^[A-Za-z0-9+/]+={0,2}$", value))

    def _manipulate_base64(self, value: str) -> List[str]:
        import base64
        results = []
        try:
            decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
            # Try numeric sweep on decoded value
            try:
                num = int(decoded)
                for i in [-1, 1]:
                    results.append(base64.b64encode(str(num + i).encode()).decode())
            except ValueError:
                # Try simple string change
                results.append(base64.b64encode(f"admin_{decoded}".encode()).decode())
                results.append(base64.b64encode(b"1").decode())
        except Exception: pass
        return results

    def _semantic_reasons(self, baseline: Dict[str, object], variant: Dict[str, object]) -> List[str]:
        reasons = []
        b_status, v_status = int(baseline.get("status", 0)), int(variant.get("status", 0))
        if v_status >= 500 or v_status in {400, 404, 422} or self._looks_like_auth_error(variant):
            return []
        if v_status in {200, 201, 202, 204, 206} and b_status in {401, 403, 404}:
            reasons.append("auth_bypass_status_change")
        if variant.get("sensitive") and not baseline.get("sensitive"):
            reasons.append("new_sensitive_fields")
        if (v_status in {200, 201, 202, 204, 206} and v_status == b_status and 
            variant.get("body_md5") != baseline.get("body_md5") and not self._looks_like_validation_error(variant)):
            reasons.append("successful_response_changed")
        return list(dict.fromkeys(reasons))

    def _assemble_finding(self, candidate: Candidate, url: str, meta: Dict[str, object], auth_label: str, token: Optional[str], baseline: Dict[str, object], variant: Dict[str, object], reasons: List[str]) -> Dict[str, object]:
        poc_header = f" -H 'Authorization: {token}'" if token else ""
        return {
            "type": "idor_suspect", "source": "idor-stage", "url": url, "auth": auth_label,
            "baseline_status": baseline["status"], "variant_status": variant["status"],
            "baseline_md5": baseline["body_md5"], "variant_md5": variant["body_md5"],
            "baseline_sensitive": baseline["sensitive"], "variant_sensitive": variant["sensitive"],
            "details": {**meta, "reasons": reasons}, "poc": f"curl -k{poc_header} '{url}'",
            "score": min(70 + len(reasons) * 10, 95), "priority": "high", "tags": ["idor"],
        }

    def _extract_sensitive(self, data_json: Dict[str, object], text: str) -> Dict[str, object]:
        payload = {}
        if data_json: self._collect_sensitive(data_json, payload, prefix="", depth=0)
        if not payload and text:
            lowered = text.lower()
            for key in self.SENSITIVE_KEYS:
                if key in lowered: payload[key] = True
        return payload

    def _extract_subject_ids(self, data_json: Dict[str, object], text: str) -> Set[str]:
        subjects = set()
        if data_json: self._collect_subject_ids(data_json, subjects, depth=0)
        if not subjects and text:
            for match in UUID_RE.findall(text): subjects.add(match.lower())
        return subjects

    def _collect_sensitive(self, node: object, out: Dict[str, object], *, prefix: str, depth: int) -> None:
        if depth > 4: return
        if isinstance(node, dict):
            for key, value in node.items():
                k = str(key).lower()
                new_p = f"{prefix}.{k}" if prefix else k
                if k in self.SENSITIVE_KEYS: out[new_p] = value
                self._collect_sensitive(value, out, prefix=new_p, depth=depth + 1)
        elif isinstance(node, list):
            for item in node[:10]: self._collect_sensitive(item, out, prefix=prefix, depth=depth + 1)

    def _collect_subject_ids(self, node: object, out: Set[str], *, depth: int) -> None:
        if depth > 4: return
        if isinstance(node, dict):
            for key, value in node.items():
                k = str(key).lower()
                if k in self.SUBJECT_KEYS or k.endswith("_id"):
                    val = self._normalize_subject(value)
                    if val: out.add(val)
                self._collect_subject_ids(value, out, depth=depth + 1)
        elif isinstance(node, list):
            for item in node[:20]: self._collect_subject_ids(item, out, depth=depth + 1)

    @staticmethod
    def _normalize_subject(value: object) -> str:
        if isinstance(value, (int, float)): return str(int(value))
        if isinstance(value, str):
            c = value.strip().strip('"').strip("'")
            if UUID_RE.fullmatch(c) or c.isdigit() or 3 <= len(c) <= 64: return c[:64]
        return ""

    def _looks_like_validation_error(self, payload: Dict[str, object]) -> bool:
        if int(payload.get("status", 0)) in {400, 422}: return True
        return any(h in str(payload.get("text_sample", "")).lower() for h in ("validation", "invalid", "malformed"))

    def _looks_like_auth_error(self, payload: Dict[str, object]) -> bool:
        if int(payload.get("status", 0)) in {401, 403}: return True
        return any(h in str(payload.get("text_sample", "")).lower() for h in self.AUTH_ERROR_HINTS)
