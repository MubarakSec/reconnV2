from __future__ import annotations

import hashlib
import json
import asyncio
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.utils import time as time_utils
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class IDORValidatorStage(Stage):
    name = "idor_validator"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_idor_validator", True))

    async def run_async(self, context: PipelineContext) -> None:
        runtime = context.runtime_config
        max_candidates = max(1, int(getattr(runtime, "idor_validator_max_candidates", 40)))
        max_per_host = max(1, int(getattr(runtime, "idor_validator_max_per_host", 8)))
        min_score = int(getattr(runtime, "idor_validator_min_score", 60))
        timeout = max(1, int(getattr(runtime, "idor_validator_timeout", 10)))
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        
        candidates = self._collect_candidates(context, min_score=min_score, max_candidates=max_candidates, max_per_host=max_per_host)
        context.update_stats(self.name, attempted=0, confirmed=0, skipped=0)
        if not candidates:
            return

        helper = IDORStage()
        client_config = HTTPClientConfig(
            max_concurrent=15, total_timeout=float(timeout), verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "idor_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config, context=context) as client:
            # 1. Identity Selection (Phase 1 integration)
            identities = context._auth_manager.get_all_identities()
            
            # Determine host-specific Soft-404 Fingerprint
            host = urlparse(str(candidates[0].get("baseline_url") or "")).hostname or ""
            soft_404_fingerprint = await self._get_soft_404_fingerprint(context, client, host, timeout)

            for candidate in candidates:
                variant_url = str(candidate.get("url") or "")
                baseline_url = str(candidate.get("baseline_url") or "")
                if not variant_url or not baseline_url: continue

                host = urlparse(baseline_url).hostname or ""
                
                # Filter identities relevant to this host
                host_identities = [i for i in identities if not i.host or i.host == host]
                if not host_identities:
                    # Fallback to legacy resolve_token if needed, but UnifiedAuthManager is preferred
                    token_a = self._resolve_token(context, "token-a", host, runtime)
                    if token_a:
                        context._auth_manager.register_identity("legacy-a", "user", {"bearer": token_a}, host=host, source="legacy")
                        host_identities = context._auth_manager.get_all_identities()

                if not host_identities:
                    context.update_stats(self.name, skipped=1)
                    continue

                # 2. Baseline: Fetch target resource with its legitimate identity
                harvest_id = host_identities[0].identity_id
                profile_a, _ = await self._fetch_profile(context, client, helper, variant_url, identity_id=harvest_id)
                
                if profile_a and soft_404_fingerprint:
                    if profile_a["status"] == soft_404_fingerprint["status"] and profile_a["body_md5"] == soft_404_fingerprint["body_md5"]:
                        continue
                if not profile_a or profile_a["status"] >= 400: continue

                # 3. Cross-Role Validation Loop (Adaptive)
                # Test with ALL other identities + Anonymous
                test_identities = [i for i in host_identities if i.identity_id != harvest_id]
                test_targets = [(ti.identity_id, ti.identity_id) for ti in test_identities]
                test_targets.append(("anon", None))

                for auth_label, identity_id in test_targets:
                    context.update_stats(self.name, attempted=1)
                    # Fetch SAME resource with test identity
                    profile_test, _ = await self._fetch_profile(context, client, helper, variant_url, identity_id=identity_id)
                    
                    if profile_test and profile_test["status"] == profile_a["status"] and profile_test["body_md5"] == profile_a["body_md5"]:
                        # IDOR CONFIRMED!
                        reasons = ["cross_user_access_confirmed"] if identity_id else ["unauthenticated_access_confirmed"]
                        signal_id = context.emit_signal("idor_confirmed", "url", variant_url, 
                                                       confidence=1.0, source=self.name, 
                                                       tags=["idor", "confirmed"], evidence={"auth": auth_label})
                        
                        finding = {
                            "type": "finding", "finding_type": "idor", "source": self.name, "url": variant_url, "hostname": host,
                            "description": f"IDOR confirmed via {auth_label} cross-check",
                            "details": {"auth": auth_label, "reasons": reasons, "baseline_status": profile_a["status"], "variant_status": profile_test["status"]},
                            "proof": f"reconn scan {variant_url} --identity {auth_label}", "tags": ["idor", "confirmed"],
                            "score": max(95, int(candidate.get("score", 0))), "priority": "high", "severity": "critical", "confidence_label": "verified", "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding):
                            context.update_stats(self.name, confirmed=1)
                            # Add to Target Graph
                            context.target_graph.add_entity("vulnerability", f"idor:{variant_url}", type="idor", confirmed=True)
                            break 

    async def _fetch_profile(self, context: PipelineContext, client: AsyncHTTPClient, helper: IDORStage, 
                             url: str, *, identity_id: Optional[str]) -> Tuple[Optional[Dict[str, Any]], str]:
        if not context.url_allowed(url): return None, "skipped"
        try:
            # Multi-identity support (Phase 1)
            resp = await client.get(url, identity_id=identity_id)
            body = resp.body
            data_json = {}
            try: data_json = json.loads(body)
            except Exception: pass
            
            # Use helper to harvest IDs
            sids = set()
            helper._collect_subject_ids(data_json, sids, depth=0)

            return {
                "status": resp.status, "body_md5": hashlib.md5(body.encode(), usedforsecurity=False).hexdigest(),
                "sensitive": helper._extract_sensitive(data_json, body[:4000]), "subject_ids": sids, "url": url, "identity_id": identity_id,
            }, "ok"
        except Exception: return None, "failed"

    def _swap_id_in_url(self, url: str, new_id: str) -> Optional[str]:
        # Simple ID swapper for BOLA testing
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated = []
        replaced = False
        for k, v in params:
            if k.lower() in ["id", "uid", "user", "account"] and not replaced:
                updated.append((k, new_id)); replaced = True
            else: updated.append((k, v))
        if replaced:
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
        return None

    async def _get_soft_404_fingerprint(self, context: PipelineContext, client: AsyncHTTPClient, host: str, timeout: int) -> Optional[Dict[str, Any]]:
        import uuid
        if not host: return None
        url = f"http://{host}/this-does-not-exist-{uuid.uuid4().hex[:10]}"
        try:
            resp = await client.get(url)
            return {"status": resp.status, "body_md5": hashlib.md5(resp.body.encode(), usedforsecurity=False).hexdigest()}
        except Exception: return None

    def _collect_candidates(self, context: PipelineContext, *, min_score: int, max_candidates: int, max_per_host: int) -> List[Dict[str, Any]]:
        grouped = defaultdict(list)
        seen = set()
        count = 0
        for entry in context.iter_results():
            count += 1
            etype = str(entry.get("type") or "").lower()
            if etype != "idor_suspect":
                continue
            
            url = str(entry.get("url") or "").strip()
            if not url or url in seen: continue
            
            details = entry.get("details")
            if not isinstance(details, dict):
                context.logger.warning("IDORValidator: Candidate %s has no details dict", url)
                continue
                
            baseline_url = self._derive_baseline_url(url, details)
            if not baseline_url:
                context.logger.warning("IDORValidator: Could not derive baseline URL for %s from details %s", url, details)
                continue
            
            score = int(entry.get("score", 0) or 0)
            if score < min_score:
                continue
            
            host = urlparse(url).hostname or ""
            grouped[host].append({"url": url, "auth": entry.get("auth", "anon"), "score": score, "baseline_url": baseline_url})
            seen.add(url)

        context.logger.info("IDORValidator: Iterated %d results, found %d unique suspects, %d candidates selected after score/host filtering", 
                            count, len(seen), sum(len(v) for v in grouped.values()))

        selected = []
        for items in grouped.values():
            items.sort(key=lambda x: x["score"], reverse=True)
            selected.extend(items[:max_per_host])
        return selected[:max_candidates]

    @staticmethod
    def _derive_baseline_url(url: str, details: Dict[str, Any]) -> str:
        try:
            parsed = urlparse(url)
            original = str(details.get("original") or "")
            if not original: return ""
            parameter = str(details.get("parameter") or "")
            if parameter:
                params = parse_qsl(parsed.query, keep_blank_values=True)
                updated = []
                replaced = False
                for k, v in params:
                    if k == parameter and not replaced: updated.append((k, original)); replaced = True
                    else: updated.append((k, v))
                if replaced: return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            
            p_idx = details.get("path_index")
            if isinstance(p_idx, int):
                parts = [p for p in parsed.path.split("/") if p]
                if 0 <= p_idx < len(parts):
                    parts[p_idx] = original
                    return urlunparse(parsed._replace(path="/" + "/".join(parts)))
        except Exception: pass
        return ""

    def _resolve_token(self, context: PipelineContext, auth_label: str, host: str, runtime) -> Optional[str]:
        if auth_label == "token-a":
            token = str(getattr(runtime, "idor_token_a", "") or "").strip()
            if token: return token
        elif auth_label == "token-b":
            token = str(getattr(runtime, "idor_token_b", "") or "").strip()
            if token: return token
        try:
            art_path = context.record.paths.artifact(f"sessions_{host}.json")
            if art_path.exists():
                sessions = fs.read_json(art_path)
                idx = 0 if auth_label == "token-a" else 1
                if idx < len(sessions):
                    sess = sessions[idx]
                    tokens = sess.get("tokens", {})
                    if "access_token" in tokens: return f"Bearer {tokens['access_token']}"
                    cookies = sess.get("cookies", {})
                    if cookies: return "; ".join([f"{k}={v}" for k, v in cookies.items()])
        except Exception: pass
        return None
