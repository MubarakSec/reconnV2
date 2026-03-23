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
        stats = context.record.metadata.stats.setdefault("idor_validator", {})
        if not candidates:
            stats.update({"attempted": 0, "confirmed": 0, "failed": 0, "skipped": 0})
            context.manager.update_metadata(context.record)
            return

        helper = IDORStage()
        attempted, confirmed, failed, skipped = 0, 0, 0, 0
        artifacts: List[Dict[str, object]] = []
        seen: Set[Tuple[str, str]] = set()

        client_config = HTTPClientConfig(
            max_concurrent=15, total_timeout=float(timeout), verify_ssl=verify_tls,
            requests_per_second=float(getattr(runtime, "idor_validator_rps", 20.0))
        )

        async with AsyncHTTPClient(client_config) as client:
            # Determine host-specific Soft-404 Fingerprint
            host = urlparse(str(candidates[0].get("baseline_url") or "")).hostname or ""
            soft_404_fingerprint = await self._get_soft_404_fingerprint(context, client, host, timeout)

            for candidate in candidates:
                variant_url = str(candidate.get("url") or "")
                auth_label = str(candidate.get("auth") or "anon")
                baseline_url = str(candidate.get("baseline_url") or "")
                key = (variant_url, auth_label)
                if not variant_url or not baseline_url or key in seen: continue
                seen.add(key)

                host = urlparse(baseline_url).hostname or ""
                token_a = self._resolve_token(context, "token-a", host, runtime)
                token_b = self._resolve_token(context, "token-b", host, runtime)
                if not token_a: skipped += 1; continue

                # 1. Fetch User A Profile (Baseline)
                profile_a, _ = await self._fetch_profile(context, client, helper, baseline_url, auth_label="token-a", token=token_a)
                
                # Soft-404 Check
                if profile_a and soft_404_fingerprint:
                    if profile_a["status"] == soft_404_fingerprint["status"] and profile_a["body_md5"] == soft_404_fingerprint["body_md5"]:
                        skipped += 1; continue
                if not profile_a or profile_a["status"] >= 400: continue

                # ELITE: Harvest real IDs for cross-account testing
                harvested_ids = profile_a.get("subject_ids") or set()
                
                # 2. Test User B & Anon with both original variant AND harvested variants
                test_urls = [(variant_url, "original")]
                for hid in list(harvested_ids)[:2]:
                    h_url = self._swap_id_in_url(variant_url, hid)
                    if h_url: test_urls.append((h_url, f"harvested:{hid}"))

                for t_url, t_desc in test_urls:
                    attempted += 1
                    profile_b = await self._fetch_profile(context, client, helper, t_url, auth_label="token-b", token=token_b) if token_b else (None, "")
                    profile_b = profile_b[0] if isinstance(profile_b, tuple) else profile_b
                    
                    profile_anon, _ = await self._fetch_profile(context, client, helper, t_url, auth_label="anon", token=None)
                    
                    is_confirmed = False
                    reasons = []
                    final_profile = None
                    final_auth = "none"

                    if profile_b and profile_b["status"] == profile_a["status"] and profile_b["body_md5"] == profile_a["body_md5"]:
                        is_confirmed, final_profile, final_auth = True, profile_b, "token-b"
                        reasons.append("cross_user_access_confirmed")
                    elif profile_anon and profile_anon["status"] == profile_a["status"] and profile_anon["body_md5"] == profile_a["body_md5"]:
                        is_confirmed, final_profile, final_auth = True, profile_anon, "anon"
                        reasons.append("unauthenticated_access_confirmed")

                    if is_confirmed:
                        signal_id = context.emit_signal("idor_confirmed", "url", t_url, confidence=1.0, source=self.name, tags=["idor", "confirmed", t_desc], evidence={"auth": final_auth})
                        finding = {
                            "type": "finding", "finding_type": "idor", "source": self.name, "url": t_url, "hostname": host,
                            "description": f"IDOR confirmed via {final_auth} cross-check ({t_desc})",
                            "details": {"auth": final_auth, "variant": t_desc, "baseline_status": profile_a["status"], "variant_status": final_profile["status"]},
                            "proof": f"curl -k -H 'Authorization: {final_auth}' '{t_url}'", "tags": ["idor", "confirmed", "logic-aware"],
                            "score": max(95, int(candidate.get("score", 0))), "priority": "high", "severity": "critical", "confidence_label": "verified", "evidence_id": signal_id or None,
                        }
                        if context.results.append(finding): confirmed += 1; break # Found one for this candidate, move on

        stats.update({"attempted": attempted, "confirmed": confirmed, "failed": failed, "skipped": skipped, "candidates": len(candidates)})
        context.manager.update_metadata(context.record)

    async def _fetch_profile(self, context: PipelineContext, client: AsyncHTTPClient, helper: IDORStage, url: str, *, auth_label: str, token: Optional[str]) -> Tuple[Optional[Dict[str, Any]], str]:
        if not context.url_allowed(url): return None, "skipped"
        headers = {"User-Agent": "recon-cli idor-validator"}
        if token: headers["Authorization"] = token
        try:
            resp = await client.get(url, headers=headers)
            body = resp.body
            data_json = {}
            try: data_json = json.loads(body)
            except Exception: pass
            
            # Use helper to harvest IDs
            sids = set()
            helper._collect_subject_ids(data_json, sids, depth=0)

            return {
                "status": resp.status, "body_md5": hashlib.md5(body.encode(), usedforsecurity=False).hexdigest(),
                "sensitive": helper._extract_sensitive(data_json, body[:4000]), "subject_ids": sids, "url": url, "auth": auth_label,
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
        for entry in context.iter_results():
            if str(entry.get("type") or "").lower() != "idor_suspect": continue
            url = str(entry.get("url") or "").strip()
            if not url or url in seen: continue
            
            details = entry.get("details")
            if not isinstance(details, dict): continue
            baseline_url = self._derive_baseline_url(url, details)
            if not baseline_url: continue
            
            score = int(entry.get("score", 0) or 0)
            if score < min_score: continue
            
            host = urlparse(url).hostname or ""
            grouped[host].append({"url": url, "auth": entry.get("auth", "anon"), "score": score, "baseline_url": baseline_url})
            seen.add(url)

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
