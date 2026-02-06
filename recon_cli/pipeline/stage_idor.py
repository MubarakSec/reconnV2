from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import ParseResult, parse_qsl, urlencode, urlparse, urlunparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl


UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
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
        "id",
        "user",
        "uid",
        "account",
        "acct",
        "org",
        "tenant",
        "project",
    }
    SENSITIVE_KEYS = {"email", "role", "roles", "balance", "owner_id", "user_id", "account_id"}
    MAX_TARGETS = 40
    MAX_VARIANTS_PER_PARAM = 7

    def is_enabled(self, context: PipelineContext) -> bool:
        if requests is None:
            context.logger.info("requests library not available; skipping IDOR stage")
            return False
        return True

    def execute(self, context: PipelineContext) -> None:
        items = read_jsonl(context.record.paths.results_jsonl)
        candidates = self._collect_candidates(context, items)
        if not candidates:
            context.logger.info("IDOR stage: no suitable endpoints found")
            return
        runtime = context.runtime_config
        tokens: List[Tuple[str, Optional[str]]] = [("anon", None)]
        if getattr(runtime, "idor_token_a", None):
            tokens.append(("token-a", runtime.idor_token_a))
        if getattr(runtime, "idor_token_b", None):
            tokens.append(("token-b", runtime.idor_token_b))
        session = requests.Session()
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        if not verify_tls:
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            except Exception:
                pass
        stats = context.record.metadata.stats.setdefault("idor", {"tests": 0, "suspects": 0})
        other_id = getattr(runtime, "idor_other_identifier", None)
        timeout = getattr(runtime, "idor_timeout", 10)
        baseline_cache: Dict[Tuple[str, str], Dict[str, object]] = {}
        for candidate in candidates:
            variants = self._generate_variants(candidate, other_id)
            if not variants:
                continue
            for auth_label, token in tokens:
                baseline_url = candidate.url
                baseline_key = (baseline_url, auth_label)
                if baseline_key not in baseline_cache:
                    baseline_data = self._fetch(session, context, baseline_url, auth_label, token, timeout, verify_tls)
                    if not baseline_data:
                        continue
                    baseline_cache[baseline_key] = baseline_data
                else:
                    baseline_data = baseline_cache[baseline_key]
                for variant_url, variant_meta in variants:
                    stats["tests"] += 1
                    data = self._fetch(session, context, variant_url, auth_label, token, timeout, verify_tls)
                    if not data:
                        continue
                    if self._is_interesting(baseline_data, data):
                        finding = self._assemble_finding(
                            candidate,
                            variant_url,
                            variant_meta,
                            auth_label,
                            token,
                            baseline_data,
                            data,
                        )
                        if context.results.append(finding):
                            stats["suspects"] += 1
        context.manager.update_metadata(context.record)

    def _collect_candidates(self, context: PipelineContext, items: Iterable[Dict[str, object]]) -> List[Candidate]:
        collected: List[Candidate] = []
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            matched_params: List[str] = []
            for key, value in params:
                key_lower = key.lower()
                if any(keyword in key_lower for keyword in self.PARAM_KEYWORDS):
                    matched_params.append(key)
                    continue
                if self._looks_like_identifier(value):
                    matched_params.append(key)
            path_parts = [part for part in parsed.path.split('/') if part]
            matched_path_indexes: List[int] = []
            for idx, part in enumerate(path_parts):
                if self._looks_like_identifier(part) or any(keyword in part.lower() for keyword in self.PARAM_KEYWORDS):
                    matched_path_indexes.append(idx)
            if not matched_params and not matched_path_indexes:
                continue
            collected.append(Candidate(entry=entry, url=url, parsed=parsed, params=params, path_parts=path_parts, matched_params=matched_params, matched_path_indexes=matched_path_indexes))
            if len(collected) >= self.MAX_TARGETS:
                break
        return collected

    @staticmethod
    def _looks_like_identifier(value: str) -> bool:
        if not value:
            return False
        if value.isdigit():
            return True
        if UUID_RE.fullmatch(value):
            return True
        if any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value):
            return True
        return False

    def _generate_variants(self, candidate: Candidate, other_id: Optional[str]) -> List[Tuple[str, Dict[str, object]]]:
        variants: List[Tuple[str, Dict[str, object]]] = []
        parsed = candidate.parsed
        if candidate.matched_params:
            for key in candidate.matched_params:
                originals = [value for k, value in candidate.params if k == key]
                if not originals:
                    continue
                base_value = originals[0]
                for variant_value in self._value_variants(base_value, other_id):
                    if variant_value == base_value:
                        continue
                    new_params = []
                    replaced = False
                    for name, value in candidate.params:
                        if name == key and not replaced:
                            new_params.append((name, variant_value))
                            replaced = True
                        else:
                            new_params.append((name, value))
                    new_query = urlencode(new_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    variants.append((new_url, {"parameter": key, "original": base_value, "variant": variant_value}))
        if candidate.matched_path_indexes:
            for idx in candidate.matched_path_indexes:
                base_value = candidate.path_parts[idx]
                for variant_value in self._value_variants(base_value, other_id):
                    if variant_value == base_value:
                        continue
                    new_parts = list(candidate.path_parts)
                    new_parts[idx] = variant_value
                    new_path = "/" + "/".join(new_parts)
                    new_url = urlunparse(parsed._replace(path=new_path))
                    variants.append((new_url, {"path_index": idx, "original": base_value, "variant": variant_value}))
        seen = set()
        unique_variants: List[Tuple[str, Dict[str, object]]] = []
        for url, meta in variants:
            if url in seen:
                continue
            seen.add(url)
            unique_variants.append((url, meta))
            if len(unique_variants) >= 50:
                break
        return unique_variants

    def _value_variants(self, value: str, other_id: Optional[str]) -> List[str]:
        variants: List[str] = []
        numeric_variants: List[int] = []
        try:
            num = int(value)
            numeric_variants = [num - 1, num, num + 1, 0, 1, 999999]
        except ValueError:
            pass
        for num in numeric_variants:
            variants.append(str(num))
        variants.extend(["null", "true", "false"])
        if value:
            variants.append("x" + value)
        if other_id:
            variants.append(other_id)
        variants.append(ZERO_UUID)
        variants.append("")
        return variants[: self.MAX_VARIANTS_PER_PARAM]

    def _fetch(self, session: "requests.Session", context: PipelineContext, url: str, auth_label: str, token: Optional[str], timeout: int, verify_tls: bool) -> Optional[Dict[str, object]]:
        if not context.url_allowed(url):
            return None
        headers = {"User-Agent": "recon-cli idor"}
        if token:
            headers["Authorization"] = token
        cache_entry = context.get_cache_entry(url)
        if cache_entry and not context.force:
            if cache_entry.get("etag"):
                headers["If-None-Match"] = cache_entry["etag"]
            if cache_entry.get("last_modified"):
                headers["If-Modified-Since"] = cache_entry["last_modified"]
        try:
            resp = session.get(url, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
        except Exception as exc:
            context.logger.debug("IDOR request failed for %s (%s): %s", url, auth_label, exc)
            return None
        if resp.status_code == 304 and not context.force:
            return None
        body = resp.content or b""
        body_md5 = hashlib.md5(body).hexdigest()
        headers_lower = {key.lower(): value for key, value in resp.headers.items()}
        etag = headers_lower.get("etag")
        last_modified = headers_lower.get("last-modified")
        context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
        data = {
            "status": resp.status_code,
            "body_md5": body_md5,
            "headers": headers_lower,
            "sensitive": self._extract_sensitive(resp),
            "url": url,
            "auth": auth_label,
        }
        return data

    def _extract_sensitive(self, response: "requests.Response") -> Dict[str, object]:
        payload: Dict[str, object] = {}
        text = ""
        try:
            text = response.text[:2000]
        except Exception:
            pass
        try:
            data = response.json()
            if isinstance(data, dict):
                for key in self.SENSITIVE_KEYS:
                    if key in data:
                        payload[key] = data[key]
        except json.JSONDecodeError:
            pass
        if not payload and text:
            for key in self.SENSITIVE_KEYS:
                if key in text:
                    payload[key] = True
        return payload

    def _is_interesting(self, baseline: Dict[str, object], variant: Dict[str, object]) -> bool:
        if variant["status"] >= 500:
            return False
        if variant["body_md5"] == baseline["body_md5"] and variant["status"] == baseline["status"] and variant["sensitive"] == baseline["sensitive"]:
            return False
        if variant["status"] == baseline["status"] and not variant["sensitive"] and variant["body_md5"] == baseline["body_md5"]:
            return False
        return True

    def _assemble_finding(self, candidate: Candidate, url: str, meta: Dict[str, object], auth_label: str, token: Optional[str], baseline: Dict[str, object], variant: Dict[str, object]) -> Dict[str, object]:
        poc_header = ""
        if token:
            label = "Token-A" if auth_label == "token-a" else "Token-B"
            poc_header = f" -H 'Authorization: {label}'"
        poc_command = f"curl -k{poc_header} '{url}'"
        return {
            "type": "idor_suspect",
            "source": "idor-stage",
            "url": url,
            "auth": auth_label,
            "baseline_status": baseline["status"],
            "variant_status": variant["status"],
            "baseline_md5": baseline["body_md5"],
            "variant_md5": variant["body_md5"],
            "baseline_sensitive": baseline["sensitive"],
            "variant_sensitive": variant["sensitive"],
            "details": meta,
            "poc": poc_command,
            "score": 75,
            "priority": "high",
        }
