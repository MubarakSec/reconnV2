from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
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
    SUBJECT_KEYS = {"id", "user_id", "owner_id", "account_id", "uid", "tenant_id", "org_id", "project_id"}
    AUTH_ERROR_HINTS = ("unauthorized", "forbidden", "access denied", "permission", "login required")
    MAX_TARGETS = 40
    MAX_PER_HOST = 6
    MAX_VARIANTS_PER_PARAM = 7
    PATH_HINTS = (
        "user",
        "users",
        "account",
        "accounts",
        "profile",
        "tenant",
        "org",
        "project",
        "order",
        "invoice",
        "payment",
        "admin",
    )
    STATIC_EXTENSIONS = (
        ".js",
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
        ".pdf",
        ".zip",
        ".gz",
        ".mp4",
        ".mp3",
        ".webp",
    )

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
        limiter = context.get_rate_limiter(
            "idor_probe",
            rps=float(getattr(runtime, "idor_rps", 0)),
            per_host=float(getattr(runtime, "idor_per_host_rps", 0)),
        )
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
                    baseline_data = self._fetch(
                        session,
                        context,
                        baseline_url,
                        auth_label,
                        token,
                        timeout,
                        verify_tls,
                        limiter,
                    )
                    if not baseline_data:
                        continue
                    baseline_cache[baseline_key] = baseline_data
                else:
                    baseline_data = baseline_cache[baseline_key]
                for variant_url, variant_meta in variants:
                    stats["tests"] += 1
                    data = self._fetch(
                        session,
                        context,
                        variant_url,
                        auth_label,
                        token,
                        timeout,
                        verify_tls,
                        limiter,
                    )
                    if not data:
                        continue
                    reasons = self._semantic_reasons(baseline_data, data)
                    if reasons:
                        finding = self._assemble_finding(
                            candidate,
                            variant_url,
                            variant_meta,
                            auth_label,
                            token,
                            baseline_data,
                            data,
                            reasons,
                        )
                        if context.results.append(finding):
                            stats["suspects"] += 1
        context.manager.update_metadata(context.record)

    def _collect_candidates(self, context: PipelineContext, items: Iterable[Dict[str, object]]) -> List[Candidate]:
        max_targets = max(1, int(getattr(context.runtime_config, "idor_max_targets", self.MAX_TARGETS)))
        max_per_host = max(1, int(getattr(context.runtime_config, "idor_max_per_host", self.MAX_PER_HOST)))
        scored: List[Tuple[int, Candidate]] = []
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            if self._is_static_asset(parsed.path):
                continue
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
            candidate = Candidate(
                entry=entry,
                url=url,
                parsed=parsed,
                params=params,
                path_parts=path_parts,
                matched_params=matched_params,
                matched_path_indexes=matched_path_indexes,
            )
            score = self._candidate_priority(candidate)
            scored.append((score, candidate))

        if not scored:
            return []
        scored.sort(key=lambda item: item[0], reverse=True)
        selected: List[Candidate] = []
        host_counts: Dict[str, int] = {}
        for _, candidate in scored:
            host = (candidate.parsed.hostname or "").lower()
            if host and host_counts.get(host, 0) >= max_per_host:
                continue
            selected.append(candidate)
            if host:
                host_counts[host] = host_counts.get(host, 0) + 1
            if len(selected) >= max_targets:
                break
        return selected

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

    def _is_static_asset(self, path: str) -> bool:
        lower = (path or "").lower()
        return any(lower.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _candidate_priority(self, candidate: Candidate) -> int:
        score = int(candidate.entry.get("score") or 0)
        path = (candidate.parsed.path or "").lower()
        url = candidate.url.lower()
        if path.startswith("/api") or "/api/" in path:
            score += 30
        if any(hint in path for hint in self.PATH_HINTS):
            score += 20
        if candidate.matched_params:
            score += 20 + min(10, len(candidate.matched_params) * 3)
        if candidate.matched_path_indexes:
            score += 15 + min(10, len(candidate.matched_path_indexes) * 3)
        if "graphql" in path:
            score -= 20
        tags = candidate.entry.get("tags")
        if isinstance(tags, list):
            lowered_tags = {str(tag).lower() for tag in tags}
            if any(tag.startswith("api") for tag in lowered_tags):
                score += 12
        status = int(candidate.entry.get("status_code") or 0)
        if status in {200, 401, 403}:
            score += 8
        if "logout" in url:
            score -= 40
        return score

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

    def _fetch(
        self,
        session: "requests.Session",
        context: PipelineContext,
        url: str,
        auth_label: str,
        token: Optional[str],
        timeout: int,
        verify_tls: bool,
        limiter=None,
    ) -> Optional[Dict[str, object]]:
        if not context.url_allowed(url):
            return None
        headers = {"User-Agent": "recon-cli idor"}
        if token:
            headers["Authorization"] = token
        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return None
        try:
            resp = session.get(url, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
        except Exception as exc:
            context.logger.debug("IDOR request failed for %s (%s): %s", url, auth_label, exc)
            if limiter:
                limiter.on_error(url)
            return None
        if limiter:
            limiter.on_response(url, resp.status_code)
        body = resp.content or b""
        body_md5 = hashlib.md5(body).hexdigest()
        headers_lower = {key.lower(): value for key, value in resp.headers.items()}
        text = ""
        try:
            text = resp.text[:4000]
        except Exception:
            text = ""
        data_json = self._safe_json_dict(resp)
        data = {
            "status": resp.status_code,
            "body_md5": body_md5,
            "headers": headers_lower,
            "sensitive": self._extract_sensitive(data_json, text),
            "subject_ids": self._extract_subject_ids(data_json, text),
            "text_sample": text,
            "url": url,
            "auth": auth_label,
        }
        return data

    def _extract_sensitive(self, data_json: Dict[str, object], text: str) -> Dict[str, object]:
        payload: Dict[str, object] = {}
        if data_json:
            self._collect_sensitive(data_json, payload, prefix="", depth=0)
        if not payload and text:
            lowered = text.lower()
            for key in self.SENSITIVE_KEYS:
                if key in lowered:
                    payload[key] = True
        return payload

    def _extract_subject_ids(self, data_json: Dict[str, object], text: str) -> Set[str]:
        subjects: Set[str] = set()
        if data_json:
            self._collect_subject_ids(data_json, subjects, depth=0)
        if not subjects and text:
            for match in UUID_RE.findall(text):
                subjects.add(match.lower())
            for match in re.findall(r"\\b\\d{2,12}\\b", text):
                subjects.add(match)
                if len(subjects) >= 10:
                    break
        return subjects

    def _semantic_reasons(self, baseline: Dict[str, object], variant: Dict[str, object]) -> List[str]:
        reasons: List[str] = []
        base_status = int(baseline.get("status") or 0)
        var_status = int(variant.get("status") or 0)
        if var_status >= 500:
            return reasons
        if var_status in {400, 404, 422}:
            return reasons
        if self._looks_like_auth_error(variant):
            return reasons
        if var_status in {200, 201, 202, 204, 206} and base_status in {401, 403, 404}:
            reasons.append("auth_bypass_status_change")
        if variant.get("sensitive") and not baseline.get("sensitive"):
            reasons.append("new_sensitive_fields")
        base_subjects = set(baseline.get("subject_ids") or [])
        var_subjects = set(variant.get("subject_ids") or [])
        if base_subjects and var_subjects and base_subjects != var_subjects:
            reasons.append("subject_identifier_changed")
        if (
            var_status in {200, 201, 202, 204, 206}
            and var_status == base_status
            and variant.get("body_md5") != baseline.get("body_md5")
            and not self._looks_like_validation_error(variant)
        ):
            reasons.append("successful_response_changed")
        if not reasons:
            return reasons
        if (
            variant.get("body_md5") == baseline.get("body_md5")
            and var_status == base_status
            and not variant.get("sensitive")
            and base_subjects == var_subjects
        ):
            return []
        return list(dict.fromkeys(reasons))

    def _assemble_finding(
        self,
        candidate: Candidate,
        url: str,
        meta: Dict[str, object],
        auth_label: str,
        token: Optional[str],
        baseline: Dict[str, object],
        variant: Dict[str, object],
        reasons: List[str],
    ) -> Dict[str, object]:
        poc_header = ""
        if token:
            label = "Token-A" if auth_label == "token-a" else "Token-B"
            poc_header = f" -H 'Authorization: {label}'"
        poc_command = f"curl -k{poc_header} '{url}'"
        base_score = 70
        if "auth_bypass_status_change" in reasons:
            base_score += 15
        if "new_sensitive_fields" in reasons:
            base_score += 10
        if "subject_identifier_changed" in reasons:
            base_score += 10
        score = min(base_score, 95)
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
            "details": {
                **meta,
                "reasons": reasons,
                "baseline_subject_ids": sorted(set(baseline.get("subject_ids") or []))[:20],
                "variant_subject_ids": sorted(set(variant.get("subject_ids") or []))[:20],
            },
            "poc": poc_command,
            "score": score,
            "priority": "high",
        }

    @staticmethod
    def _safe_json_dict(response: "requests.Response") -> Dict[str, object]:
        try:
            data = response.json()
        except Exception:
            return {}
        if isinstance(data, dict):
            return data
        return {}

    def _collect_sensitive(self, node: object, out: Dict[str, object], *, prefix: str, depth: int) -> None:
        if depth > 4:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                key_str = str(key).lower()
                new_prefix = f"{prefix}.{key_str}" if prefix else key_str
                if key_str in self.SENSITIVE_KEYS:
                    out[new_prefix] = value
                self._collect_sensitive(value, out, prefix=new_prefix, depth=depth + 1)
                if len(out) >= 25:
                    return
        elif isinstance(node, list):
            for item in node[:10]:
                self._collect_sensitive(item, out, prefix=prefix, depth=depth + 1)
                if len(out) >= 25:
                    return

    def _collect_subject_ids(self, node: object, out: Set[str], *, depth: int) -> None:
        if depth > 4:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                key_str = str(key).lower()
                if key_str in self.SUBJECT_KEYS or key_str.endswith("_id"):
                    extracted = self._normalize_subject(value)
                    if extracted:
                        out.add(extracted)
                self._collect_subject_ids(value, out, depth=depth + 1)
                if len(out) >= 20:
                    return
        elif isinstance(node, list):
            for item in node[:20]:
                self._collect_subject_ids(item, out, depth=depth + 1)
                if len(out) >= 20:
                    return

    @staticmethod
    def _normalize_subject(value: object) -> str:
        if isinstance(value, (int, float)):
            return str(int(value))
        if isinstance(value, str):
            cleaned = value.strip().strip('"').strip("'")
            if not cleaned:
                return ""
            if UUID_RE.fullmatch(cleaned):
                return cleaned.lower()
            if cleaned.isdigit():
                return cleaned
            if 3 <= len(cleaned) <= 64:
                return cleaned[:64]
        return ""

    def _looks_like_validation_error(self, payload: Dict[str, object]) -> bool:
        status = int(payload.get("status") or 0)
        if status in {400, 422}:
            return True
        text = str(payload.get("text_sample") or "").lower()
        validation_hints = ("validation", "invalid", "malformed", "missing required")
        return any(hint in text for hint in validation_hints)

    def _looks_like_auth_error(self, payload: Dict[str, object]) -> bool:
        status = int(payload.get("status") or 0)
        if status in {401, 403}:
            return True
        text = str(payload.get("text_sample") or "").lower()
        return any(hint in text for hint in self.AUTH_ERROR_HINTS)
