from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.jsonl import read_jsonl

SENSITIVE_KEYS = {"email", "role", "roles", "balance", "owner_id", "user_id", "account_id"}


@dataclass
class AuthRecord:
    url: str
    auth: str
    status: int
    body_md5: str
    length: int
    sensitive: Dict[str, object]


class AuthMatrixStage(Stage):
    name = "auth_matrix"
    optional = True
    MAX_TARGETS = 80

    def is_enabled(self, context: PipelineContext) -> bool:
        if requests is None:
            context.logger.info("requests library not available; skipping AuthMatrix stage")
            return False
        return True

    def execute(self, context: PipelineContext) -> None:
        urls = self._collect_urls(context)
        if not urls:
            context.logger.info("AuthMatrix stage: no URLs to evaluate")
            return
        runtime = context.runtime_config
        tokens: List[Tuple[str, Optional[str]]] = [("anon", None)]
        if getattr(runtime, "idor_token_a", None):
            tokens.append(("token-a", runtime.idor_token_a))
        if getattr(runtime, "idor_token_b", None):
            tokens.append(("token-b", runtime.idor_token_b))
        if len(tokens) < 2:
            context.logger.info("AuthMatrix stage: additional tokens not configured; skipping")
            return
        session = requests.Session()
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        if not verify_tls:
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            except Exception:
                pass
        timeout = getattr(runtime, "idor_timeout", 10)
        stats = context.record.metadata.stats.setdefault("auth_matrix", {"tests": 0, "issues": 0})
        tsv_lines = ["url	auth	status	body_md5	length	sensitive_keys"]
        for url in urls:
            records: List[AuthRecord] = []
            baseline_data: Dict[str, Dict[str, object]] = {}
            for auth_label, token in tokens:
                data = self._fetch(session, context, url, auth_label, token, timeout, verify_tls)
                if not data:
                    continue
                stats["tests"] += 1
                record = AuthRecord(
                    url=url,
                    auth=auth_label,
                    status=data["status"],
                    body_md5=data["body_md5"],
                    length=data["length"],
                    sensitive=data["sensitive"],
                )
                records.append(record)
                baseline_data[auth_label] = data
                sensitive_keys = ",".join(sorted(record.sensitive.keys())) if record.sensitive else ""
                tsv_lines.append(
                    f"{url}	{auth_label}	{record.status}	{record.body_md5}	{record.length}	{sensitive_keys}"
                )
            issues = self._detect_issues(records, baseline_data)
            for issue in issues:
                if context.results.append(issue):
                    stats["issues"] += 1
        artifacts_dir = context.record.paths.ensure_subdir("auth_matrix")
        (artifacts_dir / "auth_matrix.tsv").write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")
        context.manager.update_metadata(context.record)

    def _collect_urls(self, context: PipelineContext) -> List[str]:
        items = read_jsonl(context.record.paths.results_jsonl)
        urls: List[str] = []
        seen = set()
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if url in seen:
                continue
            if not context.url_allowed(url):
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= self.MAX_TARGETS:
                break
        return urls

    def _fetch(
        self,
        session: "requests.Session",
        context: PipelineContext,
        url: str,
        auth_label: str,
        token: Optional[str],
        timeout: int,
        verify_tls: bool,
    ) -> Optional[Dict[str, object]]:
        headers = {"User-Agent": "recon-cli auth-matrix"}
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
            context.logger.debug("AuthMatrix request failed for %s (%s): %s", url, auth_label, exc)
            return None
        if resp.status_code == 304 and not context.force:
            return None
        body = resp.content or b""
        body_md5 = hashlib.md5(body).hexdigest()
        headers_lower = {key.lower(): value for key, value in resp.headers.items()}
        etag = headers_lower.get("etag")
        last_modified = headers_lower.get("last-modified")
        context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
        sensitive = self._extract_sensitive(resp)
        return {
            "status": resp.status_code,
            "body_md5": body_md5,
            "length": len(body),
            "headers": headers_lower,
            "sensitive": sensitive,
        }

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
                for key in SENSITIVE_KEYS:
                    if key in data:
                        payload[key] = data[key]
        except json.JSONDecodeError:
            pass
        if not payload and text:
            for key in SENSITIVE_KEYS:
                if key in text:
                    payload[key] = True
        return payload

    def _detect_issues(
        self,
        records: Sequence[AuthRecord],
        baseline_data: Dict[str, Dict[str, object]],
    ) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        record_map = {record.auth: record for record in records}
        if "token-a" in record_map and "anon" in record_map:
            a = record_map["token-a"]
            anon = record_map["anon"]
            if anon.status == a.status and anon.body_md5 == a.body_md5:
                findings.append(
                    self._build_finding(
                        url=a.url,
                        reason="unauthenticated_response_matches_token_a",
                        involved=["anon", "token-a"],
                        record_map=record_map,
                    )
                )
        if "token-a" in record_map and "token-b" in record_map:
            a = record_map["token-a"]
            b = record_map["token-b"]
            if a.body_md5 == b.body_md5 and a.status == b.status:
                findings.append(
                    self._build_finding(
                        url=a.url,
                        reason="token_b_sees_same_content_as_token_a",
                        involved=["token-a", "token-b"],
                        record_map=record_map,
                    )
                )
            elif a.sensitive and b.sensitive and a.sensitive == b.sensitive:
                findings.append(
                    self._build_finding(
                        url=a.url,
                        reason="token_b_sensitive_matches_token_a",
                        involved=["token-a", "token-b"],
                        record_map=record_map,
                    )
                )
        if "anon" in record_map and "token-b" in record_map:
            anon = record_map["anon"]
            b = record_map["token-b"]
            if anon.status == b.status and anon.body_md5 == b.body_md5:
                findings.append(
                    self._build_finding(
                        url=b.url,
                        reason="unauthenticated_response_matches_token_b",
                        involved=["anon", "token-b"],
                        record_map=record_map,
                    )
                )
        return findings

    def _build_finding(
        self,
        *,
        url: str,
        reason: str,
        involved: Sequence[str],
        record_map: Dict[str, AuthRecord],
    ) -> Dict[str, object]:
        details = {
            label: {
                "status": record_map[label].status,
                "body_md5": record_map[label].body_md5,
                "sensitive": record_map[label].sensitive,
            }
            for label in involved
        }
        return {
            "type": "auth_matrix_issue",
            "source": "auth-matrix",
            "url": url,
            "reason": reason,
            "details": details,
        }
