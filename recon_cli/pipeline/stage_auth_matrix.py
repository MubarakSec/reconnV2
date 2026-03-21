from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage

SENSITIVE_KEYS = {
    "email",
    "role",
    "roles",
    "balance",
    "owner_id",
    "user_id",
    "account_id",
}
SUBJECT_KEYS = {
    "id",
    "user_id",
    "owner_id",
    "account_id",
    "uid",
    "tenant_id",
    "org_id",
    "project_id",
}
AUTH_HINTS = (
    "unauthorized",
    "forbidden",
    "access denied",
    "permission",
    "login required",
)
USER_SCOPED_HINTS = (
    "/me",
    "/profile",
    "/account",
    "/user",
    "/users",
    "/tenant",
    "/org",
    "/project",
)
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


@dataclass
class AuthRecord:
    url: str
    auth: str
    status: int
    body_md5: str
    length: int
    sensitive: Dict[str, object]
    subject_ids: Set[str]
    auth_error: bool


class AuthMatrixStage(Stage):
    name = "auth_matrix"
    optional = True
    MAX_TARGETS = 80
    MAX_PER_HOST = 10
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
            context.logger.info(
                "requests library not available; skipping AuthMatrix stage"
            )
            return False
        return True

    def execute(self, context: PipelineContext) -> None:
        urls = self._collect_urls(context)
        if not urls:
            context.logger.info("AuthMatrix stage: no URLs to evaluate")
            return

        runtime = context.runtime_config
        limiter = context.get_rate_limiter(
            "auth_matrix",
            rps=float(getattr(runtime, "auth_matrix_rps", 0)),
            per_host=float(getattr(runtime, "auth_matrix_per_host_rps", 0)),
        )

        tokens: List[Tuple[str, Optional[str]]] = [("anon", None)]
        if getattr(runtime, "idor_token_a", None):
            tokens.append(("token-a", runtime.idor_token_a))
        if getattr(runtime, "idor_token_b", None):
            tokens.append(("token-b", runtime.idor_token_b))
        if len(tokens) < 2:
            context.logger.info(
                "AuthMatrix stage: additional tokens not configured; skipping"
            )
            return

        session = requests.Session()
        verify_tls = bool(getattr(runtime, "verify_tls", True))
        if not verify_tls:
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            except Exception:
                context.logger.debug(
                    "Failed to disable urllib3 warnings", exc_info=True
                )

        timeout = int(getattr(runtime, "idor_timeout", 10))
        stats = context.record.metadata.stats.setdefault(
            "auth_matrix", {"tests": 0, "issues": 0}
        )
        tsv_lines = ["url\tauth\tstatus\tbody_md5\tlength\tsensitive_keys\tsubject_ids"]

        for url in urls:
            records: List[AuthRecord] = []
            for auth_label, token in tokens:
                data = self._fetch(
                    session,
                    context,
                    url,
                    auth_label,
                    token,
                    timeout,
                    verify_tls,
                    limiter,
                )
                if not data:
                    continue
                stats["tests"] += 1
                record = AuthRecord(
                    url=url,
                    auth=auth_label,
                    status=int(data["status"]),  # type: ignore[call-overload]
                    body_md5=str(data["body_md5"]),
                    length=int(data["length"]),  # type: ignore[call-overload]
                    sensitive=dict(data["sensitive"]),  # type: ignore[call-overload]
                    subject_ids=set(data.get("subject_ids") or []),  # type: ignore[call-overload]
                    auth_error=bool(data.get("auth_error")),
                )
                records.append(record)
                sensitive_keys = (
                    ",".join(sorted(record.sensitive.keys()))
                    if record.sensitive
                    else ""
                )
                subject_ids = (
                    ",".join(sorted(record.subject_ids)) if record.subject_ids else ""
                )
                tsv_lines.append(
                    f"{url}\t{auth_label}\t{record.status}\t{record.body_md5}\t{record.length}\t{sensitive_keys}\t{subject_ids}"
                )

            issues = self._detect_issues(url, records)
            for issue in issues:
                if context.results.append(issue):
                    stats["issues"] += 1

        artifacts_dir = context.record.paths.ensure_subdir("auth_matrix")
        (artifacts_dir / "auth_matrix.tsv").write_text(
            "\n".join(tsv_lines) + "\n", encoding="utf-8"
        )
        context.manager.update_metadata(context.record)

    def _collect_urls(self, context: PipelineContext) -> List[str]:
        items = context.get_results()
        max_targets = max(
            1,
            int(
                getattr(
                    context.runtime_config, "auth_matrix_max_targets", self.MAX_TARGETS
                )
            ),
        )
        max_per_host = max(
            1,
            int(
                getattr(
                    context.runtime_config,
                    "auth_matrix_max_per_host",
                    self.MAX_PER_HOST,
                )
            ),
        )
        candidates: List[Tuple[int, str, str]] = []
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
            parsed = urlparse(url)
            if self._is_static_asset(parsed.path):
                continue
            seen.add(url)
            host = (parsed.hostname or "").lower()
            score = self._url_priority(entry, url)
            candidates.append((score, url, host))

        if not candidates:
            return []
        candidates.sort(key=lambda item: item[0], reverse=True)
        urls: List[str] = []
        host_counts: Dict[str, int] = {}
        for _, url, host in candidates:
            if host and host_counts.get(host, 0) >= max_per_host:
                continue
            urls.append(url)
            if host:
                host_counts[host] = host_counts.get(host, 0) + 1
            if len(urls) >= max_targets:
                break
        return urls

    def _is_static_asset(self, path: str) -> bool:
        lowered = (path or "").lower()
        return any(lowered.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _url_priority(self, entry: Dict[str, object], url: str) -> int:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        score = int(entry.get("score") or 0)  # type: ignore[call-overload]
        if path.startswith("/api") or "/api/" in path:
            score += 30
        if any(hint in path for hint in self.PATH_HINTS):
            score += 20
        if "graphql" in path:
            score -= 20
        if "logout" in path:
            score -= 40
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        for key, _ in query_params:
            key_lower = key.lower()
            if (
                key_lower in SUBJECT_KEYS
                or key_lower.endswith("_id")
                or key_lower in {"id", "uid"}
            ):
                score += 10
        tags = entry.get("tags")
        if isinstance(tags, list):
            lowered_tags = {str(tag).lower() for tag in tags}
            if any(tag.startswith("api") for tag in lowered_tags):
                score += 12
        status = int(entry.get("status_code") or 0)  # type: ignore[call-overload]
        if status in {200, 401, 403}:
            score += 8
        return score

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
        headers = {"User-Agent": "recon-cli auth-matrix"}
        if token:
            headers["Authorization"] = token
        if limiter and not limiter.wait_for_slot(url, timeout=timeout):
            return None
        try:
            resp = session.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException as exc:
            context.logger.debug(
                "AuthMatrix request failed for %s (%s): %s", url, auth_label, exc
            )
            if limiter:
                limiter.on_error(url)
            return None
        if limiter:
            limiter.on_response(url, resp.status_code)

        body = resp.content or b""
        body_md5 = hashlib.md5(body, usedforsecurity=False).hexdigest()
        headers_lower = {key.lower(): value for key, value in resp.headers.items()}
        text = ""
        try:
            text = resp.text[:4000]
        except Exception:
            text = ""
        data_json = self._safe_json_dict(resp)
        sensitive = self._extract_sensitive(data_json, text)
        subject_ids = self._extract_subject_ids(data_json, text)
        auth_error = self._looks_like_auth_error(resp.status_code, text)

        return {
            "status": int(resp.status_code or 0),
            "body_md5": body_md5,
            "length": len(body),
            "headers": headers_lower,
            "sensitive": sensitive,
            "subject_ids": subject_ids,
            "auth_error": auth_error,
        }

    def _extract_sensitive(
        self, data_json: Dict[str, object], text: str
    ) -> Dict[str, object]:
        payload: Dict[str, object] = {}
        if data_json:
            self._collect_sensitive(data_json, payload, prefix="", depth=0)
        if not payload and text:
            lowered = text.lower()
            for key in SENSITIVE_KEYS:
                if key in lowered:
                    payload[key] = True
        return payload

    def _extract_subject_ids(self, data_json: Dict[str, object], text: str) -> Set[str]:
        subject_ids: Set[str] = set()
        if data_json:
            self._collect_subject_ids(data_json, subject_ids, depth=0)
        if not subject_ids and text:
            for match in UUID_RE.findall(text):
                subject_ids.add(match.lower())
            for match in re.findall(r"\b\d{2,12}\b", text):
                subject_ids.add(match)
                if len(subject_ids) >= 10:
                    break
        return subject_ids

    def _detect_issues(
        self, url: str, records: Sequence[AuthRecord]
    ) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        record_map = {record.auth: record for record in records}
        user_scoped = self._is_user_scoped(url)
        seen_reasons: Set[str] = set()

        if "token-a" in record_map and "anon" in record_map:
            a = record_map["token-a"]
            anon = record_map["anon"]
            if self._is_exposed_pair(anon, a):
                reason = "unauthenticated_response_matches_token_a"
                if reason not in seen_reasons:
                    seen_reasons.add(reason)
                    findings.append(
                        self._build_finding(
                            url=url,
                            reason=reason,
                            involved=["anon", "token-a"],
                            record_map=record_map,
                            severity="high",
                            score=82,
                        )
                    )
            elif anon.sensitive and a.sensitive and self._shares_subject(anon, a):
                reason = "unauthenticated_sensitive_subject_matches_token_a"
                if reason not in seen_reasons:
                    seen_reasons.add(reason)
                    findings.append(
                        self._build_finding(
                            url=url,
                            reason=reason,
                            involved=["anon", "token-a"],
                            record_map=record_map,
                            severity="high",
                            score=85,
                        )
                    )

        if "anon" in record_map and "token-b" in record_map:
            anon = record_map["anon"]
            b = record_map["token-b"]
            if self._is_exposed_pair(anon, b):
                reason = "unauthenticated_response_matches_token_b"
                if reason not in seen_reasons:
                    seen_reasons.add(reason)
                    findings.append(
                        self._build_finding(
                            url=url,
                            reason=reason,
                            involved=["anon", "token-b"],
                            record_map=record_map,
                            severity="high",
                            score=82,
                        )
                    )
            elif anon.sensitive and b.sensitive and self._shares_subject(anon, b):
                reason = "unauthenticated_sensitive_subject_matches_token_b"
                if reason not in seen_reasons:
                    seen_reasons.add(reason)
                    findings.append(
                        self._build_finding(
                            url=url,
                            reason=reason,
                            involved=["anon", "token-b"],
                            record_map=record_map,
                            severity="high",
                            score=85,
                        )
                    )

        if "token-a" in record_map and "token-b" in record_map:
            a = record_map["token-a"]
            b = record_map["token-b"]
            if not self._is_blocked(a) and not self._is_blocked(b):
                if user_scoped and a.status == b.status and a.body_md5 == b.body_md5:
                    reason = "token_b_sees_same_content_as_token_a"
                    if reason not in seen_reasons:
                        seen_reasons.add(reason)
                        findings.append(
                            self._build_finding(
                                url=url,
                                reason=reason,
                                involved=["token-a", "token-b"],
                                record_map=record_map,
                                severity="high",
                                score=80,
                            )
                        )
                elif user_scoped and self._shares_subject(a, b):
                    reason = "token_b_subject_matches_token_a"
                    if reason not in seen_reasons:
                        seen_reasons.add(reason)
                        findings.append(
                            self._build_finding(
                                url=url,
                                reason=reason,
                                involved=["token-a", "token-b"],
                                record_map=record_map,
                                severity="high",
                                score=85,
                            )
                        )
                elif a.sensitive and b.sensitive and a.sensitive == b.sensitive:
                    reason = "token_b_sensitive_matches_token_a"
                    if reason not in seen_reasons:
                        seen_reasons.add(reason)
                        findings.append(
                            self._build_finding(
                                url=url,
                                reason=reason,
                                involved=["token-a", "token-b"],
                                record_map=record_map,
                                severity="medium",
                                score=68,
                            )
                        )
        return findings

    @staticmethod
    def _safe_json_dict(response: "requests.Response") -> Dict[str, object]:
        try:
            data = response.json()
        except Exception:
            return {}
        if isinstance(data, dict):
            return data
        return {}

    def _collect_sensitive(
        self, node: object, out: Dict[str, object], *, prefix: str, depth: int
    ) -> None:
        if depth > 4:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                key_str = str(key).lower()
                new_prefix = f"{prefix}.{key_str}" if prefix else key_str
                if key_str in SENSITIVE_KEYS:
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
                if key_str in SUBJECT_KEYS or key_str.endswith("_id"):
                    normalized = self._normalize_subject(value)
                    if normalized:
                        out.add(normalized)
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

    @staticmethod
    def _looks_like_auth_error(status: int, text: str) -> bool:
        if status in {401, 403}:
            return True
        lowered = (text or "").lower()
        return any(hint in lowered for hint in AUTH_HINTS)

    @staticmethod
    def _is_blocked(record: AuthRecord) -> bool:
        return record.status in {401, 403, 404} or record.auth_error

    def _is_exposed_pair(self, unauth: AuthRecord, authd: AuthRecord) -> bool:
        if self._is_blocked(unauth):
            return False
        if self._is_blocked(authd):
            return False
        if unauth.status != authd.status:
            return False
        return unauth.body_md5 == authd.body_md5 and unauth.length > 0

    @staticmethod
    def _shares_subject(left: AuthRecord, right: AuthRecord) -> bool:
        if not left.subject_ids or not right.subject_ids:
            return False
        return bool(left.subject_ids.intersection(right.subject_ids))

    def _is_user_scoped(self, url: str) -> bool:
        lower_url = url.lower()
        if any(hint in lower_url for hint in USER_SCOPED_HINTS):
            return True
        parsed = urlparse(lower_url)
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            key_lower = key.lower()
            if key_lower in SUBJECT_KEYS or key_lower.endswith("_id"):
                return True
        return False

    def _build_finding(
        self,
        *,
        url: str,
        reason: str,
        involved: Sequence[str],
        record_map: Dict[str, AuthRecord],
        severity: str,
        score: int,
    ) -> Dict[str, object]:
        hostname = urlparse(url).hostname
        details = {
            label: {
                "status": record_map[label].status,
                "body_md5": record_map[label].body_md5,
                "sensitive": record_map[label].sensitive,
                "subject_ids": sorted(record_map[label].subject_ids),
            }
            for label in involved
        }
        priority = "high" if severity == "high" else "medium"
        return {
            "type": "finding",
            "finding_type": "auth_matrix_issue",
            "source": "auth-matrix",
            "hostname": hostname,
            "url": url,
            "description": f"Auth matrix mismatch: {reason}",
            "reason": reason,
            "details": details,
            "tags": ["auth", "auth-matrix", reason],
            "score": score,
            "priority": priority,
            "severity": severity,
        }
