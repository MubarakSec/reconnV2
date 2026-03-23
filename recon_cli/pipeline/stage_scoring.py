from __future__ import annotations

import json
from typing import Dict, List
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import enrich as enrich_utils
from recon_cli import rules as rules_engine


class ScoringStage(Stage):
    name = "scoring_tagging"

    ADMIN_PATTERNS = [
        "/admin",
        "/wp-admin",
        "/login",
        "/signin",
        "/auth",
        "/account/login",
        "/user/login",
    ]
    RESET_PATTERNS = ["/forgot", "/reset", "/password", "/recover"]
    REGISTER_PATTERNS = ["/register", "/signup", "/sign-up"]
    SENSITIVE_QUERY_KEYS = {"password", "token", "secret", "key"}
    BACKUP_EXTENSIONS = {".sql", ".bak", ".zip", ".tar", ".gz"}
    ENV_BOOST_TAGS = {"env:dev", "env:staging", "env:test", "env:qa", "env:preprod"}
    CONFIRMED_SIGNAL_TYPES = {
        "ssrf_confirmed",
        "xxe_confirmed",
        "open_redirect_confirmed",
        "lfi_confirmed",
        "poc_validated",
        "api_auth_weak",
        "upload_dir_exposed",
    }
    HIGH_SIGNAL_TAGS = {
        "ssrf:confirmed",
        "xxe:confirmed",
        "lfi:confirmed",
        "redirect:confirmed",
        "api:auth-weak",
        "upload:exposed",
        "waf-bypass-possible",
        "secret-hit",
    }
    AUTH_SURFACE_CLUSTER_STATUSES = {401, 403, 404, 410}
    AUTH_SURFACE_CLUSTER_THRESHOLD = 8
    AUTH_SURFACE_REPETITIVE_CAP = 45

    def execute(self, context: PipelineContext) -> None:
        self.rules = getattr(self, "rules", rules_engine.load_rules())
        items = context.get_results()
        if not items:
            return
        if hasattr(context, "signal_index"):
            signals = context.signal_index()
        else:
            signals = {"by_host": {}, "by_url": {}}

        enrichment_map: Dict[str, list] = {}
        enrichment_artifact = context.record.paths.artifact("ip_enrichment.json")
        if enrichment_artifact.exists():
            try:
                import json as _json

                enrichment_map = _json.loads(
                    enrichment_artifact.read_text(encoding="utf-8")
                )
            except Exception:
                context.logger.debug(
                    "Failed to load IP enrichment artifact", exc_info=True
                )
                enrichment_map = {}

        soft_404_hosts = set(
            context.record.metadata.stats.get("soft_404", {}).get("hosts", [])
        )
        auth_cluster_sizes = self._build_auth_surface_clusters(items)
        is_hunter = getattr(context.record.spec, "mode", "default") == "hunter"
        updated: List[dict] = []
        for entry in items:
            ptype = entry.get("type")
            if ptype == "finding":
                score = int(entry.get("score", 0))
                severity = entry.get("severity", "info").lower()
                tags = set(entry.get("tags", []))
                
                if is_hunter:
                    # Hunter Mode: Massive boosts for critical bug bounty types
                    if severity == "critical": score = max(score, 95)
                    if severity == "high": score = max(score, 85)
                    
                    if "pii" in tags: score += 50
                    if "vulnerability" in tags: score += 40
                    if "exploit" in tags: score += 60
                    if "confirmed" in tags: score += 30
                    
                    # Elite Logic Bug Boosts
                    f_type = entry.get("finding_type", "")
                    if f_type in ["bola", "mass_assignment", "ssrf_internal_pivot", "cache_poisoning", "prototype_pollution"]:
                        score = max(score, 98)
                        tags.add("hunter:critical-logic")
                    
                entry["score"] = min(score, 100)
                entry["priority"] = enrich_utils.classify_priority(entry["score"])
                updated.append(entry)
                continue

            if ptype == "hostname":
                hostname = entry.get("hostname")
                if hostname:
                    tags = set(entry.get("tags", []))
                    tags.update(enrich_utils.hostname_tags(hostname))
                    host_signals = signals.get("by_host", {}).get(hostname, set())
                    if "waf_detected" in host_signals:
                        tags.add("service:waf")
                    if "api_surface" in host_signals:
                        tags.add("service:api")
                    if "cms_drupal" in host_signals:
                        tags.add("cms:drupal")
                        tags.add("service:cms")
                    if "cms_joomla" in host_signals:
                        tags.add("cms:joomla")
                        tags.add("service:cms")
                    if "cms_magento" in host_signals:
                        tags.add("cms:magento")
                        tags.add("service:cms")
                    if "oauth_config" in host_signals:
                        tags.add("service:oauth")
                    if "oidc_config" in host_signals:
                        tags.add("service:oidc")
                    if "grpc_detected" in host_signals:
                        tags.add("service:grpc")
                    if "ws_detected" in host_signals:
                        tags.add("service:ws")
                    if "auth_surface" in host_signals:
                        tags.add("surface:login")
                    tags.update(rules_engine.apply_rules(entry, self.rules))
                    if tags:
                        entry["tags"] = sorted(tags)
                updated.append(entry)
                continue
            if ptype == "asset":
                host = entry.get("hostname")
                if host and host in enrichment_map:
                    tags = set(entry.get("tags", []))
                    for enriched in enrichment_map[host]:
                        tags.update(enriched.get("tags", []))
                        entry.setdefault("asn", enriched.get("asn"))
                        entry.setdefault("org", enriched.get("org"))
                        entry.setdefault("country", enriched.get("country"))
                    if tags:
                        entry["tags"] = sorted(tags)
                updated.append(entry)
                continue
            if ptype != "url":
                updated.append(entry)
                continue

            score = int(entry.get("score", 0))
            tags = set(entry.get("tags", []))
            url = entry.get("url", "")
            if not isinstance(url, str):
                updated.append(entry)
                continue
            parsed_url = urlparse(url)
            path = (parsed_url.path or "/").lower()
            lower_url = url.lower()
            host = entry.get("hostname") or parsed_url.hostname
            url_signals = signals.get("by_url", {}).get(url, set())
            host_signals = (
                signals.get("by_host", {}).get(host, set()) if host else set()
            )
            host_enrichments = enrichment_map.get(host, []) if host else []
            if host_enrichments:
                for enriched in host_enrichments:
                    tags.update(enriched.get("tags", []))
                    provider = enriched.get("provider")
                    if provider:
                        tags.add(provider)
                    if enriched.get("is_cdn"):
                        tags.add("service:cdn")
                        score -= 5
                    if enriched.get("is_cloud"):
                        score += 5

            tags.update(enrich_utils.infer_service_tags(url))

            for pattern in self.ADMIN_PATTERNS:
                if pattern in lower_url:
                    tags.add("surface:admin")
                    score += 25
            for pattern in self.RESET_PATTERNS:
                if pattern in lower_url:
                    tags.add("surface:password-reset")
                    score += 20
            for pattern in self.REGISTER_PATTERNS:
                if pattern in lower_url:
                    tags.add("surface:register")
                    score += 15
            if any(f"{key}=" in lower_url for key in self.SENSITIVE_QUERY_KEYS):
                tags.add("possible-cred-leak")
                score += 100
            for ext in self.BACKUP_EXTENSIONS:
                if lower_url.endswith(ext):
                    tags.add("backup")
                    score += 60

            if "api_surface" in host_signals or "api_surface" in url_signals:
                if "service:api" not in tags:
                    tags.add("service:api")
                    score += 10
            if "api_spec_auth_required" in url_signals:
                tags.add("api:spec-auth-required")
                score += 10
            if "api_spec_auth_challenge" in url_signals:
                tags.add("api:spec-auth-challenge")
                score += 8
            if "api_schema_endpoint" in url_signals:
                tags.add("api:schema")
                score += 10
            if "api_auth_required" in url_signals:
                tags.add("api:auth-required")
                score += 10
            if "api_auth_weak" in url_signals:
                tags.add("api:auth-weak")
                score += 25
            if "api_auth_challenge" in url_signals:
                tags.add("api:auth-challenge")
                score += 10
            if "api_public_endpoint" in url_signals:
                tags.add("api:public")
                score += 5
            if "graphql_detected" in url_signals:
                tags.add("api:graphql")
                score += 10
            if "graphql_introspection_enabled" in url_signals:
                tags.add("api:graphql:introspection")
                score += 15
            if "graphql_sensitive_schema" in url_signals:
                tags.add("api:graphql:sensitive")
                score += 10
            if "graphql_query_enabled" in url_signals:
                tags.add("api:graphql:query")
                score += 5
            if "auth_surface" in url_signals:
                if "surface:login" not in tags:
                    tags.add("surface:login")
                    score += 15
            if "admin_surface" in url_signals:
                tags.add("surface:admin")
                score += 20
            if "internal_surface" in url_signals:
                tags.add("surface:internal")
                score += 12
            if "debug_surface" in url_signals:
                tags.add("surface:debug")
                score += 15
            if "sensitive_surface" in url_signals:
                tags.add("surface:sensitive")
                score += 15
            if "form_discovered" in url_signals:
                tags.add("surface:form")
                score += 5
            if "oauth_authorize_endpoint" in url_signals:
                tags.add("surface:authorize")
                score += 20
            if "oauth_token_endpoint" in url_signals:
                tags.add("surface:token")
                score += 25
            if "oauth_config" in host_signals:
                tags.add("service:oauth")
            if "oidc_config" in host_signals:
                tags.add("service:oidc")
            if "ws_detected" in url_signals:
                tags.add("service:ws")
                tags.add("surface:ws")
                score += 10
            if "ws_candidate" in url_signals:
                tags.add("surface:ws")
                score += 5
            if "grpc_detected" in host_signals or "grpc_detected" in url_signals:
                tags.add("service:grpc")
                score += 10
            if "upload_surface" in url_signals:
                tags.add("surface:upload")
                score += 10
            if "upload_dir_exposed" in url_signals:
                tags.add("upload:exposed")
                score += 30
            if "waf_detected" in host_signals or "waf_detected" in url_signals:
                tags.add("service:waf")
            if "waf_bypass_possible" in url_signals:
                tags.add("waf-bypass-possible")
                score += 15
            if "xss_candidate" in url_signals:
                tags.add("xss:candidate")
                score += 10
            if "sqli_candidate" in url_signals:
                tags.add("sqli:candidate")
                score += 15
            if "vhost_found" in host_signals:
                tags.add("surface:vhost")
                score += 10
            if (
                "cloud_asset_public" in url_signals
                or "cloud_asset_public" in host_signals
            ):
                tags.add("cloud:exposed")
                score += 25
            if "cms_drupal" in host_signals:
                tags.add("cms:drupal")
                tags.add("service:cms")
                score += 5
            if "cms_joomla" in host_signals:
                tags.add("cms:joomla")
                tags.add("service:cms")
                score += 5
            if "cms_magento" in host_signals:
                tags.add("cms:magento")
                tags.add("service:cms")
                score += 5
            if "ct_discovery" in host_signals:
                tags.add("source:ct")
                score += 5
            if "verified_live" in url_signals:
                tags.add("verified:live")
                score += 10
            if "verified_blocked" in url_signals:
                tags.add("verified:blocked")
                score = max(score - 10, 0)
            if "portal_login" in url_signals:
                tags.add("surface:login")
                tags.add("portal:login")
                score += 20
            if "portal_admin" in url_signals:
                tags.add("surface:admin")
                tags.add("portal:admin")
                score += 25
            if "portal_dashboard" in url_signals:
                tags.add("portal:dashboard")
                score += 10
            if "ssrf_confirmed" in url_signals:
                tags.add("ssrf:confirmed")
                score += 40
            if "xxe_confirmed" in url_signals:
                tags.add("xxe:confirmed")
                score += 35
            if "open_redirect_confirmed" in url_signals:
                tags.add("redirect:confirmed")
                score += 25
            if "lfi_confirmed" in url_signals:
                tags.add("lfi:confirmed")
                score += 35

            status_code = entry.get("status_code")
            length = (
                entry.get("length")
                or entry.get("content_length")
                or entry.get("content-length")
            )
            if enrich_utils.detect_noise(
                url, status_code, entry.get("source", ""), length
            ):
                tags.add("noise")
                entry["noise"] = True
                score = 0
            else:
                if status_code in {401, 403}:
                    score += 35
                    tags.add("auth-required")
                if host and host in soft_404_hosts:
                    tags.add("soft-404")
                    score = max(score - 15, 0)
                if any(tag.startswith("waf:") for tag in tags):
                    tags.add("service:waf")
                    if status_code in {401, 403}:
                        tags.add("waf-blocked")
                        score += 5
                if status_code and 400 <= status_code < 500 and "service:api" in tags:
                    score += 50
                if status_code in {200, 302} and "service:api" in tags:
                    score += 25
                if tags.intersection(self.ENV_BOOST_TAGS):
                    score += 25
                if "surface:login" in tags or "service:sso" in tags:
                    score += 40
                if "secret-hit" in tags or "secret" in tags:
                    score = max(score, 95)
                server = entry.get("server")
                score += enrich_utils.legacy_score(server)
                cluster_size = auth_cluster_sizes.get((path, int(status_code or 0)), 0)
                score = self._calibrate_risk_score(
                    score,
                    status_code,
                    tags,
                    url_signals,
                    auth_cluster_size=cluster_size,
                )

            rule_tags = rules_engine.apply_rules(entry, self.rules)
            if rule_tags:
                tags.update(rule_tags)

            if is_hunter:
                # Hunter Mode: Prioritize surface area most likely to have bugs
                if "surface:admin" in tags: score += 40
                if "surface:login" in tags: score += 20
                if "env-file" in tags: score += 30
                if "service:api" in tags: score += 25
                if "vuln-suspect" in tags: score += 45

            entry["tags"] = sorted(tags)
            entry["score"] = max(score, 0)
            entry["priority"] = enrich_utils.classify_priority(entry["score"])
            updated.append(entry)

        if hasattr(context, "results") and hasattr(context.results, "replace_all"):
            context.results.replace_all(updated)
        else:
            context.record.paths.results_jsonl.write_text(
                "\n".join(
                    json.dumps(item, separators=(",", ":"), ensure_ascii=True)
                    for item in updated
                )
                + "\n",
                encoding="utf-8",
            )
        surface_stats = context.record.metadata.stats.setdefault("auth_surface", {})
        surface_stats["login"] = sum(
            1 for entry in updated if "surface:login" in entry.get("tags", [])
        )
        surface_stats["password_reset"] = sum(
            1 for entry in updated if "surface:password-reset" in entry.get("tags", [])
        )
        surface_stats["register"] = sum(
            1 for entry in updated if "surface:register" in entry.get("tags", [])
        )
        context.manager.update_metadata(context.record)

    def _calibrate_risk_score(
        self,
        score: int,
        status_code: object,
        tags: set[str],
        url_signals: set[str],
        auth_cluster_size: int = 0,
    ) -> int:
        status = int(status_code or 0)  # type: ignore[call-overload]
        has_high_signal = self._has_high_signal(tags, url_signals)

        if status in {401, 403} and "auth-required" in tags and not has_high_signal:
            tags.add("auth:challenge")
            challenge_cap = 65
            if "probe++" in tags:
                challenge_cap = min(challenge_cap, 55)
                tags.add("probe:challenge")
            if "service:waf" in tags:
                challenge_cap = min(challenge_cap, 50)
            if "surface:login" in tags:
                challenge_cap = min(challenge_cap, 60)
            if "surface:admin" in tags and "surface:login" in tags:
                challenge_cap = min(challenge_cap, 55)
            score = min(score, challenge_cap)

        if status == 410 and not has_high_signal:
            tags.add("surface:retired")
            score = min(score, 35)
        elif (
            status == 404
            and not has_high_signal
            and tags.intersection({"surface:login", "surface:admin"})
        ):
            score = min(score, 40)
        if (
            auth_cluster_size >= self.AUTH_SURFACE_CLUSTER_THRESHOLD
            and status in self.AUTH_SURFACE_CLUSTER_STATUSES
            and tags.intersection({"surface:login", "surface:admin"})
            and not has_high_signal
        ):
            tags.add("auth:repetitive")
            score = min(score, self.AUTH_SURFACE_REPETITIVE_CAP)

        return max(score, 0)

    def _has_high_signal(self, tags: set[str], url_signals: set[str]) -> bool:
        return bool(self.CONFIRMED_SIGNAL_TYPES.intersection(url_signals)) or bool(
            self.HIGH_SIGNAL_TAGS.intersection(tags)
        )

    def _build_auth_surface_clusters(
        self, items: List[dict]
    ) -> Dict[tuple[str, int], int]:
        clusters: Dict[tuple[str, int], set[str]] = {}
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            status = int(entry.get("status_code") or 0)
            if status not in self.AUTH_SURFACE_CLUSTER_STATUSES:
                continue
            parsed = urlparse(url)
            path = (parsed.path or "/").lower()
            if not any(token in path for token in self.ADMIN_PATTERNS):
                continue
            host = str(entry.get("hostname") or parsed.hostname or "").lower()
            if not host:
                continue
            key = (path, status)
            if key not in clusters:
                clusters[key] = set()
            clusters[key].add(host)
        return {key: len(hosts) for key, hosts in clusters.items()}
