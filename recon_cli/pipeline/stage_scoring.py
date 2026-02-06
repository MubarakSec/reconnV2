from __future__ import annotations

from typing import Dict, List

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import enrich as enrich_utils
from recon_cli.utils.jsonl import read_jsonl
from recon_cli import rules as rules_engine


class ScoringStage(Stage):
    name = "scoring_tagging"

    ADMIN_PATTERNS = ["/admin", "/wp-admin", "/login", "/signin", "/auth", "/account/login", "/user/login"]
    RESET_PATTERNS = ["/forgot", "/reset", "/password", "/recover"]
    REGISTER_PATTERNS = ["/register", "/signup", "/sign-up"]
    SENSITIVE_QUERY_KEYS = {"password", "token", "secret", "key"}
    BACKUP_EXTENSIONS = {".sql", ".bak", ".zip", ".tar", ".gz"}
    ENV_BOOST_TAGS = {"env:dev", "env:staging", "env:test", "env:qa", "env:preprod"}

    def execute(self, context: PipelineContext) -> None:
        self.rules = getattr(self, "rules", rules_engine.load_rules())
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return
        items = read_jsonl(results_path)
        if not items:
            return

        enrichment_map: Dict[str, list] = {}
        enrichment_artifact = context.record.paths.artifact("ip_enrichment.json")
        if enrichment_artifact.exists():
            try:
                import json as _json

                enrichment_map = _json.loads(enrichment_artifact.read_text(encoding="utf-8"))
            except Exception:
                enrichment_map = {}

        soft_404_hosts = set(context.record.metadata.stats.get("soft_404", {}).get("hosts", []))
        updated: List[dict] = []
        for entry in items:
            ptype = entry.get("type")
            if ptype == "hostname":
                hostname = entry.get("hostname")
                if hostname:
                    tags = set(entry.get("tags", []))
                    tags.update(enrich_utils.hostname_tags(hostname))
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
            lower_url = url.lower()
            host = entry.get("hostname")
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

            status_code = entry.get("status_code")
            length = entry.get("length") or entry.get("content_length") or entry.get("content-length")
            if enrich_utils.detect_noise(url, status_code, entry.get("source", ""), length):
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

            rule_tags = rules_engine.apply_rules(entry, self.rules)
            if rule_tags:
                tags.update(rule_tags)

            entry["tags"] = sorted(tags)
            entry["score"] = max(score, 0)
            entry["priority"] = enrich_utils.classify_priority(entry["score"])
            updated.append(entry)

        context.results.replace_all(updated)
        surface_stats = context.record.metadata.stats.setdefault("auth_surface", {})
        surface_stats["login"] = sum(1 for entry in updated if "surface:login" in entry.get("tags", []))
        surface_stats["password_reset"] = sum(
            1 for entry in updated if "surface:password-reset" in entry.get("tags", [])
        )
        surface_stats["register"] = sum(1 for entry in updated if "surface:register" in entry.get("tags", []))
        context.manager.update_metadata(context.record)
