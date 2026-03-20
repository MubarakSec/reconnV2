from __future__ import annotations

from typing import Dict

from recon_cli import config
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils import enrich as enrich_utils
from recon_cli.utils import fs


class EnrichmentStage(Stage):
    name = "asset_enrichment"

    def execute(self, context: PipelineContext) -> None:
        items = context.get_results()
        assets = [
            entry for entry in items if entry.get("type") == "asset" and entry.get("ip")
        ]
        if not assets:
            context.logger.info("No assets to enrich")
            return

        client = enrich_utils.IpInfoClient()
        enrichment_store: Dict[str, dict] = {}
        artifacts_path = context.record.paths.artifact("ip_enrichment.json")
        appended = 0
        cache_path = config.RECON_HOME / "cache" / "enrich.json"
        cache_data: Dict[str, dict] = (
            fs.read_json(cache_path, default={}) if cache_path.exists() else {}
        )
        for asset in assets:
            hostname = asset.get("hostname")
            ip = asset.get("ip")
            if not hostname or not ip:
                continue
            key = f"{hostname}:{ip}"
            if key in enrichment_store:
                continue
            cached = cache_data.get(key)
            if cached:
                cached = dict(cached)
                cached["source"] = cached.get("source", "cache")
                enrichment_store[key] = cached
                if context.results.append(cached):
                    appended += 1
                continue
            try:
                info = enrich_utils.enrich_asset(hostname, ip, client)
            except Exception as exc:  # pragma: no cover - defensive
                context.logger.debug(
                    "Enrichment failed for %s (%s): %s", hostname, ip, exc
                )
                continue
            payload = {
                "type": "asset_enrichment",
                "source": "ipinfo" if client.session else "heuristics",
                "hostname": hostname,
                "ip": ip,
                "asn": info.asn,
                "org": info.org,
                "country": info.country,
                "city": info.city,
                "provider": info.provider_tag,
                "is_cdn": info.is_cdn,
                "is_cloud": info.is_cloud,
                "tags": sorted(info.tags),
            }
            enrichment_store[key] = payload
            if context.results.append(payload):
                appended += 1
        if enrichment_store:
            import json

            mapped: Dict[str, list] = {}
            for key, data in enrichment_store.items():
                hostname = data["hostname"]
                mapped.setdefault(hostname, []).append(data)
            artifacts_path.write_text(
                json.dumps(mapped, indent=2, sort_keys=True), encoding="utf-8"
            )
            try:
                fs.ensure_directory(cache_path.parent)
                cache_data.update(enrichment_store)
                cache_path.write_text(
                    json.dumps(cache_data, indent=2, sort_keys=True), encoding="utf-8"
                )
            except Exception:
                context.logger.debug("Failed to persist enrichment cache")
            context.record.metadata.stats["asset_enrichments"] = appended
            context.manager.update_metadata(context.record)
