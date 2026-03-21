from __future__ import annotations

import json
from typing import Dict, List

from recon_cli.active import modules as active_modules
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class ActiveIntelligenceStage(Stage):
    name = "active_intelligence"

    def is_enabled(self, context: PipelineContext) -> bool:
        modules = [m.lower() for m in context.record.spec.active_modules]
        if modules:
            return True
        return bool(getattr(context.runtime_config, "auto_active_modules", True))

    def execute(self, context: PipelineContext) -> None:
        modules = list(
            dict.fromkeys(m.lower() for m in context.record.spec.active_modules)
        )
        if not modules and getattr(context.runtime_config, "auto_active_modules", True):
            modules = active_modules.available_modules()
        if not modules:
            context.logger.info("No active modules requested")
            return
        available = set(active_modules.available_modules())
        selected: List[str] = []
        for module in modules:
            if module not in available:
                context.logger.warning("Unknown active module '%s'", module)
                continue
            selected.append(module)
        if not selected:
            context.logger.info("No valid active modules requested")
            return

        items = context.get_results()
        url_entries = [entry for entry in items if entry.get("type") == "url"]
        host_scores: Dict[str, int] = {}
        for entry in url_entries:
            host = entry.get("hostname")
            if not host:
                continue
            score = int(entry.get("score", 0))
            host_scores[host] = max(host_scores.get(host, 0), score)
        ranked_hosts = [
            host
            for host, _ in sorted(
                host_scores.items(), key=lambda item: item[1], reverse=True
            )
        ]

        apply_auth = (
            bool(getattr(context.runtime_config, "auth_apply_active_modules", False))
            and context.auth_enabled()
        )
        headers = (
            context.auth_headers({"User-Agent": active_modules.USER_AGENT})
            if apply_auth
            else {"User-Agent": active_modules.USER_AGENT}
        )
        auth_session = context.auth_session() if apply_auth else None
        cookies = auth_session.cookies.get_dict() if auth_session else None
        session = active_modules.create_session(
            headers=headers,
            cookies=cookies,
            verify_tls=bool(context.runtime_config.verify_tls),
        )
        artifact_dir = context.record.paths.ensure_subdir("active")
        stats: Dict[str, int] = {}
        for module in selected:
            try:
                result = active_modules.execute_module(
                    module,
                    url_entries=url_entries,
                    hosts=ranked_hosts,
                    session=session,
                )
            except Exception as exc:  # pragma: no cover - defensive
                context.logger.exception("Active module %s failed: %s", module, exc)
                continue
            added = context.results.extend(result.payloads) if result.payloads else 0
            stats[module] = added
            if result.artifact_data:
                artifact_path = artifact_dir / result.artifact_name
                try:
                    artifact_path.write_text(
                        json.dumps(result.artifact_data, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )
                except TypeError:
                    artifact_path.write_text(
                        json.dumps(result.artifact_data), encoding="utf-8"
                    )
        if stats:
            context.record.metadata.stats.setdefault("active_modules", {}).update(stats)
            context.manager.update_metadata(context.record)
            context.logger.info(
                "Active modules executed: %s",
                ", ".join(f"{name}={count}" for name, count in stats.items()),
            )
