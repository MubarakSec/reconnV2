from __future__ import annotations

import httpx
from typing import List, Dict, Any, Optional
from urllib.parse import quote

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class GitHubReconStage(Stage):
    """
    GitHub Reconnaissance Stage
    Searches GitHub for the target domains to find leaked secrets and endpoints.
    """

    name = "github_recon"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_github_recon", False))

    async def _search_github(
        self, query: str, token: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not token:
            return []

        url = f"https://api.github.com/search/code?q={quote(query)}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp.json().get("items", [])
                elif resp.status_code == 403:
                    # Rate limited or invalid token
                    return []
            except Exception:
                pass
        return []

    async def run_async(self, context: PipelineContext) -> None:
        token = getattr(context.runtime_config, "github_token", None)
        if not token:
            context.logger.info("GitHub token not configured; skipping GitHub recon")
            return

        targets = context.scope_targets()
        if not targets:
            return

        context.logger.info("Starting GitHub recon for %d targets", len(targets))

        for target in targets:
            # Search for the domain in code
            items = await self._search_github(target, token)
            for item in items:
                repo = item.get("repository", {}).get("full_name")
                file_url = item.get("html_url")

                context.results.append(
                    {
                        "type": "finding",
                        "finding_type": "github_leak",
                        "source": "github-recon",
                        "hostname": target,
                        "url": file_url,
                        "description": f"Target domain found in GitHub repository: {repo}",
                        "severity": "info",
                        "details": {
                            "repository": repo,
                            "file_path": item.get("path"),
                            "file_url": file_url,
                        },
                        "tags": ["github", "osint"],
                    }
                )

    def execute(self, context: PipelineContext) -> None:
        import asyncio

        asyncio.run(self.run_async(context))
