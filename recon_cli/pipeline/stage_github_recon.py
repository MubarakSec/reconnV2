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
        self, context: PipelineContext, query: str, token: str
    ) -> List[Dict[str, Any]]:
        url = f"https://api.github.com/search/code?q={quote(query)}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}",
            "User-Agent": "recon-cli github-recon",
        }

        # Address Risk 2.6: Circuit Breaker for External APIs
        from recon_cli.utils.circuit_breaker import registry as circuit_registry
        breaker = circuit_registry.get_or_create("github-api", failure_threshold=3, recovery_timeout=120)

        try:
            async with breaker:
                # Address Risk 3.2: Use shared AsyncHTTPClient
                http = context.http_client
                resp = await http.get(url, headers=headers, timeout=20.0)
                
                if resp.status == 200:
                    try:
                        data = json.loads(resp.body)
                        return data.get("items", [])
                    except json.JSONDecodeError:
                        context.logger.warning("GitHub API returned invalid JSON for %s", query)
                        return []
                elif resp.status == 403:
                    context.logger.warning("GitHub API rate limit hit or invalid token")
                    return []
                elif resp.status >= 400:
                    context.logger.debug("GitHub API returned %d for %s", resp.status, query)
                    return []
        except Exception as exc:
            context.logger.warning("GitHub search failed for %s: %s", query, exc)
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
            items = await self._search_github(context, target, token)
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
            
            # Simple rate limit between queries to GitHub
            await asyncio.sleep(2.0)
