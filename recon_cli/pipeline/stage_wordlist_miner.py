from __future__ import annotations

import re
import asyncio
from collections import Counter
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urlparse
from html.parser import HTMLParser

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig


class WordlistMinerStage(Stage):
    """
    Target-Aware Wordlist Miner.
    Scrapes the target's own content to build a custom dictionary.
    Helps find hidden subdomains and paths that generic lists miss.
    """
    name = "wordlist_miner"

    # Regex to find words (alphanumeric + hyphen/underscore, 3-30 chars)
    WORD_PATTERN = re.compile(r"\b[a-zA-Z0-9_-]{3,30}\b")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_wordlist_miner", True))

    async def run_async(self, context: PipelineContext) -> None:
        results = [r for r in context.filter_results("url")]
        # Select a few main pages to mine
        targets = [r["url"] for r in results if urlparse(r["url"]).path in ["", "/", "/index.html", "/index.php"]]
        targets = list(dict.fromkeys(targets))[:10]

        if not targets:
            context.logger.info("No main pages found for wordlist mining")
            return

        runtime = context.runtime_config
        config = HTTPClientConfig(
            max_concurrent=5,
            total_timeout=float(getattr(runtime, "wordlist_miner_timeout", 10)),
            verify_ssl=bool(getattr(runtime, "verify_tls", True))
        )

        word_counts = Counter()
        context.logger.info("Mining target-aware words from %d pages concurrently", len(targets))

        async with AsyncHTTPClient(config, context=context) as client:
            tasks = [client.get(url, headers=context.auth_headers({"User-Agent": "recon-cli wordlist-miner"}), follow_redirects=True) for url in targets]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for url, resp in zip(targets, responses):
                if isinstance(resp, Exception) or resp.status != 200:
                    continue
                
                body = resp.body
                # Simple text extraction (strip tags)
                text_only = re.sub(r"<[^>]+>", " ", body)
                words = self.WORD_PATTERN.findall(text_only)
                for w in words:
                    word_counts[w.lower()] += 1
                
                # Also mine from comments (special regex)
                comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
                for c in comments:
                    word_counts.update([w.lower() for w in self.WORD_PATTERN.findall(c)])

        if word_counts:
            # Keep top 500 words
            mined_words = [w for w, count in word_counts.most_common(500)]
            
            artifact_path = context.record.paths.artifact("custom_wordlist.txt")
            artifact_path.write_text("\n".join(mined_words), encoding="utf-8")
            
            context.logger.info("Generated target-aware wordlist with %d words", len(mined_words))
            host = urlparse(targets[0]).hostname or "unknown"
            context.emit_signal("wordlist_mined", "host", host, confidence=0.8, source=self.name, evidence={"count": len(mined_words)})
            
            # Save to data store for use by other stages (like FuzzStage)
            context.set_data("custom_target_words", mined_words)
