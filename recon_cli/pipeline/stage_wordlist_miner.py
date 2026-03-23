from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Set, Any
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage


class WordlistMinerStage(Stage):
    """
    Target-Aware Wordlist Miner.
    Scrapes the target's own content to build a custom dictionary.
    Helps find hidden subdomains and paths that generic lists miss.
    """
    name = "wordlist_miner"

    # Regex to find words (alphanumeric, 3-20 chars)
    WORD_PATTERN = re.compile(r"\b[a-zA-Z0-9-]{3,20}\b")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_wordlist_miner", True))

    def execute(self, context: PipelineContext) -> None:
        import requests
        from bs4 import BeautifulSoup

        results = context.get_results()
        # Select a few main pages to mine
        targets = [r["url"] for r in results if r.get("type") == "url" and urlparse(r["url"]).path in ["", "/"]]
        targets = list(dict.fromkeys(targets))[:5]

        if not targets:
            return

        context.logger.info("Mining target-aware words from %d pages", len(targets))
        word_counts = Counter()

        session = requests.Session()
        session.verify = getattr(context.runtime_config, "verify_tls", True)

        for url in targets:
            try:
                resp = session.get(url, timeout=10)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    # Extract text from body
                    text = soup.get_text()
                    words = self.WORD_PATTERN.findall(text)
                    for w in words:
                        word_counts[w.lower()] += 1
                    
                    # Also mine from meta tags and comments
                    comments = soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in str(text))
                    for c in comments:
                        word_counts.update([w.lower() for w in self.WORD_PATTERN.findall(str(c))])
            except Exception: pass

        if word_counts:
            # Keep words that appear more than once or look like technical terms
            mined_words = [w for w, count in word_counts.most_common(500)]
            
            artifact_path = context.record.paths.artifact("custom_wordlist.txt")
            artifact_path.write_text("\n".join(mined_words))
            
            context.logger.info("Generated target-aware wordlist with %d words", len(mined_words))
            context.emit_signal("wordlist_mined", "host", urlparse(targets[0]).hostname, confidence=0.8, source=self.name, evidence={"count": len(mined_words)})
            
            # Save to data store for use by FuzzStage
            context.set_data("custom_target_words", mined_words)
