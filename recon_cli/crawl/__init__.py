"""Crawl module for JavaScript-enabled web crawling.

This module provides Playwright-based web crawling for
dynamic content extraction and JavaScript analysis.
"""

from recon_cli.crawl.runtime import (
    PLAYWRIGHT_AVAILABLE,
    CrawlResult,
    NetworkEntry,
    crawl_urls,
    dom_artifact_name,
    save_results,
)

__all__ = [
    "PLAYWRIGHT_AVAILABLE",
    "CrawlResult",
    "NetworkEntry",
    "crawl_urls",
    "dom_artifact_name",
    "save_results",
]
