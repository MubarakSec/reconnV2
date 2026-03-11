"""
Async Secrets Scanner - ماسح أسرار غير متزامن

نسخة محسنة من SecretsDetector تستخدم async HTTP
لفحص URLs متعددة بشكل متزامن وسريع.

Example:
    >>> scanner = AsyncSecretsScanner()
    >>> results = await scanner.scan_urls([
    ...     "https://example.com/app.js",
    ...     "https://example.com/config.js"
    ... ])
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from recon_cli.secrets.detector import (
    SECRETS_PATTERNS,
    TEXT_LIKE_EXTENSIONS,
    shannon_entropy,
    SecretMatch,
)

try:
    from recon_cli.utils.async_http import AsyncHTTPClient, HTTPClientConfig, HTTPResponse
    ASYNC_HTTP_AVAILABLE = True
except ImportError:
    ASYNC_HTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """نتيجة فحص URL واحد"""
    url: str
    matches: List[SecretMatch]
    status: int
    error: Optional[str] = None
    scan_time: float = 0.0
    
    @property
    def has_secrets(self) -> bool:
        return len(self.matches) > 0
    
    @property
    def high_confidence_count(self) -> int:
        return sum(1 for m in self.matches if m.confidence == "high")


class AsyncSecretsScanner:
    """
    ماسح أسرار غير متزامن عالي الأداء.
    
    يفحص URLs متعددة بشكل متزامن للبحث عن:
    - AWS Keys
    - API Keys
    - Tokens
    - Private Keys
    - أي أسرار أخرى
    
    Example:
        >>> scanner = AsyncSecretsScanner(max_concurrent=50)
        >>> async with scanner:
        ...     results = await scanner.scan_urls(urls)
        ...     for r in results:
        ...         if r.has_secrets:
        ...             print(f"{r.url}: {len(r.matches)} secrets")
    """
    
    def __init__(
        self,
        max_concurrent: int = 30,
        timeout: float = 15.0,
        verify_ssl: bool = True,
        min_entropy: float = 3.5,
    ):
        """
        Args:
            max_concurrent: الحد الأقصى للطلبات المتزامنة
            timeout: timeout لكل طلب
            verify_ssl: التحقق من SSL
            min_entropy: الحد الأدنى للـ entropy للأسرار العامة
        """
        if not ASYNC_HTTP_AVAILABLE:
            raise ImportError("async_http module not available")
        
        self.config = HTTPClientConfig(
            max_concurrent=max_concurrent,
            total_timeout=timeout,
            verify_ssl=verify_ssl,
            user_agent="recon-cli-secrets/0.2",
        )
        self.min_entropy = min_entropy
        self._client: Optional[AsyncHTTPClient] = None
        self._stats = {
            "urls_scanned": 0,
            "secrets_found": 0,
            "high_confidence": 0,
            "errors": 0,
        }
    
    async def __aenter__(self) -> "AsyncSecretsScanner":
        self._client = AsyncHTTPClient(self.config)
        await self._client.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            await self._client.close()
    
    def _should_scan(self, url: str, content_type: str = "") -> bool:
        """هل يجب فحص هذا الـ URL"""
        # Check extension
        path = url.split("?")[0].lower()
        ext = path.split(".")[-1] if "." in path else ""
        
        if ext in TEXT_LIKE_EXTENSIONS:
            return True
        
        # Check content type
        if "text" in content_type.lower():
            return True
        if "javascript" in content_type.lower():
            return True
        if "json" in content_type.lower():
            return True
        
        return False
    
    def _scan_text(self, text: str) -> List[SecretMatch]:
        """فحص نص للبحث عن أسرار"""
        matches: List[SecretMatch] = []
        seen_hashes: Set[str] = set()
        
        for name, pattern in SECRETS_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                
                # حساب hash للتجنب التكرار
                value_hash = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
                if value_hash in seen_hashes:
                    continue
                seen_hashes.add(value_hash)
                
                # حساب entropy
                entropy = shannon_entropy(value)
                
                # تجاهل generic secrets مع entropy منخفضة
                if name == "generic_secret" and entropy < self.min_entropy:
                    continue
                
                matches.append(SecretMatch(
                    pattern=name,
                    value_hash=value_hash,
                    length=len(value),
                    entropy=entropy,
                    start=match.start(),
                    end=match.end(),
                ))
        
        return matches
    
    async def scan_url(self, url: str) -> ScanResult:
        """
        فحص URL واحد.
        
        Args:
            url: الـ URL للفحص
            
        Returns:
            ScanResult مع النتائج
        """
        if not self._client:
            raise RuntimeError("Scanner not started. Use 'async with' context.")
        
        try:
            response = await self._client.get(url)
        except Exception as exc:
            self._stats["errors"] += 1
            return ScanResult(
                url=url,
                matches=[],
                status=0,
                error=str(exc),
                scan_time=0.0,
            )
        
        if response.error:
            self._stats["errors"] += 1
            return ScanResult(
                url=url,
                matches=[],
                status=0,
                error=response.error,
                scan_time=response.elapsed,
            )
        
        self._stats["urls_scanned"] += 1
        
        # Check if scannable
        content_type = response.headers.get("Content-Type", "")
        if not self._should_scan(url, content_type):
            return ScanResult(
                url=url,
                matches=[],
                status=response.status,
                scan_time=response.elapsed,
            )
        
        # Scan content
        matches = self._scan_text(response.body)
        
        # Update stats
        self._stats["secrets_found"] += len(matches)
        self._stats["high_confidence"] += sum(1 for m in matches if m.confidence == "high")
        
        return ScanResult(
            url=url,
            matches=matches,
            status=response.status,
            scan_time=response.elapsed,
        )
    
    async def scan_urls(
        self,
        urls: List[str],
        filter_text_only: bool = True,
    ) -> List[ScanResult]:
        """
        فحص URLs متعددة بشكل متزامن.
        
        Args:
            urls: قائمة الـ URLs
            filter_text_only: فحص النصية فقط
            
        Returns:
            قائمة ScanResult
        """
        if not self._client:
            raise RuntimeError("Scanner not started. Use 'async with' context.")
        
        # Filter URLs if needed
        if filter_text_only:
            filtered_urls = [
                url for url in urls
                if self._should_scan(url, "")
            ]
            logger.info(
                "Scanning %d/%d URLs (filtered to text-like)",
                len(filtered_urls), len(urls)
            )
        else:
            filtered_urls = urls
        
        # Scan all URLs concurrently
        tasks = [self.scan_url(url) for url in filtered_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(ScanResult(
                    url=filtered_urls[i],
                    matches=[],
                    status=0,
                    error=str(result),
                ))
            else:
                processed.append(result)
        
        return processed
    
    def get_stats(self) -> Dict[str, int]:
        """إحصائيات الفحص"""
        return self._stats.copy()


# ═══════════════════════════════════════════════════════════
#                     Convenience Functions
# ═══════════════════════════════════════════════════════════

async def scan_urls_for_secrets(
    urls: List[str],
    max_concurrent: int = 30,
) -> List[ScanResult]:
    """
    فحص URLs للبحث عن أسرار.
    
    Example:
        >>> results = await scan_urls_for_secrets([
        ...     "https://example.com/app.js",
        ...     "https://example.com/config.json",
        ... ])
    """
    async with AsyncSecretsScanner(max_concurrent=max_concurrent) as scanner:
        return await scanner.scan_urls(urls)


def run_secrets_scan(urls: List[str], **kwargs) -> List[ScanResult]:
    """
    Synchronous wrapper.
    
    Example:
        >>> results = run_secrets_scan(["https://example.com/app.js"])
    """
    return asyncio.run(scan_urls_for_secrets(urls, **kwargs))
