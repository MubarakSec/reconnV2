"""
Async DNS Resolver - محلل DNS غير متزامن

محلل DNS عالي الأداء يدعم:
- استعلامات متزامنة
- تخزين مؤقت
- Retry مع fallback
- دعم resolvers متعددة

Example:
    >>> resolver = AsyncDNSResolver()
    >>> results = await resolver.resolve_many([
    ...     "example.com", "test.com"
    ... ])
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# DNS record types
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]


@dataclass
class DNSRecord:
    """سجل DNS"""

    domain: str
    record_type: str
    value: str
    ttl: int = 300
    timestamp: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.timestamp + self.ttl


@dataclass
class DNSResult:
    """نتيجة استعلام DNS"""

    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    error: Optional[str] = None
    query_time: float = 0.0
    resolver_used: str = ""

    @property
    def has_records(self) -> bool:
        return len(self.records) > 0

    @property
    def a_records(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == "A"]

    @property
    def cname_records(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == "CNAME"]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "records": [
                {"type": r.record_type, "value": r.value, "ttl": r.ttl}
                for r in self.records
            ],
            "error": self.error,
            "query_time": self.query_time,
        }


class DNSCache:
    """
    Cache لنتائج DNS.

    يخزن النتائج مع TTL.
    """

    def __init__(self, default_ttl: int = 300, negative_ttl: int = 60):
        self.default_ttl = default_ttl
        self.negative_ttl = negative_ttl
        self._cache: Dict[Tuple[str, str], DNSRecord] = {}
        self._negative_cache: Dict[Tuple[str, str], float] = {}
        self._hits = 0
        self._misses = 0

    def get(self, domain: str, record_type: str = "A") -> Optional[DNSRecord]:
        """الحصول على سجل من الـ cache"""
        key = (domain.lower(), record_type)
        
        # Check negative cache
        if key in self._negative_cache:
            if time.time() < self._negative_cache[key]:
                self._hits += 1
                return DNSRecord(domain, record_type, "", ttl=0) # Marker for negative hit
            else:
                del self._negative_cache[key]

        record = self._cache.get(key)

        if record and not record.is_expired:
            self._hits += 1
            return record

        self._misses += 1
        if record:
            del self._cache[key]
        return None

    def set(self, record: DNSRecord) -> None:
        """تخزين سجل"""
        key = (record.domain.lower(), record.record_type)
        self._cache[key] = record

    def set_negative(self, domain: str, record_type: str = "A") -> None:
        """تخزين نتيجة سلبية"""
        key = (domain.lower(), record_type)
        self._negative_cache[key] = time.time() + self.negative_ttl

    def is_negative(self, record: DNSRecord) -> bool:
        """هل هو سجل سلبي؟"""
        return record.ttl == 0 and record.value == ""

    def clear_expired(self) -> int:
        """مسح السجلات المنتهية"""
        expired = [k for k, v in self._cache.items() if v.is_expired]
        for k in expired:
            del self._cache[k]
        return len(expired)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / max(1, self._hits + self._misses),  # type: ignore[dict-item]
        }


class AsyncDNSResolver:
    """
    محلل DNS غير متزامن.

    Example:
        >>> async with AsyncDNSResolver() as resolver:
        ...     result = await resolver.resolve("example.com")
        ...     print(result.a_records)
    """

    DEFAULT_RESOLVERS = [
        "8.8.8.8",  # Google
        "8.8.4.4",  # Google
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",  # Cloudflare
        "9.9.9.9",  # Quad9
    ]

    def __init__(
        self,
        resolvers: Optional[List[str]] = None,
        max_concurrent: int = 100,
        timeout: float = 5.0,
        retries: int = 2,
        use_cache: bool = True,
        cache_ttl: int = 300,
    ):
        """
        Args:
            resolvers: قائمة خوادم DNS
            max_concurrent: الحد الأقصى للاستعلامات المتزامنة
            timeout: timeout لكل استعلام
            retries: عدد المحاولات
            use_cache: استخدام cache
            cache_ttl: TTL للـ cache
        """
        self.resolvers = resolvers or self.DEFAULT_RESOLVERS.copy()
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.retries = retries

        self._cache = DNSCache(cache_ttl) if use_cache else None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._stats = {
            "queries": 0,
            "successful": 0,
            "failed": 0,
            "cached": 0,
        }

    async def __aenter__(self) -> "AsyncDNSResolver":
        return self

    async def __aexit__(self, *args) -> None:
        pass

    @classmethod
    def load_resolvers(cls, file_path: str) -> List[str]:
        """تحميل resolvers من ملف"""
        resolvers = []
        path = Path(file_path)

        if not path.exists():
            logger.warning(f"Resolvers file not found: {file_path}")
            return cls.DEFAULT_RESOLVERS.copy()

        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    resolvers.append(line)

        return resolvers or cls.DEFAULT_RESOLVERS.copy()

    async def _resolve_single(
        self,
        domain: str,
        record_type: str = "A",
    ) -> DNSResult:
        """استعلام واحد"""
        start = time.time()
        self._stats["queries"] += 1

        # Check cache
        if self._cache:
            cached = self._cache.get(domain, record_type)
            if cached:
                if self._cache.is_negative(cached):
                    return DNSResult(domain=domain, error="NXDOMAIN (cached)", query_time=0)
                self._stats["cached"] += 1
                return DNSResult(
                    domain=domain,
                    records=[cached],
                    query_time=0,
                    resolver_used="cache",
                )

        async with self._semaphore:
            for attempt in range(self.retries + 1):
                resolver = random.choice(self.resolvers)

                try:
                    # Use asyncio.to_thread for blocking DNS lookup
                    loop = asyncio.get_event_loop()

                    if record_type == "A":
                        # Get A records
                        result = await asyncio.wait_for(
                            loop.run_in_executor(None, socket.gethostbyname_ex, domain),
                            timeout=self.timeout,
                        )

                        hostname, aliases, addresses = result
                        records = [
                            DNSRecord(
                                domain=domain,
                                record_type="A",
                                value=addr,
                                ttl=300,
                            )
                            for addr in addresses
                        ]

                        # Cache results
                        if self._cache:
                            self._cache.set_many(records)

                        self._stats["successful"] += 1
                        return DNSResult(
                            domain=domain,
                            records=records,
                            query_time=time.time() - start,
                            resolver_used=resolver,
                        )

                    else:
                        # For other record types, use dns.resolver if available
                        try:
                            import dns.resolver

                            answers = await asyncio.wait_for(
                                loop.run_in_executor(
                                    None,
                                    lambda: list(
                                        dns.resolver.resolve(domain, record_type)
                                    ),
                                ),
                                timeout=self.timeout,
                            )

                            records = [
                                DNSRecord(
                                    domain=domain,
                                    record_type=record_type,
                                    value=str(rdata),
                                    ttl=300,
                                )
                                for rdata in answers
                            ]

                            if self._cache:
                                self._cache.set_many(records)

                            self._stats["successful"] += 1
                            return DNSResult(
                                domain=domain,
                                records=records,
                                query_time=time.time() - start,
                                resolver_used=resolver,
                            )

                        except ImportError:
                            # Fall back to A record only
                            return DNSResult(
                                domain=domain,
                                error=f"dnspython not installed for {record_type} lookups",
                                query_time=time.time() - start,
                            )

                except socket.gaierror as e:
                    if attempt == self.retries:
                        if self._cache: self._cache.set_negative(domain, record_type)
                        self._stats["failed"] += 1
                        return DNSResult(
                            domain=domain,
                            error=f"DNS resolution failed: {e}",
                            query_time=time.time() - start,
                        )

                except asyncio.TimeoutError:
                    if attempt == self.retries:
                        self._stats["failed"] += 1
                        return DNSResult(
                            domain=domain,
                            error="DNS resolution timeout",
                            query_time=time.time() - start,
                        )

                except Exception as e:
                    if attempt == self.retries:
                        self._stats["failed"] += 1
                        return DNSResult(
                            domain=domain,
                            error=str(e),
                            query_time=time.time() - start,
                        )

        return DNSResult(
            domain=domain,
            error="Max retries exceeded",
            query_time=time.time() - start,
        )

    async def resolve(
        self,
        domain: str,
        record_types: Optional[List[str]] = None,
    ) -> DNSResult:
        """
        حل domain واحد.

        Args:
            domain: الـ domain
            record_types: أنواع السجلات (default: ["A"])

        Returns:
            DNSResult
        """
        record_types = record_types or ["A"]

        # Get all record types
        all_records = []
        for rtype in record_types:
            result = await self._resolve_single(domain, rtype)
            all_records.extend(result.records)

        return DNSResult(
            domain=domain,
            records=all_records,
            query_time=sum(r.ttl for r in all_records) / max(1, len(all_records)),
        )

    async def resolve_many(
        self,
        domains: List[str],
        record_type: str = "A",
    ) -> List[DNSResult]:
        """
        حل domains متعددة بالتوازي.

        Args:
            domains: قائمة الـ domains
            record_type: نوع السجل

        Returns:
            قائمة DNSResult
        """
        tasks = [self._resolve_single(domain, record_type) for domain in domains]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed = []
        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                processed.append(
                    DNSResult(
                        domain=domain,
                        error=str(result),
                    )
                )
            else:
                processed.append(result)  # type: ignore[arg-type]

        return processed

    async def reverse_lookup(self, ip: str) -> DNSResult:
        """
        Reverse DNS lookup.

        Args:
            ip: عنوان IP

        Returns:
            DNSResult
        """
        start = time.time()

        try:
            loop = asyncio.get_event_loop()
            hostname, aliases, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=self.timeout,
            )

            records = [
                DNSRecord(
                    domain=ip,
                    record_type="PTR",
                    value=hostname,
                    ttl=300,
                )
            ]

            for alias in aliases:
                records.append(
                    DNSRecord(
                        domain=ip,
                        record_type="PTR",
                        value=alias,
                        ttl=300,
                    )
                )

            return DNSResult(
                domain=ip,
                records=records,
                query_time=time.time() - start,
            )

        except Exception as e:
            return DNSResult(
                domain=ip,
                error=str(e),
                query_time=time.time() - start,
            )

    async def check_wildcard(self, domain: str) -> bool:
        """
        فحص إذا كان الـ domain يستخدم wildcard DNS.

        Args:
            domain: الـ domain

        Returns:
            True إذا كان wildcard
        """
        # Generate random subdomain
        random_sub = f"random-{random.randint(100000, 999999)}.{domain}"

        result = await self._resolve_single(random_sub, "A")
        return result.has_records

    def get_stats(self) -> Dict[str, int]:
        """إحصائيات"""
        stats = self._stats.copy()
        if self._cache:
            stats["cache"] = self._cache.stats  # type: ignore[assignment]
        return stats


# ═══════════════════════════════════════════════════════════
#                     Convenience Functions
# ═══════════════════════════════════════════════════════════


async def bulk_resolve(
    domains: List[str],
    max_concurrent: int = 100,
) -> Dict[str, List[str]]:
    """
    حل domains متعددة وإرجاع A records.

    Example:
        >>> results = await bulk_resolve(["google.com", "example.com"])
        >>> print(results["google.com"])  # ["142.250.185.46", ...]
    """
    async with AsyncDNSResolver(max_concurrent=max_concurrent) as resolver:
        results = await resolver.resolve_many(domains)

    return {r.domain: r.a_records for r in results}


async def filter_resolvable(
    domains: List[str],
    max_concurrent: int = 100,
) -> List[str]:
    """
    تصفية الـ domains القابلة للحل.

    Example:
        >>> valid = await filter_resolvable(["google.com", "invalid.test"])
        >>> print(valid)  # ["google.com"]
    """
    async with AsyncDNSResolver(max_concurrent=max_concurrent) as resolver:
        results = await resolver.resolve_many(domains)

    return [r.domain for r in results if r.has_records]


def run_bulk_resolve(domains: List[str], **kwargs) -> Dict[str, List[str]]:
    """Synchronous wrapper."""
    return asyncio.run(bulk_resolve(domains, **kwargs))
