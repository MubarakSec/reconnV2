from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

LOGGER = logging.getLogger(__name__)

ENV_KEYWORDS = {
    "dev": "env:dev",
    "development": "env:dev",
    "staging": "env:staging",
    "stage": "env:staging",
    "qa": "env:qa",
    "test": "env:test",
    "preprod": "env:preprod",
    "prod": "env:prod",
    "internal": "scope:internal",
    "corp": "scope:internal",
    "intranet": "scope:internal",
}

SERVICE_KEYWORDS = {
    "api": "service:api",
    "auth": "service:auth",
    "login": "surface:login",
    "admin": "surface:admin",
    "sso": "service:sso",
    "vpn": "service:vpn",
    "cdn": "service:cdn",
}

NOISE_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
}

CDN_KEYWORDS = [
    "cloudflare",
    "fastly",
    "akamai",
    "edgecast",
    "cloudfront",
    "incapsula",
    "imperva",
    "stackpath",
]

CLOUD_KEYWORDS = {
    "amazon": "cloud:aws",
    "aws": "cloud:aws",
    "google": "cloud:gcp",
    "microsoft": "cloud:azure",
    "azure": "cloud:azure",
    "digitalocean": "cloud:do",
    "linode": "cloud:linode",
    "oracle": "cloud:oracle",
    "alibaba": "cloud:alibaba",
}

LEGACY_TECH = {
    "apache/2.2": 20,
    "apache/2.0": 20,
    "iis/6.0": 30,
    "php/5": 25,
    "tomcat/6": 25,
    "jboss": 30,
}


@dataclass
class IpEnrichment:
    ip: str
    asn: Optional[str]
    org: Optional[str]
    country: Optional[str]
    city: Optional[str]
    provider_tag: Optional[str]
    is_cdn: bool
    is_cloud: bool
    tags: set[str]


class IpInfoClient:
    def __init__(self) -> None:
        self.token = os.environ.get("IPINFO_TOKEN")
        self.session = requests.Session() if self.token else None
        self.cache: Dict[str, Dict[str, str]] = {}

    def lookup(self, ip: str) -> Dict[str, str]:
        if ip in self.cache:
            return self.cache[ip]
        if not self.session:
            self.cache[ip] = {}
            return {}
        try:
            resp = self.session.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5,
                headers={"Accept": "application/json"},
                params={"token": self.token},
            )
            if resp.status_code == 429:
                LOGGER.warning("ipinfo rate limited; skipping further lookups")
                self.session = None
                self.cache[ip] = {}
                return {}
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # pragma: no cover - network path
            LOGGER.debug("ipinfo lookup failed for %s: %s", ip, exc)
            data = {}
        self.cache[ip] = data
        return data


def classify_provider(org: Optional[str]) -> tuple[Optional[str], bool, bool]:
    if not org:
        return None, False, False
    lowered = org.lower()
    is_cdn = any(keyword in lowered for keyword in CDN_KEYWORDS)
    provider_tag = None
    for keyword, tag in CLOUD_KEYWORDS.items():
        if keyword in lowered:
            provider_tag = tag
            break
    is_cloud = provider_tag is not None
    if is_cdn:
        provider_tag = provider_tag or "service:cdn"
    return provider_tag, is_cdn, is_cloud


def hostname_tags(hostname: str) -> set[str]:
    tags: set[str] = set()
    lowered = hostname.lower()
    parts = lowered.replace("_", "-").split('.')
    for token in parts:
        for keyword, tag in ENV_KEYWORDS.items():
            if keyword in token:
                tags.add(tag)
        for keyword, tag in SERVICE_KEYWORDS.items():
            if keyword in token:
                tags.add(tag)
    return tags


def enrich_asset(hostname: str, ip: str, client: IpInfoClient) -> IpEnrichment:
    tags = hostname_tags(hostname)
    is_private = ipaddress.ip_address(ip).is_private
    if is_private:
        tags.add("scope:internal")
    payload = client.lookup(ip)
    asn = payload.get("asn") or payload.get("org", "").split()[0] if payload else None
    org = payload.get("org") if payload else None
    country = payload.get("country") if payload else None
    city = payload.get("city") if payload else None
    provider_tag, is_cdn, is_cloud = classify_provider(org)
    if provider_tag:
        tags.add(provider_tag)
    if is_cdn:
        tags.add("service:cdn")
    if is_cloud:
        tags.add("surface:cloud")
    return IpEnrichment(
        ip=ip,
        asn=asn,
        org=org,
        country=country,
        city=city,
        provider_tag=provider_tag,
        is_cdn=is_cdn,
        is_cloud=is_cloud,
        tags=tags,
    )


def infer_service_tags(url: str) -> set[str]:
    parsed = urlparse(url)
    tags: set[str] = set()
    path = parsed.path.lower()
    for keyword, tag in SERVICE_KEYWORDS.items():
        if keyword in path:
            tags.add(tag)
    if parsed.query:
        lower_query = parsed.query.lower()
        if "token=" in lower_query:
            tags.add("indicator:token")
        if "password" in lower_query:
            tags.add("indicator:password")
    return tags


def detect_noise(url: str, status_code: Optional[int], source: str, length: Optional[int]) -> bool:
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    for ext in NOISE_EXTENSIONS:
        if path.endswith(ext):
            if parsed.query:
                break
            if status_code and 400 <= status_code < 500:
                break
            return True
    if source in {"waybackurls", "gau"} and status_code in {None, 0}:
        return True
    return False


def legacy_score(server: Optional[str]) -> int:
    if not server:
        return 0
    lowered = server.lower()
    for fingerprint, modifier in LEGACY_TECH.items():
        if fingerprint in lowered:
            return modifier
    return 0


def classify_priority(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score <= 0:
        return "noise"
    return "low"

