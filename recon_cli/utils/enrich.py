from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
from dataclasses import dataclass

from typing import Dict, Iterable, Optional
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
    "signin": "surface:login",
    "sign-in": "surface:login",
    "sign_in": "surface:login",
    "logout": "surface:logout",
    "register": "surface:register",
    "signup": "surface:register",
    "sign-up": "surface:register",
    "sign_up": "surface:register",
    "forgot": "surface:password-reset",
    "reset": "surface:password-reset",
    "recover": "surface:password-reset",
    "password": "surface:password-reset",
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

WAF_KEYWORDS = {
    "cloudflare": "waf:cloudflare",
    "akamai": "waf:akamai",
    "imperva": "waf:imperva",
    "incapsula": "waf:incapsula",
    "sucuri": "waf:sucuri",
    "fastly": "waf:fastly",
    "barracuda": "waf:barracuda",
    "modsecurity": "waf:modsecurity",
    "f5": "waf:f5",
    "wallarm": "waf:wallarm",
    "radware": "waf:radware",
}

COOKIE_TECH_KEYWORDS: Dict[str, set[str]] = {
    "wordpress": {"tech:wordpress", "cms:wordpress"},
    "wp-": {"tech:wordpress", "cms:wordpress"},
    "wp_": {"tech:wordpress", "cms:wordpress"},
    "drupal": {"cms:drupal"},
    "joomla": {"cms:joomla"},
    "laravel": {"framework:laravel"},
    "laravel_session": {"framework:laravel"},
    "django": {"framework:django"},
    "csrftoken": {"framework:django"},
    "sessionid": {"framework:django"},
    "jsessionid": {"tech:java"},
    "phpsessid": {"tech:php"},
    "asp.net": {"tech:aspnet"},
    "aspnet": {"tech:aspnet"},
    "express": {"framework:express"},
    "rails": {"framework:rails"},
    "_rails": {"framework:rails"},
    "next-auth": {"framework:nextjs"},
    "nextauth": {"framework:nextjs"},
    "nextjs": {"framework:nextjs"},
    "shopify": {"platform:shopify"},
    "cfduid": {"waf:cloudflare", "service:waf", "service:cdn"},
    "__cf": {"waf:cloudflare", "service:waf", "service:cdn"},
    "incap_ses": {"waf:imperva", "service:waf"},
    "visid_incap": {"waf:imperva", "service:waf"},
    "awsalb": {"cloud:aws"},
    "awsalbtg": {"cloud:aws"},
}

SOFT_404_PATTERNS = [
    "page not found",
    "not found",
    "404",
    "the page you requested",
    "no longer exists",
    "does not exist",
    "requested url was not found",
    "invalid page",
    "file not found",
    "error 404",
]


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
    parts = lowered.replace("_", "-").split(".")
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


def infer_tech_tags(
    technologies: Optional[list[str]],
    server: Optional[str] = None,
    title: Optional[str] = None,
) -> set[str]:
    tags: set[str] = set()
    tech_values: set[str] = set()
    if technologies:
        tech_values.update({str(item).lower() for item in technologies if item})
    if server:
        tech_values.add(server.lower())
    if title:
        tech_values.add(title.lower())
    if any("wordpress" in tech for tech in tech_values):
        tags.add("tech:wordpress")
        tags.add("cms:wordpress")
    if any("drupal" in tech for tech in tech_values):
        tags.add("cms:drupal")
    if any("joomla" in tech for tech in tech_values):
        tags.add("cms:joomla")
    if any("laravel" in tech for tech in tech_values):
        tags.add("framework:laravel")
    if any("django" in tech for tech in tech_values):
        tags.add("framework:django")
    if any("rails" in tech for tech in tech_values):
        tags.add("framework:rails")
    if any("express" in tech for tech in tech_values):
        tags.add("framework:express")
    if any("next.js" in tech or "nextjs" in tech for tech in tech_values):
        tags.add("framework:nextjs")
    if any("react" in tech for tech in tech_values):
        tags.add("framework:react")
    if any("vue" in tech for tech in tech_values):
        tags.add("framework:vue")
    if any("angular" in tech for tech in tech_values):
        tags.add("framework:angular")
    if any("spring" in tech for tech in tech_values):
        tags.add("framework:spring")
    if any("node" in tech for tech in tech_values):
        tags.add("tech:nodejs")
    if any("php" in tech for tech in tech_values):
        tags.add("tech:php")
    if any("asp.net" in tech or "aspnet" in tech for tech in tech_values):
        tags.add("tech:aspnet")
    if any("shopify" in tech for tech in tech_values):
        tags.add("platform:shopify")
    if any("nginx" in tech for tech in tech_values):
        tags.add("tech:nginx")
    if any("apache" in tech for tech in tech_values):
        tags.add("tech:apache")
    if any("iis" in tech for tech in tech_values):
        tags.add("tech:iis")
    return tags


def infer_cookie_tags(set_cookie_headers: Optional[Iterable[str]]) -> set[str]:
    tags: set[str] = set()
    if not set_cookie_headers:
        return tags
    for header in set_cookie_headers:
        if not header:
            continue
        cookie_pair = header.split(";", 1)[0]
        if "=" not in cookie_pair:
            continue
        name = cookie_pair.split("=", 1)[0].strip().lower()
        if not name:
            continue
        for keyword, keyword_tags in COOKIE_TECH_KEYWORDS.items():
            if keyword in name:
                tags.update(keyword_tags)
    return tags


def detect_waf_tags(server: Optional[str], cdn: Optional[str] = None) -> set[str]:
    tags: set[str] = set()
    parts: list[str] = []
    for value in (server, cdn):
        if not value:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (list, tuple, set)):
            parts.extend(str(item) for item in value if item)
        else:
            parts.append(str(value))
    if not parts:
        return tags
    haystack = " ".join(parts).lower()
    for keyword, tag in WAF_KEYWORDS.items():
        if keyword in haystack:
            tags.add(tag)
            tags.add("service:waf")
    return tags


def get_soft_404_fingerprint(body: str, title: str = "") -> dict:
    """Generate a fingerprint for a potential soft 404 page."""
    words = body.lower().split()
    return {
        "length": len(body),
        "word_count": len(words),
        "title": title.strip().lower(),
        "hash": hashlib.md5(body.encode("utf-8", errors="ignore"), usedforsecurity=False).hexdigest()[:16],
    }


def looks_like_soft_404(
    status_code: Optional[int], body_snippet: str, title: str = ""
) -> bool:
    if status_code not in {200, 301, 302}:
        return False
    combined = f"{title} {body_snippet}".lower()
    return any(pattern in combined for pattern in SOFT_404_PATTERNS)


def detect_noise(
    url: str, status_code: Optional[int], source: str, length: Optional[int]
) -> bool:
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
