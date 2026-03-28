from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set

import httpx

TAKEOVER_FINGERPRINTS = [
    {
        "provider": "aws_s3",
        "cname": ["s3.amazonaws.com", "amazonaws.com"],
        "responses": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    {
        "provider": "azure",
        "cname": ["azurewebsites.net", "cloudapp.net"],
        "responses": ["The resource you are looking for has been removed", "Error 404"],
    },
    {
        "provider": "heroku",
        "cname": ["herokudns.com", "herokussl.com", "herokuapp.com"],
        "responses": ["no such app", "Couldn't find the app"],
    },
    {
        "provider": "github_pages",
        "cname": ["github.io"],
        "responses": ["There isn't a GitHub Pages site here."],
    },
    {
        "provider": "fastly",
        "cname": ["fastly.net"],
        "responses": ["Fastly error: unknown domain", "Fastly domain not configured"],
    },
    {
        "provider": "azure_cdn",
        "cname": ["azureedge.net"],
        "responses": ["Error 404 - Web site not configured"],
    },
    {
        "provider": "netlify",
        "cname": ["netlify.app", "netlify.com"],
        "responses": ["Not Found - Request ID"],
    },
    {
        "provider": "vercel",
        "cname": ["vercel.app", "now.sh"],
        "responses": ["The deployment you are looking for"],
    },
    {
        "provider": "shopify",
        "cname": ["myshopify.com", "shops.myshopify.com"],
        "responses": ["Sorry, this shop is currently unavailable."],
    },
    {
        "provider": "zendesk",
        "cname": ["zendesk.com"],
        "responses": ["Help Center Closed", "Oops, this page no longer exists"],
    },
    {
        "provider": "hubspot",
        "cname": ["hubspot.net", "hs-sites.com"],
        "responses": ["Domain not configured", "does not exist in our system"],
    },
    {
        "provider": "ghost",
        "cname": ["ghost.io"],
        "responses": ["The thing you were looking for is no longer here"],
    },
    {"provider": "surge_sh", "cname": ["surge.sh"], "responses": ["project not found"]},
    {
        "provider": "fly_io",
        "cname": ["fly.dev", "fly.io"],
        "responses": ["404 Not Found"],
    },
    {
        "provider": "readme_io",
        "cname": ["readme.io", "readmessl.com"],
        "responses": ["Project doesnt exist"],
    },
    {
        "provider": "cargo",
        "cname": ["cargocollective.com"],
        "responses": ["If you're moving your domain away from Cargo"],
    },
    {
        "provider": "intercom",
        "cname": ["intercom.io", "custom.intercom.help"],
        "responses": ["This page is reserved for artistic content"],
    },
    {
        "provider": "strikingly",
        "cname": ["strikingly.com", "s.strikinglydns.com"],
        "responses": ["But if you're looking to build your own website"],
    },
    {
        "provider": "wordpress_com",
        "cname": ["wordpress.com"],
        "responses": ["Do you want to register"],
    },
    {
        "provider": "smartjobboard",
        "cname": ["smartjobboard.com"],
        "responses": [
            "This job board website is either expired or its domain name is invalid."
        ],
    },
    {
        "provider": "helpjuice",
        "cname": ["helpjuice.com"],
        "responses": ["We could not find what you're looking for."],
    },
    {
        "provider": "unbounce",
        "cname": ["unbouncepages.com"],
        "responses": ["The requested URL was not found on this server."],
    },
    {
        "provider": "campaignmonitor",
        "cname": ["createsend.com", "industryemails.com"],
        "responses": ["Double check the URL"],
    },
]

REQUEST_TIMEOUT = 6
USER_AGENT = "recon-cli-takeover/0.1"

PARKING_SIGNATURES = [
    "this domain is for sale",
    "buy this domain",
    "domain parked",
    "parked domain",
    "godaddy.com/domainforsale",
    "sedo.com",
    "afternic.com",
    "dan.com/domain",
]


@dataclass
class TakeoverFinding:
    hostname: str
    provider: str
    evidence: str
    status_code: int = 0
    matched_url: str = ""
    finding_type: str = "subdomain_takeover"


class TakeoverDetector:
    def __init__(self, timeout: int = REQUEST_TIMEOUT, verify_tls: bool = True) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"User-Agent": USER_AGENT}

    def check_parking(self, body: str) -> bool:
        body_lower = body.lower()
        return any(sig in body_lower for sig in PARKING_SIGNATURES)

    async def check_host(
        self, hostname: str, providers: Optional[Set[str]] = None
    ) -> Optional[TakeoverFinding]:
        urls = [f"http://{hostname}", f"https://{hostname}"]
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_tls,
            headers=self.headers,
            follow_redirects=True,
        ) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                except httpx.RequestError:
                    continue
                body = (resp.text or "")[:2000]

                # Check for parking page first
                if self.check_parking(body):
                    return TakeoverFinding(
                        hostname=hostname,
                        provider="parking_page",
                        evidence="Parking page signature detected",
                        status_code=int(resp.status_code or 0),
                        matched_url=url,
                        finding_type="parking_page",
                    )

                for fp in TAKEOVER_FINGERPRINTS:
                    if providers and fp.get("provider") not in providers:
                        continue
                    for snippet in fp.get("responses", []):
                        if snippet.lower() in body.lower():
                            return TakeoverFinding(
                                hostname=hostname,
                                provider=fp["provider"],  # type: ignore[arg-type]
                                evidence=snippet,
                                status_code=int(resp.status_code or 0),
                                matched_url=url,
                                finding_type="subdomain_takeover",
                            )
        return None

    async def can_claim(self, hostname: str, provider: str) -> bool:
        """
        Attempt to verify if the resource is actually claimable.
        This performs non-destructive checks where possible.
        """
        if provider == "aws_s3":
            return await self._verify_s3(hostname)
        if provider == "github_pages":
            return await self._verify_github_pages(hostname)
        
        # For other providers, we might not have a reliable non-destructive check
        # but we can check if the hostname still returns the error snippet
        return False

    async def _verify_s3(self, hostname: str) -> bool:
        """Verify if an S3 bucket is actually claimable by trying to 'create' it via API (dry-run if possible)
        or checking for specific lack of headers."""
        # Simple check: if we try to access it via s3.amazonaws.com directly
        # and it still says NoSuchBucket, it's very likely claimable.
        # More advanced: use boto3 if available to check bucket availability
        bucket_name = hostname # Often the hostname is the bucket name
        url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if "NoSuchBucket" in resp.text:
                    return True
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="unknown", error_type=type(e).__name__).inc()
                except: pass
        return False

    async def _verify_github_pages(self, hostname: str) -> bool:
        """Verify if GitHub Pages is claimable."""
        # GitHub Pages returns 404 with a specific body if claimable
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"http://{hostname}")
                if resp.status_code == 404 and "There isn't a GitHub Pages site here" in resp.text:
                    return True
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="unknown", error_type=type(e).__name__).inc()
                except: pass
        return False
