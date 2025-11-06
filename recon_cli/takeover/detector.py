from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

TAKEOVER_FINGERPRINTS = [
    {
        "provider": "aws_s3",
        "cname": ["s3.amazonaws.com", "amazonaws.com"],
        "responses": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    {
        "provider": "azure",
        "responses": ["The resource you are looking for has been removed", "Error 404"],
    },
    {
        "provider": "heroku",
        "responses": ["no such app", "Couldn't find the app"],
    },
    {
        "provider": "github_pages",
        "responses": ["There isn't a GitHub Pages site here."],
    },
    {
        "provider": "fastly",
        "responses": ["Fastly error: unknown domain", "Fastly domain not configured"],
    },
    {
        "provider": "azure_cdn",
        "responses": ["Error 404 - Web site not configured"],
    },
]

REQUEST_TIMEOUT = 6
USER_AGENT = "recon-cli-takeover/0.1"


@dataclass
class TakeoverFinding:
    hostname: str
    provider: str
    evidence: str


class TakeoverDetector:
    def __init__(self, timeout: int = REQUEST_TIMEOUT) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.timeout = timeout

    def check_host(self, hostname: str) -> Optional[TakeoverFinding]:
        urls = [f"http://{hostname}", f"https://{hostname}"]
        for url in urls:
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            except requests.RequestException:
                continue
            body = (resp.text or "")[:2000]
            for fp in TAKEOVER_FINGERPRINTS:
                for snippet in fp.get("responses", []):
                    if snippet.lower() in body.lower():
                        return TakeoverFinding(hostname=hostname, provider=fp["provider"], evidence=snippet)
        return None


