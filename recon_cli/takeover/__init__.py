"""Takeover detection module for subdomain takeover vulnerabilities.

This module provides detection of subdomain takeover vulnerabilities
by checking for dangling DNS records and vulnerable service fingerprints.
"""

from recon_cli.takeover.detector import (
    TAKEOVER_FINGERPRINTS,
    TakeoverDetector,
    TakeoverFinding,
)

__all__ = [
    "TAKEOVER_FINGERPRINTS",
    "TakeoverDetector",
    "TakeoverFinding",
]
