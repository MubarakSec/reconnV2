"""
Secrets Module - Secret Detection and Analysis

This package provides secret detection capabilities:
- detector: Synchronous secrets detector with pattern matching
- async_scanner: Asynchronous concurrent secrets scanner
"""

from .detector import SecretsDetector, SecretMatch, SECRETS_PATTERNS, shannon_entropy
from .async_scanner import AsyncSecretsScanner

__all__ = [
    # Detector
    "SecretsDetector",
    "SecretMatch",
    "SECRETS_PATTERNS",
    "shannon_entropy",
    # Async Scanner
    "AsyncSecretsScanner",
]

