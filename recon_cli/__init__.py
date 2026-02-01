"""
ReconnV2 - Advanced Security Reconnaissance Pipeline

This package provides comprehensive tools for security reconnaissance:
- Multi-stage scanning pipeline
- Vulnerability and secret detection
- Integration with external tools (nuclei, subfinder, httpx, etc.)
- REST API and Web Dashboard
- Extensible plugin system

Version: 0.1.0
"""

__version__ = "0.1.0"
__author__ = "Recon Team"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "config",
    "cli",
    "api",
    "jobs",
    "pipeline",
    "tools",
    "utils",
    "secrets",
    "scanners",
    "plugins",
    "db",
    "web",
]

