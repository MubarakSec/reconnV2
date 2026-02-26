"""
ReconnV2 - Advanced Security Reconnaissance Pipeline

This package provides comprehensive tools for security reconnaissance:
- Multi-stage scanning pipeline with parallel execution
- Vulnerability and secret detection
- Integration with external tools (nuclei, subfinder, httpx, naabu, dalfox, etc.)
- REST API and Web Dashboard
- Extensible plugin system
- Prometheus metrics and distributed tracing
- Multi-channel alerting (Slack, Discord, Telegram, Email)
- Job scheduling with cron expressions
- Asset inventory management
- Multi-user support with RBAC

Version: 0.2.0
"""

from importlib import import_module

__version__ = "0.2.0"
__author__ = "Recon Team"
__license__ = "MIT"

_LAZY_SUBMODULES = {
    "active",
    "api",
    "cli",
    "cli_wizard",
    "completions",
    "config",
    "correlation",
    "crawl",
    "db",
    "exceptions",
    "inventory",
    "jobs",
    "learning",
    "pipeline",
    "plugins",
    "reports",
    "scanners",
    "scheduler",
    "secrets",
    "settings",
    "takeover",
    "tools",
    "users",
    "utils",
    "web",
}

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    # Core
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
    "plugins_pkg",
    # Feature modules
    "active",
    "correlation",
    "crawl",
    "db",
    "learning",
    "takeover",
    "web",
    # New improvements
    "exceptions",
    "settings",
    "scheduler",
    "inventory",
    "users",
    # Phase 8 - CLI Polish & Reports
    "cli_wizard",
    "completions",
    "reports",
]


def __getattr__(name: str):
    if name == "plugins_pkg":
        return import_module(".plugins", __name__)
    if name in _LAZY_SUBMODULES:
        return import_module(f".{name}", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
