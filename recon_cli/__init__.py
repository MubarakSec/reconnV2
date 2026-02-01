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

__version__ = "0.2.0"
__author__ = "Recon Team"
__license__ = "MIT"

# Core modules
from . import config
from . import cli
from . import api
from . import jobs
from . import pipeline
from . import tools
from . import utils
from . import secrets
from . import scanners

# Plugins subpackage (separate from plugins.py module)
from . import plugins as plugins_pkg

# Additional feature modules
from . import active
from . import correlation
from . import crawl
from . import db
from . import learning
from . import takeover
from . import web

# New modules from improvements
from . import exceptions

# Phase 8 modules
try:
    from . import cli_wizard
except ImportError:
    cli_wizard = None  # type: ignore

try:
    from . import completions
except ImportError:
    completions = None  # type: ignore

try:
    from . import reports
except ImportError:
    reports = None  # type: ignore

# Optional modules that have extra dependencies
try:
    from . import settings
except ImportError:
    settings = None  # type: ignore

try:
    from . import scheduler
except ImportError:
    scheduler = None  # type: ignore

try:
    from . import inventory
except ImportError:
    inventory = None  # type: ignore

try:
    from . import users
except ImportError:
    users = None  # type: ignore

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



