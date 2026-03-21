"""Active scanning module for active vulnerability testing.

This module provides active scanning capabilities including
backup file detection, CORS checks, JavaScript secret scanning, and more.
"""

from recon_cli.active.modules import (
    BACKUP_SUFFIXES,
    JS_SECRET_PATTERNS,
    ActiveResult,
    create_session,
    run_backup_hunt,
    run_cors_checks,
    run_js_secret_harvest,
    run_response_diff,
    available_modules,
    execute_module,
)

__all__ = [
    "BACKUP_SUFFIXES",
    "JS_SECRET_PATTERNS",
    "ActiveResult",
    "create_session",
    "run_backup_hunt",
    "run_cors_checks",
    "run_js_secret_harvest",
    "run_response_diff",
    "available_modules",
    "execute_module",
]
