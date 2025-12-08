from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Optional


def _default_home() -> Path:
    env = os.environ.get("RECON_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return Path.cwd()


LOG_LEVEL_NAME = os.environ.get("RECON_LOG_LEVEL", "INFO").upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL_NAME, logging.INFO)
LOG_FORMAT = os.environ.get("RECON_LOG_FORMAT", "text").lower()
LOG_FORMAT = os.environ.get("RECON_LOG_FORMAT", "text").lower()

RECON_HOME: Path = _default_home()
JOBS_ROOT: Path = RECON_HOME / "jobs"
QUEUED_JOBS: Path = JOBS_ROOT / "queued"
RUNNING_JOBS: Path = JOBS_ROOT / "running"
FINISHED_JOBS: Path = JOBS_ROOT / "finished"
FAILED_JOBS: Path = JOBS_ROOT / "failed"
ARCHIVE_ROOT: Path = RECON_HOME / "archive"

LOG_RELATIVE_PATH = Path("logs") / "pipeline.log"
RESULTS_JSONL_NAME = "results.jsonl"
RESULTS_TEXT_NAME = "results.txt"
SPEC_NAME = "spec.json"
METADATA_NAME = "metadata.json"
ARTIFACTS_DIRNAME = "artifacts"


DEFAULT_RESOLVERS = RECON_HOME / "config" / "resolvers.txt"
DEFAULT_RESOLVERS_PARENT = DEFAULT_RESOLVERS.parent
DEFAULT_RESOLVERS_CONTENT = """1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
208.67.222.222
208.67.220.220
"""
DEFAULT_PROFILES = RECON_HOME / "config" / "profiles.json"
DEFAULT_PROFILES_CONTENT = """{
  "quick": {
    "base_profile": "passive",
    "runtime": {
      "timeout_http": 5,
      "httpx_threads": 25,
      "runtime_crawl_max_urls": 5,
      "runtime_crawl_timeout": 8,
      "runtime_crawl_concurrency": 1,
      "max_global_concurrency": 10,
      "max_fuzz_hosts": 0,
      "enable_fuzz": false,
      "enable_runtime_crawl": false,
      "enable_screenshots": false,
      "enable_secrets": true,
      "secrets_max_files": 10,
      "retry_count": 0
    }
  },
  "deep": {
    "base_profile": "full",
    "runtime": {
      "timeout_http": 20,
      "httpx_threads": 80,
      "runtime_crawl_max_urls": 40,
      "runtime_crawl_concurrency": 4,
      "runtime_crawl_timeout": 30,
      "max_fuzz_hosts": 12,
      "enable_fuzz": true,
      "enable_runtime_crawl": true,
      "enable_screenshots": true,
      "enable_secrets": true,
      "secrets_max_files": 60,
      "max_screenshots": 40,
      "retry_count": 2
    }
  },
  "api-only": {
    "base_profile": "full",
    "runtime": {
      "enable_fuzz": true,
      "enable_runtime_crawl": true,
      "enable_screenshots": false,
      "enable_secrets": true,
      "url_path_allow_regex": "(/api|/graphql)",
      "runtime_crawl_max_urls": 25,
      "runtime_crawl_concurrency": 2,
      "max_fuzz_hosts": 6,
      "secrets_max_files": 30,
      "httpx_threads": 40,
      "timeout_http": 10
    }
  }
}
"""
DEFAULT_SECLISTS_ROOT = Path(os.environ.get("SECLISTS_ROOT", "/opt/recon-tools/seclists"))

def ensure_base_directories(force: bool = False) -> None:
    global _PROFILES_CACHE
    for path in [
        RECON_HOME,
        JOBS_ROOT,
        QUEUED_JOBS,
        RUNNING_JOBS,
        FINISHED_JOBS,
        FAILED_JOBS,
        ARCHIVE_ROOT,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    DEFAULT_RESOLVERS_PARENT.mkdir(parents=True, exist_ok=True)
    profiles_written = False
    if force or not DEFAULT_RESOLVERS.exists():
        DEFAULT_RESOLVERS.write_text(DEFAULT_RESOLVERS_CONTENT, encoding="utf-8")
        try:
            DEFAULT_RESOLVERS.chmod(0o600)
        except PermissionError:
            pass
    if force or not DEFAULT_PROFILES.exists():
        DEFAULT_PROFILES.write_text(DEFAULT_PROFILES_CONTENT, encoding="utf-8")
        try:
            DEFAULT_PROFILES.chmod(0o600)
        except PermissionError:
            pass
        profiles_written = True
    if profiles_written or force:
        _PROFILES_CACHE = None


_PROFILES_CACHE: Dict[str, Dict[str, Any]] | None = None
_PROFILE_ERRORS: list[str] = []


def load_profiles() -> Dict[str, Dict[str, Any]]:
    global _PROFILES_CACHE
    global _PROFILE_ERRORS
    if _PROFILES_CACHE is not None:
        return _PROFILES_CACHE
    _PROFILE_ERRORS = []
    if not DEFAULT_PROFILES.exists():
        _PROFILES_CACHE = {}
        return _PROFILES_CACHE
    try:
        data = json.loads(DEFAULT_PROFILES.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        data = {}
    if isinstance(data, dict):
        validated: Dict[str, Dict[str, Any]] = {}
        for key, value in data.items():
            if not isinstance(value, dict):
                _PROFILE_ERRORS.append(f"profile '{key}' invalid: expected object")
                continue
            name = str(key).lower()
            base_profile = value.get("base_profile")
            if base_profile is None or not isinstance(base_profile, str):
                _PROFILE_ERRORS.append(f"profile '{name}' missing base_profile")
                continue
            runtime = value.get("runtime")
            if runtime is not None and not isinstance(runtime, dict):
                _PROFILE_ERRORS.append(f"profile '{name}' runtime must be object")
                continue
            validated[name] = value
        _PROFILES_CACHE = validated
    else:
        _PROFILES_CACHE = {}
    return _PROFILES_CACHE


def get_profile(name: str) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    return load_profiles().get(name.lower())


def available_profiles() -> Dict[str, Dict[str, Any]]:
    return load_profiles().copy()


def profile_errors() -> list[str]:
    load_profiles()
    return list(_PROFILE_ERRORS)


@dataclass
class RuntimeConfig:
    max_global_concurrency: int = int(os.environ.get("RECON_MAX_GLOBAL_CONCURRENCY", 20))
    per_domain_rps: float = float(os.environ.get("RECON_PER_DOMAIN_RPS", 5))
    httpx_threads: int = int(os.environ.get("RECON_HTTPX_THREADS", 50))
    httpx_max_hosts: int = int(os.environ.get("RECON_HTTPX_MAX_HOSTS", 300))
    max_fuzz_hosts: int = int(os.environ.get("RECON_MAX_FUZZ_HOSTS", 5))
    ffuf_threads: int = int(os.environ.get("RECON_FFUF_THREADS", 30))
    max_screenshots: int = int(os.environ.get("RECON_MAX_SCREENSHOTS", 10))
    max_targets_per_job: int = int(os.environ.get("RECON_MAX_TARGETS_PER_JOB", 200))
    max_probe_hosts: int = int(os.environ.get("RECON_MAX_PROBE_HOSTS", 400))
    retry_count: int = int(os.environ.get("RECON_RETRY_COUNT", 1))
    retry_backoff_base: float = float(os.environ.get("RECON_RETRY_BACKOFF_BASE", 1.0))
    retry_backoff_factor: float = float(os.environ.get("RECON_RETRY_BACKOFF_FACTOR", 2.0))
    timeout_http: int = int(os.environ.get("RECON_TIMEOUT_HTTP", 10))
    max_scanner_hosts: int = int(os.environ.get("RECON_MAX_SCANNER_HOSTS", 10))
    scanner_timeout: int = int(os.environ.get("RECON_SCANNER_TIMEOUT", 300))
    secrets_max_files: int = int(os.environ.get("RECON_SECRETS_MAX_FILES", 50))
    secrets_timeout: int = int(os.environ.get("RECON_SECRETS_TIMEOUT", 10))
    runtime_crawl_max_urls: int = int(os.environ.get("RECON_RUNTIME_CRAWL_MAX_URLS", 25))
    runtime_crawl_per_host_limit: int = int(os.environ.get("RECON_RUNTIME_CRAWL_PER_HOST", 3))
    runtime_crawl_timeout: int = int(os.environ.get("RECON_RUNTIME_CRAWL_TIMEOUT", 15))
    runtime_crawl_concurrency: int = int(os.environ.get("RECON_RUNTIME_CRAWL_CONCURRENCY", 2))
    enable_fuzz: bool = os.environ.get("RECON_ENABLE_FUZZ", "0") not in {"0", "false", "False"}
    enable_runtime_crawl: bool = os.environ.get("RECON_ENABLE_RUNTIME_CRAWL", "0") not in {"0", "false", "False"}
    enable_secrets: bool = os.environ.get("RECON_ENABLE_SECRETS", "1") not in {"0", "false", "False"}
    enable_screenshots: bool = os.environ.get("RECON_ENABLE_SCREENSHOTS", "0") not in {"0", "false", "False"}
    verify_tls: bool = os.environ.get("RECON_VERIFY_TLS", "1") not in {"0", "false", "False"}
    url_path_allow_regex: Optional[str] = os.environ.get("RECON_URL_PATH_ALLOW_REGEX")
    trim_url_max_per_host: int = int(os.environ.get("RECON_TRIM_URL_MAX_PER_HOST", 200))
    trim_finding_max_per_host: int = int(os.environ.get("RECON_TRIM_FINDING_MAX_PER_HOST", 100))
    trim_finding_min_score: int = int(os.environ.get("RECON_TRIM_FINDING_MIN_SCORE", 20))
    trim_tag_per_host_limit: int = int(os.environ.get("RECON_TRIM_TAG_PER_HOST", 50))
    idor_token_a: Optional[str] = os.environ.get("RECON_IDOR_TOKEN_A")
    idor_token_b: Optional[str] = os.environ.get("RECON_IDOR_TOKEN_B")
    idor_other_identifier: Optional[str] = os.environ.get("RECON_IDOR_OTHER_ID")
    idor_timeout: int = int(os.environ.get("RECON_IDOR_TIMEOUT", 10))
    telegram_token: Optional[str] = os.environ.get("RECON_TELEGRAM_TOKEN")
    telegram_chat_id: Optional[str] = os.environ.get("RECON_TELEGRAM_CHAT_ID")
    telegram_timeout: int = int(os.environ.get("RECON_TELEGRAM_TIMEOUT", 5))
    seclists_root: Path = DEFAULT_SECLISTS_ROOT
    fallback_dns_limit: int = int(os.environ.get("RECON_FALLBACK_DNS_LIMIT", 200))
    correlation_max_records: int = int(os.environ.get("RECON_CORRELATION_MAX_RECORDS", 10000))
    correlation_svg_node_limit: int = int(os.environ.get("RECON_CORRELATION_SVG_NODE_LIMIT", 2500))
    resolvers_file: Optional[Path] = field(default_factory=lambda: DEFAULT_RESOLVERS if DEFAULT_RESOLVERS.exists() else None)
    tool_timeout: int = int(os.environ.get("RECON_TOOL_TIMEOUT", 120))

    def clone(self, **overrides: Any) -> "RuntimeConfig":
        valid_overrides = {key: value for key, value in overrides.items() if hasattr(self, key)}
        return replace(self, **valid_overrides)


RUNTIME_CONFIG = RuntimeConfig()
