from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def _default_home() -> Path:
    env = os.environ.get("RECON_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return Path.cwd()


LOG_LEVEL_NAME = os.environ.get("RECON_LOG_LEVEL", "INFO").upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL_NAME, logging.INFO)
LOG_FORMAT = os.environ.get("RECON_LOG_FORMAT", "text").lower()

RECON_HOME: Path = _default_home()
CONFIG_DIR: Path = RECON_HOME / "config"
JOBS_ROOT: Path = RECON_HOME / "jobs"
QUEUED_JOBS: Path = JOBS_ROOT / "queued"
RUNNING_JOBS: Path = JOBS_ROOT / "running"
FINISHED_JOBS: Path = JOBS_ROOT / "finished"
FAILED_JOBS: Path = JOBS_ROOT / "failed"
ARCHIVE_ROOT: Path = RECON_HOME / "archive"
GLOBAL_CACHE_DIR: Path = RECON_HOME / "cache"
DATA_DIR: Path = RECON_HOME / "data"

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
      "tool_timeout": 120,
      "scanner_timeout": 300,
      "ffuf_maxtime": 60,
      "nuclei_batch_size": 20,
      "nuclei_batch_timeout_base": 180,
      "nuclei_batch_timeout_per_target": 20,
      "nuclei_batch_timeout_max": 600,
      "nuclei_single_timeout": 300,
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
  "secure": {
    "base_profile": "passive",
    "runtime": {
      "timeout_http": 8,
      "httpx_threads": 20,
      "tool_timeout": 180,
      "scanner_timeout": 450,
      "ffuf_maxtime": 120,
      "nuclei_batch_size": 15,
      "nuclei_batch_timeout_base": 240,
      "nuclei_batch_timeout_per_target": 25,
      "nuclei_batch_timeout_max": 900,
      "nuclei_single_timeout": 600,
      "httpx_max_hosts": 150,
      "max_probe_hosts": 150,
      "max_global_concurrency": 10,
      "max_fuzz_hosts": 0,
      "enable_fuzz": false,
      "enable_runtime_crawl": false,
      "enable_screenshots": false,
      "enable_secrets": true,
      "secrets_max_files": 25,
      "retry_count": 1,
      "retry_backoff_base": 1.0,
      "retry_backoff_factor": 2.0
    }
  },
  "deep": {
    "base_profile": "full",
    "runtime": {
      "timeout_http": 20,
      "httpx_threads": 80,
      "tool_timeout": 240,
      "scanner_timeout": 600,
      "ffuf_maxtime": 180,
      "nuclei_batch_size": 12,
      "nuclei_batch_timeout_base": 300,
      "nuclei_batch_timeout_per_target": 35,
      "nuclei_batch_timeout_max": 1200,
      "nuclei_single_timeout": 900,
      "enable_auth_discovery": true,
      "auth_discovery_max_urls": 50,
      "enable_js_intel": true,
      "js_intel_max_files": 60,
      "js_intel_max_urls": 200,
      "enable_api_recon": true,
      "api_recon_max_hosts": 60,
      "enable_param_mining": true,
      "param_mining_max_urls": 200,
      "param_mining_max_params": 80,
      "enable_waf_probe": true,
      "enable_takeover": true,
      "takeover_require_cname": true,
      "waf_probe_max_urls": 20,
      "enable_dalfox": true,
      "dalfox_max_urls": 20,
      "enable_sqlmap": true,
      "sqlmap_max_urls": 10,
      "enable_nmap": true,
      "nmap_top_ports": 1000,
      "nmap_timeout": 1200,
      "nmap_batch_size": 20,
      "nmap_max_hosts": 200,
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
  "ultra-deep": {
    "base_profile": "full",
    "active_modules": ["backup", "cors", "js-secrets", "diff"],
    "runtime": {
      "timeout_http": 30,
      "httpx_threads": 150,
      "tool_timeout": 600,
      "scanner_timeout": 1800,
      "ffuf_maxtime": 600,
      "nuclei_batch_size": 10,
      "nuclei_batch_timeout_base": 600,
      "nuclei_batch_timeout_per_target": 120,
      "nuclei_batch_timeout_max": 3600,
      "nuclei_single_timeout": 2400,
      "enable_auth_discovery": true,
      "auth_discovery_max_urls": 150,
      "auth_discovery_max_forms": 300,
      "enable_js_intel": true,
      "js_intel_max_files": 200,
      "js_intel_max_urls": 1000,
      "enable_api_recon": true,
      "api_recon_max_hosts": 300,
      "enable_api_schema_probe": true,
      "api_schema_max_specs": 100,
      "api_schema_max_endpoints": 1000,
      "enable_param_mining": true,
      "param_mining_max_urls": 1000,
      "param_mining_max_params": 300,
      "param_mining_mutations_per_param": 25,
      "enable_html_form_mining": true,
      "html_form_max_urls": 500,
      "html_form_max_forms": 1000,
      "html_form_max_params": 200,
      "enable_waf_probe": true,
      "waf_probe_max_urls": 100,
      "enable_takeover": true,
      "takeover_require_cname": true,
      "enable_dalfox": true,
      "dalfox_max_urls": 100,
      "enable_sqlmap": true,
      "sqlmap_max_urls": 50,
      "sqlmap_level": 5,
      "sqlmap_risk": 3,
      "enable_nmap": true,
      "nmap_top_ports": 5000,
      "nmap_timeout": 3600,
      "nmap_batch_size": 10,
      "nmap_max_hosts": 500,
      "nmap_udp": true,
      "nmap_udp_top_ports": 1000,
      "runtime_crawl_max_urls": 500,
      "runtime_crawl_per_host_limit": 15,
      "runtime_crawl_concurrency": 10,
      "runtime_crawl_timeout": 120,
      "max_fuzz_hosts": 100,
      "enable_fuzz": true,
      "enable_runtime_crawl": true,
      "enable_screenshots": true,
      "enable_secrets": true,
      "secrets_max_files": 500,
      "max_screenshots": 500,
      "enable_extended_validation": true,
      "enable_correlation": true,
      "enable_learning": true,
      "extended_validation_max_duration": 28800,
      "extended_validation_max_probes": 5000,
      "verify_max_total": 2000,
      "exploit_max_total": 500,
      "max_global_concurrency": 50,
      "retry_count": 5
    }
  },
  "api-only": {
    "base_profile": "full",
    "runtime": {
      "enable_fuzz": true,
      "enable_runtime_crawl": true,
      "enable_screenshots": false,
      "enable_secrets": true,
      "tool_timeout": 240,
      "scanner_timeout": 600,
      "ffuf_maxtime": 180,
      "nuclei_batch_size": 12,
      "nuclei_batch_timeout_base": 300,
      "nuclei_batch_timeout_per_target": 35,
      "nuclei_batch_timeout_max": 1200,
      "nuclei_single_timeout": 900,
      "url_path_allow_regex": "(/api|/graphql)",
      "enable_auth_discovery": true,
      "auth_discovery_max_urls": 40,
      "enable_js_intel": true,
      "js_intel_max_files": 40,
      "js_intel_max_urls": 150,
      "enable_api_recon": true,
      "api_recon_max_hosts": 60,
      "enable_param_mining": true,
      "param_mining_max_urls": 150,
      "param_mining_max_params": 60,
      "enable_waf_probe": true,
      "waf_probe_max_urls": 15,
      "enable_dalfox": true,
      "dalfox_max_urls": 15,
      "enable_sqlmap": true,
      "sqlmap_max_urls": 8,
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


def _detect_seclists_root() -> Path:
    env_value = os.environ.get("SECLISTS_ROOT")
    if env_value:
        return Path(env_value).expanduser()
    candidates = [
        RECON_HOME / "seclists",
        Path("/opt/recon-tools/seclists"),
        Path("/usr/share/seclists"),
        Path("/usr/share/wordlists/seclists"),
        Path.home() / "seclists",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path("/opt/recon-tools/seclists")


DEFAULT_SECLISTS_ROOT = _detect_seclists_root()


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
    max_global_concurrency: int = int(
        os.environ.get("RECON_MAX_GLOBAL_CONCURRENCY", 20)
    )
    parallel_stages: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_PARALLEL_STAGES", "0") not in {"0", "false", "False"}
        )
    )
    max_parallel_stages: int = int(os.environ.get("RECON_MAX_PARALLEL_STAGES", 4))
    requests_per_second: float = float(os.environ.get("RECON_REQUESTS_PER_SECOND", 10))
    per_host_limit: float = float(os.environ.get("RECON_PER_HOST_LIMIT", 5))
    per_domain_rps: float = float(os.environ.get("RECON_PER_DOMAIN_RPS", 5))
    httpx_threads: int = int(os.environ.get("RECON_HTTPX_THREADS", 50))
    httpx_max_hosts: int = int(os.environ.get("RECON_HTTPX_MAX_HOSTS", 300))
    max_fuzz_hosts: int = int(os.environ.get("RECON_MAX_FUZZ_HOSTS", 5))
    ffuf_threads: int = int(os.environ.get("RECON_FFUF_THREADS", 30))
    ffuf_maxtime: int = int(os.environ.get("RECON_FFUF_MAXTIME", 180))
    ffuf_timeout_buffer: int = int(os.environ.get("RECON_FFUF_TIMEOUT_BUFFER", 30))
    ffuf_retry_on_timeout: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_FFUF_RETRY_ON_TIMEOUT", "1")
            not in {"0", "false", "False"}
        )
    )
    ffuf_retry_extra_time: int = int(os.environ.get("RECON_FFUF_RETRY_EXTRA_TIME", 120))
    fuzz_custom_max_words: int = int(
        os.environ.get("RECON_FUZZ_CUSTOM_MAX_WORDS", 1500)
    )
    fuzz_combined_max_words: int = int(
        os.environ.get("RECON_FUZZ_COMBINED_MAX_WORDS", 6000)
    )
    fuzz_param_max_words: int = int(os.environ.get("RECON_FUZZ_PARAM_MAX_WORDS", 500))
    max_screenshots: int = int(os.environ.get("RECON_MAX_SCREENSHOTS", 10))
    screenshot_ocr_max: int = int(os.environ.get("RECON_SCREENSHOT_OCR_MAX", 10))
    screenshot_ocr_lang: str = os.environ.get("RECON_SCREENSHOT_OCR_LANG", "eng")
    max_targets_per_job: int = int(os.environ.get("RECON_MAX_TARGETS_PER_JOB", 200))
    max_probe_hosts: int = int(os.environ.get("RECON_MAX_PROBE_HOSTS", 400))
    enable_nmap: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_NMAP", "0") not in {"0", "false", "False"}
        )
    )
    nmap_top_ports: int = int(os.environ.get("RECON_NMAP_TOP_PORTS", 1000))
    nmap_ports: Optional[str] = os.environ.get("RECON_NMAP_PORTS")
    nmap_args: Optional[str] = os.environ.get("RECON_NMAP_ARGS")
    nmap_timeout: int = int(os.environ.get("RECON_NMAP_TIMEOUT", 900))
    nmap_batch_size: int = int(os.environ.get("RECON_NMAP_BATCH_SIZE", 25))
    nmap_max_hosts: int = int(os.environ.get("RECON_NMAP_MAX_HOSTS", 200))
    retry_count: int = int(os.environ.get("RECON_RETRY_COUNT", 1))
    retry_backoff_base: float = float(os.environ.get("RECON_RETRY_BACKOFF_BASE", 1.0))
    retry_backoff_factor: float = float(
        os.environ.get("RECON_RETRY_BACKOFF_FACTOR", 2.0)
    )
    stage_heartbeat_seconds: int = int(
        os.environ.get("RECON_STAGE_HEARTBEAT_SECONDS", 1200)
    )
    stage_sla_seconds: int = int(os.environ.get("RECON_STAGE_SLA_SECONDS", 0))
    timeout_http: int = int(os.environ.get("RECON_TIMEOUT_HTTP", 10))
    max_scanner_hosts: int = int(os.environ.get("RECON_MAX_SCANNER_HOSTS", 10))
    scanner_timeout: int = int(os.environ.get("RECON_SCANNER_TIMEOUT", 900))
    nuclei_batch_size: int = int(os.environ.get("RECON_NUCLEI_BATCH_SIZE", 10))
    nuclei_batch_timeout_base: int = int(
        os.environ.get("RECON_NUCLEI_BATCH_TIMEOUT_BASE", 300)
    )
    nuclei_batch_timeout_per_target: int = int(
        os.environ.get("RECON_NUCLEI_BATCH_TIMEOUT_PER_TARGET", 45)
    )
    nuclei_batch_timeout_max: int = int(
        os.environ.get("RECON_NUCLEI_BATCH_TIMEOUT_MAX", 1800)
    )
    nuclei_single_timeout: int = int(
        os.environ.get("RECON_NUCLEI_SINGLE_TIMEOUT", 1200)
    )
    nuclei_timeout: int = int(os.environ.get("RECON_NUCLEI_TIMEOUT", 10))
    nuclei_retries: int = int(os.environ.get("RECON_NUCLEI_RETRIES", 1))
    secrets_max_files: int = int(os.environ.get("RECON_SECRETS_MAX_FILES", 50))
    secrets_timeout: int = int(os.environ.get("RECON_SECRETS_TIMEOUT", 10))
    runtime_crawl_max_urls: int = int(
        os.environ.get("RECON_RUNTIME_CRAWL_MAX_URLS", 25)
    )
    runtime_crawl_per_host_limit: int = int(
        os.environ.get("RECON_RUNTIME_CRAWL_PER_HOST", 3)
    )
    runtime_crawl_timeout: int = int(os.environ.get("RECON_RUNTIME_CRAWL_TIMEOUT", 15))
    runtime_crawl_concurrency: int = int(
        os.environ.get("RECON_RUNTIME_CRAWL_CONCURRENCY", 2)
    )
    auto_scanners: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_AUTO_SCANNERS", "1") not in {"0", "false", "False"}
        )
    )
    auto_active_modules: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_AUTO_ACTIVE_MODULES", "1")
            not in {"0", "false", "False"}
        )
    )
    nuclei_tags: Optional[str] = os.environ.get(
        "RECON_NUCLEI_TAGS",
        "cves,exposures,misconfiguration,default-logins,auth,xss,sqli,ssrf,lfi,rce,redirect,xxe,cmdi,csrf,deserialization",
    )
    soft_404_probe: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_SOFT_404_PROBE", "1") not in {"0", "false", "False"}
        )
    )
    soft_404_max_hosts: int = int(os.environ.get("RECON_SOFT_404_MAX_HOSTS", 25))
    soft_404_paths: int = int(os.environ.get("RECON_SOFT_404_PATHS", 1))
    soft_404_timeout: int = int(os.environ.get("RECON_SOFT_404_TIMEOUT", 6))
    enable_correlation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_CORRELATION", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_learning: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_LEARNING", "0") not in {"0", "false", "False"}
        )
    )
    enable_fuzz: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_FUZZ", "0") not in {"0", "false", "False"}
        )
    )
    enable_param_fuzz: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_PARAM_FUZZ", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_runtime_crawl: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_RUNTIME_CRAWL", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_secrets: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SECRETS", "1") not in {"0", "false", "False"}
        )
    )
    enable_screenshots: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SCREENSHOTS", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_screenshot_ocr: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SCREENSHOT_OCR", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_auth_discovery: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_AUTH_DISCOVERY", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_js_intel: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_JS_INTEL", "0") not in {"0", "false", "False"}
        )
    )
    enable_api_recon: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_API_RECON", "0") not in {"0", "false", "False"}
        )
    )
    enable_api_schema_probe: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_API_SCHEMA_PROBE", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_param_mining: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_PARAM_MINING", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_html_form_mining: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_HTML_FORM_MINING", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_graphql_recon: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_GRAPHQL_RECON", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_graphql_exploit: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_GRAPHQL_EXPLOIT", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_oauth_discovery: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_OAUTH_DISCOVERY", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_ws_grpc_discovery: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_WS_GRPC_DISCOVERY", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_upload_probe: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_UPLOAD_PROBE", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_cms_scan: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_CMS_SCAN", "0") not in {"0", "false", "False"}
        )
    )
    enable_vhost: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_VHOST", "0") not in {"0", "false", "False"}
        )
    )
    enable_subdomain_permute: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SUBDOMAIN_PERMUTE", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_cloud_discovery: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_CLOUD_DISCOVERY", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_ct_pivot: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_CT_PIVOT", "0") not in {"0", "false", "False"}
        )
    )
    enable_asn_pivot: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_ASN_PIVOT", "0") not in {"0", "false", "False"}
        )
    )
    enable_waf_probe: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_WAF_PROBE", "0") not in {"0", "false", "False"}
        )
    )
    enable_takeover: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_TAKEOVER", "0") not in {"0", "false", "False"}
        )
    )
    takeover_require_cname: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_TAKEOVER_REQUIRE_CNAME", "1")
            not in {"0", "false", "False"}
        )
    )
    enable_authenticated_scan: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_AUTH_SCAN", "0") not in {"0", "false", "False"}
        )
    )
    enable_dalfox: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_DALFOX", "0") not in {"0", "false", "False"}
        )
    )
    enable_sqlmap: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SQLMAP", "0") not in {"0", "false", "False"}
        )
    )
    enable_verification: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_VERIFICATION", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_exploit_validation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_EXPLOIT_VALIDATION", "0")
            not in {"0", "false", "False"}
        )
    )
    enable_extended_validation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_EXTENDED_VALIDATION", "0")
            not in {"0", "false", "False"}
        )
    )
    extended_validation_max_duration: int = int(
        os.environ.get("RECON_EXTENDED_VALIDATION_MAX_DURATION", 7200)
    )
    extended_validation_max_probes: int = int(
        os.environ.get("RECON_EXTENDED_VALIDATION_MAX_PROBES", 500)
    )
    enable_oast_validation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_OAST_VALIDATION", "1")
            not in {"0", "false", "False"}
        )
    )
    oast_backend: str = os.environ.get("RECON_OAST_BACKEND", "interactsh")
    oast_domain: Optional[str] = os.environ.get("RECON_OAST_DOMAIN")
    oast_wait_seconds: int = int(os.environ.get("RECON_OAST_WAIT_SECONDS", 60))
    oast_poll_interval: int = int(os.environ.get("RECON_OAST_POLL_INTERVAL", 5))
    oast_max_targets: int = int(os.environ.get("RECON_OAST_MAX_TARGETS", 40))
    oast_max_per_host: int = int(os.environ.get("RECON_OAST_MAX_PER_HOST", 8))
    oast_timeout: int = int(os.environ.get("RECON_OAST_TIMEOUT", 10))
    oast_rps: float = float(os.environ.get("RECON_OAST_RPS", 0))
    oast_per_host_rps: float = float(os.environ.get("RECON_OAST_PER_HOST_RPS", 0))
    enable_redirect_validation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_REDIRECT_VALIDATION", "1")
            not in {"0", "false", "False"}
        )
    )
    redirect_max_urls: int = int(os.environ.get("RECON_REDIRECT_MAX_URLS", 40))
    enable_idor_validator: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_IDOR_VALIDATOR", "1")
            not in {"0", "false", "False"}
        )
    )
    idor_validator_max_candidates: int = int(
        os.environ.get("RECON_IDOR_VALIDATOR_MAX_CANDIDATES", 40)
    )
    idor_validator_max_per_host: int = int(
        os.environ.get("RECON_IDOR_VALIDATOR_MAX_PER_HOST", 8)
    )
    idor_validator_min_score: int = int(
        os.environ.get("RECON_IDOR_VALIDATOR_MIN_SCORE", 60)
    )
    idor_validator_timeout: int = int(
        os.environ.get("RECON_IDOR_VALIDATOR_TIMEOUT", 10)
    )
    idor_validator_rps: float = float(os.environ.get("RECON_IDOR_VALIDATOR_RPS", 0))
    idor_validator_per_host_rps: float = float(
        os.environ.get("RECON_IDOR_VALIDATOR_PER_HOST_RPS", 0)
    )
    enable_ssrf_validator: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SSRF_VALIDATOR", "1")
            not in {"0", "false", "False"}
        )
    )
    ssrf_validator_max_urls: int = int(
        os.environ.get("RECON_SSRF_VALIDATOR_MAX_URLS", 25)
    )
    ssrf_validator_max_per_host: int = int(
        os.environ.get("RECON_SSRF_VALIDATOR_MAX_PER_HOST", 6)
    )
    ssrf_validator_min_score: int = int(
        os.environ.get("RECON_SSRF_VALIDATOR_MIN_SCORE", 40)
    )
    ssrf_validator_timeout: int = int(
        os.environ.get("RECON_SSRF_VALIDATOR_TIMEOUT", 10)
    )
    ssrf_validator_rps: float = float(os.environ.get("RECON_SSRF_VALIDATOR_RPS", 0))
    ssrf_validator_per_host_rps: float = float(
        os.environ.get("RECON_SSRF_VALIDATOR_PER_HOST_RPS", 0)
    )
    ssrf_validator_enable_oast: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_SSRF_VALIDATOR_ENABLE_OAST", "1")
            not in {"0", "false", "False"}
        )
    )
    ssrf_validator_oast_wait_seconds: int = int(
        os.environ.get("RECON_SSRF_VALIDATOR_OAST_WAIT_SECONDS", 45)
    )
    ssrf_validator_oast_poll_interval: int = int(
        os.environ.get("RECON_SSRF_VALIDATOR_OAST_POLL_INTERVAL", 5)
    )
    ssrf_validator_enable_internal: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_SSRF_VALIDATOR_ENABLE_INTERNAL", "1")
            not in {"0", "false", "False"}
        )
    )
    enable_open_redirect_validator: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_OPEN_REDIRECT_VALIDATOR", "1")
            not in {"0", "false", "False"}
        )
    )
    open_redirect_validator_max_urls: int = int(
        os.environ.get("RECON_OPEN_REDIRECT_VALIDATOR_MAX_URLS", 30)
    )
    open_redirect_validator_max_per_host: int = int(
        os.environ.get("RECON_OPEN_REDIRECT_VALIDATOR_MAX_PER_HOST", 6)
    )
    open_redirect_validator_min_score: int = int(
        os.environ.get("RECON_OPEN_REDIRECT_VALIDATOR_MIN_SCORE", 40)
    )
    open_redirect_validator_timeout: int = int(
        os.environ.get("RECON_OPEN_REDIRECT_VALIDATOR_TIMEOUT", 10)
    )
    open_redirect_validator_rps: float = float(
        os.environ.get("RECON_OPEN_REDIRECT_VALIDATOR_RPS", 0)
    )
    open_redirect_validator_per_host_rps: float = float(
        os.environ.get("RECON_OPEN_REDIRECT_VALIDATOR_PER_HOST_RPS", 0)
    )
    enable_auth_bypass_validator: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_AUTH_BYPASS_VALIDATOR", "1")
            not in {"0", "false", "False"}
        )
    )
    auth_bypass_validator_max_urls: int = int(
        os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_MAX_URLS", 25)
    )
    auth_bypass_validator_max_per_host: int = int(
        os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_MAX_PER_HOST", 6)
    )
    auth_bypass_validator_min_score: int = int(
        os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_MIN_SCORE", 35)
    )
    auth_bypass_validator_timeout: int = int(
        os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_TIMEOUT", 10)
    )
    auth_bypass_validator_rps: float = float(
        os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_RPS", 0)
    )
    auth_bypass_validator_per_host_rps: float = float(
        os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_PER_HOST_RPS", 0)
    )
    auth_bypass_validator_enable_forced_browse: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_ENABLE_FORCED_BROWSE", "1")
            not in {"0", "false", "False"}
        )
    )
    auth_bypass_validator_enable_privilege_boundary: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_AUTH_BYPASS_VALIDATOR_ENABLE_PRIVILEGE_BOUNDARY", "1")
            not in {"0", "false", "False"}
        )
    )
    enable_secret_exposure_validator: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SECRET_EXPOSURE_VALIDATOR", "1")
            not in {"0", "false", "False"}
        )
    )
    secret_exposure_validator_max_findings: int = int(
        os.environ.get("RECON_SECRET_EXPOSURE_VALIDATOR_MAX_FINDINGS", 40)
    )
    secret_exposure_validator_min_score: int = int(
        os.environ.get("RECON_SECRET_EXPOSURE_VALIDATOR_MIN_SCORE", 40)
    )
    secret_exposure_validator_timeout: int = int(
        os.environ.get("RECON_SECRET_EXPOSURE_VALIDATOR_TIMEOUT", 10)
    )
    secret_exposure_validator_rps: float = float(
        os.environ.get("RECON_SECRET_EXPOSURE_VALIDATOR_RPS", 0)
    )
    secret_exposure_validator_per_host_rps: float = float(
        os.environ.get("RECON_SECRET_EXPOSURE_VALIDATOR_PER_HOST_RPS", 0)
    )
    enable_lfi_validation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_LFI_VALIDATION", "1")
            not in {"0", "false", "False"}
        )
    )
    lfi_max_urls: int = int(os.environ.get("RECON_LFI_MAX_URLS", 40))
    enable_header_validation: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_HEADER_VALIDATION", "1")
            not in {"0", "false", "False"}
        )
    )
    header_validation_max_urls: int = int(
        os.environ.get("RECON_HEADER_VALIDATION_MAX_URLS", 30)
    )
    verify_min_score: int = int(os.environ.get("RECON_VERIFY_MIN_SCORE", 80))
    verify_top_per_host: int = int(os.environ.get("RECON_VERIFY_TOP_PER_HOST", 10))
    verify_max_total: int = int(os.environ.get("RECON_VERIFY_MAX_TOTAL", 200))
    verify_timeout: int = int(os.environ.get("RECON_VERIFY_TIMEOUT", 12))
    verify_rps: float = float(os.environ.get("RECON_VERIFY_RPS", 0))
    verify_per_host_rps: float = float(os.environ.get("RECON_VERIFY_PER_HOST_RPS", 0))
    verify_tls: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_VERIFY_TLS", "1") not in {"0", "false", "False"}
        )
    )
    exploit_min_score: int = int(os.environ.get("RECON_EXPLOIT_MIN_SCORE", 85))
    exploit_top_per_host: int = int(os.environ.get("RECON_EXPLOIT_TOP_PER_HOST", 3))
    exploit_max_total: int = int(os.environ.get("RECON_EXPLOIT_MAX_TOTAL", 30))
    exploit_timeout: int = int(os.environ.get("RECON_EXPLOIT_TIMEOUT", 900))
    url_path_allow_regex: Optional[str] = os.environ.get("RECON_URL_PATH_ALLOW_REGEX")
    trim_url_max_per_host: int = int(os.environ.get("RECON_TRIM_URL_MAX_PER_HOST", 200))
    trim_finding_max_per_host: int = int(
        os.environ.get("RECON_TRIM_FINDING_MAX_PER_HOST", 100)
    )
    trim_finding_min_score: int = int(
        os.environ.get("RECON_TRIM_FINDING_MIN_SCORE", 20)
    )
    trim_tag_per_host_limit: int = int(os.environ.get("RECON_TRIM_TAG_PER_HOST", 50))
    wayback_max_urls: int = int(os.environ.get("RECON_WAYBACK_MAX_URLS", 10000))
    wayback_max_per_target: int = int(
        os.environ.get("RECON_WAYBACK_MAX_PER_TARGET", 2000)
    )
    wayback_fair_share: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_WAYBACK_FAIR_SHARE", "1")
            not in {"0", "false", "False"}
        )
    )
    idor_token_a: Optional[str] = os.environ.get("RECON_IDOR_TOKEN_A")
    idor_token_b: Optional[str] = os.environ.get("RECON_IDOR_TOKEN_B")
    idor_other_identifier: Optional[str] = os.environ.get("RECON_IDOR_OTHER_ID")
    idor_timeout: int = int(os.environ.get("RECON_IDOR_TIMEOUT", 10))
    telegram_token: Optional[str] = os.environ.get("RECON_TELEGRAM_TOKEN")
    telegram_chat_id: Optional[str] = os.environ.get("RECON_TELEGRAM_CHAT_ID")
    telegram_timeout: int = int(os.environ.get("RECON_TELEGRAM_TIMEOUT", 5))
    securitytrails_api_key: Optional[str] = os.environ.get(
        "RECON_SECURITYTRAILS_API_KEY"
    )
    github_token: Optional[str] = os.environ.get("RECON_GITHUB_TOKEN")
    viewdns_api_key: Optional[str] = os.environ.get("RECON_VIEWDNS_API_KEY")
    whoisfreaks_api_key: Optional[str] = os.environ.get("RECON_WHOISFREAKS_API_KEY")
    seclists_root: Path = DEFAULT_SECLISTS_ROOT
    fallback_dns_limit: int = int(os.environ.get("RECON_FALLBACK_DNS_LIMIT", 200))
    correlation_max_records: int = int(
        os.environ.get("RECON_CORRELATION_MAX_RECORDS", 10000)
    )
    correlation_svg_node_limit: int = int(
        os.environ.get("RECON_CORRELATION_SVG_NODE_LIMIT", 2500)
    )
    correlation_attack_path_limit: int = int(
        os.environ.get("RECON_CORRELATION_ATTACK_PATH_LIMIT", 30)
    )
    resolvers_file: Optional[Path] = field(
        default_factory=lambda: (
            DEFAULT_RESOLVERS if DEFAULT_RESOLVERS.exists() else None
        )
    )
    tool_timeout: int = int(os.environ.get("RECON_TOOL_TIMEOUT", 300))
    auth_discovery_max_urls: int = int(
        os.environ.get("RECON_AUTH_DISCOVERY_MAX_URLS", 40)
    )
    auth_discovery_timeout: int = int(
        os.environ.get("RECON_AUTH_DISCOVERY_TIMEOUT", 10)
    )
    auth_discovery_max_forms: int = int(
        os.environ.get("RECON_AUTH_DISCOVERY_MAX_FORMS", 80)
    )
    auth_discovery_rps: float = float(os.environ.get("RECON_AUTH_DISCOVERY_RPS", 0))
    auth_discovery_per_host_rps: float = float(
        os.environ.get("RECON_AUTH_DISCOVERY_PER_HOST_RPS", 0)
    )
    js_intel_max_files: int = int(os.environ.get("RECON_JS_INTEL_MAX_FILES", 40))
    js_intel_timeout: int = int(os.environ.get("RECON_JS_INTEL_TIMEOUT", 12))
    js_intel_max_urls: int = int(os.environ.get("RECON_JS_INTEL_MAX_URLS", 120))
    js_intel_rps: float = float(os.environ.get("RECON_JS_INTEL_RPS", 0))
    js_intel_per_host_rps: float = float(
        os.environ.get("RECON_JS_INTEL_PER_HOST_RPS", 0)
    )
    js_intel_extract_dynamic_routes: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_JS_INTEL_DYNAMIC_ROUTES", "1")
            not in {"0", "false", "False"}
        )
    )
    js_intel_extract_hidden_params: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_JS_INTEL_HIDDEN_PARAMS", "1")
            not in {"0", "false", "False"}
        )
    )
    api_recon_max_hosts: int = int(os.environ.get("RECON_API_RECON_MAX_HOSTS", 50))
    api_recon_timeout: int = int(os.environ.get("RECON_API_RECON_TIMEOUT", 8))
    api_recon_rps: float = float(os.environ.get("RECON_API_RECON_RPS", 0))
    api_recon_per_host_rps: float = float(
        os.environ.get("RECON_API_RECON_PER_HOST_RPS", 0)
    )
    api_recon_enrich_from_js: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_API_RECON_ENRICH_FROM_JS", "1")
            not in {"0", "false", "False"}
        )
    )
    api_recon_max_enriched_paths: int = int(
        os.environ.get("RECON_API_RECON_MAX_ENRICHED_PATHS", 40)
    )
    api_schema_max_specs: int = int(os.environ.get("RECON_API_SCHEMA_MAX_SPECS", 25))
    api_schema_max_endpoints: int = int(
        os.environ.get("RECON_API_SCHEMA_MAX_ENDPOINTS", 200)
    )
    api_schema_max_per_host: int = int(
        os.environ.get("RECON_API_SCHEMA_MAX_PER_HOST", 0)
    )
    api_schema_param_max: int = int(os.environ.get("RECON_API_SCHEMA_PARAM_MAX", 120))
    api_schema_timeout: int = int(os.environ.get("RECON_API_SCHEMA_TIMEOUT", 10))
    api_schema_probe_safe_writes: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_API_SCHEMA_SAFE_WRITES", "1")
            not in {"0", "false", "False"}
        )
    )
    api_schema_rps: float = float(os.environ.get("RECON_API_SCHEMA_RPS", 0))
    api_schema_per_host_rps: float = float(
        os.environ.get("RECON_API_SCHEMA_PER_HOST_RPS", 0)
    )
    graphql_max_urls: int = int(os.environ.get("RECON_GRAPHQL_MAX_URLS", 40))
    graphql_timeout: int = int(os.environ.get("RECON_GRAPHQL_TIMEOUT", 10))
    graphql_rps: float = float(os.environ.get("RECON_GRAPHQL_RPS", 0))
    graphql_per_host_rps: float = float(os.environ.get("RECON_GRAPHQL_PER_HOST_RPS", 0))
    graphql_exploit_max_urls: int = int(
        os.environ.get("RECON_GRAPHQL_EXPLOIT_MAX_URLS", 30)
    )
    graphql_exploit_max_per_host: int = int(
        os.environ.get("RECON_GRAPHQL_EXPLOIT_MAX_PER_HOST", 0)
    )
    graphql_exploit_max_queries: int = int(
        os.environ.get("RECON_GRAPHQL_EXPLOIT_MAX_QUERIES", 6)
    )
    graphql_exploit_timeout: int = int(
        os.environ.get("RECON_GRAPHQL_EXPLOIT_TIMEOUT", 10)
    )
    graphql_exploit_rps: float = float(os.environ.get("RECON_GRAPHQL_EXPLOIT_RPS", 0))
    graphql_exploit_per_host_rps: float = float(
        os.environ.get("RECON_GRAPHQL_EXPLOIT_PER_HOST_RPS", 0)
    )
    oauth_max_hosts: int = int(os.environ.get("RECON_OAUTH_MAX_HOSTS", 50))
    oauth_timeout: int = int(os.environ.get("RECON_OAUTH_TIMEOUT", 8))
    oauth_rps: float = float(os.environ.get("RECON_OAUTH_RPS", 0))
    oauth_per_host_rps: float = float(os.environ.get("RECON_OAUTH_PER_HOST_RPS", 0))
    ws_grpc_max_urls: int = int(os.environ.get("RECON_WS_GRPC_MAX_URLS", 80))
    ws_grpc_timeout: int = int(os.environ.get("RECON_WS_GRPC_TIMEOUT", 8))
    ws_grpc_rps: float = float(os.environ.get("RECON_WS_GRPC_RPS", 0))
    ws_grpc_per_host_rps: float = float(os.environ.get("RECON_WS_GRPC_PER_HOST_RPS", 0))
    upload_max_hosts: int = int(os.environ.get("RECON_UPLOAD_MAX_HOSTS", 60))
    upload_max_urls: int = int(os.environ.get("RECON_UPLOAD_MAX_URLS", 120))
    upload_timeout: int = int(os.environ.get("RECON_UPLOAD_TIMEOUT", 8))
    upload_rps: float = float(os.environ.get("RECON_UPLOAD_RPS", 0))
    upload_per_host_rps: float = float(os.environ.get("RECON_UPLOAD_PER_HOST_RPS", 0))
    cms_max_hosts: int = int(os.environ.get("RECON_CMS_MAX_HOSTS", 50))
    cms_timeout: int = int(os.environ.get("RECON_CMS_TIMEOUT", 600))
    cms_rps: float = float(os.environ.get("RECON_CMS_RPS", 0))
    cms_per_host_rps: float = float(os.environ.get("RECON_CMS_PER_HOST_RPS", 0))
    cms_module_max: int = int(os.environ.get("RECON_CMS_MODULE_MAX", 60))
    vhost_wordlist: Optional[str] = os.environ.get("RECON_VHOST_WORDLIST")
    vhost_max_hosts: int = int(os.environ.get("RECON_VHOST_MAX_HOSTS", 30))
    vhost_max_candidates: int = int(os.environ.get("RECON_VHOST_MAX_CANDIDATES", 1500))
    vhost_max_probes: int = int(os.environ.get("RECON_VHOST_MAX_PROBES", 1000))
    vhost_max_duration: int = int(os.environ.get("RECON_VHOST_MAX_DURATION", 1800))
    vhost_timeout: int = int(os.environ.get("RECON_VHOST_TIMEOUT", 8))
    vhost_progress_every: int = int(os.environ.get("RECON_VHOST_PROGRESS_EVERY", 100))
    vhost_max_response_bytes: int = int(
        os.environ.get("RECON_VHOST_MAX_RESPONSE_BYTES", 65536)
    )
    vhost_rps: float = float(os.environ.get("RECON_VHOST_RPS", 0))
    vhost_per_host_rps: float = float(os.environ.get("RECON_VHOST_PER_HOST_RPS", 0))
    permute_max: int = int(os.environ.get("RECON_PERMUTE_MAX", 500))
    permute_prefixes: int = int(os.environ.get("RECON_PERMUTE_PREFIXES", 8))
    permute_suffixes: int = int(os.environ.get("RECON_PERMUTE_SUFFIXES", 8))
    cloud_max_checks: int = int(os.environ.get("RECON_CLOUD_MAX_CHECKS", 400))
    cloud_timeout: int = int(os.environ.get("RECON_CLOUD_TIMEOUT", 8))
    cloud_max_duration: int = int(os.environ.get("RECON_CLOUD_MAX_DURATION", 1200))
    cloud_progress_every: int = int(os.environ.get("RECON_CLOUD_PROGRESS_EVERY", 50))
    cloud_rps: float = float(os.environ.get("RECON_CLOUD_RPS", 0))
    cloud_per_host_rps: float = float(os.environ.get("RECON_CLOUD_PER_HOST_RPS", 0))
    ct_max_domains: int = int(os.environ.get("RECON_CT_MAX_DOMAINS", 15))
    ct_max_names: int = int(os.environ.get("RECON_CT_MAX_NAMES", 200))
    ct_timeout: int = int(os.environ.get("RECON_CT_TIMEOUT", 10))
    ct_rps: float = float(os.environ.get("RECON_CT_RPS", 0))
    ct_per_host_rps: float = float(os.environ.get("RECON_CT_PER_HOST_RPS", 0))
    asn_max: int = int(os.environ.get("RECON_ASN_MAX", 10))
    asn_prefix_max: int = int(os.environ.get("RECON_ASN_PREFIX_MAX", 120))
    asn_timeout: int = int(os.environ.get("RECON_ASN_TIMEOUT", 10))
    asn_rps: float = float(os.environ.get("RECON_ASN_RPS", 0))
    asn_per_host_rps: float = float(os.environ.get("RECON_ASN_PER_HOST_RPS", 0))
    param_mining_max_urls: int = int(os.environ.get("RECON_PARAM_MINING_MAX_URLS", 150))
    param_mining_max_params: int = int(
        os.environ.get("RECON_PARAM_MINING_MAX_PARAMS", 60)
    )
    param_mining_generate_mutations: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_PARAM_MINING_MUTATIONS", "1")
            not in {"0", "false", "False"}
        )
    )
    param_mining_mutations_per_param: int = int(
        os.environ.get("RECON_PARAM_MINING_MUTATIONS_PER_PARAM", 8)
    )
    html_form_max_urls: int = int(os.environ.get("RECON_HTML_FORM_MAX_URLS", 80))
    html_form_timeout: int = int(os.environ.get("RECON_HTML_FORM_TIMEOUT", 10))
    html_form_max_forms: int = int(os.environ.get("RECON_HTML_FORM_MAX_FORMS", 200))
    html_form_max_params: int = int(os.environ.get("RECON_HTML_FORM_MAX_PARAMS", 80))
    html_form_rps: float = float(os.environ.get("RECON_HTML_FORM_RPS", 0))
    html_form_per_host_rps: float = float(
        os.environ.get("RECON_HTML_FORM_PER_HOST_RPS", 0)
    )
    waf_probe_max_urls: int = int(os.environ.get("RECON_WAF_PROBE_MAX_URLS", 25))
    waf_probe_timeout: int = int(os.environ.get("RECON_WAF_PROBE_TIMEOUT", 8))
    waf_probe_rps: float = float(os.environ.get("RECON_WAF_PROBE_RPS", 0))
    waf_probe_per_host_rps: float = float(
        os.environ.get("RECON_WAF_PROBE_PER_HOST_RPS", 0)
    )
    enable_security_headers: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_SECURITY_HEADERS", "0")
            not in {"0", "false", "False"}
        )
    )
    security_headers_max_urls: int = int(
        os.environ.get("RECON_SECURITY_HEADERS_MAX_URLS", 40)
    )
    security_headers_timeout: int = int(
        os.environ.get("RECON_SECURITY_HEADERS_TIMEOUT", 8)
    )
    security_headers_rps: float = float(os.environ.get("RECON_SECURITY_HEADERS_RPS", 0))
    security_headers_per_host_rps: float = float(
        os.environ.get("RECON_SECURITY_HEADERS_PER_HOST_RPS", 0)
    )
    enable_tls_hygiene: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_ENABLE_TLS_HYGIENE", "0")
            not in {"0", "false", "False"}
        )
    )
    tls_hygiene_max_hosts: int = int(os.environ.get("RECON_TLS_HYGIENE_MAX_HOSTS", 40))
    tls_hygiene_timeout: int = int(os.environ.get("RECON_TLS_HYGIENE_TIMEOUT", 6))
    tls_hygiene_rps: float = float(os.environ.get("RECON_TLS_HYGIENE_RPS", 0))
    tls_hygiene_per_host_rps: float = float(
        os.environ.get("RECON_TLS_HYGIENE_PER_HOST_RPS", 0)
    )
    takeover_max_hosts: int = int(os.environ.get("RECON_TAKEOVER_MAX_HOSTS", 50))
    takeover_timeout: int = int(os.environ.get("RECON_TAKEOVER_TIMEOUT", 6))
    takeover_dns_timeout: int = int(os.environ.get("RECON_TAKEOVER_DNS_TIMEOUT", 6))
    idor_rps: float = float(os.environ.get("RECON_IDOR_RPS", 0))
    idor_per_host_rps: float = float(os.environ.get("RECON_IDOR_PER_HOST_RPS", 0))
    idor_max_targets: int = int(os.environ.get("RECON_IDOR_MAX_TARGETS", 60))
    idor_max_per_host: int = int(os.environ.get("RECON_IDOR_MAX_PER_HOST", 8))
    auth_profile_name: Optional[str] = os.environ.get("RECON_AUTH_PROFILE")
    auth_profiles: list = field(default_factory=list)
    auth_headers: Optional[str] = os.environ.get("RECON_AUTH_HEADERS")
    auth_cookies: Optional[str] = os.environ.get("RECON_AUTH_COOKIES")
    auth_bearer_token: Optional[str] = os.environ.get("RECON_AUTH_BEARER")
    auth_basic_user: Optional[str] = os.environ.get("RECON_AUTH_BASIC_USER")
    auth_basic_pass: Optional[str] = os.environ.get("RECON_AUTH_BASIC_PASS")
    auth_login_url: Optional[str] = os.environ.get("RECON_AUTH_LOGIN_URL")
    auth_login_method: str = os.environ.get("RECON_AUTH_LOGIN_METHOD", "POST")
    auth_login_payload: Optional[str] = os.environ.get("RECON_AUTH_LOGIN_PAYLOAD")
    auth_login_headers: Optional[str] = os.environ.get("RECON_AUTH_LOGIN_HEADERS")
    auth_login_content_type: Optional[str] = os.environ.get(
        "RECON_AUTH_LOGIN_CONTENT_TYPE"
    )
    auth_login_success_regex: Optional[str] = os.environ.get(
        "RECON_AUTH_LOGIN_SUCCESS_REGEX"
    )
    auth_login_fail_regex: Optional[str] = os.environ.get("RECON_AUTH_LOGIN_FAIL_REGEX")
    auth_login_cookie_names: Optional[str] = os.environ.get(
        "RECON_AUTH_LOGIN_COOKIE_NAMES"
    )
    auth_login_timeout: int = int(os.environ.get("RECON_AUTH_LOGIN_TIMEOUT", 15))
    runtime_crawl_role_aware: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_RUNTIME_CRAWL_ROLE_AWARE", "1")
            not in {"0", "false", "False"}
        )
    )
    runtime_crawl_max_auth_profiles: int = int(
        os.environ.get("RECON_RUNTIME_CRAWL_MAX_AUTH_PROFILES", 3)
    )
    auth_apply_active_modules: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_AUTH_APPLY_ACTIVE", "0")
            not in {"0", "false", "False"}
        )
    )
    auth_matrix_rps: float = float(os.environ.get("RECON_AUTH_MATRIX_RPS", 0))
    auth_matrix_per_host_rps: float = float(
        os.environ.get("RECON_AUTH_MATRIX_PER_HOST_RPS", 0)
    )
    auth_matrix_max_targets: int = int(
        os.environ.get("RECON_AUTH_MATRIX_MAX_TARGETS", 120)
    )
    auth_matrix_max_per_host: int = int(
        os.environ.get("RECON_AUTH_MATRIX_MAX_PER_HOST", 12)
    )
    dalfox_max_urls: int = int(os.environ.get("RECON_DALFOX_MAX_URLS", 20))
    dalfox_timeout: int = int(os.environ.get("RECON_DALFOX_TIMEOUT", 600))
    sqlmap_max_urls: int = int(os.environ.get("RECON_SQLMAP_MAX_URLS", 10))
    sqlmap_timeout: int = int(os.environ.get("RECON_SQLMAP_TIMEOUT", 900))
    sqlmap_level: int = int(os.environ.get("RECON_SQLMAP_LEVEL", 1))
    sqlmap_risk: int = int(os.environ.get("RECON_SQLMAP_RISK", 1))
    wpscan_enumerate: Optional[str] = os.environ.get("RECON_WPSCAN_ENUMERATE")
    wpscan_plugins_detection: Optional[str] = os.environ.get(
        "RECON_WPSCAN_PLUGINS_DETECTION"
    )
    wpscan_random_user_agent: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_WPSCAN_RANDOM_UA", "1") not in {"0", "false", "False"}
        )
    )
    wpscan_max_threads: int = int(os.environ.get("RECON_WPSCAN_MAX_THREADS", 20))
    wpscan_api_token: Optional[str] = os.environ.get("RECON_WPSCAN_API_TOKEN")
    nmap_udp: bool = field(
        default_factory=lambda: (
            os.environ.get("RECON_NMAP_UDP", "0") not in {"0", "false", "False"}
        )
    )
    nmap_udp_top_ports: int = int(os.environ.get("RECON_NMAP_UDP_TOP_PORTS", 200))
    nmap_scripts: Optional[str] = os.environ.get("RECON_NMAP_SCRIPTS")

    def clone(self, **overrides: Any) -> "RuntimeConfig":
        valid_overrides = {
            key: value for key, value in overrides.items() if hasattr(self, key)
        }
        return replace(self, **valid_overrides)


RUNTIME_CONFIG = RuntimeConfig()
