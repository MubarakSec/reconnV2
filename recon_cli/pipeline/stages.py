
import json
import hashlib
import heapq
import math
import re
import shlex
import socket
import time
from abc import ABC
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urljoin

from recon_cli.crawl.runtime import (
    PLAYWRIGHT_AVAILABLE,
    crawl_urls,
    dom_artifact_name,
    save_results as save_crawl_results,
)

# Import rate limiter and cache utilities
try:
    from recon_cli.utils.rate_limiter import RateLimiter, RateLimitConfig
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False
    RateLimiter = None
    RateLimitConfig = None

try:
    from recon_cli.utils.cache import HybridCache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    HybridCache = None

FEATURE_KEYS = ["has_api", "has_login", "js_secrets_count", "url_count", "finding_count", "asn_score", "tag_entropy"]

HIGH_RISK_ASNS = {"AS46606", "AS16276", "AS45102", "AS36351", "AS137409", "AS20473", "AS13414"}


def compute_asn_score(asn: str | None) -> float:
    if not asn:
        return 0.0
    asn_upper = asn.upper()
    if asn_upper in HIGH_RISK_ASNS:
        return 0.9
    if asn_upper.startswith("AS1") or asn_upper.startswith("AS3"):
        return 0.6
    return 0.2


def root_domain(host: str) -> str:
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


FEATURE_KEYS = ["has_api", "has_login", "js_secrets_count", "url_count", "finding_count", "asn_score", "tag_entropy"]


from recon_cli import config
from recon_cli.correlation.graph import Graph
from recon_cli.jobs.results import ResultsTracker
from recon_cli.pipeline.context import PipelineContext
from recon_cli.secrets.detector import SecretsDetector
from recon_cli.tools.executor import CommandExecutor, CommandError
from recon_cli.utils import fs
from recon_cli.utils import enrich as enrich_utils
from recon_cli.active import modules as active_modules
from recon_cli.utils import time as time_utils
from recon_cli.utils import validation
from recon_cli.utils.jsonl import iter_jsonl, read_jsonl
from recon_cli.pipeline.progress import ProgressLogger
from recon_cli import rules as rules_engine
try:
    from recon_cli.learning.collector import DatasetStore, HostFeatures
    from recon_cli.learning.model import LearningModel
    from recon_cli.scanners import integrations as scanner_integrations
except ImportError:
    DatasetStore = None  # type: ignore
    HostFeatures = None  # type: ignore
    LearningModel = None  # type: ignore
    scanner_integrations = None  # type: ignore


class StageError(RuntimeError):
    pass


@dataclass
class StageResult:
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


try:  # pragma: no cover - test helper
    import builtins
    builtins.StageResult = StageResult
except Exception:
    pass


def _note_missing_tool(context: "PipelineContext", tool: str) -> None:
    missing = context.record.metadata.stats.setdefault("missing_tools", [])
    if tool not in missing:
        missing.append(tool)
        context.manager.update_metadata(context.record)


class Stage(ABC):
    name: str = "stage"
    optional: bool = False

    def is_enabled(self, context: PipelineContext) -> bool:
        return True

    def should_run(self, context: PipelineContext) -> bool:
        if context.force:
            return True
        return self.name not in context.record.metadata.checkpoints

    def before(self, context: PipelineContext) -> None:  # pragma: no cover - hook
        pass

    def execute(self, context: PipelineContext) -> None:
        raise NotImplementedError('Stage subclasses must implement execute()')

    def after(self, context: PipelineContext) -> None:  # pragma: no cover - hook
        pass

    def run(self, context: PipelineContext) -> bool:
        logger = context.logger
        if not self.is_enabled(context):
            logger.info("Stage %s disabled for this profile", self.name)
            return False
        if not self.should_run(context):
            logger.info("Stage %s already checkpointed; skipping", self.name)
            return False
        attempts = context.max_retries + 1
        backoff_base = max(0.1, float(context.runtime_config.retry_backoff_base))
        backoff_factor = max(1.0, float(context.runtime_config.retry_backoff_factor))
        for attempt in range(1, attempts + 1):
            context.increment_attempt(self.name)
            context.record.metadata.stage = self.name
            context.manager.update_metadata(context.record)
            logger.info("Stage %s attempt %s/%s", self.name, attempt, attempts)
            try:
                self.before(context)
                self.execute(context)
                self.after(context)
                context.checkpoint(self.name)
                logger.info("Stage %s completed", self.name)
                return True
            except Exception as exc:  # pragma: no cover - runtime path
                logger.exception("Stage %s failed: %s", self.name, exc)
                if attempt >= attempts:
                    raise StageError(f"Stage {self.name} failed after {attempts} attempts") from exc
                delay = backoff_base * (backoff_factor ** (attempt - 1))
                logger.info("Retrying stage %s after %ss", self.name, delay)
                time.sleep(delay)
        return False


class NormalizeStage(Stage):
    name = "normalize_scope"

    def execute(self, context: PipelineContext) -> None:
        spec = context.record.spec
        allow_ip = spec.allow_ip
        if spec.targets_file:
            targets_path = Path(spec.targets_file)
            if not targets_path.is_absolute():
                targets_path = Path.cwd() / targets_path
            if not targets_path.exists():
                raise StageError(f"Targets file not found: {targets_path}")
            targets = validation.load_targets_from_file(str(targets_path), allow_ip=allow_ip)
        else:
            targets = [validation.validate_target(spec.target, allow_ip=allow_ip)]
        limit = max(0, context.runtime_config.max_targets_per_job)
        total_targets = len(targets)
        if limit and total_targets > limit:
            context.logger.warning("Target list capped at %s (received %s)", limit, total_targets)
            targets = targets[:limit]
            context.record.metadata.stats.setdefault("targets_capped", {})["total"] = total_targets
        context.targets = targets
        spec.target = targets[0]
        context.manager.update_spec(context.record)
        targets_artifact = context.record.paths.artifact("targets.txt")
        targets_artifact.write_text("\n".join(targets) + "\n", encoding="utf-8")
        context.record.metadata.stats["targets"] = len(targets)
        context.manager.update_metadata(context.record)


class PassiveEnumerationStage(Stage):
    """
    مرحلة الاكتشاف السلبي للنطاقات الفرعية.
    
    تستخدم أدوات مثل subfinder, amass, waybackurls
    لاكتشاف النطاقات الفرعية بدون إرسال طلبات للهدف مباشرة.
    """
    name = "passive_enumeration"

    def is_enabled(self, context: PipelineContext) -> bool:
        return context.record.spec.profile in {"passive", "full"}

    def execute(self, context: PipelineContext) -> None:
        logger = context.logger
        executor = context.executor
        targets = context.targets
        artifacts = context.record.paths
        allow_ip = context.record.spec.allow_ip
        tool_timeout = context.runtime_config.tool_timeout

        logger.info("Starting passive enumeration for %d targets", len(targets))
        logger.debug("Tool timeout: %ds, Allow IP: %s", tool_timeout, allow_ip)

        subfinder_out = artifacts.artifact("subfinder.txt")
        amass_out = artifacts.artifact("amass.json")
        wayback_out = artifacts.artifact("waybackurls.txt")
        passive_hosts_out = artifacts.artifact("passive_hosts.txt")
        targets_file = artifacts.artifact("targets.txt")

        subfinder_hosts: set[str] = set()
        amass_hosts: set[str] = set()
        wayback_urls: List[str] = []
        seed_hosts: set[str] = set()
        for target in targets:
            if allow_ip and validation.is_ip(target):
                seed_hosts.add(target)
                continue
            try:
                seed_hosts.add(validation.normalize_hostname(target))
            except ValueError:
                logger.debug("Skipping invalid target: %s", target)
                continue

        # ── Subfinder ──────────────────────────────────────────────────
        if executor.available("subfinder"):
            logger.info("Running subfinder...")
            try:
                completed = executor.run(
                    ["subfinder", "-dL", str(targets_file), "-silent"],
                    capture_output=True,
                    check=False,
                    timeout=tool_timeout,
                )
                output = (completed.stdout or "") if hasattr(completed, "stdout") else ""
                if output:
                    lines = [line.strip() for line in output.splitlines() if line.strip()]
                    subfinder_hosts.update(lines)
                    subfinder_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    logger.info("subfinder found %d subdomains", len(lines))
                else:
                    logger.debug("subfinder returned no output")
            except CommandError as e:
                logger.warning("subfinder execution failed: %s", e)
        else:
            logger.warning("subfinder not available; skipping")
            _note_missing_tool(context, "subfinder")

        # ── Amass ──────────────────────────────────────────────────────
        if executor.available("amass"):
            logger.info("Running amass passive enum...")
            try:
                executor.run(
                    [
                        "amass",
                        "enum",
                        "-passive",
                        "-df",
                        str(targets_file),
                        "-o",
                        str(amass_out),
                    ],
                    check=False,
                    timeout=tool_timeout,
                )
                if amass_out.exists():
                    with amass_out.open("r", encoding="utf-8") as handle:
                        for line in handle:
                            try:
                                payload = json.loads(line)
                            except json.JSONDecodeError:
                                payload = None
                            if isinstance(payload, dict):
                                name = payload.get("name")
                                if name:
                                    amass_hosts.add(name.strip())
                                    continue
                            host = line.strip()
                            if host:
                                amass_hosts.add(host)
            except CommandError:
                context.logger.warning("amass execution failed; continuing")
        else:
            context.logger.warning("amass not available; skipping")
            _note_missing_tool(context, "amass")

        wayback_cmd = None
        if executor.available("waybackurls"):
            wayback_cmd = "waybackurls"
        elif executor.available("gau"):
            wayback_cmd = "gau"
        if wayback_cmd:
            aggregated: List[str] = []
            for target in targets:
                try:
                    completed = executor.run([wayback_cmd, target], capture_output=True, check=False, timeout=tool_timeout)
                except CommandError:
                    context.logger.warning("%s failed for %s", wayback_cmd, target)
                    continue
                output = (completed.stdout or "") if hasattr(completed, "stdout") else ""
                if output:
                    aggregated.extend(line.strip() for line in output.splitlines() if line.strip())
            if aggregated:
                wayback_out.write_text("\n".join(aggregated) + "\n", encoding="utf-8")
                wayback_urls.extend(aggregated)
        else:
            context.logger.warning("waybackurls/gau not available; skipping URL discovery")
            _note_missing_tool(context, "waybackurls/gau")

        tracker = context.results
        added = 0
        for hostname in sorted(subfinder_hosts):
            try:
                normalized = validation.normalize_hostname(hostname)
            except ValueError:
                continue
            payload = {
                "type": "hostname",
                "source": "subfinder",
                "hostname": normalized,
            }
            if tracker.append(payload):
                added += 1
        for hostname in sorted(amass_hosts):
            try:
                normalized = validation.normalize_hostname(hostname)
            except ValueError:
                continue
            payload = {
                "type": "hostname",
                "source": "amass",
                "hostname": normalized,
            }
            tracker.append(payload)
        for url in wayback_urls:
            parsed = urlparse(url)
            host = parsed.hostname
            hostname = None
            if host:
                try:
                    hostname = validation.normalize_hostname(host)
                except ValueError:
                    hostname = None
            if not context.url_allowed(url):
                continue
            payload = {
                "type": "url",
                "source": wayback_cmd or "waybackurls",
                "url": url,
                "hostname": hostname,
            }
            tracker.append(payload)

        for hostname in sorted(seed_hosts):
            tracker.append(
                {
                    "type": "hostname",
                    "source": "input",
                    "hostname": hostname,
                }
            )

        passive_hosts_set: set[str] = set()
        for host in (subfinder_hosts | amass_hosts | seed_hosts):
            if not host:
                continue
            if allow_ip and validation.is_ip(host):
                passive_hosts_set.add(host)
                continue
            try:
                passive_hosts_set.add(validation.normalize_hostname(host))
            except ValueError:
                continue
        passive_hosts = sorted(passive_hosts_set)
        if passive_hosts:
            passive_hosts_out.write_text("\n".join(passive_hosts) + "\n", encoding="utf-8")
        context.record.metadata.stats["passive_hostnames"] = len(passive_hosts)
        context.manager.update_metadata(context.record)


class DedupeStage(Stage):
    name = "dedupe_canonicalize"

    def execute(self, context: PipelineContext) -> None:
        passive_hosts_path = context.record.paths.artifact("passive_hosts.txt")
        if not passive_hosts_path.exists():
            context.logger.info("No passive hosts found; skipping dedupe")
            return
        dedupe_path = context.record.paths.artifact("dedupe_hosts.txt")
        seen = set()
        normalized: List[str] = []
        with passive_hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if not host:
                    continue
                if context.record.spec.allow_ip and validation.is_ip(host):
                    canonical = host
                else:
                    try:
                        canonical = validation.normalize_hostname(host)
                    except ValueError:
                        context.logger.debug("Skipping invalid host from passive list: %s", host)
                        continue
                if canonical not in seen:
                    seen.add(canonical)
                    normalized.append(canonical)
        dedupe_path.write_text("\n".join(normalized) + "\n", encoding="utf-8")
        context.record.metadata.stats["dedupe_hosts"] = len(normalized)
        context.manager.update_metadata(context.record)
        # Incremental: seed prior dedupe hosts if available
        prev_job_id = getattr(context.record.spec, "incremental_from", None)
        if prev_job_id:
            prev = context.manager.load_job(prev_job_id)
            if prev:
                prev_dedupe = prev.paths.artifact("dedupe_hosts.txt")
                if prev_dedupe.exists():
                    try:
                        prev_hosts = {line.strip() for line in prev_dedupe.read_text(encoding="utf-8").splitlines() if line.strip()}
                        merged = sorted(set(normalized) | prev_hosts)
                        dedupe_path.write_text("\n".join(merged) + "\n", encoding="utf-8")
                        context.record.metadata.stats["dedupe_hosts"] = len(merged)
                        context.manager.update_metadata(context.record)
                    except Exception:
                        context.logger.warning("Failed to merge previous dedupe hosts for incremental run")


class ResolveStage(Stage):
    name = "dns_resolve"

    def execute(self, context: PipelineContext) -> None:

        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts to resolve")
            return

        hosts: List[str] = []
        with hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if host:
                    hosts.append(host)

        total_hosts = len(hosts)
        if total_hosts == 0:
            context.logger.info("No hosts to resolve")
            return

        output_path = context.record.paths.artifact("massdns.out")
        tracker = context.results
        executor = context.executor
        resolutions: List[tuple[str, str]] = []

        if executor.available("massdns") and context.runtime_config.resolvers_file:
            context.logger.info("Resolving %s hosts with massdns", total_hosts)
            cmd = [
                "massdns",
                "-r",
                str(context.runtime_config.resolvers_file),
                "-t",
                "A",
                "-o",
                "S",
                "-w",
                str(output_path),
                str(hosts_path),
            ]
            try:
                executor.run(cmd, check=False, timeout=context.runtime_config.tool_timeout)
            except CommandError:
                context.logger.warning("massdns execution failed; falling back to system resolver")
        else:
            if not executor.available("massdns"):
                context.logger.info("massdns not available; using system resolver for %s hosts", total_hosts)
                _note_missing_tool(context, "massdns")
            else:
                context.logger.info("Resolvers file missing; system resolver fallback for %s hosts", total_hosts)

        if not output_path.exists() or output_path.stat().st_size == 0:
            resolutions = self._fallback_resolve(context, hosts)
            if resolutions:
                with output_path.open("w", encoding="utf-8") as handle:
                    for hostname, ip in resolutions:
                        handle.write(f"{hostname} A {ip}\n")
        else:
            with output_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        hostname = parts[0].rstrip('.')
                        ip = parts[-1]
                        resolutions.append((hostname, ip))

        for hostname, ip in resolutions:
            payload = {
                "type": "asset",
                "source": "massdns",
                "hostname": hostname,
                "ip": ip,
                "record_type": "A",
            }
            tracker.append(payload)
        context.record.metadata.stats["resolved_hosts"] = len({host for host, _ in resolutions})
        context.manager.update_metadata(context.record)

    def _fallback_resolve(self, context: PipelineContext, hosts: List[str]) -> List[tuple[str, str]]:
        limit = context.runtime_config.fallback_dns_limit
        results: List[tuple[str, str]] = []
        for idx, target in enumerate(hosts):
            if limit and idx >= limit:
                context.logger.warning(
                    "Fallback DNS limit reached (%s hosts); skipping remaining %s entries",
                    limit,
                    max(0, len(hosts) - limit),
                )
                break
            try:
                infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                continue
            ips = {info[4][0] for info in infos}
            if ips:
                for ip in ips:
                    results.append((target, ip))
            if (idx + 1) % 50 == 0:
                context.logger.debug(
                    "Fallback DNS progress: processed %s hosts (%s resolved)",
                    idx + 1,
                    len(results),
                )
        return results


class EnrichmentStage(Stage):
    name = "asset_enrichment"

    def execute(self, context: PipelineContext) -> None:
        items = read_jsonl(context.record.paths.results_jsonl)
        assets = [entry for entry in items if entry.get("type") == "asset" and entry.get("ip")]
        if not assets:
            context.logger.info("No assets to enrich")
            return

        client = enrich_utils.IpInfoClient()
        enrichment_store: Dict[str, dict] = {}
        artifacts_path = context.record.paths.artifact("ip_enrichment.json")
        appended = 0
        cache_path = config.RECON_HOME / "cache" / "enrich.json"
        cache_data: Dict[str, dict] = fs.read_json(cache_path, default={}) if cache_path.exists() else {}
        for asset in assets:
            hostname = asset.get("hostname")
            ip = asset.get("ip")
            if not hostname or not ip:
                continue
            key = f"{hostname}:{ip}"
            if key in enrichment_store:
                continue
            cached = cache_data.get(key)
            if cached:
                cached = dict(cached)
                cached["source"] = cached.get("source", "cache")
                enrichment_store[key] = cached
                if context.results.append(cached):
                    appended += 1
                continue
            try:
                info = enrich_utils.enrich_asset(hostname, ip, client)
            except Exception as exc:  # pragma: no cover - defensive
                context.logger.debug("Enrichment failed for %s (%s): %s", hostname, ip, exc)
                continue
            payload = {
                "type": "asset_enrichment",
                "source": "ipinfo" if client.session else "heuristics",
                "hostname": hostname,
                "ip": ip,
                "asn": info.asn,
                "org": info.org,
                "country": info.country,
                "city": info.city,
                "provider": info.provider_tag,
                "is_cdn": info.is_cdn,
                "is_cloud": info.is_cloud,
                "tags": sorted(info.tags),
            }
            enrichment_store[key] = payload
            if context.results.append(payload):
                appended += 1
        if enrichment_store:
            import json
            mapped: Dict[str, list] = {}
            for key, data in enrichment_store.items():
                hostname = data["hostname"]
                mapped.setdefault(hostname, []).append(data)
            artifacts_path.write_text(json.dumps(mapped, indent=2, sort_keys=True), encoding="utf-8")
            try:
                fs.ensure_directory(cache_path.parent)
                cache_data.update(enrichment_store)
                cache_path.write_text(json.dumps(cache_data, indent=2, sort_keys=True), encoding="utf-8")
            except Exception:
                context.logger.debug("Failed to persist enrichment cache")
            context.record.metadata.stats["asset_enrichments"] = appended
            context.manager.update_metadata(context.record)


class NmapStage(Stage):
    name = "nmap_scan"

    HIGH_RISK_PORTS = {
        21,
        22,
        23,
        25,
        53,
        110,
        111,
        135,
        139,
        143,
        389,
        445,
        465,
        512,
        513,
        514,
        873,
        1099,
        1433,
        1521,
        2049,
        2181,
        2375,
        2376,
        2483,
        2484,
        3306,
        3389,
        3632,
        4444,
        5432,
        5672,
        5900,
        5985,
        5986,
        6379,
        7001,
        7002,
        8080,
        8081,
        8443,
        9200,
        9300,
        11211,
        15672,
        27017,
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_nmap", False))

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        if not executor.available("nmap"):
            context.logger.warning("nmap not available; skipping nmap stage")
            _note_missing_tool(context, "nmap")
            return
        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts for nmap scan")
            return
        with hosts_path.open("r", encoding="utf-8") as handle:
            hosts = [line.strip() for line in handle if line.strip()]
        if not hosts:
            context.logger.info("No hosts for nmap scan")
            return
        runtime = context.runtime_config
        max_hosts = max(0, int(getattr(runtime, "nmap_max_hosts", 0)))
        if max_hosts:
            hosts = hosts[:max_hosts]
        if not hosts:
            context.logger.info("No hosts after nmap cap")
            return
        batch_size = max(1, int(getattr(runtime, "nmap_batch_size", 25)))
        top_ports = int(getattr(runtime, "nmap_top_ports", 0))
        ports = getattr(runtime, "nmap_ports", None)
        nmap_args = getattr(runtime, "nmap_args", None)
        nmap_scripts = getattr(runtime, "nmap_scripts", None)
        timeout = int(getattr(runtime, "nmap_timeout", runtime.tool_timeout))
        nmap_dir = context.record.paths.ensure_subdir("nmap")
        total_ports = 0
        total_services = 0
        findings_added = 0

        for idx in range(0, len(hosts), batch_size):
            batch = hosts[idx: idx + batch_size]
            if not batch:
                continue
            batch_file = nmap_dir / f"targets_{idx // batch_size + 1}.txt"
            xml_path = nmap_dir / f"scan_{idx // batch_size + 1}.xml"
            batch_file.write_text("\n".join(batch) + "\n", encoding="utf-8")
            cmd = ["nmap", "-sV", "-Pn", "-oX", str(xml_path), "-iL", str(batch_file)]
            if ports:
                cmd.extend(["-p", str(ports)])
            elif top_ports:
                cmd.extend(["--top-ports", str(top_ports)])
            if nmap_scripts:
                cmd.extend(["--script", str(nmap_scripts)])
            if nmap_args:
                try:
                    cmd.extend(shlex.split(str(nmap_args)))
                except ValueError:
                    context.logger.warning("Invalid nmap_args; ignoring: %s", nmap_args)
            try:
                executor.run(cmd, check=False, timeout=timeout)
            except CommandError:
                context.logger.warning("nmap failed for batch %s", idx // batch_size + 1)
                continue
            if not xml_path.exists():
                continue
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(xml_path)
            except Exception:
                continue
            root = tree.getroot()
            for host_node in root.findall("host"):
                status = host_node.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                addr = None
                for address in host_node.findall("address"):
                    if address.get("addrtype") == "ipv4":
                        addr = address.get("addr")
                        break
                hostnames = [hn.get("name") for hn in host_node.findall("hostnames/hostname") if hn.get("name")]
                hostname = hostnames[0] if hostnames else addr
                for port_node in host_node.findall("ports/port"):
                    state = port_node.find("state")
                    if state is None or state.get("state") not in {"open", "open|filtered"}:
                        continue
                    port_id = int(port_node.get("portid", "0"))
                    protocol = port_node.get("protocol") or "tcp"
                    service_node = port_node.find("service")
                    service_name = service_node.get("name") if service_node is not None else None
                    product = service_node.get("product") if service_node is not None else None
                    version = service_node.get("version") if service_node is not None else None
                    tags = {f"port:{port_id}", f"proto:{protocol}"}
                    if service_name:
                        tags.add(f"service:{service_name}")
                    if port_id in self.HIGH_RISK_PORTS:
                        tags.add("risk:exposed")
                    payload = {
                        "type": "service",
                        "source": "nmap",
                        "hostname": hostname,
                        "ip": addr,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "tags": sorted(tags),
                        "score": 35 if port_id in self.HIGH_RISK_PORTS else 10,
                    }
                    if context.results.append(payload):
                        total_services += 1
                        total_ports += 1
                    if port_id in self.HIGH_RISK_PORTS:
                        finding = {
                            "type": "finding",
                            "source": "nmap",
                            "hostname": hostname,
                            "description": f"Potentially risky service exposed on port {port_id}",
                            "details": {
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "product": product,
                                "version": version,
                                "ip": addr,
                            },
                            "tags": ["nmap", "exposure", f"port:{port_id}"],
                            "score": 55,
                            "priority": "medium",
                        }
                        if context.results.append(finding):
                            findings_added += 1

        stats = context.record.metadata.stats.setdefault("nmap", {})
        stats["hosts"] = len(hosts)
        stats["services"] = total_services
        stats["findings"] = findings_added
        context.manager.update_metadata(context.record)

        if getattr(runtime, "nmap_udp", False):
            udp_ports = int(getattr(runtime, "nmap_udp_top_ports", 200))
            udp_xml = nmap_dir / "scan_udp.xml"
            udp_targets = nmap_dir / "targets_udp.txt"
            udp_targets.write_text("\n".join(hosts) + "\n", encoding="utf-8")
            udp_cmd = ["nmap", "-sU", "-Pn", "-oX", str(udp_xml), "-iL", str(udp_targets), "--top-ports", str(udp_ports)]
            if nmap_scripts:
                udp_cmd.extend(["--script", str(nmap_scripts)])
            if nmap_args:
                try:
                    udp_cmd.extend(shlex.split(str(nmap_args)))
                except ValueError:
                    pass
            try:
                executor.run(udp_cmd, check=False, timeout=timeout)
            except CommandError:
                context.logger.warning("nmap UDP scan failed")
                return
            if udp_xml.exists():
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(udp_xml)
                except Exception:
                    return
                root = tree.getroot()
                udp_services = 0
                for host_node in root.findall("host"):
                    status = host_node.find("status")
                    if status is not None and status.get("state") != "up":
                        continue
                    addr = None
                    for address in host_node.findall("address"):
                        if address.get("addrtype") == "ipv4":
                            addr = address.get("addr")
                            break
                    hostnames = [hn.get("name") for hn in host_node.findall("hostnames/hostname") if hn.get("name")]
                    hostname = hostnames[0] if hostnames else addr
                    for port_node in host_node.findall("ports/port"):
                        state = port_node.find("state")
                        if state is None or state.get("state") not in {"open", "open|filtered"}:
                            continue
                        port_id = int(port_node.get("portid", "0"))
                        service_node = port_node.find("service")
                        service_name = service_node.get("name") if service_node is not None else None
                        payload = {
                            "type": "service",
                            "source": "nmap-udp",
                            "hostname": hostname,
                            "ip": addr,
                            "port": port_id,
                            "protocol": "udp",
                            "service": service_name,
                            "tags": ["udp", f"port:{port_id}"],
                            "score": 25,
                        }
                        if context.results.append(payload):
                            udp_services += 1
                if udp_services:
                    stats = context.record.metadata.stats.setdefault("nmap", {})
                    stats["udp_services"] = udp_services
                    context.manager.update_metadata(context.record)


class HttpProbeStage(Stage):
    name = "http_probe"

    PROBE_PATHS = [
        "/robots.txt",
        "/.well-known/security.txt",
        "/sitemap.xml",
        "/api/",
        "/login",
        "/signin",
        "/auth",
        "/account/login",
        "/user/login",
        "/register",
        "/signup",
        "/forgot",
        "/forgot-password",
        "/reset",
        "/password/reset",
        "/admin",
    ]
    HEADER_TAG_KEYS = [
        "server",
        "x-powered-by",
        "server-timing",
        "location",
        "access-control-allow-origin",
        "www-authenticate",
    ]

    def execute(self, context: PipelineContext) -> None:
        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts to probe")
            return
        with hosts_path.open("r", encoding="utf-8") as handle:
            hosts = [line.strip() for line in handle if line.strip()]
        if not hosts:
            context.logger.info("No hosts to probe")
            return
        httpx_input = context.record.paths.artifact("hosts_for_httpx.txt")
        httpx_output = context.record.paths.artifact("httpx_raw.json")
        fs.ensure_directory(httpx_input.parent)
        max_hosts = max(0, context.runtime_config.max_probe_hosts)
        httpx_host_limit = max(0, context.runtime_config.httpx_max_hosts)
        cap = max_hosts if max_hosts else len(hosts)
        if httpx_host_limit:
            cap = min(cap, httpx_host_limit)
        selected_hosts = hosts[:cap]
        if len(selected_hosts) < len(hosts):
            context.logger.info("HTTP probe limiting hosts to %s of %s (max_probe_hosts/httpx_max_hosts)", len(selected_hosts), len(hosts))
            stats = context.record.metadata.stats.setdefault("http_probe", {})
            stats["hosts_total"] = len(hosts)
            stats["hosts_capped"] = len(hosts) - len(selected_hosts)
            context.manager.update_metadata(context.record)
        httpx_input.write_text("\n".join(selected_hosts) + "\n", encoding="utf-8")
        hosts = selected_hosts
        if not hosts:
            context.logger.info("No hosts to probe after applying caps")
            return
        executor = context.executor
        tool_timeout = context.runtime_config.tool_timeout
        tracker = context.results
        seen_urls: Set[str] = set()
        used_httpx = False
        if executor.available("httpx"):
            cmd = [
                "httpx",
                "-l",
                str(httpx_input),
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-web-server",
                "-cdn",
                "-favicon",
                "-o",
                str(httpx_output),
                "-threads",
                str(context.runtime_config.httpx_threads),
                "-timeout",
                str(context.runtime_config.timeout_http),
                "-follow-redirects",
            ]
            try:
                executor.run(cmd, check=False, timeout=tool_timeout)
                used_httpx = True
            except CommandError:
                context.logger.warning("httpx execution failed; attempting fallback probe")
        if used_httpx and httpx_output.exists():
            with httpx_output.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    status_code = payload.get("status-code") or payload.get("status_code")
                    content_length = (
                        payload.get("content-length")
                        or payload.get("content_length")
                        or payload.get("content-length")
                    )
                    server = payload.get("webserver") or payload.get("server") or payload.get("web-server")
                    technologies = payload.get("tech") or payload.get("technologies") or []
                    title = payload.get("title")
                    cdn = payload.get("cdn")
                    entry = {
                        "type": "url",
                        "source": "httpx",
                        "url": payload.get("url"),
                        "hostname": payload.get("host") or payload.get("input"),
                        "ip": payload.get("a") or payload.get("ip"),
                        "status_code": status_code,
                        "title": title,
                        "server": server,
                        "tls": bool(payload.get("tls")),
                        "response_time_ms": payload.get("rtt"),
                        "content_length": content_length,
                        "cdn": cdn,
                        "technologies": technologies,
                    }
                    url_value = entry.get("url")
                    if url_value and not context.url_allowed(url_value):
                        continue
                    if url_value and url_value in seen_urls:
                        continue
                    tags = set(entry.get("tags", []))
                    if url_value:
                        tags.update(enrich_utils.infer_service_tags(url_value))
                    tags.update(enrich_utils.infer_tech_tags(technologies if isinstance(technologies, list) else [str(technologies)], server, title))
                    tags.update(enrich_utils.detect_waf_tags(server, cdn))
                    if tags:
                        entry["tags"] = sorted(tags)
                    appended = tracker.append(entry)
                    if appended and url_value:
                        seen_urls.add(url_value)
        else:
            self._fallback_probe(context, hosts_path, seen_urls)
        self._probe_additional_paths(context, hosts, seen_urls)
        self._probe_soft_404(context, hosts)
        context.record.metadata.stats["http_urls"] = context.results.stats.get("type:url", 0)
        context.manager.update_metadata(context.record)

    def _fallback_probe(self, context: PipelineContext, hosts_path: Path, seen_urls: Set[str]) -> None:
        import http.client
        import ssl

        # Initialize rate limiter if available
        rate_limiter = None
        if RATE_LIMITER_AVAILABLE and RateLimiter:
            rate_limiter = RateLimiter(RateLimitConfig(
                requests_per_second=context.runtime_config.requests_per_second if hasattr(context.runtime_config, 'requests_per_second') else 10,
                per_host_limit=context.runtime_config.per_host_limit if hasattr(context.runtime_config, 'per_host_limit') else 5,
            ))

        tracker = context.results
        with hosts_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                host = line.strip()
                if not host:
                    continue
                for scheme, port in (("http", 80), ("https", 443)):
                    url = f"{scheme}://{host}/"
                    if not context.url_allowed(url):
                        continue
                    if url in seen_urls:
                        continue
                    
                    # Apply rate limiting
                    if rate_limiter:
                        rate_limiter.wait_for_slot(url)
                    
                    conn = None
                    try:
                        if scheme == "https":
                            ssl_ctx = ssl.create_default_context()
                            conn = http.client.HTTPSConnection(host, port=port, timeout=5, context=ssl_ctx)
                        else:
                            conn = http.client.HTTPConnection(host, port=port, timeout=5)
                        headers = {"User-Agent": "recon-cli"}
                        cache_entry = context.get_cache_entry(url)
                        if cache_entry and not context.force:
                            if cache_entry.get("etag"):
                                headers["If-None-Match"] = cache_entry["etag"]
                            if cache_entry.get("last_modified"):
                                headers["If-Modified-Since"] = cache_entry["last_modified"]
                        conn.request("GET", "/", headers=headers)
                        resp = conn.getresponse()
                        
                        # Report response to rate limiter
                        if rate_limiter:
                            rate_limiter.on_response(url, resp.status)
                        
                        if resp.status == 304 and not context.force:
                            break
                        body = resp.read(2048) or b""
                        raw_headers = resp.getheaders()
                        headers_lower = {k.lower(): v for k, v in raw_headers}
                        etag = headers_lower.get("etag")
                        last_modified = headers_lower.get("last-modified")
                        body_md5 = hashlib.md5(body).hexdigest()
                        if context.should_skip_due_to_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5):
                            context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                            break
                        set_cookie_headers = [value for key, value in raw_headers if key.lower() == "set-cookie" and value]
                        header_values = [value for value in (headers_lower.get("x-powered-by"), headers_lower.get("server")) if value]
                        payload = {
                            "type": "url",
                            "source": "probe",
                            "url": url,
                            "hostname": host,
                            "status_code": resp.status,
                            "server": headers_lower.get("server"),
                            "tls": scheme == "https",
                            "content_type": headers_lower.get("content-type"),
                            "length": len(body),
                            "body_md5": body_md5,
                            "etag": etag,
                            "last_modified": last_modified,
                        }
                        tags = set(enrich_utils.infer_service_tags(url))
                        if header_values:
                            tags.update(enrich_utils.infer_tech_tags(header_values))
                        tags.update(enrich_utils.infer_cookie_tags(set_cookie_headers))
                        tags.update(enrich_utils.detect_waf_tags(payload.get("server")))
                        if tags:
                            payload["tags"] = sorted(tags)
                        context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                        appended = tracker.append(payload)
                        if appended:
                            seen_urls.add(url)
                    except Exception:
                        continue
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass

    def _probe_additional_paths(self, context: PipelineContext, hosts: List[str], seen_urls: Set[str]) -> None:
        if not hosts:
            return
        runtime = context.runtime_config
        host_limit = runtime.max_global_concurrency or len(hosts)
        total_added = 0
        for idx, host in enumerate(hosts):
            if idx >= host_limit:
                break
            total_added += self._probe_host_paths(context, host, seen_urls)
        if total_added:
            stats = context.record.metadata.stats.setdefault("http_probe", {})
            stats["extra"] = stats.get("extra", 0) + total_added
            context.manager.update_metadata(context.record)

    def _probe_soft_404(self, context: PipelineContext, hosts: List[str]) -> None:
        runtime = context.runtime_config
        if not getattr(runtime, "soft_404_probe", True):
            return
        if not hosts:
            return
        try:
            import requests
        except Exception:
            return
        max_hosts = max(0, int(getattr(runtime, "soft_404_max_hosts", 25)))
        if max_hosts == 0:
            return
        max_paths = max(1, int(getattr(runtime, "soft_404_paths", 1)))
        timeout = max(1, int(getattr(runtime, "soft_404_timeout", 6)))
        soft_hosts: set[str] = set()
        for host in hosts[:max_hosts]:
            for scheme in ("https", "http"):
                if host in soft_hosts:
                    break
                for _ in range(max_paths):
                    random_path = f"/recon404-{int(time.time() * 1000)}-{hashlib.md5(host.encode()).hexdigest()[:6]}"
                    url = f"{scheme}://{host}{random_path}"
                    if not context.url_allowed(url):
                        continue
                    try:
                        resp = requests.get(
                            url,
                            timeout=timeout,
                            allow_redirects=True,
                            verify=context.runtime_config.verify_tls,
                            headers={"User-Agent": "recon-cli soft-404"},
                        )
                    except Exception:
                        continue
                    body_snippet = (resp.text or "")[:2048]
                    title = ""
                    if "<title" in body_snippet.lower():
                        try:
                            import re as _re
                            match = _re.search(r"<title[^>]*>(.*?)</title>", body_snippet, _re.IGNORECASE | _re.DOTALL)
                            if match:
                                title = match.group(1).strip()
                        except Exception:
                            title = ""
                    if enrich_utils.looks_like_soft_404(resp.status_code, body_snippet, title):
                        soft_hosts.add(host)
                        break
        if soft_hosts:
            stats = context.record.metadata.stats.setdefault("soft_404", {})
            stats["hosts"] = sorted(soft_hosts)
            stats["count"] = len(soft_hosts)
            context.manager.update_metadata(context.record)

    def _probe_host_paths(self, context: PipelineContext, host: str, seen_urls: Set[str]) -> int:
        import http.client
        import ssl
        added = 0
        paths = self.PROBE_PATHS
        for path in paths:
            base_tags = ["probe++", f"path:{path.lstrip('/') or '/'}"]
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}{path}"
                if not context.url_allowed(url):
                    continue
                if url in seen_urls:
                    continue
                conn = None
                try:
                    start = time.perf_counter()
                    if scheme == "https":
                        conn = http.client.HTTPSConnection(host, timeout=5, context=ssl.create_default_context())
                    else:
                        conn = http.client.HTTPConnection(host, timeout=5)
                    headers = {"User-Agent": "recon-cli probe++"}
                    cache_entry = context.get_cache_entry(url)
                    if cache_entry and not context.force:
                        if cache_entry.get("etag"):
                            headers["If-None-Match"] = cache_entry["etag"]
                        if cache_entry.get("last_modified"):
                            headers["If-Modified-Since"] = cache_entry["last_modified"]
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    if resp.status == 304 and not context.force:
                        break
                    body = resp.read(2048) or b""
                    duration_ms = int((time.perf_counter() - start) * 1000)
                    raw_headers = resp.getheaders()
                    headers_lower = {k.lower(): v for k, v in raw_headers}
                    etag = headers_lower.get("etag")
                    last_modified = headers_lower.get("last-modified")
                    body_md5 = hashlib.md5(body).hexdigest()
                    if context.should_skip_due_to_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5):
                        context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                        continue
                    set_cookie_headers = [value for key, value in raw_headers if key.lower() == "set-cookie" and value]
                    header_values = [value for value in (headers_lower.get("x-powered-by"), headers_lower.get("server")) if value]
                    tags = list(base_tags)
                    tags.extend(enrich_utils.infer_service_tags(url))
                    if header_values:
                        tags.extend(enrich_utils.infer_tech_tags(header_values))
                    tags.extend(enrich_utils.infer_cookie_tags(set_cookie_headers))
                    tags.extend(enrich_utils.detect_waf_tags(headers_lower.get("server")))
                    for header_name in self.HEADER_TAG_KEYS:
                        value = headers_lower.get(header_name)
                        if value:
                            tags.append(f"header:{header_name}={value.strip()[:80]}")
                    content_type = headers_lower.get("content-type")
                    payload = {
                        "type": "url",
                        "source": "probe",
                        "url": url,
                        "hostname": host,
                        "status_code": resp.status,
                        "content_type": content_type,
                        "length": len(body),
                        "body_md5": body_md5,
                        "tags": sorted(set(tags)),
                        "tls": scheme == "https",
                        "response_time_ms": duration_ms,
                        "etag": etag,
                        "last_modified": last_modified,
                    }
                    location = headers_lower.get("location")
                    if location:
                        payload["redirect_location"] = location
                    context.update_cache(url, etag=etag, last_modified=last_modified, body_md5=body_md5)
                    appended = context.results.append(payload)
                    if appended:
                        added += 1
                        seen_urls.add(url)
                    break
                except Exception:
                    continue
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
        return added




class ScoringStage(Stage):
    name = "scoring_tagging"

    ADMIN_PATTERNS = ["/admin", "/wp-admin", "/login", "/signin", "/auth", "/account/login", "/user/login"]
    RESET_PATTERNS = ["/forgot", "/reset", "/password", "/recover"]
    REGISTER_PATTERNS = ["/register", "/signup", "/sign-up"]
    SENSITIVE_QUERY_KEYS = {"password", "token", "secret", "key"}
    BACKUP_EXTENSIONS = {".sql", ".bak", ".zip", ".tar", ".gz"}
    ENV_BOOST_TAGS = {"env:dev", "env:staging", "env:test", "env:qa", "env:preprod"}

    def execute(self, context: PipelineContext) -> None:
        self.rules = getattr(self, "rules", rules_engine.load_rules())
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return
        items = read_jsonl(results_path)
        if not items:
            return

        enrichment_map: Dict[str, list] = {}
        enrichment_artifact = context.record.paths.artifact("ip_enrichment.json")
        if enrichment_artifact.exists():
            try:
                import json as _json

                enrichment_map = _json.loads(enrichment_artifact.read_text(encoding="utf-8"))
            except Exception:
                enrichment_map = {}

        soft_404_hosts = set(context.record.metadata.stats.get("soft_404", {}).get("hosts", []))
        updated: List[dict] = []
        for entry in items:
            ptype = entry.get("type")
            if ptype == "hostname":
                hostname = entry.get("hostname")
                if hostname:
                    tags = set(entry.get("tags", []))
                    tags.update(enrich_utils.hostname_tags(hostname))
                    tags.update(rules_engine.apply_rules(entry, self.rules))
                    if tags:
                        entry["tags"] = sorted(tags)
                updated.append(entry)
                continue
            if ptype == "asset":
                host = entry.get("hostname")
                if host and host in enrichment_map:
                    tags = set(entry.get("tags", []))
                    for enriched in enrichment_map[host]:
                        tags.update(enriched.get("tags", []))
                        entry.setdefault("asn", enriched.get("asn"))
                        entry.setdefault("org", enriched.get("org"))
                        entry.setdefault("country", enriched.get("country"))
                    if tags:
                        entry["tags"] = sorted(tags)
                updated.append(entry)
                continue
            if ptype != "url":
                updated.append(entry)
                continue

            score = int(entry.get("score", 0))
            tags = set(entry.get("tags", []))
            url = entry.get("url", "")
            lower_url = url.lower()
            host = entry.get("hostname")
            host_enrichments = enrichment_map.get(host, []) if host else []
            if host_enrichments:
                for enriched in host_enrichments:
                    tags.update(enriched.get("tags", []))
                    provider = enriched.get("provider")
                    if provider:
                        tags.add(provider)
                    if enriched.get("is_cdn"):
                        tags.add("service:cdn")
                        score -= 5
                    if enriched.get("is_cloud"):
                        score += 5

            tags.update(enrich_utils.infer_service_tags(url))

            for pattern in self.ADMIN_PATTERNS:
                if pattern in lower_url:
                    tags.add("surface:admin")
                    score += 25
            for pattern in self.RESET_PATTERNS:
                if pattern in lower_url:
                    tags.add("surface:password-reset")
                    score += 20
            for pattern in self.REGISTER_PATTERNS:
                if pattern in lower_url:
                    tags.add("surface:register")
                    score += 15
            if any(f"{key}=" in lower_url for key in self.SENSITIVE_QUERY_KEYS):
                tags.add("possible-cred-leak")
                score += 100
            for ext in self.BACKUP_EXTENSIONS:
                if lower_url.endswith(ext):
                    tags.add("backup")
                    score += 60

            status_code = entry.get("status_code")
            length = (
                entry.get("length")
                or entry.get("content_length")
                or entry.get("content-length")
            )
            if enrich_utils.detect_noise(url, status_code, entry.get("source", ""), length):
                tags.add("noise")
                entry["noise"] = True
                score = 0
            else:
                if status_code in {401, 403}:
                    score += 35
                    tags.add("auth-required")
                if host and host in soft_404_hosts:
                    tags.add("soft-404")
                    score = max(score - 15, 0)
                if any(tag.startswith("waf:") for tag in tags):
                    tags.add("service:waf")
                    if status_code in {401, 403}:
                        tags.add("waf-blocked")
                        score += 5
                if status_code and 400 <= status_code < 500 and "service:api" in tags:
                    score += 50
                if status_code in {200, 302} and "service:api" in tags:
                    score += 25
                if tags.intersection(self.ENV_BOOST_TAGS):
                    score += 25
                if "surface:login" in tags or "service:sso" in tags:
                    score += 40
                if "secret-hit" in tags or "secret" in tags:
                    score = max(score, 95)
                server = entry.get("server")
                score += enrich_utils.legacy_score(server)

            rule_tags = rules_engine.apply_rules(entry, self.rules)
            if rule_tags:
                tags.update(rule_tags)

            entry["tags"] = sorted(tags)
            entry["score"] = max(score, 0)
            entry["priority"] = enrich_utils.classify_priority(entry["score"])
            updated.append(entry)

        tmp = results_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for entry in updated:
                json.dump(entry, handle, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")
        tmp.replace(results_path)
        surface_stats = context.record.metadata.stats.setdefault("auth_surface", {})
        surface_stats["login"] = sum(1 for entry in updated if "surface:login" in entry.get("tags", []))
        surface_stats["password_reset"] = sum(1 for entry in updated if "surface:password-reset" in entry.get("tags", []))
        surface_stats["register"] = sum(1 for entry in updated if "surface:register" in entry.get("tags", []))
        context.manager.update_metadata(context.record)


class AuthDiscoveryStage(Stage):
    name = "auth_discovery"

    AUTH_HINTS = ("login", "signin", "signup", "register", "forgot", "reset", "password", "auth")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_auth_discovery", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
            from html.parser import HTMLParser
        except Exception:
            context.logger.warning("auth discovery requires requests; skipping")
            return

        class FormParser(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.forms: List[Dict[str, object]] = []
                self._current: Optional[Dict[str, object]] = None

            def handle_starttag(self, tag, attrs):
                attrs_dict = {key.lower(): value for key, value in attrs if key}
                if tag == "form":
                    self._current = {
                        "action": attrs_dict.get("action") or "",
                        "method": (attrs_dict.get("method") or "get").lower(),
                        "inputs": [],
                    }
                elif tag in {"input", "textarea", "select"} and self._current is not None:
                    name = attrs_dict.get("name") or attrs_dict.get("id") or ""
                    input_type = attrs_dict.get("type") or tag
                    if name:
                        self._current["inputs"].append({"name": name, "type": input_type})

            def handle_endtag(self, tag):
                if tag == "form" and self._current is not None:
                    self.forms.append(self._current)
                    self._current = None

        candidates: List[Dict[str, object]] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            status = entry.get("status_code")
            if status not in {200, 302}:
                continue
            url = entry.get("url")
            if not url:
                continue
            tags = set(entry.get("tags", []))
            path = urlparse(url).path.lower()
            has_hint = any(hint in path for hint in self.AUTH_HINTS)
            if tags.intersection({"surface:login", "surface:register", "surface:password-reset", "surface:admin"}) or has_hint:
                candidates.append(
                    {
                        "url": url,
                        "score": int(entry.get("score", 0)),
                        "tags": list(tags),
                    }
                )
        if not candidates:
            context.logger.info("No auth candidates discovered")
            return
        candidates.sort(key=lambda item: item.get("score", 0), reverse=True)
        max_urls = int(getattr(context.runtime_config, "auth_discovery_max_urls", 40))
        timeout = int(getattr(context.runtime_config, "auth_discovery_timeout", 10))
        max_forms = int(getattr(context.runtime_config, "auth_discovery_max_forms", 80))
        forms_found = 0
        artifacts: List[Dict[str, object]] = []
        for candidate in candidates[:max_urls]:
            if forms_found >= max_forms:
                break
            url = candidate["url"]
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "recon-cli auth-discovery"},
                    verify=context.runtime_config.verify_tls,
                )
            except Exception:
                continue
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "<form" not in (resp.text or "").lower():
                continue
            parser = FormParser()
            parser.feed(resp.text or "")
            for form in parser.forms:
                if forms_found >= max_forms:
                    break
                action = form.get("action") or ""
                action_url = urljoin(url, action) if action else url
                inputs = form.get("inputs") or []
                tags = set(candidate.get("tags", []))
                input_names = [item.get("name") for item in inputs if isinstance(item, dict)]
                lower_action = str(action_url).lower()
                if any(item.get("type") == "password" for item in inputs if isinstance(item, dict)):
                    tags.add("surface:login")
                if "reset" in lower_action or "forgot" in lower_action:
                    tags.add("surface:password-reset")
                if "register" in lower_action or "signup" in lower_action:
                    tags.add("surface:register")
                if any(name for name in input_names if name and "csrf" in name.lower()):
                    tags.add("indicator:csrf")
                payload = {
                    "type": "auth_form",
                    "source": "form-discovery",
                    "hostname": urlparse(url).hostname,
                    "url": url,
                    "action": action_url,
                    "method": form.get("method"),
                    "inputs": inputs,
                    "tags": sorted(tags),
                    "score": 40 if "surface:login" in tags else 20,
                }
                if context.results.append(payload):
                    forms_found += 1
                    artifacts.append(payload)
        if artifacts:
            artifact_path = context.record.paths.artifact("auth_forms.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")
            stats = context.record.metadata.stats.setdefault("auth_discovery", {})
            stats["forms"] = forms_found
            context.manager.update_metadata(context.record)


class WafProbeStage(Stage):
    name = "waf_probe"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_waf_probe", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("waf probe requires requests; skipping")
            return
        candidates: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url:
                continue
            status = entry.get("status_code") or 0
            tags = entry.get("tags", [])
            if status in {403, 429} or any(tag.startswith("waf:") or tag == "service:waf" for tag in tags):
                candidates.append(url)
        if not candidates:
            return
        max_urls = int(getattr(context.runtime_config, "waf_probe_max_urls", 25))
        timeout = int(getattr(context.runtime_config, "waf_probe_timeout", 8))
        findings = 0
        for url in candidates[:max_urls]:
            try:
                resp_default = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers={"User-Agent": "recon-cli waf-probe"},
                )
            except Exception:
                continue
            try:
                resp_alt = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=context.runtime_config.verify_tls,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                        "X-Forwarded-For": "127.0.0.1",
                        "X-Originating-IP": "127.0.0.1",
                        "X-Real-IP": "127.0.0.1",
                    },
                )
            except Exception:
                continue
            if resp_default.status_code in {403, 429} and resp_alt.status_code not in {403, 429}:
                finding = {
                    "type": "finding",
                    "source": "waf-probe",
                    "hostname": urlparse(url).hostname,
                    "description": "Potential WAF bypass via alternate headers",
                    "details": {
                        "url": url,
                        "baseline_status": resp_default.status_code,
                        "alternate_status": resp_alt.status_code,
                        "baseline_length": len(resp_default.text or ""),
                        "alternate_length": len(resp_alt.text or ""),
                    },
                    "tags": ["waf", "bypass-possible"],
                    "score": 60,
                    "priority": "medium",
                }
                if context.results.append(finding):
                    findings += 1
        if findings:
            stats = context.record.metadata.stats.setdefault("waf_probe", {})
            stats["findings"] = findings
            context.manager.update_metadata(context.record)
class FuzzStage(Stage):
    name = "fuzzing"

    def is_enabled(self, context: PipelineContext) -> bool:
        spec = context.record.spec
        if not context.runtime_config.enable_fuzz and not spec.wordlist:
            return False
        return spec.profile in {"full", "fuzz-only"} or bool(spec.wordlist)

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        runtime = context.runtime_config
        tool_timeout = runtime.tool_timeout
        per_host_limit = max(runtime.trim_url_max_per_host, 0)
        per_host_counts: Dict[str, int] = defaultdict(int)
        stage_seen: Set[str] = set()
        if not executor.available("ffuf"):
            context.logger.warning("ffuf not available; skipping fuzzing stage")
            _note_missing_tool(context, "ffuf")
            return
        spec = context.record.spec
        wordlist_override = Path(spec.wordlist) if spec.wordlist else None
        if wordlist_override and not wordlist_override.exists():
            context.logger.warning("Wordlist not found: %s", wordlist_override)
            return
        targets = self._select_hosts_for_fuzz(context)
        if not targets:
            context.logger.info("No hosts qualified for fuzzing")
            return
        host_tags = self._tags_for_hosts(context)
        for host in targets[: context.runtime_config.max_fuzz_hosts]:
            wordlist_path = wordlist_override or self._select_wordlist_for_host(runtime, host, host_tags.get(host, set()))
            if not wordlist_path.exists():
                context.logger.warning("Wordlist not found: %s", wordlist_path)
                continue
            artifact = context.record.paths.artifact(f"ffuf_{host}.json")
            cmd = [
                "ffuf",
                "-w",
                str(wordlist_path),
                "-u",
                f"https://{host}/FUZZ",
                "-t",
                str(context.runtime_config.ffuf_threads),
                "-mc",
                "200,301,302,401,403",
                "-ac",
                "-of",
                "json",
                "-o",
                str(artifact),
            ]
            try:
                ffuf_maxtime = max(0, int(getattr(runtime, "ffuf_maxtime", 0)))
                if ffuf_maxtime:
                    cmd.extend(["-maxtime", str(ffuf_maxtime)])
                timeout = tool_timeout
                if ffuf_maxtime:
                    timeout = ffuf_maxtime + max(0, int(getattr(runtime, "ffuf_timeout_buffer", 30)))
                executor.run(cmd, check=False, timeout=timeout)
            except CommandError as exc:
                retried = False
                if getattr(runtime, "ffuf_retry_on_timeout", True) and "timeout" in str(exc).lower():
                    retry_maxtime = max(ffuf_maxtime + int(getattr(runtime, "ffuf_retry_extra_time", 120)), ffuf_maxtime)
                    retry_threads = max(10, int(context.runtime_config.ffuf_threads // 2) or 10)
                    retry_cmd = [part for part in cmd if part not in {"-maxtime", str(ffuf_maxtime)}]
                    retry_cmd = list(retry_cmd)
                    if "-t" in retry_cmd:
                        t_idx = retry_cmd.index("-t") + 1
                        if t_idx < len(retry_cmd):
                            retry_cmd[t_idx] = str(retry_threads)
                    if retry_maxtime:
                        retry_cmd.extend(["-maxtime", str(retry_maxtime)])
                    retry_timeout = retry_maxtime + max(0, int(getattr(runtime, "ffuf_timeout_buffer", 30)))
                    try:
                        executor.run(retry_cmd, check=False, timeout=retry_timeout)
                        retried = True
                    except CommandError:
                        pass
                if not retried:
                    context.logger.warning("ffuf failed for %s", host)
                continue
            if artifact.exists():
                try:
                    data = json.loads(artifact.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    continue
                for result in data.get("results", []):
                    payload = {
                        "type": "url",
                        "source": "ffuf",
                        "url": result.get("url"),
                        "status_code": result.get("status"),
                        "length": result.get("length"),
                        "tags": ["fuzz"],
                        "score": 50,
                    }
                    entry_url = payload.get("url")
                    if not entry_url:
                        continue
                    if not context.url_allowed(entry_url):
                        continue
                    if entry_url in stage_seen:
                        continue
                    host = payload.get("hostname") or urlparse(entry_url).hostname
                    if host:
                        payload.setdefault("hostname", host)
                    if host and per_host_limit > 0 and per_host_counts[host] >= per_host_limit:
                        continue
                    appended = context.results.append(payload)
                    if appended:
                        stage_seen.add(entry_url)
                        if host:
                            per_host_counts[host] += 1

    def _select_hosts_for_fuzz(self, context: PipelineContext) -> List[str]:
        hosts = defaultdict(int)
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return []
        for entry in read_jsonl(results_path):
            if entry.get("type") == "url" and entry.get("status_code") in {200, 204}:
                url_value = entry.get("url")
                if url_value and not context.url_allowed(url_value):
                    continue
                host = entry.get("hostname")
                if host:
                    hosts[host] = max(hosts[host], int(entry.get("score", 0)))
        sorted_hosts = sorted(hosts.items(), key=lambda item: item[1], reverse=True)
        return [host for host, _ in sorted_hosts]

    def _tags_for_hosts(self, context: PipelineContext) -> Dict[str, set[str]]:
        tags_by_host: Dict[str, set[str]] = defaultdict(set)
        results_path = context.record.paths.results_jsonl
        if not results_path.exists():
            return tags_by_host
        for entry in read_jsonl(results_path):
            if entry.get("type") != "url":
                continue
            url_value = entry.get("url")
            host = entry.get("hostname") or (urlparse(url_value).hostname if url_value else None)
            if not host:
                continue
            for tag in entry.get("tags", []):
                tags_by_host[host].add(tag)
            if url_value:
                path = urlparse(url_value).path.lower()
                if "/api" in path:
                    tags_by_host[host].add("service:api")
                if any(token in path for token in ("/wp-", "/wp-admin", "/wp-content", "/wp-json", "/xmlrpc.php")):
                    tags_by_host[host].add("cms:wordpress")
        return tags_by_host

    def _select_wordlist_for_host(self, runtime, host: str, tags: set[str]) -> Path:
        base = runtime.seclists_root
        candidates: List[Path] = []
        if "cms:wordpress" in tags or "tech:wordpress" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "CMS" / "wordpress.fuzz.txt")
        if "service:api" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "api" / "common-api-endpoints.txt")
        if tags.intersection({"surface:login", "surface:password-reset", "surface:register"}):
            candidates.append(base / "Discovery" / "Web-Content" / "Logins.fuzz.txt")
        if "surface:admin" in tags:
            candidates.append(base / "Discovery" / "Web-Content" / "admin.txt")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return base / "Discovery" / "Web-Content" / "common.txt"



class ActiveIntelligenceStage(Stage):
    name = "active_intelligence"

    def is_enabled(self, context: PipelineContext) -> bool:
        modules = [m.lower() for m in context.record.spec.active_modules]
        if modules:
            return True
        return bool(getattr(context.runtime_config, "auto_active_modules", True))

    def execute(self, context: PipelineContext) -> None:
        modules = list(dict.fromkeys(m.lower() for m in context.record.spec.active_modules))
        if not modules and getattr(context.runtime_config, "auto_active_modules", True):
            modules = active_modules.available_modules()
        if not modules:
            context.logger.info("No active modules requested")
            return
        available = set(active_modules.available_modules())
        selected: List[str] = []
        for module in modules:
            if module not in available:
                context.logger.warning("Unknown active module '%s'", module)
                continue
            selected.append(module)
        if not selected:
            context.logger.info("No valid active modules requested")
            return

        items = read_jsonl(context.record.paths.results_jsonl)
        url_entries = [entry for entry in items if entry.get("type") == "url"]
        host_scores: Dict[str, int] = {}
        for entry in url_entries:
            host = entry.get("hostname")
            if not host:
                continue
            score = int(entry.get("score", 0))
            host_scores[host] = max(host_scores.get(host, 0), score)
        ranked_hosts = [host for host, _ in sorted(host_scores.items(), key=lambda item: item[1], reverse=True)]

        session = active_modules.create_session()
        artifact_dir = context.record.paths.ensure_subdir("active")
        stats: Dict[str, int] = {}
        for module in selected:
            try:
                result = active_modules.execute_module(
                    module,
                    url_entries=url_entries,
                    hosts=ranked_hosts,
                    session=session,
                )
            except Exception as exc:  # pragma: no cover - defensive
                context.logger.exception("Active module %s failed: %s", module, exc)
                continue
            added = context.results.extend(result.payloads) if result.payloads else 0
            stats[module] = added
            if result.artifact_data:
                artifact_path = artifact_dir / result.artifact_name
                try:
                    artifact_path.write_text(json.dumps(result.artifact_data, indent=2, sort_keys=True), encoding="utf-8")
                except TypeError:
                    artifact_path.write_text(json.dumps(result.artifact_data), encoding="utf-8")
        if stats:
            context.record.metadata.stats.setdefault("active_modules", {}).update(stats)
            context.manager.update_metadata(context.record)
            context.logger.info(
                "Active modules executed: %s",
                ", ".join(f"{name}={count}" for name, count in stats.items()),
            )


class SecretsDetectionStage(Stage):
    name = "secrets_detection"

    def is_enabled(self, context: PipelineContext) -> bool:
        if not context.runtime_config.enable_secrets:
            return False
        return context.runtime_config.secrets_max_files > 0

    def execute(self, context: PipelineContext) -> None:
        items = read_jsonl(context.record.paths.results_jsonl)
        if not items:
            return
        detector = SecretsDetector(timeout=context.runtime_config.secrets_timeout, verify_tls=bool(context.runtime_config.verify_tls))
        candidates: List[tuple[int, str, str]] = []  # (score, url, host)
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url or not isinstance(url, str):
                continue
            if not context.url_allowed(url):
                continue
            parsed = urlparse(url)
            ext = (parsed.path.split(".")[-1].lower() if "." in parsed.path else "")
            if ext not in {"js", "json", "env", "config", "txt", "properties", "yml", "yaml"}:
                continue
            score = int(entry.get("score", 0))
            host = entry.get("hostname") or parsed.hostname or ""
            candidates.append((score, url, host))
        if not candidates:
            context.logger.info("No URL candidates for secrets detection")
            return
        candidates.sort(reverse=True, key=lambda item: item[0])
        max_files = context.runtime_config.secrets_max_files
        selected_urls = [url for _, url, _ in candidates[:max_files]]
        results = detector.scan_urls(selected_urls, max_files)
        if not results:
            context.logger.info("Secrets detector found no matches")
            return

        artifacts_dir = context.record.paths.ensure_subdir("secrets")
        artifact_path = artifacts_dir / "matches.json"
        serialised = {
            url: [
                {
                    "pattern": match.pattern,
                    "value_hash": match.value_hash,
                    "length": match.length,
                    "entropy": match.entropy,
                    "start": match.start,
                    "end": match.end,
                }
                for match in matches
            ]
            for url, matches in results.items()
        }
        artifact_path.write_text(json.dumps(serialised, indent=2, sort_keys=True), encoding="utf-8")

        pattern_counter: Counter[str] = Counter()
        total_matches = 0
        for url, matches in results.items():
            if not context.url_allowed(url):
                continue
            host = urlparse(url).hostname or ""
            for match in matches:
                total_matches += 1
                pattern_counter[match.pattern] += 1
                score, priority = self._score_priority(match.confidence)
                context.results.append(
                    {
                        "type": "finding",
                        "source": "secrets-static",
                        "hostname": host,
                        "url": url,
                        "description": f"{match.pattern} ({match.confidence})",
                        "details": {
                            "pattern": match.pattern,
                            "value_hash": match.value_hash,
                            "length": match.length,
                            "entropy": match.entropy,
                            "location": {"start": match.start, "end": match.end},
                        },
                        "tags": ["secret", "static", match.confidence],
                        "score": score,
                        "priority": priority,
                    }
                )

        boosted_urls = {
            url: max(self._score_priority(match.confidence)[0] for match in matches)
            for url, matches in results.items()
            if matches
        }
        if boosted_urls:
            results_path = context.record.paths.results_jsonl
            updated_entries = []
            for entry in iter_jsonl(results_path):
                if entry.get("type") == "url":
                    entry_url = entry.get("url")
                    if entry_url in boosted_urls:
                        tags = set(entry.get("tags", []))
                        tags.update({"secret", "secret-hit"})
                        entry["tags"] = sorted(tags)
                        entry["score"] = max(int(entry.get("score", 0)), boosted_urls[entry_url])
                        entry["priority"] = enrich_utils.classify_priority(entry["score"])
                updated_entries.append(entry)
            tmp_path = results_path.with_suffix(".tmp")
            with tmp_path.open("w", encoding="utf-8") as handle:
                for entry in updated_entries:
                    json.dump(entry, handle, separators=(",", ":"), ensure_ascii=True)
                    handle.write("\n")
            tmp_path.replace(results_path)

        stats = context.record.metadata.stats.setdefault("secrets", {})
        stats.update(
            {
                "findings": total_matches,
                "urls": len(results),
                "patterns": dict(pattern_counter),
                "guidance": "Rotate/revoke affected keys and update secrets management immediately.",
            }
        )
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Secrets detection found %s matches across %s URLs", total_matches, len(results)
        )

    @staticmethod
    def _score_priority(confidence: str) -> tuple[int, str]:
        if confidence == "high":
            return 95, "critical"
        if confidence == "medium":
            return 80, "high"
        return 55, "medium"



class RuntimeCrawlStage(Stage):
    name = "runtime_crawl"
    optional = True

    def is_enabled(self, context: PipelineContext) -> bool:
        if not context.runtime_config.enable_runtime_crawl:
            return False
        max_urls = getattr(context.runtime_config, "runtime_crawl_max_urls", 0)
        return max_urls > 0

    @staticmethod
    def _dom_relpath(context: PipelineContext, artifact_dir: Path, url: str) -> Optional[str]:
        dom_name = dom_artifact_name(url)
        dom_path = artifact_dir / dom_name
        if not dom_path.exists():
            return None
        try:
            return str(dom_path.relative_to(context.record.paths.root))
        except ValueError:
            return str(dom_path)

    def execute(self, context: PipelineContext) -> None:
        logger = context.logger
        items = read_jsonl(context.record.paths.results_jsonl)
        if not items:
            logger.info("No results recorded; skipping runtime crawl stage")
            stats = context.record.metadata.stats.setdefault("runtime_crawl", {})
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "no_input",
                }
            )
            context.manager.update_metadata(context.record)
            return

        stats = context.record.metadata.stats.setdefault("runtime_crawl", {})
        max_urls = max(0, getattr(context.runtime_config, "runtime_crawl_max_urls", 0))
        per_host_limit = max(1, getattr(context.runtime_config, "runtime_crawl_per_host_limit", 3))
        timeout = max(1, getattr(context.runtime_config, "runtime_crawl_timeout", 15))
        concurrency = max(1, getattr(context.runtime_config, "runtime_crawl_concurrency", 2))

        if not PLAYWRIGHT_AVAILABLE:
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "playwright_missing",
                }
            )
            context.manager.update_metadata(context.record)
            logger.warning("playwright not installed; skipping runtime crawl stage")
            _note_missing_tool(context, "playwright")
            return

        candidates: List[tuple[int, str, str]] = []
        score_map: Dict[str, int] = {}
        seen_urls: set[str] = set()
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            if not context.url_allowed(url):
                continue
            if url in seen_urls:
                continue
            parsed = urlparse(url)
            host = entry.get("hostname") or parsed.hostname
            if not host:
                continue
            status = entry.get("status_code")
            if isinstance(status, int) and status >= 500:
                continue
            score = int(entry.get("score", 0))
            path_lower = (parsed.path or "").lower()
            content_type = str(entry.get("content_type") or "").lower()
            tags = entry.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            tags_lower = [str(tag).lower() for tag in tags]
            if path_lower.endswith(".js"):
                score += 60
            elif ".js" in path_lower:
                score += 25
            if "javascript" in content_type:
                score += 40
            if "api" in tags_lower:
                score += 10
            if "login" in tags_lower:
                score += 5
            if parsed.query:
                score += 5
            if score < 0:
                score = 0
            candidates.append((score, url, host))
            score_map[url] = score
            seen_urls.add(url)

        if not candidates:
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "no_candidates",
                }
            )
            context.manager.update_metadata(context.record)
            logger.info("Runtime crawl stage skipped; no eligible URL candidates")
            return

        candidates.sort(key=lambda item: item[0], reverse=True)

        selected_urls: List[str] = []
        host_counts: Dict[str, int] = defaultdict(int)
        for score, url, host in candidates:
            if host_counts[host] >= per_host_limit:
                continue
            selected_urls.append(url)
            host_counts[host] += 1
            if len(selected_urls) >= max_urls:
                break

        if not selected_urls:
            stats.update(
                {
                    "selected": 0,
                    "crawled": 0,
                    "success": 0,
                    "failures": 0,
                    "javascript_files": 0,
                    "status": "host_limit_exhausted",
                }
            )
            context.manager.update_metadata(context.record)
            logger.info("Runtime crawl stage skipped; host limits filtered all candidates")
            return

        logger.info(
            "Runtime crawl targeting %s URLs (timeout=%ss, concurrency=%s)",
            len(selected_urls),
            timeout,
            concurrency,
        )

        try:
            results = crawl_urls(selected_urls, timeout, concurrency)
        except Exception as exc:
            message = str(exc)
            missing_browsers = "playwright install" in message.lower() or "executable doesn't exist" in message.lower()
            stats.update(
                {
                    "selected": len(selected_urls),
                    "crawled": 0,
                    "success": 0,
                    "failures": len(selected_urls),
                    "javascript_files": 0,
                    "status": "playwright_browsers_missing" if missing_browsers else "crawl_error",
                    "error": message,
                }
            )
            context.manager.update_metadata(context.record)
            if missing_browsers:
                logger.warning("Playwright browsers not installed; skipping runtime crawl stage")
                _note_missing_tool(context, "playwright-browsers")
            else:
                logger.warning("Runtime crawl failed; skipping stage: %s", message)
            return
        if not results:
            stats.update(
                {
                    "selected": len(selected_urls),
                    "crawled": 0,
                    "success": 0,
                    "failures": len(selected_urls),
                    "javascript_files": 0,
                    "status": "crawl_failed",
                }
            )
            context.manager.update_metadata(context.record)
            logger.warning("Runtime crawl returned no results")
            return

        artifact_dir = context.record.paths.ensure_subdir("runtime_crawl")
        save_crawl_results(results, artifact_dir)

        success_count = sum(1 for result in results.values() if result.success)
        failure_count = len(results) - success_count
        javascript_total = sum(len(result.javascript_files) for result in results.values())

        stats.update(
            {
                "selected": len(selected_urls),
                "crawled": len(results),
                "success": success_count,
                "failures": failure_count,
                "javascript_files": javascript_total,
                "status": "completed",
            }
        )
        context.manager.update_metadata(context.record)

        appended = 0
        for url, result in results.items():
            if not context.url_allowed(url):
                continue
            artifact_rel = self._dom_relpath(context, artifact_dir, url)
            payload = {
                "type": "runtime_crawl",
                "source": "playwright",
                "url": url,
                "hostname": urlparse(url).hostname or "",
                "success": result.success,
                "javascript_files": result.javascript_files,
                "javascript_count": len(result.javascript_files),
                "errors": result.errors,
                "error_count": len(result.errors),
                "console_messages": result.console_messages,
                "console_count": len(result.console_messages),
                "network_requests": len(result.network),
                "score": score_map.get(url, 0),
            }
            if artifact_rel:
                payload["dom_artifact"] = artifact_rel
            if context.results.append(payload):
                appended += 1

        logger.info(
            "Runtime crawl completed: %s/%s successful, %s JS files discovered (%s new records)",
            success_count,
            len(results),
            javascript_total,
            appended,
        )


class JSIntelligenceStage(Stage):
    name = "js_intelligence"

    ENDPOINT_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
    RELATIVE_PATTERN = re.compile(r"/(?:api|graphql|v1|v2|v3|v4|auth|oauth|login|logout|register)[^\s\"'<>]*")
    SOURCEMAP_PATTERN = re.compile(r"sourceMappingURL=([^\s\"']+)")

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_js_intel", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("js intelligence requires requests; skipping")
            return
        items = read_jsonl(context.record.paths.results_jsonl)
        js_urls = []
        for entry in items:
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if not url or not isinstance(url, str):
                continue
            if url.lower().endswith(".js") or "javascript" in str(entry.get("content_type", "")).lower():
                if entry.get("status_code") in {200, 302}:
                    js_urls.append(url)
        if not js_urls:
            context.logger.info("No JS URLs for intelligence stage")
            return
        max_files = int(getattr(context.runtime_config, "js_intel_max_files", 40))
        timeout = int(getattr(context.runtime_config, "js_intel_timeout", 12))
        max_urls = int(getattr(context.runtime_config, "js_intel_max_urls", 120))
        js_urls = list(dict.fromkeys(js_urls))[:max_files]
        artifacts: List[Dict[str, object]] = []
        discovered_urls: List[str] = []
        for js_url in js_urls:
            try:
                resp = requests.get(
                    js_url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "recon-cli js-intel"},
                    verify=context.runtime_config.verify_tls,
                )
            except Exception:
                continue
            if resp.status_code >= 400:
                continue
            content = resp.text or ""
            endpoints = set(self.ENDPOINT_PATTERN.findall(content))
            rels = set(self.RELATIVE_PATTERN.findall(content))
            for rel in rels:
                endpoints.add(urljoin(js_url, rel))
            source_map = None
            map_match = self.SOURCEMAP_PATTERN.search(content)
            if map_match:
                source_map = urljoin(js_url, map_match.group(1))
                try:
                    map_resp = requests.get(
                        source_map,
                        timeout=timeout,
                        allow_redirects=True,
                        headers={"User-Agent": "recon-cli js-intel"},
                        verify=context.runtime_config.verify_tls,
                    )
                    if map_resp.status_code < 400 and map_resp.text:
                        try:
                            map_data = json.loads(map_resp.text)
                        except json.JSONDecodeError:
                            map_data = {}
                        sources_content = map_data.get("sourcesContent") or []
                        for source_blob in sources_content[:5]:
                            if not source_blob or not isinstance(source_blob, str):
                                continue
                            endpoints.update(self.ENDPOINT_PATTERN.findall(source_blob))
                            for rel in self.RELATIVE_PATTERN.findall(source_blob):
                                endpoints.add(urljoin(js_url, rel))
                except Exception:
                    pass
            endpoints = list(endpoints)[:max_urls]
            artifacts.append(
                {
                    "js_url": js_url,
                    "endpoints": endpoints,
                    "source_map": source_map,
                }
            )
            for endpoint in endpoints:
                if not context.url_allowed(endpoint):
                    continue
                payload = {
                    "type": "url",
                    "source": "js-intel",
                    "url": endpoint,
                    "hostname": urlparse(endpoint).hostname,
                    "tags": ["js:discovered", "source:js"],
                    "score": 30,
                }
                if context.results.append(payload):
                    discovered_urls.append(endpoint)
        if artifacts:
            artifact_path = context.record.paths.artifact("js_intel.json")
            artifact_path.write_text(json.dumps(artifacts, indent=2, sort_keys=True), encoding="utf-8")
            context.set_data("js_endpoints", discovered_urls)
            stats = context.record.metadata.stats.setdefault("js_intel", {})
            stats["files"] = len(artifacts)
            stats["endpoints"] = len(discovered_urls)
            context.manager.update_metadata(context.record)


class APIReconStage(Stage):
    name = "api_recon"

    PROBE_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/openapi.yaml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/swagger/v1/swagger.yaml",
        "/api-docs",
        "/graphql",
        "/graphiql",
        "/graphql/console",
    ]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_api_recon", False))

    def execute(self, context: PipelineContext) -> None:
        try:
            import requests
        except Exception:
            context.logger.warning("api recon requires requests; skipping")
            return
        hosts: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            host = entry.get("hostname") or (entry.get("url") and urlparse(entry["url"]).hostname)
            if host:
                hosts.append(host)
        if not hosts:
            return
        hosts = list(dict.fromkeys(hosts))
        max_hosts = int(getattr(context.runtime_config, "api_recon_max_hosts", 50))
        timeout = int(getattr(context.runtime_config, "api_recon_timeout", 8))
        specs_found = 0
        urls_added = 0
        for host in hosts[:max_hosts]:
            base = f"https://{host}"
            for path in self.PROBE_PATHS:
                url = urljoin(base, path)
                if not context.url_allowed(url):
                    continue
                try:
                    resp = requests.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers={"User-Agent": "recon-cli api-recon"},
                        verify=context.runtime_config.verify_tls,
                    )
                except Exception:
                    continue
                if resp.status_code >= 400:
                    continue
                text = resp.text or ""
                content_type = resp.headers.get("Content-Type", "").lower()
                if "graphql" in path:
                    if "graphql" in text.lower() or resp.status_code in {200, 400}:
                        payload = {
                            "type": "api",
                            "source": "api-recon",
                            "hostname": host,
                            "url": url,
                            "tags": ["api:graphql"],
                            "score": 40,
                        }
                        if context.results.append(payload):
                            urls_added += 1
                    continue
                if "json" in content_type or text.strip().startswith("{"):
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        data = {}
                    if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                        specs_found += 1
                        paths = data.get("paths") or {}
                        if isinstance(paths, dict):
                            for api_path in list(paths.keys())[:200]:
                                full_url = urljoin(base, api_path)
                                if not context.url_allowed(full_url):
                                    continue
                                payload = {
                                    "type": "url",
                                    "source": "api-spec",
                                    "url": full_url,
                                    "hostname": host,
                                    "tags": ["api:spec"],
                                    "score": 35,
                                }
                                if context.results.append(payload):
                                    urls_added += 1
                        spec_payload = {
                            "type": "api_spec",
                            "source": "api-recon",
                            "hostname": host,
                            "url": url,
                            "tags": ["api:openapi"],
                            "score": 40,
                        }
                        context.results.append(spec_payload)
        if specs_found or urls_added:
            stats = context.record.metadata.stats.setdefault("api_recon", {})
            stats["specs"] = specs_found
            stats["urls_added"] = urls_added
            context.manager.update_metadata(context.record)


class ParamMiningStage(Stage):
    name = "param_mining"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_param_mining", False))

    def execute(self, context: PipelineContext) -> None:
        candidates: List[str] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            url = entry.get("url")
            if url and "?" in url:
                candidates.append(url)
        js_endpoints = context.get_data("js_endpoints", []) or []
        for url in js_endpoints:
            if url and "?" in url:
                candidates.append(url)
        if not candidates:
            context.logger.info("No parameterized URLs found")
            return
        candidates = list(dict.fromkeys(candidates))
        max_urls = int(getattr(context.runtime_config, "param_mining_max_urls", 150))
        candidates = candidates[:max_urls]
        params = Counter()
        examples: Dict[str, List[str]] = defaultdict(list)
        for url in candidates:
            parsed = urlparse(url)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                params[name] += 1
                if len(examples[name]) < 3:
                    examples[name].append(url)
        max_params = int(getattr(context.runtime_config, "param_mining_max_params", 60))
        for name, count in params.most_common(max_params):
            payload = {
                "type": "parameter",
                "source": "param-mining",
                "name": name,
                "count": count,
                "examples": examples.get(name, []),
                "score": min(50, 10 + count),
                "tags": ["param"],
            }
            context.results.append(payload)
        artifact_path = context.record.paths.artifact("param_mining.json")
        artifact_path.write_text(
            json.dumps(
                {
                    "params": params.most_common(max_params),
                    "examples": examples,
                    "candidates": candidates,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context.set_data("param_urls", candidates)
        stats = context.record.metadata.stats.setdefault("param_mining", {})
        stats["params"] = min(len(params), max_params)
        stats["urls"] = len(candidates)
        context.manager.update_metadata(context.record)


class VulnScanStage(Stage):
    name = "vuln_scan"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_dalfox", False) or getattr(context.runtime_config, "enable_sqlmap", False))

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        candidates = context.get_data("param_urls", []) or []
        if not candidates:
            context.logger.info("No parameterized URLs for vuln scan")
            return
        artifacts_dir = context.record.paths.ensure_subdir("vuln_scans")
        findings = 0
        if getattr(context.runtime_config, "enable_dalfox", False) and executor.available("dalfox"):
            max_urls = int(getattr(context.runtime_config, "dalfox_max_urls", 20))
            timeout = int(getattr(context.runtime_config, "dalfox_timeout", 600))
            for url in candidates[:max_urls]:
                artifact = artifacts_dir / f"dalfox_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
                cmd = ["dalfox", "url", url]
                try:
                    result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
                except CommandError:
                    context.logger.warning("dalfox failed for %s", url)
                    continue
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                artifact.write_text(output, encoding="utf-8")
                if re.search(r"\bVULN\b|\bPOC\b|reflected", output, re.IGNORECASE):
                    payload = {
                        "type": "finding",
                        "source": "dalfox",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "Potential XSS detected by dalfox",
                        "details": {"output_snippet": output[:1000]},
                        "tags": ["xss", "dalfox"],
                        "score": 80,
                        "priority": "high",
                    }
                    if context.results.append(payload):
                        findings += 1
        if getattr(context.runtime_config, "enable_sqlmap", False) and executor.available("sqlmap"):
            max_urls = int(getattr(context.runtime_config, "sqlmap_max_urls", 10))
            timeout = int(getattr(context.runtime_config, "sqlmap_timeout", 900))
            level = int(getattr(context.runtime_config, "sqlmap_level", 1))
            risk = int(getattr(context.runtime_config, "sqlmap_risk", 1))
            for url in candidates[:max_urls]:
                artifact = artifacts_dir / f"sqlmap_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
                cmd = [
                    "sqlmap",
                    "-u",
                    url,
                    "--batch",
                    "--level",
                    str(level),
                    "--risk",
                    str(risk),
                    "--random-agent",
                    "--threads",
                    "2",
                    "--timeout",
                    "10",
                    "--retries",
                    "1",
                ]
                try:
                    result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
                except CommandError:
                    context.logger.warning("sqlmap failed for %s", url)
                    continue
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                artifact.write_text(output, encoding="utf-8")
                if re.search(r"parameter .* is vulnerable|sqlmap identified", output, re.IGNORECASE):
                    payload = {
                        "type": "finding",
                        "source": "sqlmap",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "Potential SQL injection detected by sqlmap",
                        "details": {"output_snippet": output[:1200]},
                        "tags": ["sqli", "sqlmap"],
                        "score": 85,
                        "priority": "high",
                    }
                    if context.results.append(payload):
                        findings += 1
        if findings:
            stats = context.record.metadata.stats.setdefault("vuln_scan", {})
            stats["findings"] = findings
            context.manager.update_metadata(context.record)



class TrimResultsStage(Stage):
    name = "trim_results"

    def execute(self, context: PipelineContext) -> None:
        results_path = context.record.paths.results_jsonl
        trimmed_path = context.record.paths.trimmed_results_jsonl
        if not results_path.exists():
            if trimmed_path.exists():
                try:
                    trimmed_path.unlink()
                except OSError:
                    pass
            context.logger.info("No results available for trimming")
            return

        runtime = context.runtime_config
        url_limit = max(runtime.trim_url_max_per_host, 0)
        finding_limit = max(runtime.trim_finding_max_per_host, 0)
        finding_min_score = max(runtime.trim_finding_min_score, 0)
        tag_limit = max(runtime.trim_tag_per_host_limit, 0)
        progress = ProgressLogger(context.logger, interval=2.0)
        progress = ProgressLogger(context.logger, interval=2.0)

        order = 0
        progress = ProgressLogger(context.logger, interval=2.0)
        url_best: Dict[str, tuple[int, int, Dict[str, object], str]] = {}
        finding_buckets: Dict[str, List[tuple[int, int, Dict[str, object], str]]] = defaultdict(list)
        low_priority_handle = None
        other_entries: List[tuple[int, Dict[str, object]]] = []

        stats: Dict[str, int] = {
            "urls_total": 0,
            "urls_unique": 0,
            "urls_retained": 0,
            "urls_dropped": 0,
            "findings_total": 0,
            "findings_retained": 0,
            "findings_low_priority": 0,
            "findings_dropped_limit": 0,
        }

        for entry in iter_jsonl(results_path):
            if not isinstance(entry, dict):
                continue
            order += 1
            progress.maybe(f"Trim progress: processed {order} entries")
            etype = entry.get("type")
            if etype == "url":
                stats["urls_total"] += 1
                cloned = self._clone_entry(entry)
                host = self._extract_host(cloned)
                if host and not cloned.get("hostname"):
                    cloned["hostname"] = host
                url_value = cloned.get("url")
                if not isinstance(url_value, str):
                    continue
                score = self._coerce_int(cloned.get("score", 0))
                existing = url_best.get(url_value)
                host_key = host or ""
                if existing:
                    prev_score, prev_order, _, _ = existing
                    if score > prev_score or (score == prev_score and order < prev_order):
                        url_best[url_value] = (score, order, cloned, host_key)
                else:
                    url_best[url_value] = (score, order, cloned, host_key)
                continue
            if etype == "finding":
                stats["findings_total"] += 1
                score = self._coerce_int(entry.get("score", 0))
                if score < finding_min_score:
                    if low_priority_handle is None:
                        trim_dir = context.record.paths.ensure_subdir("trim")
                        low_priority_path = trim_dir / "low_priority_findings.jsonl"
                        low_priority_handle = low_priority_path.open("w", encoding="utf-8")
                    json.dump(entry, low_priority_handle, separators=(",", ":"), ensure_ascii=True)
                    low_priority_handle.write("\n")
                    stats["findings_low_priority"] += 1
                    continue
                cloned = self._clone_entry(entry)
                host = cloned.get("hostname") or ""
                bucket = finding_buckets[host]
                item = (score, order, cloned, host)
                if finding_limit > 0:
                    if len(bucket) < finding_limit:
                        heapq.heappush(bucket, item)
                    else:
                        worst = bucket[0]
                        if score > worst[0] or (score == worst[0] and order < worst[1]):
                            heapq.heapreplace(bucket, item)
                            stats["findings_dropped_limit"] += 1
                        else:
                            stats["findings_dropped_limit"] += 1
                else:
                    bucket.append(item)
                continue
            other_entries.append((order, self._clone_entry(entry)))

        per_host_urls: Dict[str, List[tuple[int, int, Dict[str, object]]]] = defaultdict(list)
        for score, order_idx, entry_data, host in url_best.values():
            bucket = host or "__unknown__"
            per_host_urls[bucket].append((score, order_idx, entry_data))

        selected_urls: List[tuple[int, Dict[str, object]]] = []
        urls_dropped = 0
        for entries in per_host_urls.values():
            entries.sort(key=lambda item: (-item[0], item[1]))
            limit = len(entries) if url_limit <= 0 else min(url_limit, len(entries))
            keep = entries[:limit]
            urls_dropped += len(entries) - len(keep)
            for _, order_idx, entry_data in keep:
                selected_urls.append((order_idx, entry_data))
        stats["urls_unique"] = len(url_best)
        stats["urls_retained"] = len(selected_urls)
        stats["urls_dropped"] = urls_dropped

        selected_findings: List[tuple[int, Dict[str, object]]] = []
        for bucket in finding_buckets.values():
            ordered = sorted(bucket, key=lambda item: (-item[0], item[1]))
            for _, order_idx, entry_data, _ in ordered:
                selected_findings.append((order_idx, entry_data))
        stats["findings_retained"] = len(selected_findings)

        final_entries = other_entries + selected_findings + selected_urls
        final_entries.sort(key=lambda item: item[0])

        tag_tracker: Dict[str, Counter] = defaultdict(Counter)
        for _, entry in final_entries:
            host = self._extract_host(entry)
            if host:
                self._apply_tag_limit(entry, host, tag_tracker, tag_limit)

        with trimmed_path.open("w", encoding="utf-8") as handle:
            for _, entry in final_entries:
                json.dump(entry, handle, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")

        trim_dir = context.record.paths.ensure_subdir("trim")
        low_priority_path = trim_dir / "low_priority_findings.jsonl"
        if low_priority_handle:
            low_priority_handle.close()
        elif low_priority_path.exists():
            low_priority_path.unlink()

        stats["entries_written"] = len(final_entries)
        context.record.metadata.stats["trim"] = stats
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Trimmed results to %s entries (%s/%s URLs, %s/%s findings)",
            stats["entries_written"],
            stats["urls_retained"],
            stats["urls_total"],
            stats["findings_retained"],
            stats["findings_total"],
        )

    @staticmethod
    def _clone_entry(entry: Dict[str, object]) -> Dict[str, object]:
        cloned = dict(entry)
        tags = entry.get("tags")
        if isinstance(tags, list):
            cloned["tags"] = list(tags)
        return cloned

    @staticmethod
    def _extract_host(entry: Dict[str, object]) -> str:
        host = entry.get("hostname")
        if isinstance(host, str) and host:
            return host
        url_value = entry.get("url")
        if isinstance(url_value, str):
            try:
                parsed = urlparse(url_value)
            except ValueError:
                return ""
            return parsed.hostname or ""
        return ""

    @staticmethod
    def _apply_tag_limit(entry: Dict[str, object], host: str, tracker: Dict[str, Counter], limit: int) -> None:
        if limit <= 0:
            return
        tags = entry.get("tags")
        if not isinstance(tags, list) or not host:
            return
        counter = tracker.setdefault(host, Counter())
        filtered: List[str] = []
        mutated = False
        for tag in tags:
            count = counter[tag]
            if count >= limit:
                mutated = True
                continue
            counter[tag] = count + 1
            filtered.append(tag)
        if filtered:
            if mutated:
                entry["tags"] = filtered
        else:
            entry.pop("tags", None)

    @staticmethod
    def _coerce_int(value: object) -> int:
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0
class CorrelationStage(Stage):
    name = "correlation"

    def execute(self, context: PipelineContext) -> None:
        results_path = context.record.paths.results_jsonl
        trimmed_path = context.record.paths.trimmed_results_jsonl
        logger = context.logger
        source_path = trimmed_path if trimmed_path.exists() else results_path
        if trimmed_path.exists():
            logger.info("Correlation using trimmed results (%s)", trimmed_path.name)
        records = iter_jsonl(source_path)
        if records is None:
            logger.info("No results recorded; skipping correlation stage")
            return

        graph = Graph()
        ip_hosts: Dict[str, set] = defaultdict(set)
        asn_hosts: Dict[str, set] = defaultdict(set)
        provider_hosts: Dict[str, set] = defaultdict(set)
        api_endpoints: Dict[str, set] = defaultdict(set)
        tech_counter = Counter()
        features_by_host: Dict[str, Dict[str, float]] = defaultdict(lambda: {key: 0.0 for key in FEATURE_KEYS})
        tag_histogram: Dict[str, Counter] = defaultdict(Counter)

        processed = 0
        runtime = context.runtime_config
        max_records = max(0, getattr(runtime, "correlation_max_records", 0))
        svg_node_limit = max(0, getattr(runtime, "correlation_svg_node_limit", 0))
        truncated = False
        urls_seen = 0
        api_path_total = 0
        seen_any = False
        progress = ProgressLogger(context.logger, interval=2.0)

        registered_hosts: Dict[str, Tuple[str, str]] = {}

        def ensure_host(host: str) -> Tuple[str, str]:
            if host in registered_hosts:
                return registered_hosts[host]
            root = root_domain(host)
            graph.add_node("domain", root)
            graph.add_node("subdomain", host)
            graph.add_edge("subdomain", host, "belongs_to", "domain", root)
            registered_hosts[host] = (root, host)
            return registered_hosts[host]

        for entry in records:
            if max_records and processed >= max_records:
                truncated = True
                logger.info(
                    "Correlation truncated after %s records (limit=%s)",
                    processed,
                    max_records,
                )
                break
            seen_any = True
            processed += 1
            progress.maybe(
                f"Correlation processed {processed} records (hosts={len(features_by_host)}, urls={urls_seen}, apis={api_path_total})"
            )

            etype = entry.get("type")
            if etype == "hostname":
                host = entry.get("hostname")
                if not host:
                    continue
                root, subdomain = ensure_host(host)
                graph.add_node("domain", root, sources=[entry.get("source")])
                graph.add_node("subdomain", subdomain, tags=entry.get("tags"))
                _ = features_by_host[subdomain]
            elif etype == "asset":
                host = entry.get("hostname")
                ip = entry.get("ip")
                if not host or not ip:
                    continue
                root, subdomain = ensure_host(host)
                features = features_by_host[subdomain]
                graph.add_node(
                    "ip",
                    ip,
                    record_type=entry.get("record_type"),
                    org=entry.get("org"),
                    country=entry.get("country"),
                )
                graph.add_edge("subdomain", subdomain, "resolves_to", "ip", ip, source=entry.get("source"))
                ip_hosts[ip].add(subdomain)
                features["asn_score"] = max(features.get("asn_score", 0.0), compute_asn_score(entry.get("asn")))
                asn = entry.get("asn")
                if asn:
                    graph.add_node("asn", asn, org=entry.get("org"))
                    graph.add_edge("ip", ip, "belongs_to", "asn", asn)
                    asn_hosts[asn].add(subdomain)
            elif etype == "asset_enrichment":
                host = entry.get("hostname")
                ip = entry.get("ip")
                provider = entry.get("provider")
                subdomain = None
                if host:
                    root, subdomain = ensure_host(host)
                if ip:
                    graph.add_node("ip", ip)
                if subdomain and ip:
                    graph.add_edge("subdomain", subdomain, "resolves_to", "ip", ip)
                if provider and subdomain:
                    graph.add_node("provider", provider)
                    graph.add_edge("subdomain", subdomain, "served_by", "provider", provider)
                    provider_hosts[provider].add(subdomain)
            elif etype == "url":
                url = entry.get("url")
                if not url:
                    continue
                urls_seen += 1
                host = entry.get("hostname") or urlparse(url).hostname
                tags = list(entry.get("tags", []))
                graph.add_node(
                    "url",
                    url,
                    status=entry.get("status_code"),
                    tags=tags,
                    priority=entry.get("priority"),
                )
                subdomain = None
                if host:
                    root, subdomain = ensure_host(host)
                    graph.add_edge("subdomain", subdomain, "serves", "url", url, status=entry.get("status_code"))
                    features = features_by_host[subdomain]
                    features["url_count"] = features.get("url_count", 0.0) + 1.0
                parsed = urlparse(url)
                if parsed.path.endswith(".js"):
                    graph.add_edge("url", url, "category", "resource", "javascript")
                if "/api" in (parsed.path or ""):
                    endpoint_host = subdomain or parsed.netloc or ""
                    if endpoint_host:
                        if endpoint_host != subdomain:
                            _, endpoint_host = ensure_host(endpoint_host)
                        path_value = parsed.path or "/"
                        paths = api_endpoints[endpoint_host]
                        if path_value not in paths:
                            paths.add(path_value)
                            api_path_total += 1
                        graph.add_edge("subdomain", endpoint_host, "exposes_api", "endpoint", path_value)
                        features_by_host[endpoint_host]["has_api"] = 1.0
                    if "service:api" not in tags:
                        tags.append("service:api")
                    graph.add_node("url", url, tags=tags)
                if tags:
                    if subdomain:
                        tag_histogram[subdomain].update(tags)
                        if any(tag in {"surface:login", "service:sso", "surface:admin"} for tag in tags):
                            features_by_host[subdomain]["has_login"] = 1.0
                    for tag in tags:
                        graph.add_node("tag", tag)
                        graph.add_edge("url", url, "tag", "tag", tag)
                        if subdomain:
                            graph.add_edge("subdomain", subdomain, "has_tag", "tag", tag)
                if parsed.query:
                    params = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
                    if params:
                        graph.add_edge("url", url, "has_params", "param_group", ",".join(sorted(params)))
                server = entry.get("server")
                if server:
                    tech_label = server.lower()
                    graph.add_node("tech", tech_label)
                    graph.add_edge("url", url, "served_by", "tech", tech_label)
                    if subdomain:
                        graph.add_edge("subdomain", subdomain, "uses", "tech", tech_label)
                    tech_counter[f"server:{tech_label}"] += 1
                for tag in entry.get("tags", []):
                    if tag.startswith("service:") or tag.startswith("env:"):
                        tech_counter[tag] += 1
                        graph.add_node("tag", tag)
                        graph.add_edge("url", url, "tag", "tag", tag)
                        if subdomain:
                            graph.add_edge("subdomain", subdomain, "has_tag", "tag", tag)
            elif etype == "finding":
                description = entry.get("description") or entry.get("url") or entry.get("hostname") or "finding"
                finding_id = f"{entry.get('source','finding')}::{hash(description)}"
                graph.add_node("finding", finding_id, description=description, priority=entry.get("priority"), score=entry.get("score"))
                host = entry.get("hostname")
                if host:
                    root, subdomain = ensure_host(host)
                    graph.add_edge("finding", finding_id, "impacts", "subdomain", subdomain)
                    features = features_by_host[subdomain]
                    features["finding_count"] = features.get("finding_count", 0.0) + 1.0
                    source = str(entry.get("source", ""))
                    if source.startswith("active-js-secrets") or source.startswith("secrets"):
                        hits = entry.get("details", {}).get("hits")
                        increment = float(len(hits)) if isinstance(hits, list) and hits else 1.0
                        features["js_secrets_count"] = features.get("js_secrets_count", 0.0) + increment
                url = entry.get("details", {}).get("url") or entry.get("url")
                if url:
                    graph.add_node("url", url)
                    graph.add_edge("finding", finding_id, "references", "url", url)

        if not seen_any:
            logger.info("No results recorded; skipping correlation stage")
            return

        logger.info(
            "Correlation building artifacts from %s records (hosts=%s, urls=%s, apis=%s)",
            processed,
            len(features_by_host),
            urls_seen,
            api_path_total,
        )

        artifacts_dir = context.record.paths.ensure_subdir("correlation")
        graph_path = artifacts_dir / "graph.json"
        try:
            graph.save(graph_path)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to save correlation graph JSON: %s", exc)
            graph_path = None
        svg_path = artifacts_dir / "graph.svg"
        node_count = graph.node_count()
        svg_generated = False
        if svg_node_limit and node_count > svg_node_limit:
            logger.info(
                "Skipping SVG generation; node count %s exceeds limit %s",
                node_count,
                svg_node_limit,
            )
        else:
            try:
                svg_generated = graph.save_svg(svg_path)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to render correlation SVG: %s", exc)
                svg_generated = False

        clusters = {
            "ip": [
                {"value": ip, "hosts": sorted(hosts)}
                for ip, hosts in ip_hosts.items()
                if len(hosts) > 1
            ],
            "asn": [
                {"value": asn, "hosts": sorted(hosts)}
                for asn, hosts in asn_hosts.items()
                if len(hosts) > 1
            ],
            "provider": [
                {"value": provider, "hosts": sorted(hosts)}
                for provider, hosts in provider_hosts.items()
                if len(hosts) > 1
            ],
        }
        (artifacts_dir / "clusters.json").write_text(json.dumps(clusters, indent=2, sort_keys=True), encoding="utf-8")

        if tech_counter:
            (artifacts_dir / "tech_summary.json").write_text(
                json.dumps(dict(tech_counter.most_common()), indent=2, sort_keys=True),
                encoding="utf-8",
            )

        api_report = {host: sorted(paths) for host, paths in api_endpoints.items() if paths}
        if api_report:
            (artifacts_dir / "api_endpoints.json").write_text(
                json.dumps(api_report, indent=2, sort_keys=True), encoding="utf-8"
            )
        api_clusters = [
            {"subdomain": host, "paths": sorted(paths), "count": len(paths)}
            for host, paths in api_endpoints.items()
            if len(paths) > 1
        ]
        api_clusters.sort(key=lambda item: item["count"], reverse=True)

        provider_common = [
            {"provider": provider, "hosts": sorted(hosts), "count": len(hosts)}
            for provider, hosts in provider_hosts.items()
        ]
        provider_common.sort(key=lambda item: item["count"], reverse=True)

        top_nodes = graph.top_connected(limit=10)

        correlation_summary = {
            "graph_nodes": node_count,
            "graph_edges": graph.edge_count(),
            "ip_clusters": len(clusters["ip"]),
            "asn_clusters": len(clusters["asn"]),
            "provider_clusters": len(clusters["provider"]),
            "api_hosts": len(api_report),
            "top_nodes": top_nodes,
            "top_api_clusters": api_clusters[:10],
            "common_providers": provider_common[:10],
            "truncated": truncated,
            "max_records": max_records,
            "processed": processed,
        }
        if svg_generated:
            correlation_summary["graph_svg"] = str(svg_path)
        (artifacts_dir / "correlation_report.json").write_text(
            json.dumps(
                {
                    "summary": correlation_summary,
                    "top_ip_clusters": clusters["ip"][:5],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        for host, counter in tag_histogram.items():
            total = sum(counter.values())
            if total:
                entropy = 0.0
                for count in counter.values():
                    p = count / total
                    entropy -= p * math.log2(p)
                features_by_host[host]["tag_entropy"] = entropy

        features_payload = {host: {key: float(value) for key, value in features.items()} for host, features in features_by_host.items()}
        (artifacts_dir / "features.json").write_text(json.dumps(features_payload, indent=2, sort_keys=True), encoding="utf-8")

        stats = context.record.metadata.stats.setdefault("correlation", {})
        stats.update(correlation_summary)
        if tech_counter:
            stats["top_tags"] = tech_counter.most_common(10)
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Correlation graph built (nodes=%s, edges=%s)",
            graph.node_count(),
            graph.edge_count(),
        )





class LearningStage(Stage):
    name = "learning"

    def execute(self, context: PipelineContext) -> None:
        features_path = context.record.paths.artifact("correlation/features.json")
        if not features_path.exists():
            context.logger.info("No correlation features found; skipping learning stage")
            return
        try:
            features_payload = json.loads(features_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            context.logger.warning("Invalid features artifact; skipping learning stage")
            return
        if not isinstance(features_payload, dict):
            context.logger.warning("Unexpected features format; skipping learning stage")
            return

        if DatasetStore is None or HostFeatures is None or LearningModel is None:
            context.logger.warning("Learning dependencies unavailable; skipping learning stage")
            return

        learning_root = config.RECON_HOME / "learning"
        store = DatasetStore(learning_root)
        job_id = context.record.spec.job_id
        host_features: List[HostFeatures] = []
        records = []
        for host, feats in features_payload.items():
            feature_vector = {key: float(feats.get(key, 0.0)) for key in FEATURE_KEYS}
            host_feature = HostFeatures(host=host, features=feature_vector)
            host_features.append(host_feature)
            records.append(host_feature.to_record(job_id))
        if not records:
            context.logger.info("No host features available for learning stage")
            return

        store.append(records)
        labeled = store.load_labeled()
        try:
            model = LearningModel(learning_root, FEATURE_KEYS)
            trained = model.train(labeled) if labeled else False
            predictions = model.predict(host_features)
        except Exception as exc:  # pragma: no cover - optional dependency
            context.logger.warning("Learning model unavailable; skipping learning stage: %s", exc)
            return

        artifacts_dir = context.record.paths.ensure_subdir("learning")
        predictions_path = artifacts_dir / "predictions.json"
        if predictions:
            predictions_path.write_text(json.dumps(predictions, indent=2, sort_keys=True), encoding="utf-8")
            for host, probability in sorted(predictions.items(), key=lambda item: item[1], reverse=True):
                context.results.append(
                    {
                        "type": "learning_prediction",
                        "source": "learning",
                        "hostname": host,
                        "probability": probability,
                    }
                )
        stats = context.record.metadata.stats.setdefault("learning", {})
        stats.update(
            {
                "trained": bool(trained),
                "predictions": len(predictions),
            }
        )
        if predictions:
            stats["top_hosts"] = [[host, float(prob)] for host, prob in sorted(predictions.items(), key=lambda item: item[1], reverse=True)[:5]]
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Learning stage completed (trained=%s, predictions=%s)",
            trained,
            len(predictions),
        )

class ScannerStage(Stage):
    name = "scanner"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(context.record.spec.scanners) or bool(getattr(context.runtime_config, "auto_scanners", True))

    def execute(self, context: PipelineContext) -> None:
        if scanner_integrations is None:
            context.logger.warning("Scanner integrations unavailable; skipping scanner stage")
            return
        scanners = [s.lower() for s in context.record.spec.scanners]
        if not scanners and getattr(context.runtime_config, "auto_scanners", True):
            scanners = ["nuclei", "wpscan"]
        if not scanners:
            return
        available = []
        for scanner in scanners:
            if scanner not in scanner_integrations.available_scanners():
                context.logger.warning("Unknown scanner requested: %s", scanner)
                continue
            if not CommandExecutor.available(scanner):
                context.logger.info("Scanner %s not available in PATH; skipping", scanner)
                continue
            available.append(scanner)
        if not available:
            context.logger.info("No scanners to execute after availability checks")
            return

        items = read_jsonl(context.record.paths.results_jsonl)
        url_entries = [entry for entry in items if entry.get("type") == "url"]
        if not url_entries:
            context.logger.info("No URL entries available for scanner stage")
            return

        host_info: Dict[str, Dict[str, object]] = {}
        for entry in url_entries:
            host = entry.get("hostname") or (entry.get("url") and urlparse(entry["url"]).hostname)
            if not host:
                continue
            data = host_info.setdefault(host, {"urls": [], "tags": set(), "servers": set(), "api": False, "technologies": set()})
            url = entry.get("url")
            if url:
                data["urls"].append(url)
                path = urlparse(url).path.lower()
                if "/api" in path:
                    data["api"] = True
            for tag in entry.get("tags", []):
                data["tags"].add(tag)
                if tag == "service:api":
                    data["api"] = True
            server = entry.get("server")
            if server:
                data["servers"].add(server.lower())
            technologies = entry.get("technologies") or []
            if isinstance(technologies, list):
                data["technologies"].update({str(item).lower() for item in technologies if item})
            elif technologies:
                data["technologies"].add(str(technologies).lower())

        runtime = context.runtime_config
        scanner_dir = context.record.paths.ensure_subdir("scanners")
        summary: Dict[str, Dict[str, object]] = {}

        if "nuclei" in available:
            api_hosts = [host for host, info in host_info.items() if info.get("api")]
            if not api_hosts:
                api_hosts = list(host_info.keys())
            api_hosts = api_hosts[: runtime.max_scanner_hosts]
            findings: List[scanner_integrations.ScannerFinding] = []
            nuclei_tags: List[str] = []
            if getattr(runtime, "nuclei_tags", None):
                nuclei_tags = [tag.strip() for tag in str(runtime.nuclei_tags).split(",") if tag.strip()]
            targets: List[str] = []
            for host in api_hosts:
                urls = host_info[host]["urls"]
                base_url = urls[0] if urls else f"https://{host}"
                targets.append(base_url)
            batch_size = max(1, int(getattr(runtime, "nuclei_batch_size", 1)))
            pending_batches = [targets[i:i + batch_size] for i in range(0, len(targets), batch_size)]
            timed_out_batches = 0
            batches_run = 0
            retried_singles: Set[str] = set()
            while pending_batches:
                batch = pending_batches.pop(0)
                if not batch:
                    continue
                computed_timeout = int(getattr(runtime, "nuclei_batch_timeout_base", 300)) + int(
                    getattr(runtime, "nuclei_batch_timeout_per_target", 45)
                ) * len(batch)
                max_timeout = int(getattr(runtime, "nuclei_batch_timeout_max", runtime.scanner_timeout))
                if max_timeout < runtime.scanner_timeout:
                    max_timeout = runtime.scanner_timeout
                batch_timeout = min(max_timeout, max(computed_timeout, runtime.scanner_timeout))
                result = scanner_integrations.run_nuclei_batch(
                    context.executor,
                    context.logger,
                    batch,
                    scanner_dir,
                    batch_timeout,
                    tags=nuclei_tags or None,
                    request_timeout=int(getattr(runtime, "nuclei_timeout", 10)),
                    retries=int(getattr(runtime, "nuclei_retries", 1)),
                )
                batches_run += 1
                for finding in result.findings:
                    context.results.append(finding.payload)
                findings.extend(result.findings)
                if result.stats.get("timed_out"):
                    timed_out_batches += 1
                    if len(batch) > 1:
                        mid = len(batch) // 2
                        pending_batches.insert(0, batch[mid:])
                        pending_batches.insert(0, batch[:mid])
                    else:
                        single_target = batch[0]
                        if single_target not in retried_singles:
                            retried_singles.add(single_target)
                            single_timeout = int(getattr(runtime, "nuclei_single_timeout", batch_timeout))
                            retry_result = scanner_integrations.run_nuclei_batch(
                                context.executor,
                                context.logger,
                                batch,
                                scanner_dir,
                                max(single_timeout, batch_timeout),
                                tags=nuclei_tags or None,
                                request_timeout=int(getattr(runtime, "nuclei_timeout", 10)),
                                retries=int(getattr(runtime, "nuclei_retries", 1)),
                            )
                            batches_run += 1
                            for finding in retry_result.findings:
                                context.results.append(finding.payload)
                            findings.extend(retry_result.findings)
            summary["nuclei"] = {
                "targets": len(api_hosts),
                "findings": len(findings),
                "batches": batches_run,
                "timeouts": timed_out_batches,
            }

        if "wpscan" in available:
            def is_wordpress(info: Dict[str, object]) -> bool:
                tags = {t.lower() for t in info.get("tags", set())}
                if any("wordpress" in tag for tag in tags):
                    return True
                techs = info.get("technologies", set())
                if any("wordpress" in tech for tech in techs):
                    return True
                servers = info.get("servers", set())
                if any("wordpress" in server for server in servers):
                    return True
                urls = info.get("urls", [])
                for url in urls:
                    path = urlparse(url).path.lower()
                    if any(token in path for token in ("/wp-", "/wp-admin", "/wp-content", "/wp-json", "/xmlrpc.php")):
                        return True
                return False

            wp_hosts = [host for host, info in host_info.items() if is_wordpress(info)]
            wp_hosts = wp_hosts[: runtime.max_scanner_hosts]
            findings = []
            for host in wp_hosts:
                urls = host_info[host]["urls"]
                base_url = urls[0] if urls else f"https://{host}"
                result = scanner_integrations.run_wpscan(
                    context.executor,
                    context.logger,
                    host,
                    base_url,
                    scanner_dir,
                    runtime.scanner_timeout,
                )
                for finding in result.findings:
                    context.results.append(finding.payload)
                findings.extend(result.findings)
            summary["wpscan"] = {
                "targets": len(wp_hosts),
                "findings": len(findings),
            }

        if summary:
            stats = context.record.metadata.stats.setdefault("scanners", {})
            for name, data in summary.items():
                stats[name] = data
            context.manager.update_metadata(context.record)
            context.logger.info(
                "Scanner summary: %s",
                ", ".join(f"{name}:{data['findings']}" for name, data in summary.items()),
            )

class ScreenshotStage(Stage):
    name = "screenshots"

    def is_enabled(self, context: PipelineContext) -> bool:
        spec = context.record.spec
        if not context.runtime_config.enable_screenshots and not spec.max_screenshots:
            return False
        if spec.profile != "full" and not spec.max_screenshots:
            return False
        return True

    def execute(self, context: PipelineContext) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            context.logger.warning("playwright not installed; skipping screenshots")
            _note_missing_tool(context, "playwright")
            return
        max_shots = context.record.spec.max_screenshots or context.runtime_config.max_screenshots
        candidates = self._select_urls(context, max_shots)
        if not candidates:
            context.logger.info("No URLs eligible for screenshots")
            return
        screenshots_dir = context.record.paths.ensure_subdir("screenshots")
        hars_dir = context.record.paths.ensure_subdir("hars")
        manifest: List[Dict[str, object]] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context.logger.info("Capturing screenshots for %s URLs", len(candidates))
            for idx, entry in enumerate(candidates, start=1):
                url = entry["url"]
                screenshot_path = screenshots_dir / f"shot_{idx}.png"
                html_path = screenshots_dir / f"shot_{idx}.html"
                har_path = hars_dir / f"shot_{idx}.har"
                payload = None
                browser_context = None
                page = None
                try:
                    browser_context = browser.new_context(record_har_path=str(har_path))
                    page = browser_context.new_page()
                    page.goto(url, timeout=15000, wait_until="networkidle")
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    html_path.write_text(page.content(), encoding="utf-8")
                    hostname = urlparse(page.url).hostname or ""
                    payload = {
                        "type": "screenshot",
                        "source": "playwright",
                        "hostname": hostname,
                        "url": url,
                        "final_url": page.url,
                        "score": entry.get("score"),
                        "selection_source": entry.get("source"),
                        "selection_tags": entry.get("tags"),
                        "selection_reason": entry.get("reason"),
                        "screenshot_path": str(screenshot_path.relative_to(context.record.paths.root)),
                    }
                except Exception as exc:
                    if browser_context is None:
                        context.logger.warning("Failed to initialize browser context for %s: %s", url, exc)
                    else:
                        context.logger.warning("Failed to screenshot %s: %s", url, exc)
                finally:
                    if page is not None:
                        try:
                            page.close()
                        except Exception:
                            pass
                    if browser_context is not None:
                        try:
                            browser_context.close()
                        except Exception:
                            pass
                if payload:
                    if har_path.exists():
                        payload["har_path"] = str(har_path.relative_to(context.record.paths.root))
                    if html_path.exists():
                        payload["html_path"] = str(html_path.relative_to(context.record.paths.root))
                    context.results.append(payload)
                    manifest.append(payload)
            browser.close()
        if manifest:
            manifest_path = screenshots_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
            stats = context.record.metadata.stats.setdefault("screenshots", {})
            stats["count"] = len(manifest)
            stats["manifest"] = str(manifest_path.relative_to(context.record.paths.root))
            context.manager.update_metadata(context.record)

    def _select_urls(self, context: PipelineContext, limit: int) -> List[Dict[str, object]]:
        urls: List[Dict[str, object]] = []
        for entry in read_jsonl(context.record.paths.results_jsonl):
            if entry.get("type") != "url":
                continue
            status = entry.get("status_code")
            if status not in {200, 302}:
                continue
            url = entry.get("url")
            if not url:
                continue
            score = int(entry.get("score", 0))
            urls.append(
                {
                    "url": url,
                    "score": score,
                    "source": entry.get("source"),
                    "tags": entry.get("tags", []),
                    "reason": f"score={score} source={entry.get('source')}",
                }
            )
        urls.sort(key=lambda item: item.get("score", 0), reverse=True)
        return urls[:limit]


class FinalizeStage(Stage):
    name = "finalize"

    def execute(self, context: PipelineContext) -> None:
        from recon_cli.jobs import summary

        summary.generate_summary(context)


from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.pipeline.stage_auth_matrix import AuthMatrixStage

PIPELINE_STAGES: List[Stage] = [
    NormalizeStage(),
    PassiveEnumerationStage(),
    DedupeStage(),
    ResolveStage(),
    EnrichmentStage(),
    NmapStage(),
    HttpProbeStage(),
    ScoringStage(),
    AuthDiscoveryStage(),
    WafProbeStage(),
    IDORStage(),
    AuthMatrixStage(),
    FuzzStage(),
    ActiveIntelligenceStage(),
    SecretsDetectionStage(),
    RuntimeCrawlStage(),
    JSIntelligenceStage(),
    APIReconStage(),
    ParamMiningStage(),
    VulnScanStage(),
    TrimResultsStage(),
    CorrelationStage(),
    LearningStage(),
    ScannerStage(),
    ScreenshotStage(),
    FinalizeStage(),
]




