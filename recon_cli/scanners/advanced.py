"""
Advanced Scanner Integrations - تكاملات ماسحات متقدمة

تكاملات مع أدوات أمنية إضافية:
- uncover: اكتشاف سلبي للـ subdomains
- naabu: فحص سريع للمنافذ
- dalfox: فحص XSS
- sqlmap: فحص SQL Injection

Example:
    >>> scanner = NaabuScanner()
    >>> results = await scanner.scan(["example.com"])
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon_cli.tools.executor import CommandExecutor

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     Base Scanner
# ═══════════════════════════════════════════════════════════


@dataclass
class ScanResult:
    """نتيجة فحص"""

    target: str
    scanner: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    exit_code: int = 0
    duration: float = 0.0
    error: Optional[str] = None

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return self.count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scanner": self.scanner,
            "findings_count": self.count,
            "findings": self.findings,
            "duration": self.duration,
            "error": self.error,
        }


class BaseScanner(ABC):
    """Base class لجميع الماسحات"""

    name: str = "base"
    tool_name: str = "tool"

    def __init__(
        self,
        timeout: float = 300.0,
        threads: int = 10,
        extra_args: Optional[List[str]] = None,
    ):
        self.timeout = timeout
        self.threads = threads
        self.extra_args = extra_args or []
        self.executor = CommandExecutor()

    @abstractmethod
    def build_command(
        self,
        targets: List[str],
        output_file: Path,
    ) -> List[str]:
        """بناء الأمر"""
        pass

    @abstractmethod
    def parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        """تحليل المخرجات"""
        pass

    async def scan(
        self,
        targets: List[str],
        **kwargs,
    ) -> ScanResult:
        """
        تنفيذ الفحص.

        Args:
            targets: قائمة الأهداف

        Returns:
            ScanResult
        """
        import time

        start = time.time()

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as output_file:
            output_path = Path(output_file.name)

        try:
            command = self.build_command(targets, output_path)

            logger.info("Running %s on %d targets", self.name, len(targets))

            result = await self.executor.run_async(
                command,
                timeout=self.timeout,  # type: ignore[arg-type]
            )

            findings: List[Dict[str, object]] = []
            if output_path.exists():
                findings = self.parse_output(output_path)

            return ScanResult(
                target=targets[0] if len(targets) == 1 else f"{len(targets)} targets",
                scanner=self.name,
                findings=findings,
                raw_output=result.stdout,
                exit_code=result.returncode,
                duration=time.time() - start,
            )

        except asyncio.TimeoutError:
            return ScanResult(
                target=targets[0] if len(targets) == 1 else f"{len(targets)} targets",
                scanner=self.name,
                error=f"Timeout after {self.timeout}s",
                duration=time.time() - start,
            )
        except Exception as e:
            return ScanResult(
                target=targets[0] if len(targets) == 1 else f"{len(targets)} targets",
                scanner=self.name,
                error=str(e),
                duration=time.time() - start,
            )
        finally:
            if output_path.exists():
                output_path.unlink()


# ═══════════════════════════════════════════════════════════
#                     Uncover Scanner
# ═══════════════════════════════════════════════════════════


class UncoverScanner(BaseScanner):
    """
    Uncover - اكتشاف سلبي للأصول.

    يستخدم APIs متعددة: Shodan, Censys, Fofa, etc.

    Example:
        >>> scanner = UncoverScanner(engines=["shodan", "censys"])
        >>> result = await scanner.scan(["example.com"])
    """

    name = "uncover"
    tool_name = "uncover"

    SUPPORTED_ENGINES = [
        "shodan",
        "censys",
        "fofa",
        "quake",
        "hunter",
        "zoomeye",
        "netlas",
        "criminalip",
        "publicwww",
    ]

    def __init__(
        self,
        engines: Optional[List[str]] = None,
        limit: int = 100,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.engines = engines or ["shodan", "censys"]
        self.limit = limit

    def build_command(
        self,
        targets: List[str],
        output_file: Path,
    ) -> List[str]:
        cmd = [
            self.tool_name,
            "-q",
            ",".join(targets),
            "-o",
            str(output_file),
            "-json",
            "-limit",
            str(self.limit),
        ]

        for engine in self.engines:
            if engine in self.SUPPORTED_ENGINES:
                cmd.extend(["-e", engine])

        cmd.extend(self.extra_args)
        return cmd

    def parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, object]] = []

        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(
                        {
                            "type": "asset",
                            "host": data.get("host", ""),
                            "ip": data.get("ip", ""),
                            "port": data.get("port", 0),
                            "source": data.get("source", ""),
                            "url": data.get("url", ""),
                        }
                    )
                except json.JSONDecodeError:
                    continue

        return findings


# ═══════════════════════════════════════════════════════════
#                     Naabu Port Scanner
# ═══════════════════════════════════════════════════════════


class NaabuScanner(BaseScanner):
    """
    Naabu - ماسح منافذ سريع.

    Example:
        >>> scanner = NaabuScanner(ports="top-100")
        >>> result = await scanner.scan(["192.168.1.1"])
    """

    name = "naabu"
    tool_name = "naabu"

    def __init__(
        self,
        ports: str = "top-100",
        rate: int = 1000,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.ports = ports
        self.rate = rate

    def build_command(
        self,
        targets: List[str],
        output_file: Path,
    ) -> List[str]:
        # Create targets file
        targets_file = output_file.with_suffix(".targets.txt")
        with open(targets_file, "w") as f:
            f.write("\n".join(targets))

        cmd = [
            self.tool_name,
            "-l",
            str(targets_file),
            "-o",
            str(output_file),
            "-json",
            "-p",
            self.ports,
            "-rate",
            str(self.rate),
            "-c",
            str(self.threads),
            "-silent",
        ]

        cmd.extend(self.extra_args)
        return cmd

    def parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, object]] = []

        if not output_file.exists():
            return findings

        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(
                        {
                            "type": "open_port",
                            "host": data.get("host", ""),
                            "ip": data.get("ip", ""),
                            "port": data.get("port", 0),
                            "protocol": data.get("protocol", "tcp"),
                        }
                    )
                except json.JSONDecodeError:
                    # Plain text format: host:port
                    if ":" in line:
                        host, port = line.rsplit(":", 1)
                        findings.append(
                            {
                                "type": "open_port",
                                "host": host,
                                "port": int(port),
                                "protocol": "tcp",
                            }
                        )

        return findings


# ═══════════════════════════════════════════════════════════
#                     Dalfox XSS Scanner
# ═══════════════════════════════════════════════════════════


class DalfoxScanner(BaseScanner):
    """
    Dalfox - ماسح XSS.

    Example:
        >>> scanner = DalfoxScanner()
        >>> result = await scanner.scan_urls([
        ...     "https://example.com/search?q=test"
        ... ])
    """

    name = "dalfox"
    tool_name = "dalfox"

    def __init__(
        self,
        blind_url: Optional[str] = None,
        custom_payload: Optional[str] = None,
        waf_evasion: bool = True,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.blind_url = blind_url
        self.custom_payload = custom_payload
        self.waf_evasion = waf_evasion

    def build_command(
        self,
        targets: List[str],
        output_file: Path,
    ) -> List[str]:
        # Create URLs file
        urls_file = output_file.with_suffix(".urls.txt")
        with open(urls_file, "w") as f:
            f.write("\n".join(targets))

        cmd = [
            self.tool_name,
            "file",
            str(urls_file),
            "-o",
            str(output_file),
            "--format",
            "json",
            "-w",
            str(self.threads),
            "--silence",
        ]

        if self.blind_url:
            cmd.extend(["--blind", self.blind_url])

        if self.custom_payload:
            cmd.extend(["--custom-payload", self.custom_payload])

        if self.waf_evasion:
            cmd.append("--waf-evasion")

        cmd.extend(self.extra_args)
        return cmd

    def parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, object]] = []

        if not output_file.exists():
            return findings

        try:
            with open(output_file, "r") as f:
                data = json.load(f)

            for vuln in data.get("pocs", []):
                findings.append(
                    {
                        "type": "xss",
                        "severity": "high",
                        "url": vuln.get("url", ""),
                        "parameter": vuln.get("param", ""),
                        "payload": vuln.get("payload", ""),
                        "method": vuln.get("method", "GET"),
                        "evidence": vuln.get("evidence", ""),
                    }
                )
        except (json.JSONDecodeError, KeyError):
            # Try line-by-line JSON
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        findings.append(
                            {
                                "type": "xss",
                                "severity": "high",
                                "url": data.get("url", ""),
                                "parameter": data.get("param", ""),
                                "payload": data.get("payload", ""),
                            }
                        )
                    except json.JSONDecodeError:
                        continue

        return findings

    async def scan_urls(
        self,
        urls: List[str],
        **kwargs,
    ) -> ScanResult:
        """فحص URLs للـ XSS"""
        return await self.scan(urls, **kwargs)


# ═══════════════════════════════════════════════════════════
#                     SQLMap Scanner
# ═══════════════════════════════════════════════════════════


class SQLMapScanner(BaseScanner):
    """
    SQLMap - ماسح SQL Injection.

    Example:
        >>> scanner = SQLMapScanner(level=3, risk=2)
        >>> result = await scanner.scan_url(
        ...     "https://example.com/item?id=1"
        ... )
    """

    name = "sqlmap"
    tool_name = "sqlmap"

    def __init__(
        self,
        level: int = 1,
        risk: int = 1,
        dbms: Optional[str] = None,
        technique: str = "BEUSTQ",
        tamper: Optional[List[str]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.level = level
        self.risk = risk
        self.dbms = dbms
        self.technique = technique
        self.tamper = tamper or []

    def build_command(
        self,
        targets: List[str],
        output_file: Path,
    ) -> List[str]:
        # SQLMap works on single URL
        url = targets[0]

        output_dir = output_file.parent / "sqlmap_output"
        output_dir.mkdir(exist_ok=True)

        cmd = [
            self.tool_name,
            "-u",
            url,
            "--batch",
            "--output-dir",
            str(output_dir),
            "--level",
            str(self.level),
            "--risk",
            str(self.risk),
            "--technique",
            self.technique,
            "--threads",
            str(self.threads),
            "--forms",
            "--crawl=2",
        ]

        if self.dbms:
            cmd.extend(["--dbms", self.dbms])

        for t in self.tamper:
            cmd.extend(["--tamper", t])

        cmd.extend(self.extra_args)
        return cmd

    def parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, object]] = []

        output_dir = output_file.parent / "sqlmap_output"
        if not output_dir.exists():
            return findings

        # Parse SQLMap log files
        for log_file in output_dir.rglob("log"):
            if not log_file.exists():
                continue

            with open(log_file, "r") as f:
                content = f.read()

            # Look for injection points
            if "is vulnerable" in content.lower():
                # Extract vulnerable parameters
                import re

                param_matches = re.findall(
                    r"Parameter: (\w+) \((.*?)\)",
                    content,
                )

                for param, injection_type in param_matches:
                    findings.append(
                        {
                            "type": "sqli",
                            "severity": "critical",
                            "parameter": param,
                            "injection_type": injection_type,
                            "evidence": content[:500],
                        }
                    )

        return findings

    async def scan_url(
        self,
        url: str,
        **kwargs,
    ) -> ScanResult:
        """فحص URL واحد"""
        return await self.scan([url], **kwargs)


# ═══════════════════════════════════════════════════════════
#                     Nuclei Enhanced Scanner
# ═══════════════════════════════════════════════════════════


class NucleiScanner(BaseScanner):
    """
    Nuclei - ماسح ثغرات متقدم.

    Example:
        >>> scanner = NucleiScanner(
        ...     severity=["critical", "high"],
        ...     tags=["cve", "rce"]
        ... )
        >>> result = await scanner.scan(["https://example.com"])
    """

    name = "nuclei"
    tool_name = "nuclei"

    def __init__(
        self,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        templates: Optional[List[str]] = None,
        rate_limit: int = 150,
        bulk_size: int = 25,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.severity = severity or ["critical", "high", "medium"]
        self.tags = tags
        self.exclude_tags = exclude_tags
        self.templates = templates
        self.rate_limit = rate_limit
        self.bulk_size = bulk_size

    def build_command(
        self,
        targets: List[str],
        output_file: Path,
    ) -> List[str]:
        # Create targets file
        targets_file = output_file.with_suffix(".targets.txt")
        with open(targets_file, "w") as f:
            f.write("\n".join(targets))

        cmd = [
            self.tool_name,
            "-l",
            str(targets_file),
            "-o",
            str(output_file),
            "-jsonl",
            "-c",
            str(self.threads),
            "-rl",
            str(self.rate_limit),
            "-bs",
            str(self.bulk_size),
            "-silent",
        ]

        if self.severity:
            cmd.extend(["-s", ",".join(self.severity)])

        if self.tags:
            cmd.extend(["-tags", ",".join(self.tags)])

        if self.exclude_tags:
            cmd.extend(["-etags", ",".join(self.exclude_tags)])

        if self.templates:
            for template in self.templates:
                cmd.extend(["-t", template])

        cmd.extend(self.extra_args)
        return cmd

    def parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, object]] = []

        if not output_file.exists():
            return findings

        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    findings.append(
                        {
                            "type": "vulnerability",
                            "template_id": data.get("template-id", ""),
                            "name": info.get("name", ""),
                            "severity": info.get("severity", "info"),
                            "host": data.get("host", ""),
                            "matched_at": data.get("matched-at", ""),
                            "description": info.get("description", ""),
                            "tags": info.get("tags", []),
                            "reference": info.get("reference", []),
                            "curl_command": data.get("curl-command", ""),
                        }
                    )
                except json.JSONDecodeError:
                    continue

        return findings


# ═══════════════════════════════════════════════════════════
#                     Scanner Factory
# ═══════════════════════════════════════════════════════════


class ScannerFactory:
    """
    مصنع الماسحات.

    Example:
        >>> factory = ScannerFactory()
        >>> scanner = factory.create("naabu", ports="1-1000")
        >>> result = await scanner.scan(["example.com"])
    """

    SCANNERS = {
        "uncover": UncoverScanner,
        "naabu": NaabuScanner,
        "dalfox": DalfoxScanner,
        "sqlmap": SQLMapScanner,
        "nuclei": NucleiScanner,
    }

    @classmethod
    def create(cls, name: str, **kwargs) -> BaseScanner:
        """إنشاء ماسح"""
        if name not in cls.SCANNERS:
            raise ValueError(
                f"Unknown scanner: {name}. Available: {list(cls.SCANNERS.keys())}"
            )

        return cls.SCANNERS[name](**kwargs)

    @classmethod
    def available(cls) -> List[str]:
        """الماسحات المتاحة"""
        return list(cls.SCANNERS.keys())


# ═══════════════════════════════════════════════════════════
#                     Multi-Scanner
# ═══════════════════════════════════════════════════════════


class MultiScanner:
    """
    تشغيل ماسحات متعددة.

    Example:
        >>> multi = MultiScanner(["naabu", "nuclei"])
        >>> results = await multi.scan(["example.com"])
    """

    def __init__(
        self,
        scanners: List[str],
        scanner_configs: Optional[Dict[str, Dict]] = None,
    ):
        self.scanner_configs = scanner_configs or {}
        self.scanners = [
            ScannerFactory.create(
                name,
                **self.scanner_configs.get(name, {}),
            )
            for name in scanners
        ]

    async def scan(
        self,
        targets: List[str],
        parallel: bool = True,
    ) -> Dict[str, ScanResult]:
        """
        تشغيل جميع الماسحات.

        Args:
            targets: الأهداف
            parallel: تشغيل بالتوازي

        Returns:
            Dict من النتائج
        """
        results = {}

        if parallel:
            tasks = [scanner.scan(targets) for scanner in self.scanners]
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)

            for scanner, result in zip(self.scanners, scan_results):
                if isinstance(result, Exception):
                    results[scanner.name] = ScanResult(
                        target=str(targets),
                        scanner=scanner.name,
                        error=str(result),
                    )
                else:
                    results[scanner.name] = result  # type: ignore[assignment]
        else:
            for scanner in self.scanners:
                try:
                    results[scanner.name] = await scanner.scan(targets)
                except Exception as e:
                    results[scanner.name] = ScanResult(
                        target=str(targets),
                        scanner=scanner.name,
                        error=str(e),
                    )

        return results

    def summary(self, results: Dict[str, ScanResult]) -> Dict[str, Any]:
        """ملخص النتائج"""
        return {
            "scanners_run": len(results),
            "total_findings": sum(r.count for r in results.values()),
            "by_scanner": {
                name: {
                    "findings": result.count,
                    "duration": result.duration,
                    "error": result.error,
                }
                for name, result in results.items()
            },
        }
