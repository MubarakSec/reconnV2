from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from recon_cli.tools.executor import CommandError, CommandExecutor

SEVERITY_TO_SCORE = {
    "info": 10,
    "low": 25,
    "medium": 55,
    "high": 80,
    "critical": 95,
}

SEVERITY_TO_PRIORITY = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass
class ScannerFinding:
    payload: Dict[str, object]


@dataclass
class ScannerExecution:
    findings: List[ScannerFinding]
    artifact_path: Optional[Path]
    stats: Dict[str, object]


def _severity(label: Optional[str]) -> str:
    if not label:
        return "info"
    return label.lower()


def run_nuclei(
    executor: CommandExecutor,
    logger,
    host: str,
    base_url: str,
    artifact_dir: Path,
    timeout: int,
    templates: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    request_timeout: Optional[int] = None,
    retries: Optional[int] = None,
) -> ScannerExecution:
    if not shutil.which("nuclei"):
        logger.info("nuclei not available; skipping for %s", host)
        return ScannerExecution([], None, {})

    artifact_path = artifact_dir / f"nuclei_{host}.json"
    json_flags = ["-jsonl"]
    run_success = False
    last_message: Optional[str] = None
    resolved_templates: Optional[List[str]] = None
    if templates:
        resolved_templates = list(templates)
    else:
        env_dir = subprocess.os.environ.get("NUCLEI_TEMPLATES_DIR")
        default_dirs = []
        if env_dir:
            default_dirs.append(Path(env_dir).expanduser())
        default_dirs.append(Path.home() / "nuclei-templates")
        default_dirs.append(Path.home() / ".config" / "nuclei" / "nuclei-templates")
        for candidate in default_dirs:
            if candidate.exists():
                resolved_templates = [str(candidate)]
                break

    for json_flag in json_flags:
        try:
            artifact_path.unlink(missing_ok=True)
        except FileNotFoundError:  # pragma: no cover - defensive
            pass

        cmd: List[str] = ["nuclei", "-u", base_url, json_flag, "-o", str(artifact_path)]
        if resolved_templates:
            for template in resolved_templates:
                cmd.extend(["-t", template])
        elif tags:
            cmd.extend(["-tags", ",".join(tags)])
        else:
            cmd.extend(["-tags", "api"])
        if request_timeout:
            cmd.extend(["-timeout", str(request_timeout)])
        if retries is not None:
            cmd.extend(["-retries", str(retries)])

        logger.info("Running nuclei against %s with %s", base_url, json_flag)
        try:
            result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
        except CommandError as exc:  # pragma: no cover - runtime safety
            last_message = str(exc)
            logger.warning("nuclei execution failed for %s (%s): %s", host, json_flag, exc)
            return ScannerExecution([], artifact_path if artifact_path.exists() else None, {"timed_out": "timeout" in str(exc).lower()})
        except Exception as exc:  # pragma: no cover - runtime safety
            last_message = str(exc)
            logger.warning("nuclei execution failed for %s (%s): %s", host, json_flag, exc)
            continue

        if result.returncode == 0:
            run_success = True
            break

        last_message = (result.stderr or result.stdout or "non-zero exit") if result else "non-zero exit"
        logger.warning(
            "nuclei returned %s with %s for %s: %s",
            result.returncode if result else "?",
            json_flag,
            host,
            last_message.strip(),
        )

    if not run_success:
        if last_message:
            logger.warning("nuclei execution failed for %s: %s", host, last_message)
        return ScannerExecution([], artifact_path if artifact_path.exists() else None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        with artifact_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                severity = _severity(data.get("info", {}).get("severity"))
                score = SEVERITY_TO_SCORE.get(severity, 10)
                priority = SEVERITY_TO_PRIORITY.get(severity, "low")
                description = data.get("info", {}).get("name") or data.get("templateID") or "nuclei finding"
                findings.append(
                    ScannerFinding(
                        {
                            "type": "finding",
                            "source": "scanner-nuclei",
                            "hostname": data.get("host") or host,
                            "description": description,
                            "details": {
                                "template_id": data.get("templateID"),
                                "matched_at": data.get("matched-at"),
                                "info": data.get("info"),
                            },
                            "tags": ["scanner", "nuclei", severity],
                            "score": score,
                            "priority": priority,
                            "url": data.get("matched-at") or base_url,
                        }
                    )
                )
    return ScannerExecution(findings, artifact_path if artifact_path.exists() else None, {"targets": 1, "findings": len(findings)})


def run_nuclei_batch(
    executor: CommandExecutor,
    logger,
    targets: List[str],
    artifact_dir: Path,
    timeout: int,
    artifact_suffix: Optional[str] = None,
    templates: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    request_timeout: Optional[int] = None,
    retries: Optional[int] = None,
) -> ScannerExecution:
    if not targets:
        return ScannerExecution([], None, {"targets": 0})
    if not shutil.which("nuclei"):
        logger.info("nuclei not available; skipping batch")
        return ScannerExecution([], None, {"targets": len(targets)})

    if artifact_suffix is None:
        digest = hashlib.sha1("\n".join(targets).encode("utf-8")).hexdigest()[:10]
        artifact_suffix = digest
    safe_suffix = "".join(ch for ch in str(artifact_suffix) if ch.isalnum() or ch in {"-", "_"}) or "batch"
    artifact_path = artifact_dir / f"nuclei_batch_{len(targets)}_{safe_suffix}.json"
    targets_path = artifact_dir / f"nuclei_targets_{len(targets)}_{safe_suffix}.txt"
    targets_path.write_text("\n".join(targets) + "\n", encoding="utf-8")

    resolved_templates: Optional[List[str]] = None
    if templates:
        resolved_templates = list(templates)
    else:
        env_dir = subprocess.os.environ.get("NUCLEI_TEMPLATES_DIR")
        default_dirs = []
        if env_dir:
            default_dirs.append(Path(env_dir).expanduser())
        default_dirs.append(Path.home() / "nuclei-templates")
        default_dirs.append(Path.home() / ".config" / "nuclei" / "nuclei-templates")
        for candidate in default_dirs:
            if candidate.exists():
                resolved_templates = [str(candidate)]
                break

    cmd: List[str] = ["nuclei", "-l", str(targets_path), "-jsonl", "-o", str(artifact_path)]
    if resolved_templates:
        for template in resolved_templates:
            cmd.extend(["-t", template])
    elif tags:
        cmd.extend(["-tags", ",".join(tags)])
    else:
        cmd.extend(["-tags", "api"])
    if request_timeout:
        cmd.extend(["-timeout", str(request_timeout)])
    if retries is not None:
        cmd.extend(["-retries", str(retries)])

    try:
        result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
    except CommandError as exc:
        logger.warning("nuclei batch execution failed: %s", exc)
        return ScannerExecution([], artifact_path if artifact_path.exists() else None, {"targets": len(targets), "timed_out": "timeout" in str(exc).lower()})

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "non-zero exit") if result else "non-zero exit"
        logger.warning("nuclei batch returned %s: %s", result.returncode if result else "?", str(message).strip())
        return ScannerExecution([], artifact_path if artifact_path.exists() else None, {"targets": len(targets), "returncode": result.returncode})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        with artifact_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                severity = _severity(data.get("info", {}).get("severity"))
                score = SEVERITY_TO_SCORE.get(severity, 10)
                priority = SEVERITY_TO_PRIORITY.get(severity, "low")
                description = data.get("info", {}).get("name") or data.get("templateID") or "nuclei finding"
                findings.append(
                    ScannerFinding(
                        {
                            "type": "finding",
                            "source": "scanner-nuclei",
                            "hostname": data.get("host"),
                            "description": description,
                            "details": {
                                "template_id": data.get("templateID"),
                                "matched_at": data.get("matched-at"),
                                "info": data.get("info"),
                            },
                            "tags": ["scanner", "nuclei", severity],
                            "score": score,
                            "priority": priority,
                            "url": data.get("matched-at"),
                        }
                    )
                )
    return ScannerExecution(findings, artifact_path if artifact_path.exists() else None, {"targets": len(targets), "findings": len(findings)})


def run_wpscan(
    executor: CommandExecutor,
    logger,
    host: str,
    base_url: str,
    artifact_dir: Path,
    timeout: int,
    enumerate: Optional[str] = None,
    plugins_detection: Optional[str] = None,
    random_user_agent: bool = True,
    max_threads: Optional[int] = None,
    api_token: Optional[str] = None,
) -> ScannerExecution:
    if not shutil.which("wpscan"):
        logger.info("wpscan not available; skipping for %s", host)
        return ScannerExecution([], None, {})

    artifact_path = artifact_dir / f"wpscan_{host}.json"
    cmd: List[str] = [
        "wpscan",
        "--url",
        base_url,
        "--format",
        "json",
        "--output",
        str(artifact_path),
        "--disable-tls-checks",
    ]
    if enumerate:
        cmd.extend(["--enumerate", str(enumerate)])
    if plugins_detection:
        cmd.extend(["--plugins-detection", str(plugins_detection)])
    if random_user_agent:
        cmd.append("--random-user-agent")
    if max_threads and int(max_threads) > 0:
        cmd.extend(["--max-threads", str(int(max_threads))])
    token = api_token or subprocess.os.environ.get("WPSCAN_API_TOKEN")
    if token:
        cmd.extend(["--api-token", token])

    logger.info("Running wpscan against %s", base_url)
    try:
        executor.run(cmd, check=False, timeout=timeout)
    except Exception as exc:  # pragma: no cover
        logger.warning("wpscan execution failed for %s: %s", host, exc)
        return ScannerExecution([], artifact_path if artifact_path.exists() else None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        try:
            data = json.loads(artifact_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        vulns = data.get("vulnerabilities") or []
        for vuln in vulns:
            severity = _severity(vuln.get("severity"))
            score = SEVERITY_TO_SCORE.get(severity, 40)
            priority = SEVERITY_TO_PRIORITY.get(severity, "medium")
            findings.append(
                ScannerFinding(
                    {
                        "type": "finding",
                        "source": "scanner-wpscan",
                        "hostname": host,
                        "description": vuln.get("title") or vuln.get("name") or "wpscan finding",
                        "details": vuln,
                        "tags": ["scanner", "wpscan", severity],
                        "score": score,
                        "priority": priority,
                    }
                )
            )
    return ScannerExecution(findings, artifact_path if artifact_path.exists() else None, {"targets": 1, "findings": len(findings)})


SCANNER_REGISTRY = {
    "nuclei": run_nuclei,
    "wpscan": run_wpscan,
}


def available_scanners() -> List[str]:
    return sorted(SCANNER_REGISTRY.keys())


# ============================================================================
# New Tool Integrations
# ============================================================================

def run_ffuf(
    executor: CommandExecutor,
    logger,
    host: str,
    base_url: str,
    artifact_dir: Path,
    timeout: int,
    wordlist: Optional[str] = None,
) -> ScannerExecution:
    """Run ffuf fuzzer against a target."""
    if not shutil.which("ffuf"):
        logger.info("ffuf not available; skipping for %s", host)
        return ScannerExecution([], None, {})

    artifact_path = artifact_dir / f"ffuf_{host}.json"
    
    # Use default wordlist if not specified
    if not wordlist:
        from recon_cli import config

        wordlist = str(config.DEFAULT_SECLISTS_ROOT / "Discovery" / "Web-Content" / "common.txt")
        if not Path(wordlist).exists():
            wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    cmd: List[str] = [
        "ffuf",
        "-u", f"{base_url}/FUZZ",
        "-w", wordlist,
        "-o", str(artifact_path),
        "-of", "json",
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-t", "50",
        "-timeout", "10",
        "-s",  # Silent mode
    ]
    
    logger.info("Running ffuf against %s", base_url)
    try:
        executor.run(cmd, check=False, timeout=timeout)
    except Exception as exc:
        logger.warning("ffuf execution failed for %s: %s", host, exc)
        return ScannerExecution([], None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        try:
            data = json.loads(artifact_path.read_text(encoding="utf-8"))
            results = data.get("results", [])
            for result in results:
                findings.append(
                    ScannerFinding({
                        "type": "url",
                        "source": "ffuf",
                        "hostname": host,
                        "url": result.get("url"),
                        "status_code": result.get("status"),
                        "content_length": result.get("length"),
                        "words": result.get("words"),
                        "lines": result.get("lines"),
                        "tags": ["fuzzing", "directory"],
                    })
                )
        except json.JSONDecodeError:
            pass
    
    return ScannerExecution(
        findings, 
        artifact_path if artifact_path.exists() else None, 
        {"targets": 1, "findings": len(findings)}
    )


def run_katana(
    executor: CommandExecutor,
    logger,
    host: str,
    base_url: str,
    artifact_dir: Path,
    timeout: int,
    depth: int = 2,
) -> ScannerExecution:
    """Run katana crawler against a target."""
    if not shutil.which("katana"):
        logger.info("katana not available; skipping for %s", host)
        return ScannerExecution([], None, {})

    artifact_path = artifact_dir / f"katana_{host}.json"
    
    cmd: List[str] = [
        "katana",
        "-u", base_url,
        "-d", str(depth),
        "-jc",  # JavaScript crawl
        "-kf", "all",  # Known files
        "-o", str(artifact_path),
        "-jsonl",
        "-silent",
    ]
    
    logger.info("Running katana against %s", base_url)
    try:
        executor.run(cmd, check=False, timeout=timeout)
    except Exception as exc:
        logger.warning("katana execution failed for %s: %s", host, exc)
        return ScannerExecution([], None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        with artifact_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(
                        ScannerFinding({
                            "type": "url",
                            "source": "katana",
                            "hostname": host,
                            "url": data.get("request", {}).get("endpoint") or data.get("url"),
                            "method": data.get("request", {}).get("method", "GET"),
                            "tags": ["crawl", "katana"],
                        })
                    )
                except json.JSONDecodeError:
                    # Plain URL format
                    findings.append(
                        ScannerFinding({
                            "type": "url",
                            "source": "katana",
                            "hostname": host,
                            "url": line,
                            "tags": ["crawl", "katana"],
                        })
                    )
    
    return ScannerExecution(
        findings, 
        artifact_path if artifact_path.exists() else None, 
        {"targets": 1, "findings": len(findings)}
    )


def run_dnsx(
    executor: CommandExecutor,
    logger,
    hosts: List[str],
    artifact_dir: Path,
    timeout: int,
) -> ScannerExecution:
    """Run dnsx for DNS enumeration."""
    if not shutil.which("dnsx"):
        logger.info("dnsx not available")
        return ScannerExecution([], None, {})

    input_path = artifact_dir / "dnsx_input.txt"
    artifact_path = artifact_dir / "dnsx_output.json"
    
    # Write hosts to input file
    input_path.write_text("\n".join(hosts), encoding="utf-8")
    
    cmd: List[str] = [
        "dnsx",
        "-l", str(input_path),
        "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns",
        "-resp",
        "-json",
        "-o", str(artifact_path),
        "-silent",
    ]
    
    logger.info("Running dnsx for %d hosts", len(hosts))
    try:
        executor.run(cmd, check=False, timeout=timeout)
    except Exception as exc:
        logger.warning("dnsx execution failed: %s", exc)
        return ScannerExecution([], None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        with artifact_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(
                        ScannerFinding({
                            "type": "dns",
                            "source": "dnsx",
                            "hostname": data.get("host"),
                            "a": data.get("a"),
                            "aaaa": data.get("aaaa"),
                            "cname": data.get("cname"),
                            "mx": data.get("mx"),
                            "ns": data.get("ns"),
                            "txt": data.get("txt"),
                            "resolver": data.get("resolver"),
                            "tags": ["dns", "enumeration"],
                        })
                    )
                except json.JSONDecodeError:
                    continue
    
    return ScannerExecution(
        findings, 
        artifact_path if artifact_path.exists() else None, 
        {"targets": len(hosts), "findings": len(findings)}
    )


def run_tlsx(
    executor: CommandExecutor,
    logger,
    hosts: List[str],
    artifact_dir: Path,
    timeout: int,
) -> ScannerExecution:
    """Run tlsx for TLS/SSL analysis."""
    if not shutil.which("tlsx"):
        logger.info("tlsx not available")
        return ScannerExecution([], None, {})

    input_path = artifact_dir / "tlsx_input.txt"
    artifact_path = artifact_dir / "tlsx_output.json"
    
    # Write hosts to input file
    input_path.write_text("\n".join(hosts), encoding="utf-8")
    
    cmd: List[str] = [
        "tlsx",
        "-l", str(input_path),
        "-san", "-cn", "-so", "-tv", "-ve",
        "-json",
        "-o", str(artifact_path),
        "-silent",
    ]
    
    logger.info("Running tlsx for %d hosts", len(hosts))
    try:
        executor.run(cmd, check=False, timeout=timeout)
    except Exception as exc:
        logger.warning("tlsx execution failed: %s", exc)
        return ScannerExecution([], None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        with artifact_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    
                    # Check for vulnerabilities
                    vulns = []
                    if data.get("version_error"):
                        vulns.append("version_error")
                    if data.get("expired"):
                        vulns.append("expired_cert")
                    if data.get("self_signed"):
                        vulns.append("self_signed")
                    if data.get("mismatched"):
                        vulns.append("hostname_mismatch")
                    
                    findings.append(
                        ScannerFinding({
                            "type": "tls",
                            "source": "tlsx",
                            "hostname": data.get("host"),
                            "port": data.get("port", 443),
                            "tls_version": data.get("tls_version"),
                            "cipher": data.get("cipher"),
                            "subject_cn": data.get("subject_cn"),
                            "subject_an": data.get("subject_an"),
                            "issuer_cn": data.get("issuer_cn"),
                            "not_before": data.get("not_before"),
                            "not_after": data.get("not_after"),
                            "expired": data.get("expired"),
                            "self_signed": data.get("self_signed"),
                            "vulnerabilities": vulns,
                            "tags": ["tls", "ssl", "certificate"],
                        })
                    )
                except json.JSONDecodeError:
                    continue
    
    return ScannerExecution(
        findings, 
        artifact_path if artifact_path.exists() else None, 
        {"targets": len(hosts), "findings": len(findings)}
    )


def run_httpx_extended(
    executor: CommandExecutor,
    logger,
    hosts: List[str],
    artifact_dir: Path,
    timeout: int,
) -> ScannerExecution:
    """Run httpx with extended options for comprehensive HTTP analysis."""
    if not shutil.which("httpx"):
        logger.info("httpx not available")
        return ScannerExecution([], None, {})

    input_path = artifact_dir / "httpx_input.txt"
    artifact_path = artifact_dir / "httpx_extended.json"
    
    input_path.write_text("\n".join(hosts), encoding="utf-8")
    
    cmd: List[str] = [
        "httpx",
        "-l", str(input_path),
        "-title", "-tech-detect", "-status-code", "-content-length",
        "-web-server", "-cdn", "-favicon",
        "-json",
        "-o", str(artifact_path),
        "-silent",
    ]
    
    logger.info("Running httpx extended for %d hosts", len(hosts))
    try:
        executor.run(cmd, check=False, timeout=timeout)
    except Exception as exc:
        logger.warning("httpx extended execution failed: %s", exc)
        return ScannerExecution([], None, {})

    findings: List[ScannerFinding] = []
    if artifact_path.exists():
        with artifact_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(
                        ScannerFinding({
                            "type": "url",
                            "source": "httpx-extended",
                            "hostname": data.get("host"),
                            "url": data.get("url"),
                            "status_code": data.get("status_code"),
                            "title": data.get("title"),
                            "webserver": data.get("webserver"),
                            "technologies": data.get("tech"),
                            "cdn": data.get("cdn"),
                            "content_length": data.get("content_length"),
                            "favicon_hash": data.get("favicon_hash"),
                            "tags": ["http", "probe", "tech-detect"],
                        })
                    )
                except json.JSONDecodeError:
                    continue
    
    return ScannerExecution(
        findings, 
        artifact_path if artifact_path.exists() else None, 
        {"targets": len(hosts), "findings": len(findings)}
    )


# Update scanner registry with new tools
SCANNER_REGISTRY.update({
    "ffuf": run_ffuf,
    "katana": run_katana,
    "dnsx": run_dnsx,
    "tlsx": run_tlsx,
    "httpx-extended": run_httpx_extended,
})
