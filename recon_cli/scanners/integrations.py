from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from recon_cli.tools.executor import CommandExecutor

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
) -> ScannerExecution:
    if not shutil.which("nuclei"):
        logger.info("nuclei not available; skipping for %s", host)
        return ScannerExecution([], None, {})

    artifact_path = artifact_dir / f"nuclei_{host}.json"
    json_flags = ["-jsonl"]
    run_success = False
    last_message: Optional[str] = None

    for json_flag in json_flags:
        try:
            artifact_path.unlink(missing_ok=True)
        except FileNotFoundError:  # pragma: no cover - defensive
            pass

        cmd: List[str] = ["nuclei", "-u", base_url, json_flag, "-o", str(artifact_path)]
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        else:
            cmd.extend(["-tags", "api"])

        logger.info("Running nuclei against %s with %s", base_url, json_flag)
        try:
            result = executor.run(cmd, check=False, timeout=timeout, capture_output=True)
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


def run_wpscan(
    executor: CommandExecutor,
    logger,
    host: str,
    base_url: str,
    artifact_dir: Path,
    timeout: int,
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
    api_token = subprocess.os.environ.get("WPSCAN_API_TOKEN")
    if api_token:
        cmd.extend(["--api-token", api_token])

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
