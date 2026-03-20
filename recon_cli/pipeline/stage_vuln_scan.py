from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage
from recon_cli.tools.executor import CommandError


class VulnScanStage(Stage):
    name = "vuln_scan"
    requires = ["param_mutation", "url"]
    provides = ["finding"]

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(
            getattr(context.runtime_config, "enable_dalfox", False)
            or getattr(context.runtime_config, "enable_sqlmap", False)
        )

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        candidates = self._select_candidates(context)
        if not candidates:
            context.logger.info("No parameterized URLs for vuln scan")
            return
        artifacts_dir = context.record.paths.ensure_subdir("vuln_scans")
        findings = 0
        attempted = 0
        tool_counts: Dict[str, int] = {"dalfox": 0, "sqlmap": 0}
        if getattr(
            context.runtime_config, "enable_dalfox", False
        ) and executor.available("dalfox"):
            max_urls = int(getattr(context.runtime_config, "dalfox_max_urls", 20))
            timeout = int(getattr(context.runtime_config, "dalfox_timeout", 600))
            for url in candidates[:max_urls]:
                artifact = (
                    artifacts_dir
                    / f"dalfox_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
                )
                cmd = ["dalfox", "url", url, "--format", "json", "--silence"]
                try:
                    result = executor.run(
                        cmd, check=False, timeout=timeout, capture_output=True
                    )
                except CommandError:
                    context.logger.warning("dalfox failed for %s", url)
                    continue
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                artifact.write_text(output, encoding="utf-8")
                attempted += 1
                tool_counts["dalfox"] += 1

                is_confirmed = self._dalfox_confirmed(output)
                # Any output from dalfox usually means it found something, but we want to be honest
                has_potential = (
                    "POC" in output or "VULN" in output or "parameter:" in output
                )

                if is_confirmed or has_potential:
                    score = 85 if is_confirmed else 40
                    f_type = "xss" if is_confirmed else "vulnerability_candidate"
                    signal_id = context.emit_signal(
                        "xss_confirmed" if is_confirmed else "xss_candidate",
                        "url",
                        url,
                        confidence=0.9 if is_confirmed else 0.4,
                        source="dalfox",
                        tags=["xss", "dalfox"],
                        evidence={
                            "output_snippet": output[:400],
                            "confirmed": is_confirmed,
                        },
                    )
                    payload = {
                        "type": "finding",
                        "finding_type": f_type,
                        "source": "dalfox",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "XSS detected by dalfox (Confirmed)"
                        if is_confirmed
                        else "Potential XSS candidate (Unconfirmed)",
                        "details": {
                            "output_snippet": output[:1000],
                            "confirmed": is_confirmed,
                        },
                        "tags": ["xss", "dalfox"],
                        "score": score,
                        "priority": "high" if is_confirmed else "low",
                        "severity": "high" if is_confirmed else "low",
                        "evidence_id": signal_id or None,
                    }
                    if context.results.append(payload):
                        findings += 1
        if getattr(
            context.runtime_config, "enable_sqlmap", False
        ) and executor.available("sqlmap"):
            max_urls = int(getattr(context.runtime_config, "sqlmap_max_urls", 10))
            timeout = int(getattr(context.runtime_config, "sqlmap_timeout", 900))
            level = int(getattr(context.runtime_config, "sqlmap_level", 1))
            risk = int(getattr(context.runtime_config, "sqlmap_risk", 1))
            for url in candidates[:max_urls]:
                artifact = (
                    artifacts_dir
                    / f"sqlmap_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
                )
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
                    result = executor.run(
                        cmd, check=False, timeout=timeout, capture_output=True
                    )
                except CommandError:
                    context.logger.warning("sqlmap failed for %s", url)
                    continue
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                artifact.write_text(output, encoding="utf-8")
                attempted += 1
                tool_counts["sqlmap"] += 1

                is_confirmed = self._sqlmap_confirmed(output)
                # Potential candidate: if sqlmap found something but not full confirmation
                has_potential = "parameter" in output and "appears to be" in output

                if is_confirmed or has_potential:
                    score = 90 if is_confirmed else 40
                    f_type = (
                        "sql_injection" if is_confirmed else "vulnerability_candidate"
                    )
                    signal_id = context.emit_signal(
                        "sqli_confirmed" if is_confirmed else "sqli_candidate",
                        "url",
                        url,
                        confidence=0.9 if is_confirmed else 0.4,
                        source="sqlmap",
                        tags=["sqli", "sqlmap"],
                        evidence={
                            "output_snippet": output[:400],
                            "confirmed": is_confirmed,
                        },
                    )
                    payload = {
                        "type": "finding",
                        "finding_type": f_type,
                        "source": "sqlmap",
                        "hostname": urlparse(url).hostname,
                        "url": url,
                        "description": "SQL injection detected by sqlmap (Confirmed)"
                        if is_confirmed
                        else "Potential SQL injection candidate (Unconfirmed)",
                        "details": {
                            "output_snippet": output[:1200],
                            "confirmed": is_confirmed,
                        },
                        "tags": ["sqli", "sqlmap"],
                        "score": score,
                        "priority": "high" if is_confirmed else "low",
                        "severity": "critical" if is_confirmed else "low",
                        "evidence_id": signal_id or None,
                    }
                    if context.results.append(payload):
                        findings += 1
        if findings or attempted:
            stats = context.record.metadata.stats.setdefault("vuln_scan", {})
            stats["findings"] = findings
            stats["attempted"] = attempted
            stats["by_tool"] = tool_counts
            context.manager.update_metadata(context.record)

    def _select_candidates(self, context: PipelineContext) -> List[str]:
        candidates = context.get_data("param_urls", []) or []
        if not candidates:
            return []
        results_path = context.record.paths.results_jsonl
        url_scores: Dict[str, int] = {}
        url_tags: Dict[str, set] = {}
        url_status: Dict[str, int] = {}
        if results_path.exists():
            for entry in context.get_results():
                if entry.get("type") != "url":
                    continue
                url_value = entry.get("url")
                if not url_value or url_value not in candidates:
                    continue
                url_scores[url_value] = int(entry.get("score", 0))
                url_tags[url_value] = set(entry.get("tags", []))
                try:
                    url_status[url_value] = int(entry.get("status_code") or 0)
                except Exception:
                    url_status[url_value] = 0
        signals = context.signal_index()
        scored: List[Tuple[str, int]] = []
        for url in candidates:
            if not context.url_in_scope(url) or not context.url_allowed(url):
                continue
            score = url_scores.get(url, 0)
            tags = url_tags.get(url, set())
            status_code = url_status.get(url, 0)
            if "noise" in tags or "soft-404" in tags:
                continue
            if status_code >= 500:
                score = max(score - 30, 0)
            host = urlparse(url).hostname
            if host:
                host_signals = signals.get("by_host", {}).get(host, set())
                if (
                    "waf_detected" in host_signals
                    and "waf_bypass_possible" not in host_signals
                ):
                    score = max(score - 20, 0)
            url_signals = signals.get("by_url", {}).get(url, set())
            if "auth_surface" in url_signals:
                score += 10
            if "sensitive_surface" in url_signals:
                score += 10
            if "api_schema_endpoint" in url_signals:
                score += 5
            if "surface:admin" in tags:
                score += 10
            scored.append((url, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        return [url for url, _ in scored]

    @staticmethod
    def _dalfox_confirmed(output: str) -> bool:
        if not output:
            return False
        try:
            data = json.loads(output)
        except Exception:
            data = None
        if isinstance(data, dict):
            pocs = data.get("pocs")
            if isinstance(pocs, list) and pocs:
                return True
        if isinstance(data, list) and data:
            return True
        markers = [
            bool(re.search(r"\bPOC\b", output, re.IGNORECASE)),
            bool(re.search(r"\bVULN\b", output, re.IGNORECASE)),
            bool(re.search(r"payload:", output, re.IGNORECASE)),
            bool(re.search(r"parameter:", output, re.IGNORECASE)),
        ]
        return sum(1 for item in markers if item) >= 2

    @staticmethod
    def _sqlmap_confirmed(output: str) -> bool:
        if not output:
            return False
        return bool(
            re.search(
                r"parameter .* is vulnerable|sqlmap identified the following injection point",
                output,
                re.IGNORECASE,
            )
        )
