from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from recon_cli.utils.jsonl import iter_jsonl
from recon_cli.utils.last_run import update_last_report_pointer
from recon_cli.utils.reporting import (
    build_finding_rerun_command,
    build_triage_entry,
    categorize_results,
    filter_findings,
    rank_findings,
    resolve_severity,
)
from recon_cli.utils.sanitizer import escape_html_text


@dataclass
class ReportConfig:
    """Configuration flags for legacy HTML reporter compatibility."""

    language: str = "en"
    include_quality: bool = False
    verified_only: bool = False
    hunter_mode: bool = False
    max_hunter_findings: int = 10


@dataclass
class ReportData:
    """Simple report payload assembled from a job directory."""

    job_id: str
    status: str = "unknown"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    results: List[Dict[str, Any]] = field(default_factory=list)
    spec: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_job_dir(cls, job_dir: Path) -> Optional["ReportData"]:
        if not job_dir.exists() or not job_dir.is_dir():
            return None

        metadata_path = job_dir / "metadata.json"
        if not metadata_path.exists():
            return None

        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        results = [entry for entry in iter_jsonl(job_dir / "results.jsonl") if isinstance(entry, dict)]

        spec: Dict[str, Any] = {}
        spec_path = job_dir / "spec.json"
        if spec_path.exists():
            try:
                parsed = json.loads(spec_path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    spec = parsed
            except (OSError, json.JSONDecodeError):
                spec = {}

        return cls(
            job_id=str(metadata.get("job_id", "")),
            status=str(metadata.get("status", "unknown")),
            started_at=metadata.get("started_at"),
            finished_at=metadata.get("finished_at"),
            stats=metadata.get("stats") if isinstance(metadata.get("stats"), dict) else {},
            results=results,
            spec=spec,
        )

    def get_severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for entry in self.results:
            if not isinstance(entry, dict):
                continue
            entry_type = str(entry.get("type") or "")
            if entry_type not in {"finding", "vulnerability", "vuln"} and not entry.get("finding_type"):
                continue
            severity = resolve_severity(entry)
            counts[severity] = counts.get(severity, 0) + 1
        return counts


def generate_html_report(
    job_dir: Path,
    output_path: Path,
    config: Optional[ReportConfig] = None,
) -> Optional[Path]:
    """Generate an HTML report from a job directory.

    Returns the output path when successful, otherwise None.
    """

    report_data = ReportData.from_job_dir(job_dir)
    if report_data is None:
        return None

    cfg = config or ReportConfig()
    categorized = categorize_results(report_data.results)

    findings = list(categorized.get("findings", []))
    if cfg.verified_only or cfg.hunter_mode:
        findings = filter_findings(findings, verified_only=True)
    findings = rank_findings(findings)

    hosts = [h for h in categorized.get("hosts", []) if isinstance(h, dict)]
    urls = [u for u in categorized.get("urls", []) if isinstance(u, dict)]

    html = _build_html(report_data, findings, hosts, urls, cfg)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    update_last_report_pointer(output_path)
    return output_path


def _build_html(
    report_data: ReportData,
    findings: List[Dict[str, object]],
    hosts: List[Dict[str, object]],
    urls: List[Dict[str, object]],
    config: ReportConfig,
) -> str:
    counts = report_data.get_severity_counts()

    findings_html = "".join(_finding_card(item) for item in findings) or "<p>No findings.</p>"
    hosts_html = "".join(_host_row(host) for host in hosts) or "<tr><td colspan=\"3\">No hosts.</td></tr>"
    urls_html = "".join(_url_row(item) for item in urls) or "<tr><td>No URLs.</td></tr>"

    quality_html = _quality_section(report_data) if config.include_quality else ""
    hunter_html = _hunter_section(report_data, findings, config) if config.hunter_mode else ""

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>Recon Report - {escape_html_text(report_data.job_id)}</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2rem; color: #1f2937; background: #f8fafc; }}
    .panel {{ background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: 1rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.8rem; }}
    .metric {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.7rem; text-align: center; }}
    .critical {{ border-left: 5px solid #dc2626; }}
    .high {{ border-left: 5px solid #ea580c; }}
    .medium {{ border-left: 5px solid #ca8a04; }}
    .low {{ border-left: 5px solid #2563eb; }}
    .info {{ border-left: 5px solid #6b7280; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; border-bottom: 1px solid #e5e7eb; padding: 0.5rem; vertical-align: top; }}
    code, pre {{ background: #f3f4f6; padding: 0.15rem 0.35rem; border-radius: 4px; }}
    pre {{ padding: 0.6rem; white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <div class=\"panel\">
    <h1>Recon Report</h1>
    <p><strong>Job:</strong> {escape_html_text(report_data.job_id)}</p>
    <p><strong>Status:</strong> {escape_html_text(report_data.status)}</p>
    <p><strong>Started:</strong> {escape_html_text(report_data.started_at or 'N/A')}</p>
    <p><strong>Finished:</strong> {escape_html_text(report_data.finished_at or 'N/A')}</p>
  </div>

  <div class=\"panel\">
    <h2>Summary</h2>
    <div class=\"grid\">
      <div class=\"metric\"><strong>Findings</strong><br />{len(findings)}</div>
      <div class=\"metric\"><strong>Critical</strong><br />{counts.get('critical', 0)}</div>
      <div class=\"metric\"><strong>High</strong><br />{counts.get('high', 0)}</div>
      <div class=\"metric\"><strong>Medium</strong><br />{counts.get('medium', 0)}</div>
      <div class=\"metric\"><strong>Low</strong><br />{counts.get('low', 0)}</div>
      <div class=\"metric\"><strong>Info</strong><br />{counts.get('info', 0)}</div>
    </div>
  </div>

  {quality_html}
  {hunter_html}

  <div class=\"panel\">
    <h2>Findings</h2>
    {findings_html}
  </div>

  <div class=\"panel\">
    <h2>Hosts</h2>
    <table>
      <thead><tr><th>Host</th><th>IP</th><th>Source</th></tr></thead>
      <tbody>{hosts_html}</tbody>
    </table>
  </div>

  <div class=\"panel\">
    <h2>URLs</h2>
    <table>
      <thead><tr><th>URL</th></tr></thead>
      <tbody>{urls_html}</tbody>
    </table>
  </div>
</body>
</html>
"""


def _finding_card(item: Dict[str, object]) -> str:
    severity = resolve_severity(item)
    title = item.get("title") or item.get("name") or item.get("finding_type") or item.get("type") or "finding"
    description = item.get("description") or ""
    target = item.get("url") or item.get("hostname") or item.get("host") or ""
    proof = item.get("proof") or item.get("evidence") or ""

    return f"""
    <div class=\"panel {escape_html_text(severity)}\">
      <p><strong>{escape_html_text(title)}</strong></p>
      <p><strong>Severity:</strong> {escape_html_text(severity)}</p>
      <p><strong>Target:</strong> {escape_html_text(target)}</p>
      <p>{escape_html_text(description)}</p>
      {f'<pre>{escape_html_text(proof)}</pre>' if proof else ''}
    </div>
    """


def _host_row(host: Dict[str, object]) -> str:
    return (
        "<tr>"
        f"<td>{escape_html_text(host.get('hostname') or host.get('host') or 'N/A')}</td>"
        f"<td>{escape_html_text(host.get('ip') or 'N/A')}</td>"
        f"<td>{escape_html_text(host.get('source') or 'N/A')}</td>"
        "</tr>"
    )


def _url_row(item: Dict[str, object]) -> str:
    return f"<tr><td>{escape_html_text(item.get('url') or '')}</td></tr>"


def _quality_section(report_data: ReportData) -> str:
    quality = report_data.stats.get("quality") if isinstance(report_data.stats, dict) else {}
    if not isinstance(quality, dict):
        quality = {}

    verified_ratio = quality.get("verified_ratio", 0)
    noise_ratio = quality.get("noise_ratio", 0)
    duplicate_ratio = quality.get("duplicate_ratio", 0)

    return f"""
    <div class=\"panel\">
      <h2>Quality Metrics</h2>
      <p><strong>Verified ratio</strong>: {escape_html_text(verified_ratio)}</p>
      <p><strong>Noise ratio</strong>: {escape_html_text(noise_ratio)}</p>
      <p><strong>Duplicate ratio</strong>: {escape_html_text(duplicate_ratio)}</p>
    </div>
    """


def _hunter_section(
    report_data: ReportData,
    findings: List[Dict[str, object]],
    config: ReportConfig,
) -> str:
    top_findings = findings[: max(1, int(config.max_hunter_findings))]
    triage_items = [build_triage_entry(item, job_id=report_data.job_id) for item in top_findings]

    item_html = []
    for index, entry in enumerate(triage_items):
        replay_cmd = build_finding_rerun_command(report_data.job_id, top_findings[index])
        item_html.append(
            """
            <div class=\"panel\">
              <p><strong>{title}</strong> ({severity})</p>
              <p><strong>Target:</strong> {target}</p>
              <p><strong>Submission Summary:</strong> {summary}</p>
              <p><strong>Repro Command:</strong></p>
              <pre>{repro}</pre>
              <p><strong>Replay Command:</strong></p>
              <pre>{rerun}</pre>
            </div>
            """.format(
                title=escape_html_text(entry.get("title") or "finding"),
                severity=escape_html_text(entry.get("severity") or "info"),
                target=escape_html_text(entry.get("target") or ""),
                summary=escape_html_text(entry.get("submission_summary") or ""),
                repro=escape_html_text(entry.get("repro_cmd") or ""),
                rerun=escape_html_text(replay_cmd),
            )
        )

    duplicate_hints, scope_hints = _triage_hints(report_data, top_findings)
    duplicate_html = "".join(f"<li>{escape_html_text(item)}</li>" for item in duplicate_hints) or "<li>None</li>"
    scope_html = "".join(f"<li>{escape_html_text(item)}</li>" for item in scope_hints) or "<li>None</li>"

    return f"""
    <div class=\"panel\">
      <h2>Top Actionable Findings</h2>
      {''.join(item_html) if item_html else '<p>No actionable findings.</p>'}
    </div>
    <div class=\"panel\">
      <h2>Triage Hints</h2>
      <p><strong>Likely Duplicates</strong></p>
      <ul>{duplicate_html}</ul>
      <p><strong>Likely Out of Scope</strong></p>
      <ul>{scope_html}</ul>
    </div>
    """


def _triage_hints(
    report_data: ReportData,
    findings: List[Dict[str, object]],
) -> tuple[List[str], List[str]]:
    duplicates: List[str] = []
    out_of_scope: List[str] = []

    target = str(report_data.spec.get("target") or "").strip().lower()

    for finding in findings:
        tags_raw = finding.get("tags")
        tags = {str(tag).strip().lower() for tag in tags_raw} if isinstance(tags_raw, list) else set()

        if "duplicate" in tags:
            title = finding.get("title") or finding.get("name") or finding.get("url") or "finding"
            duplicates.append(str(title))

        host = _finding_host(finding)
        if target and host and host != target and not host.endswith(f".{target}"):
            out_of_scope.append(f"host_mismatch:{host}")

    # stable unique order for deterministic report output
    duplicates = list(dict.fromkeys(duplicates))
    out_of_scope = list(dict.fromkeys(out_of_scope))
    return duplicates, out_of_scope


def _finding_host(finding: Dict[str, object]) -> str:
    direct = str(finding.get("hostname") or finding.get("host") or "").strip().lower()
    if direct:
        return direct

    raw_url = str(finding.get("url") or "").strip()
    if not raw_url:
        return ""

    try:
        return str(urlparse(raw_url).hostname or "").strip().lower()
    except ValueError:
        return ""


__all__ = ["ReportConfig", "ReportData", "generate_html_report"]
