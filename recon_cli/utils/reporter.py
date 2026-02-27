"""
HTML Report Generator - مولد تقارير HTML احترافية
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from recon_cli.utils.jsonl import read_jsonl
from recon_cli.utils.reporting import (
    build_finding_rerun_command,
    build_submission_summary,
    filter_findings,
    is_finding,
    is_secret,
    rank_findings,
    resolve_confidence_label,
    resolve_severity,
)


@dataclass
class ReportConfig:
    """إعدادات التقرير"""
    title: str = "ReconnV2 Scan Report"
    include_raw_data: bool = False
    include_screenshots: bool = True
    theme: str = "dark"  # dark, light
    language: str = "ar"  # ar, en
    verified_only: bool = False
    proof_required: bool = False
    include_quality: bool = True
    hunter_mode: bool = False
    hunter_top: int = 10


@dataclass
class ReportData:
    """Structured report data parsed from a job directory."""
    job_id: str
    status: str
    started_at: Optional[str]
    finished_at: Optional[str]
    stats: Dict[str, Any]
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    spec: Dict[str, Any]

    @classmethod
    def from_job_dir(cls, job_dir: Path) -> Optional["ReportData"]:
        if not job_dir.exists():
            return None
        metadata_path = job_dir / "metadata.json"
        spec_path = job_dir / "spec.json"
        results_path = job_dir / "results.jsonl"

        metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
        spec = json.loads(spec_path.read_text()) if spec_path.exists() else {}
        results = list(read_jsonl(results_path)) if results_path.exists() else []

        job_id = metadata.get("job_id") or spec.get("job_id") or job_dir.name
        status = metadata.get("status", "unknown")
        return cls(
            job_id=str(job_id),
            status=str(status),
            started_at=metadata.get("started_at"),
            finished_at=metadata.get("finished_at"),
            stats=metadata.get("stats", {}) or {},
            results=results,
            metadata=metadata,
            spec=spec,
        )

    def get_severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for entry in self.results:
            severity = str(entry.get("severity") or entry.get("priority") or "info").lower()
            if severity in counts:
                counts[severity] += 1
        return counts


def generate_html_report(
    job_dir: Path,
    output_path: Optional[Path] = None,
    config: Optional[ReportConfig] = None
) -> Path:
    """
    إنشاء تقرير HTML من نتائج الفحص
    
    Args:
        job_dir: مجلد المهمة
        output_path: مسار ملف التقرير (اختياري)
        config: إعدادات التقرير
    
    Returns:
        مسار ملف التقرير
    """
    config = config or ReportConfig()
    if config.hunter_mode:
        config.verified_only = True
        config.proof_required = True

    if not job_dir.exists():
        if output_path is None:
            return job_dir / "report.html"
        return output_path
    
    # قراءة البيانات
    metadata_path = job_dir / "metadata.json"
    spec_path = job_dir / "spec.json"
    results_path = job_dir / "results.jsonl"
    
    metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
    spec = json.loads(spec_path.read_text()) if spec_path.exists() else {}
    results = list(read_jsonl(results_path)) if results_path.exists() else []
    
    # تحليل النتائج
    stats = _analyze_results(
        results,
        verified_only=config.verified_only,
        proof_required=config.proof_required,
    )
    stats["quality"] = _compute_quality_stats(results, metadata)
    if config.hunter_mode:
        stats["top_findings"] = rank_findings(stats["findings"], limit=config.hunter_top)
    
    # إنشاء HTML
    html = _generate_html(spec, metadata, results, stats, config)
    
    # حفظ الملف
    if output_path is None:
        output_path = job_dir / "report.html"
    
    output_path.write_text(html, encoding="utf-8")
    
    return output_path


def _analyze_results(
    results: List[Dict],
    *,
    verified_only: bool = False,
    proof_required: bool = False,
) -> Dict[str, Any]:
    """تحليل النتائج وإنشاء إحصائيات"""
    stats = {
        "total": len(results),
        "by_type": {},
        "by_source": {},
        "hostnames": set(),
        "urls": set(),
        "hostnames_list": [],
        "urls_list": [],
        "secrets": [],
        "findings": [],
        "findings_all": [],
        "screenshots": [],
        "services": [],
        "auth_forms": [],
        "api_specs": [],
        "parameters": [],
        "js_endpoints": [],
        "waf_findings": [],
        "vuln_findings": [],
    }
    
    for result in results:
        result_type = result.get("type", "unknown")
        stats["by_type"][result_type] = stats["by_type"].get(result_type, 0) + 1
        
        source = result.get("source", "unknown")
        stats["by_source"][source] = stats["by_source"].get(source, 0) + 1
        
        if "hostname" in result:
            stats["hostnames"].add(result["hostname"])
        
        if "url" in result:
            stats["urls"].add(result["url"])
        
        if is_secret(result):
            stats["secrets"].append(result)

        if is_finding(result):
            stats["findings_all"].append(result)

        if result_type == "screenshot":
            stats["screenshots"].append(result)
        if result_type == "service":
            stats["services"].append(result)
        if result_type == "auth_form":
            stats["auth_forms"].append(result)
        if result_type in {"api_spec", "api"}:
            stats["api_specs"].append(result)
        if result_type == "parameter":
            stats["parameters"].append(result)
        if result_type == "url" and result.get("source") == "js-intel":
            stats["js_endpoints"].append(result)
        if result_type == "finding" and result.get("source") == "waf-probe":
            stats["waf_findings"].append(result)
        if result_type == "finding" and result.get("source") in {"dalfox", "sqlmap"}:
            stats["vuln_findings"].append(result)
    
    if verified_only or proof_required:
        stats["findings"] = filter_findings(
            stats["findings_all"],
            verified_only=verified_only,
            proof_required=proof_required,
        )
        stats["waf_findings"] = filter_findings(
            stats["waf_findings"],
            verified_only=verified_only,
            proof_required=proof_required,
        )
        stats["vuln_findings"] = filter_findings(
            stats["vuln_findings"],
            verified_only=verified_only,
            proof_required=proof_required,
        )
    else:
        stats["findings"] = list(stats["findings_all"])

    stats["by_severity"] = _severity_counts(stats["findings"])
    stats["hostnames_list"] = sorted(stats["hostnames"])[:50]
    stats["urls_list"] = sorted(stats["urls"])[:50]
    stats["hostnames"] = len(stats["hostnames"])
    stats["urls"] = len(stats["urls"])
    
    return stats


def _generate_html(
    spec: Dict,
    metadata: Dict,
    results: List[Dict],
    stats: Dict,
    config: ReportConfig
) -> str:
    """إنشاء HTML الكامل"""
    
    theme_colors = {
        "dark": {
            "bg": "#1a1a2e",
            "card": "#16213e",
            "text": "#eaeaea",
            "accent": "#0f3460",
            "primary": "#e94560",
            "success": "#00d26a",
            "warning": "#f9c74f",
            "danger": "#e94560",
        },
        "light": {
            "bg": "#f5f5f5",
            "card": "#ffffff",
            "text": "#333333",
            "accent": "#e0e0e0",
            "primary": "#2196f3",
            "success": "#4caf50",
            "warning": "#ff9800",
            "danger": "#f44336",
        }
    }
    
    colors = theme_colors.get(config.theme, theme_colors["dark"])
    
    # الترجمات
    translations = {
        "ar": {
            "title": "تقرير الفحص",
            "summary": "ملخص",
            "target": "الهدف",
            "profile": "الملف الشخصي",
            "status": "الحالة",
            "started": "بدأ في",
            "finished": "انتهى في",
            "total_results": "إجمالي النتائج",
            "hostnames": "المضيفين",
            "urls": "الروابط",
            "findings": "الاكتشافات",
            "secrets": "الأسرار المكتشفة",
            "by_type": "حسب النوع",
            "by_severity": "حسب الخطورة",
            "critical": "حرج",
            "high": "عالي",
            "medium": "متوسط",
            "low": "منخفض",
            "info": "معلومات",
            "quality": "جودة النتائج",
            "noise_ratio": "نسبة الضوضاء",
            "verified_ratio": "نسبة التحقق",
            "duplicate_ratio": "نسبة التكرار",
            "details": "التفاصيل",
            "top_actionable": "أهم النتائج القابلة للاستغلال",
            "confidence": "الثقة",
            "proof": "الدليل",
            "repro_cmd": "أمر الإعادة",
            "rerun_cmd": "أمر إعادة التشغيل",
            "source": "المصدر",
            "submission_summary": "ملخص جاهز للتبليغ",
            "generated": "تم إنشاؤه في",
        },
        "en": {
            "title": "Scan Report",
            "summary": "Summary",
            "target": "Target",
            "profile": "Profile",
            "status": "Status",
            "started": "Started",
            "finished": "Finished",
            "total_results": "Total Results",
            "hostnames": "Hostnames",
            "urls": "URLs",
            "findings": "Findings",
            "secrets": "Secrets Found",
            "by_type": "By Type",
            "by_severity": "By Severity",
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "quality": "Quality",
            "noise_ratio": "Noise ratio",
            "verified_ratio": "Verified ratio",
            "duplicate_ratio": "Duplicate ratio",
            "details": "Details",
            "top_actionable": "Top Actionable Findings",
            "confidence": "Confidence",
            "proof": "Proof",
            "repro_cmd": "Repro Command",
            "rerun_cmd": "Rerun Command",
            "source": "Source",
            "submission_summary": "Submission Summary",
            "generated": "Generated at",
        }
    }
    
    t = translations.get(config.language, translations["en"])
    rtl = 'dir="rtl"' if config.language == "ar" else ""
    
    job_id = str(metadata.get("job_id") or spec.get("job_id") or "")
    quality = stats.get("quality") or {}
    noise_ratio = _format_pct(quality.get("noise_ratio"))
    verified_ratio = _format_pct(quality.get("verified_ratio"))
    duplicate_ratio = _format_pct(quality.get("duplicate_ratio"))
    quality_card = ""
    if config.include_quality:
        quality_card = f'''
            <div class="card" style="text-align: center;">
                <div class="stat-number">{verified_ratio}</div>
                <div class="stat-label">{t["verified_ratio"]}</div>
                <div class="stat-label">{t["noise_ratio"]}: {noise_ratio}</div>
                <div class="stat-label">{t["duplicate_ratio"]}: {duplicate_ratio}</div>
            </div>
        '''

    html = f'''<!DOCTYPE html>
<html lang="{config.language}" {rtl}>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{config.title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: {colors["bg"]};
            color: {colors["text"]};
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, {colors["accent"]}, {colors["card"]});
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: {colors["primary"]};
        }}
        
        .header .meta {{
            opacity: 0.8;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: {colors["card"]};
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        
        .card h3 {{
            color: {colors["primary"]};
            margin-bottom: 15px;
            border-bottom: 2px solid {colors["accent"]};
            padding-bottom: 10px;
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: {colors["primary"]};
        }}
        
        .stat-label {{
            opacity: 0.7;
            font-size: 0.9em;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }}
        
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #17a2b8; color: white; }}
        .severity-info {{ background: #6c757d; color: white; }}
        
        .progress-bar {{
            height: 8px;
            background: {colors["accent"]};
            border-radius: 4px;
            overflow: hidden;
            margin: 5px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: {colors["primary"]};
            border-radius: 4px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid {colors["accent"]};
        }}
        
        th {{
            background: {colors["accent"]};
            font-weight: bold;
        }}
        
        tr:hover {{
            background: {colors["accent"]}40;
        }}
        
        .findings-list {{
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .finding-item {{
            padding: 15px;
            margin: 10px 0;
            background: {colors["accent"]}30;
            border-radius: 8px;
            border-left: 4px solid {colors["primary"]};
        }}
        
        .finding-title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            opacity: 0.6;
            margin-top: 30px;
        }}
        
        .chart-container {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .chart-item {{
            text-align: center;
        }}
        
        .chart-bar {{
            width: 40px;
            background: {colors["accent"]};
            border-radius: 4px 4px 0 0;
            margin: 0 auto;
            min-height: 20px;
            transition: height 0.3s;
        }}

        .shots-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
        }}

        .shot-card {{
            background: {colors["accent"]};
            border-radius: 8px;
            overflow: hidden;
            padding: 6px;
        }}

        .shot-card img {{
            width: 100%;
            border-radius: 6px;
            display: block;
        }}

        .shot-caption {{
            font-size: 0.8rem;
            margin-top: 6px;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {t["title"]}</h1>
            <div class="meta">
                <strong>{t["target"]}:</strong> {spec.get("target", "N/A")} |
                <strong>{t["profile"]}:</strong> {spec.get("profile", "N/A")} |
                <strong>{t["status"]}:</strong> {metadata.get("status", "N/A")} |
                <strong>ID:</strong> {job_id or "N/A"}
            </div>
        </div>
        
        <!-- إحصائيات سريعة -->
        <div class="grid">
            <div class="card" style="text-align: center;">
                <div class="stat-number">{stats["total"]}</div>
                <div class="stat-label">{t["total_results"]}</div>
            </div>
            <div class="card" style="text-align: center;">
                <div class="stat-number">{stats["hostnames"]}</div>
                <div class="stat-label">{t["hostnames"]}</div>
            </div>
            <div class="card" style="text-align: center;">
                <div class="stat-number">{stats["urls"]}</div>
                <div class="stat-label">{t["urls"]}</div>
            </div>
            <div class="card" style="text-align: center;">
                <div class="stat-number">{len(stats["findings"])}</div>
                <div class="stat-label">{t["findings"]}</div>
            </div>
            {quality_card}
        </div>
        
        <!-- الخطورة -->
        <div class="grid">
            <div class="card">
                <h3>{t["by_severity"]}</h3>
                <div class="chart-container">
                    {_generate_severity_chart(stats["by_severity"], t)}
                </div>
            </div>
            
            <div class="card">
                <h3>{t["by_type"]}</h3>
                <table>
                    <tr><th>النوع</th><th>العدد</th></tr>
                    {"".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in stats["by_type"].items())}
                </table>
            </div>
        </div>

        <!-- Hostnames / URLs -->
        <div class="grid">
            <div class="card">
                <h3>{t["hostnames"]}</h3>
                <table>
                    <tr><th>Hostname</th></tr>
                    {"".join(f'<tr><td>{host}</td></tr>' for host in stats.get("hostnames_list", []))}
                </table>
            </div>
            <div class="card">
                <h3>{t["urls"]}</h3>
                <table>
                    <tr><th>URL</th></tr>
                    {"".join(f'<tr><td>{url}</td></tr>' for url in stats.get("urls_list", []))}
                </table>
            </div>
        </div>
        
        <!-- الأسرار -->
        {_generate_secrets_section(stats["secrets"], t, colors) if stats["secrets"] else ""}

        <!-- Hunter Mode -->
        {_generate_hunter_section(stats.get("top_findings", []), t, colors, job_id) if config.hunter_mode else ""}

        <!-- الاكتشافات -->
        {_generate_findings_section(stats["findings"], t, colors) if stats["findings"] else ""}

        <!-- فحوصات الثغرات -->
        {_generate_vuln_section(stats["vuln_findings"], t, colors) if stats["vuln_findings"] else ""}

        <!-- نتائج WAF -->
        {_generate_waf_section(stats["waf_findings"], t, colors) if stats["waf_findings"] else ""}

        <!-- خدمات Nmap -->
        {_generate_services_section(stats["services"], t, colors) if stats["services"] else ""}

        <!-- نماذج الدخول -->
        {_generate_auth_section(stats["auth_forms"], t, colors) if stats["auth_forms"] else ""}

        <!-- API Specs -->
        {_generate_api_section(stats["api_specs"], t, colors) if stats["api_specs"] else ""}

        <!-- Parameters -->
        {_generate_param_section(stats["parameters"], t, colors) if stats["parameters"] else ""}

        <!-- JS Endpoints -->
        {_generate_js_section(stats["js_endpoints"], t, colors) if stats["js_endpoints"] else ""}

        <!-- Screenshots -->
        {_generate_screenshots_section(stats["screenshots"], t, colors) if config.include_screenshots and stats["screenshots"] else ""}
        
        <div class="footer">
            <p>🛡️ ReconnV2 - Advanced Reconnaissance Pipeline</p>
            <p>{t["generated"]}: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>'''
    
    return html


def _generate_severity_chart(severity_data: Dict, t: Dict) -> str:
    """إنشاء رسم بياني للخطورة"""
    max_val = max(severity_data.values()) if severity_data.values() else 1
    
    items = []
    for sev, count in severity_data.items():
        height = max(20, int((count / max_val) * 100)) if max_val > 0 else 20
        items.append(f'''
            <div class="chart-item">
                <div class="chart-bar severity-{sev}" style="height: {height}px;"></div>
                <div><strong>{count}</strong></div>
                <div class="stat-label">{t.get(sev, sev)}</div>
            </div>
        ''')
    
    return "".join(items)


def _format_pct(value: object) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except (TypeError, ValueError):
        return "n/a"


def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for entry in findings:
        severity = resolve_severity(entry)
        if severity in counts:
            counts[severity] += 1
    return counts


def _compute_quality_stats(results: List[Dict], metadata: Dict) -> Dict[str, object]:
    stats = metadata.get("stats", {}) if isinstance(metadata, dict) else {}
    quality = stats.get("quality") if isinstance(stats.get("quality"), dict) else None
    if quality:
        return quality
    total_urls = 0
    noise_count = 0
    findings_total = 0
    verified_count = 0
    for entry in results:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "url":
            total_urls += 1
            tags = entry.get("tags", [])
            if isinstance(tags, list) and "noise" in tags:
                noise_count += 1
        if is_finding(entry):
            findings_total += 1
            if resolve_confidence_label(entry) == "verified":
                verified_count += 1
    return {
        "noise_ratio": (noise_count / total_urls) if total_urls else 0.0,
        "verified_ratio": (verified_count / findings_total) if findings_total else 0.0,
        "duplicate_ratio": None,
        "noise": noise_count,
        "urls": total_urls,
        "verified_findings": verified_count,
        "findings": findings_total,
    }


def _generate_secrets_section(secrets: List[Dict], t: Dict, colors: Dict) -> str:
    """إنشاء قسم الأسرار"""
    if not secrets:
        return ""
    
    rows = []
    for secret in secrets[:20]:  # أول 20 فقط
        rows.append(f'''
            <tr>
                <td>{secret.get("pattern", "N/A")}</td>
                <td>{secret.get("url", secret.get("source", "N/A"))[:50]}...</td>
                <td><span class="severity-badge severity-high">High</span></td>
            </tr>
        ''')
    
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🔐 {t["secrets"]} ({len(secrets)})</h3>
            <table>
                <tr><th>النوع</th><th>المصدر</th><th>الخطورة</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _truncate_text(value: object, limit: int = 220) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > limit:
        return f"{text[: max(0, limit - 3)]}..."
    return text


def _extract_proof(entry: Dict[str, object], t: Dict[str, str]) -> tuple[str, str]:
    repro = entry.get("repro_cmd")
    if repro:
        return t["repro_cmd"], _truncate_text(repro)
    for key in ("proof", "evidence", "request", "response"):
        value = entry.get(key)
        if value:
            return t["proof"], _truncate_text(value)
    return "", ""


def _generate_hunter_section(findings: List[Dict], t: Dict, colors: Dict, job_id: str) -> str:
    if not findings:
        return ""
    items = []
    for finding in findings:
        severity = resolve_severity(finding)
        confidence = resolve_confidence_label(finding)
        title = finding.get("title") or finding.get("name") or finding.get("description") or "Finding"
        url = finding.get("url") or finding.get("hostname") or finding.get("host") or ""
        source = finding.get("source") or ""
        proof_label, proof_value = _extract_proof(finding, t)
        rerun_cmd = build_finding_rerun_command(job_id, finding) if job_id else ""
        submission_summary = _truncate_text(build_submission_summary(finding), limit=260)
        items.append(f'''
            <div class="finding-item">
                <div class="finding-title">
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                    {title}
                </div>
                <div><strong>{t["confidence"]}:</strong> {confidence}</div>
                {f'<div><strong>{t["source"]}:</strong> {source}</div>' if source else ''}
                {f'<div><strong>URL:</strong> {url}</div>' if url else ''}
                {f'<div><strong>{proof_label}:</strong> <code>{proof_value}</code></div>' if proof_value else ''}
                <div><strong>{t["submission_summary"]}:</strong> {submission_summary}</div>
                {f'<div><strong>{t["rerun_cmd"]}:</strong> <code>{rerun_cmd}</code></div>' if rerun_cmd else ''}
            </div>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🧭 {t["top_actionable"]} ({len(findings)})</h3>
            <div class="findings-list">
                {"".join(items)}
            </div>
        </div>
    '''


def _generate_findings_section(findings: List[Dict], t: Dict, colors: Dict) -> str:
    """إنشاء قسم الاكتشافات"""
    if not findings:
        return ""
    
    items = []
    for finding in findings[:20]:  # أول 20 فقط
        severity = finding.get("severity", "info")
        items.append(f'''
            <div class="finding-item">
                <div class="finding-title">
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                    {finding.get("title", finding.get("name", "Finding"))}
                </div>
                <div>{finding.get("description", finding.get("url", ""))[:200]}</div>
            </div>
        ''')
    
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🎯 {t["findings"]} ({len(findings)})</h3>
            <div class="findings-list">
                {"".join(items)}
            </div>
        </div>
    '''


def _generate_vuln_section(findings: List[Dict], t: Dict, colors: Dict) -> str:
    if not findings:
        return ""
    items = []
    for finding in findings[:20]:
        severity = finding.get("priority", "medium")
        items.append(f'''
            <div class="finding-item">
                <div class="finding-title">
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                    {finding.get("description", "Vulnerability")}
                </div>
                <div>{finding.get("url", "")}</div>
            </div>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🧪 Vuln Scans ({len(findings)})</h3>
            <div class="findings-list">
                {"".join(items)}
            </div>
        </div>
    '''


def _generate_waf_section(findings: List[Dict], t: Dict, colors: Dict) -> str:
    if not findings:
        return ""
    rows = []
    for finding in findings[:15]:
        rows.append(f'''
            <tr>
                <td>{finding.get("hostname", "N/A")}</td>
                <td>{finding.get("details", {}).get("baseline_status", "")}</td>
                <td>{finding.get("details", {}).get("alternate_status", "")}</td>
                <td>{finding.get("details", {}).get("url", "")}</td>
            </tr>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🧱 WAF Findings ({len(findings)})</h3>
            <table>
                <tr><th>Host</th><th>Baseline</th><th>Alternate</th><th>URL</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _generate_services_section(services: List[Dict], t: Dict, colors: Dict) -> str:
    if not services:
        return ""
    rows = []
    for svc in services[:20]:
        rows.append(f'''
            <tr>
                <td>{svc.get("hostname", "N/A")}</td>
                <td>{svc.get("port", "")}</td>
                <td>{svc.get("protocol", "")}</td>
                <td>{svc.get("service", "")}</td>
                <td>{svc.get("product", "")}</td>
                <td>{svc.get("version", "")}</td>
            </tr>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🧭 Nmap Services ({len(services)})</h3>
            <table>
                <tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _generate_auth_section(forms: List[Dict], t: Dict, colors: Dict) -> str:
    if not forms:
        return ""
    rows = []
    for form in forms[:20]:
        inputs = ", ".join(item.get("name") for item in form.get("inputs", []) if isinstance(item, dict) and item.get("name"))
        rows.append(f'''
            <tr>
                <td>{form.get("url", "")}</td>
                <td>{form.get("action", "")}</td>
                <td>{form.get("method", "")}</td>
                <td>{inputs}</td>
            </tr>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🔐 Auth Forms ({len(forms)})</h3>
            <table>
                <tr><th>Page</th><th>Action</th><th>Method</th><th>Inputs</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _generate_api_section(apis: List[Dict], t: Dict, colors: Dict) -> str:
    if not apis:
        return ""
    rows = []
    for api in apis[:20]:
        rows.append(f'''
            <tr>
                <td>{api.get("hostname", "")}</td>
                <td>{api.get("url", "")}</td>
                <td>{",".join(api.get("tags", []))}</td>
            </tr>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>📡 API Specs ({len(apis)})</h3>
            <table>
                <tr><th>Host</th><th>URL</th><th>Tags</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _generate_param_section(params: List[Dict], t: Dict, colors: Dict) -> str:
    if not params:
        return ""
    rows = []
    for param in params[:20]:
        example = ""
        if isinstance(param.get("examples"), list) and param.get("examples"):
            example = param["examples"][0]
        rows.append(f'''
            <tr>
                <td>{param.get("name", "")}</td>
                <td>{param.get("count", "")}</td>
                <td>{example}</td>
            </tr>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🧩 Parameters ({len(params)})</h3>
            <table>
                <tr><th>Name</th><th>Count</th><th>Example</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _generate_js_section(urls: List[Dict], t: Dict, colors: Dict) -> str:
    if not urls:
        return ""
    rows = []
    for entry in urls[:20]:
        rows.append(f'''
            <tr>
                <td>{entry.get("url", "")}</td>
            </tr>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🧠 JS Endpoints ({len(urls)})</h3>
            <table>
                <tr><th>URL</th></tr>
                {"".join(rows)}
            </table>
        </div>
    '''


def _generate_screenshots_section(shots: List[Dict], t: Dict, colors: Dict) -> str:
    if not shots:
        return ""
    cards = []
    for shot in shots[:12]:
        path = shot.get("screenshot_path", "")
        url = shot.get("final_url") or shot.get("url") or ""
        cards.append(f'''
            <div class="shot-card">
                <a href="{path}" target="_blank"><img src="{path}" alt="screenshot" /></a>
                <div class="shot-caption">{url}</div>
            </div>
        ''')
    return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>📸 Screenshots ({len(shots)})</h3>
            <div class="shots-grid">
                {"".join(cards)}
            </div>
        </div>
    '''


# أمر CLI للتقارير
def report_command(job_id: str, output: Optional[str] = None, theme: str = "dark", lang: str = "ar"):
    """
    أمر إنشاء التقرير من CLI
    
    مثال:
        python -m recon_cli.utils.reporter <job-id>
    """
    from recon_cli import config
    
    # البحث عن مجلد المهمة
    job_dir = None
    for status_dir in [config.FINISHED_JOBS, config.FAILED_JOBS, config.RUNNING_JOBS]:
        candidate = status_dir / job_id
        if candidate.exists():
            job_dir = candidate
            break
    
    if not job_dir:
        print(f"Job not found: {job_id}")
        return
    
    output_path = Path(output) if output else None
    
    report_config = ReportConfig(
        theme=theme,
        language=lang
    )
    
    result_path = generate_html_report(job_dir, output_path, report_config)
    print(f"Report generated: {result_path}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        job_id = sys.argv[1]
        output = sys.argv[2] if len(sys.argv) > 2 else None
        report_command(job_id, output)
    else:
        print("Usage: python reporter.py <job-id> [output-path]")
