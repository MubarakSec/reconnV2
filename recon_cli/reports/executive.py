"""
Executive Summary Generator for ReconnV2.

Generates concise executive summaries for:
- Scan results
- Security posture
- Risk assessment
- Recommendations

Example:
    >>> from recon_cli.reports.executive import ExecutiveSummaryGenerator
    >>> generator = ExecutiveSummaryGenerator()
    >>> summary = generator.generate(scan_data)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

__all__ = [
    "RiskLevel",
    "RiskScore",
    "KeyFinding",
    "Recommendation",
    "ExecutiveSummary",
    "ExecutiveSummaryGenerator",
]


class RiskLevel(Enum):
    """Risk assessment levels."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    
    @property
    def color(self) -> str:
        """Get color for risk level."""
        colors = {
            RiskLevel.CRITICAL: "#dc2626",
            RiskLevel.HIGH: "#ea580c",
            RiskLevel.MEDIUM: "#eab308",
            RiskLevel.LOW: "#3b82f6",
            RiskLevel.MINIMAL: "#10b981",
        }
        return colors.get(self, "#6b7280")
    
    @property
    def score_range(self) -> Tuple[float, float]:
        """Get score range for risk level."""
        ranges = {
            RiskLevel.CRITICAL: (9.0, 10.0),
            RiskLevel.HIGH: (7.0, 8.9),
            RiskLevel.MEDIUM: (4.0, 6.9),
            RiskLevel.LOW: (1.0, 3.9),
            RiskLevel.MINIMAL: (0.0, 0.9),
        }
        return ranges.get(self, (0.0, 10.0))


@dataclass
class RiskScore:
    """Risk assessment score."""
    
    score: float  # 0-10 scale
    level: RiskLevel
    factors: List[str] = field(default_factory=list)
    trend: str = "stable"  # improving, stable, degrading
    
    @classmethod
    def calculate(cls, findings: List[Dict[str, Any]]) -> "RiskScore":
        """Calculate risk score from findings."""
        if not findings:
            return cls(score=0.0, level=RiskLevel.MINIMAL)
        
        # Weight by severity
        severity_weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.5,
            "info": 0.5,
        }
        
        total_weight = 0.0
        factors = []
        
        for finding in findings:
            severity = finding.get("severity", "info")
            weight = severity_weights.get(severity, 0.5)
            total_weight += weight
            
            # Track significant factors
            if severity in ("critical", "high"):
                title = finding.get("title", finding.get("type", "Unknown"))
                factors.append(f"{severity.title()}: {title}")
        
        # Normalize score (logarithmic scale to prevent extreme values)
        import math
        score = min(10.0, math.log1p(total_weight) * 2)
        
        # Determine level
        level = RiskLevel.MINIMAL
        for risk_level in RiskLevel:
            low, high = risk_level.score_range
            if low <= score <= high:
                level = risk_level
                break
        
        return cls(
            score=round(score, 1),
            level=level,
            factors=factors[:5],  # Top 5 factors
        )
    
    @property
    def percentage(self) -> int:
        """Get score as percentage."""
        return int(self.score * 10)
    
    @property
    def letter_grade(self) -> str:
        """Get letter grade for score."""
        if self.score >= 9:
            return "F"
        elif self.score >= 7:
            return "D"
        elif self.score >= 5:
            return "C"
        elif self.score >= 3:
            return "B"
        else:
            return "A"


@dataclass
class KeyFinding:
    """Key finding for executive summary."""
    
    title: str
    severity: str
    impact: str
    affected_assets: List[str] = field(default_factory=list)
    recommendation: str = ""
    
    @classmethod
    def from_finding(cls, finding: Dict[str, Any]) -> "KeyFinding":
        """Create from raw finding."""
        return cls(
            title=finding.get("title", finding.get("type", "Unknown")),
            severity=finding.get("severity", "info"),
            impact=finding.get("impact", finding.get("description", "No impact description")),
            affected_assets=[finding.get("host", finding.get("target", "Unknown"))],
            recommendation=finding.get("remediation", finding.get("recommendation", "")),
        )


@dataclass
class Recommendation:
    """Security recommendation."""
    
    priority: int  # 1-5, 1 being highest
    title: str
    description: str
    effort: str  # low, medium, high
    impact: str  # low, medium, high
    category: str = "general"
    
    @property
    def priority_label(self) -> str:
        """Get human-readable priority label."""
        labels = {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Optional"}
        return labels.get(self.priority, "Unknown")


@dataclass
class ExecutiveSummary:
    """Complete executive summary."""
    
    # Metadata
    title: str
    generated_at: datetime
    scan_date: Optional[datetime]
    author: str
    
    # Overview
    target_count: int
    finding_count: int
    host_count: int
    duration: Optional[str]
    
    # Risk assessment
    risk_score: RiskScore
    
    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Key findings
    key_findings: List[KeyFinding] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[Recommendation] = field(default_factory=list)
    
    # Trends (for comparison reports)
    trend_data: Dict[str, Any] = field(default_factory=dict)
    
    # Custom sections
    custom_sections: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "scan_date": self.scan_date.isoformat() if self.scan_date else None,
            "author": self.author,
            "overview": {
                "targets": self.target_count,
                "findings": self.finding_count,
                "hosts": self.host_count,
                "duration": self.duration,
            },
            "risk": {
                "score": self.risk_score.score,
                "level": self.risk_score.level.value,
                "grade": self.risk_score.letter_grade,
                "factors": self.risk_score.factors,
            },
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "key_findings": [
                {
                    "title": kf.title,
                    "severity": kf.severity,
                    "impact": kf.impact,
                    "affected_assets": kf.affected_assets,
                    "recommendation": kf.recommendation,
                }
                for kf in self.key_findings
            ],
            "recommendations": [
                {
                    "priority": r.priority,
                    "title": r.title,
                    "description": r.description,
                    "effort": r.effort,
                    "impact": r.impact,
                }
                for r in self.recommendations
            ],
        }
    
    def to_text(self) -> str:
        """Generate plain text summary."""
        lines = [
            f"{'=' * 60}",
            f"EXECUTIVE SUMMARY: {self.title}",
            f"{'=' * 60}",
            "",
            f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Author: {self.author}",
            "",
            "OVERVIEW",
            "-" * 40,
            f"  Targets Scanned: {self.target_count}",
            f"  Total Findings:  {self.finding_count}",
            f"  Hosts Found:     {self.host_count}",
            f"  Duration:        {self.duration or 'N/A'}",
            "",
            "RISK ASSESSMENT",
            "-" * 40,
            f"  Risk Score:  {self.risk_score.score}/10 ({self.risk_score.level.value.upper()})",
            f"  Risk Grade:  {self.risk_score.letter_grade}",
            "",
            "SEVERITY BREAKDOWN",
            "-" * 40,
            f"  Critical: {self.critical_count}",
            f"  High:     {self.high_count}",
            f"  Medium:   {self.medium_count}",
            f"  Low:      {self.low_count}",
            f"  Info:     {self.info_count}",
            "",
        ]
        
        if self.key_findings:
            lines.extend([
                "KEY FINDINGS",
                "-" * 40,
            ])
            for i, kf in enumerate(self.key_findings[:5], 1):
                lines.append(f"  {i}. [{kf.severity.upper()}] {kf.title}")
            lines.append("")
        
        if self.recommendations:
            lines.extend([
                "RECOMMENDATIONS",
                "-" * 40,
            ])
            for i, rec in enumerate(self.recommendations[:5], 1):
                lines.append(f"  {i}. [P{rec.priority}] {rec.title}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def to_html(self) -> str:
        """Generate HTML summary."""
        risk_color = self.risk_score.level.color
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.title} - Executive Summary</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; padding: 40px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ font-size: 2rem; color: #1f2937; }}
        .header .meta {{ color: #6b7280; margin-top: 10px; }}
        
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .card h3 {{ color: #374151; font-size: 0.9rem; margin-bottom: 8px; }}
        .card .value {{ font-size: 2.5rem; font-weight: bold; color: #3b82f6; }}
        
        .risk-card {{ background: {risk_color}15; border: 2px solid {risk_color}; }}
        .risk-card .value {{ color: {risk_color}; }}
        .risk-card .grade {{ font-size: 3rem; font-weight: bold; color: {risk_color}; }}
        
        .severity-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }}
        .severity-item {{ text-align: center; padding: 15px; border-radius: 8px; }}
        .severity-critical {{ background: #fef2f2; color: #dc2626; }}
        .severity-high {{ background: #fff7ed; color: #ea580c; }}
        .severity-medium {{ background: #fefce8; color: #ca8a04; }}
        .severity-low {{ background: #eff6ff; color: #3b82f6; }}
        .severity-info {{ background: #f3f4f6; color: #6b7280; }}
        .severity-item .count {{ font-size: 1.5rem; font-weight: bold; }}
        .severity-item .label {{ font-size: 0.8rem; text-transform: uppercase; }}
        
        .findings-list {{ margin-top: 20px; }}
        .finding {{ background: white; border-radius: 8px; padding: 16px; margin: 10px 0; border-left: 4px solid #3b82f6; }}
        .finding.critical {{ border-left-color: #dc2626; }}
        .finding.high {{ border-left-color: #ea580c; }}
        .finding h4 {{ margin-bottom: 8px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        
        .recommendations ol {{ padding-left: 20px; }}
        .recommendations li {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 {self.title}</h1>
            <p class="meta">Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')} | Author: {self.author}</p>
        </div>
        
        <div class="grid">
            <div class="card risk-card">
                <h3>Risk Assessment</h3>
                <div class="grade">{self.risk_score.letter_grade}</div>
                <p>{self.risk_score.score}/10 - {self.risk_score.level.value.upper()}</p>
            </div>
            <div class="card">
                <h3>Targets Scanned</h3>
                <div class="value">{self.target_count}</div>
            </div>
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value">{self.finding_count}</div>
            </div>
            <div class="card">
                <h3>Hosts Discovered</h3>
                <div class="value">{self.host_count}</div>
            </div>
        </div>
        
        <div class="card">
            <h3>Severity Breakdown</h3>
            <div class="severity-grid">
                <div class="severity-item severity-critical">
                    <div class="count">{self.critical_count}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="severity-item severity-high">
                    <div class="count">{self.high_count}</div>
                    <div class="label">High</div>
                </div>
                <div class="severity-item severity-medium">
                    <div class="count">{self.medium_count}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="severity-item severity-low">
                    <div class="count">{self.low_count}</div>
                    <div class="label">Low</div>
                </div>
                <div class="severity-item severity-info">
                    <div class="count">{self.info_count}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </div>
        
        <div class="card" style="margin-top: 20px;">
            <h3>🔍 Key Findings</h3>
            <div class="findings-list">
                {''.join(f'''
                <div class="finding {kf.severity}">
                    <h4>{kf.title}</h4>
                    <span class="badge">{kf.severity}</span>
                    <p>{kf.impact[:200]}...</p>
                </div>
                ''' for kf in self.key_findings[:5])}
            </div>
        </div>
        
        <div class="card recommendations" style="margin-top: 20px;">
            <h3>💡 Recommendations</h3>
            <ol>
                {''.join(f'<li><strong>{rec.title}</strong>: {rec.description}</li>' for rec in self.recommendations[:5])}
            </ol>
        </div>
    </div>
</body>
</html>"""
        
        return html


class ExecutiveSummaryGenerator:
    """Generate executive summaries from scan data."""
    
    def __init__(
        self,
        author: str = "ReconnV2",
        title_template: str = "Security Assessment - {target}",
    ):
        self.author = author
        self.title_template = title_template
    
    def generate(
        self,
        data: Dict[str, Any],
        title: Optional[str] = None,
    ) -> ExecutiveSummary:
        """Generate executive summary from scan data."""
        findings = data.get("findings", [])
        hosts = data.get("hosts", [])
        targets = data.get("targets", [])
        
        # Calculate severity counts
        severity_counts: Dict[str, int] = defaultdict(int)
        for finding in findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = RiskScore.calculate(findings)
        
        # Extract key findings (critical and high severity)
        key_findings = []
        for finding in findings:
            if finding.get("severity") in ("critical", "high"):
                key_findings.append(KeyFinding.from_finding(finding))
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        key_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings, hosts)
        
        # Build title
        if not title:
            primary_target = targets[0] if targets else "Target"
            title = self.title_template.format(target=primary_target)
        
        # Parse dates
        scan_date = None
        if "start_time" in data:
            try:
                scan_date = datetime.fromisoformat(data["start_time"])
            except (ValueError, TypeError):
                pass
        
        # Calculate duration
        duration = None
        if "start_time" in data and "end_time" in data:
            try:
                start = datetime.fromisoformat(data["start_time"])
                end = datetime.fromisoformat(data["end_time"])
                duration = str(end - start)
            except (ValueError, TypeError):
                pass
        
        return ExecutiveSummary(
            title=title,
            generated_at=datetime.now(),
            scan_date=scan_date,
            author=self.author,
            target_count=len(targets),
            finding_count=len(findings),
            host_count=len(hosts),
            duration=duration,
            risk_score=risk_score,
            critical_count=severity_counts.get("critical", 0),
            high_count=severity_counts.get("high", 0),
            medium_count=severity_counts.get("medium", 0),
            low_count=severity_counts.get("low", 0),
            info_count=severity_counts.get("info", 0),
            key_findings=key_findings[:10],
            recommendations=recommendations,
        )
    
    def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]],
        hosts: List[Dict[str, Any]],
    ) -> List[Recommendation]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        # Analyze finding types
        finding_types: Dict[str, int] = defaultdict(int)
        for finding in findings:
            finding_type = finding.get("type", "unknown")
            finding_types[finding_type] += 1
        
        # Generate recommendations based on patterns
        if finding_types.get("sql_injection", 0) > 0:
            recommendations.append(Recommendation(
                priority=1,
                title="Address SQL Injection Vulnerabilities",
                description="Implement parameterized queries and input validation across all database interactions.",
                effort="medium",
                impact="high",
                category="application",
            ))
        
        if finding_types.get("xss", 0) > 0:
            recommendations.append(Recommendation(
                priority=2,
                title="Implement XSS Protection",
                description="Add Content Security Policy headers and sanitize all user inputs.",
                effort="medium",
                impact="high",
                category="application",
            ))
        
        if finding_types.get("subdomain_takeover", 0) > 0:
            recommendations.append(Recommendation(
                priority=1,
                title="Resolve Subdomain Takeover Risks",
                description="Remove or reclaim dangling DNS records pointing to unused services.",
                effort="low",
                impact="high",
                category="infrastructure",
            ))
        
        if finding_types.get("exposed_secret", 0) > 0:
            recommendations.append(Recommendation(
                priority=1,
                title="Rotate Exposed Credentials",
                description="Immediately rotate all exposed secrets and implement secrets management.",
                effort="medium",
                impact="high",
                category="security",
            ))
        
        # Check for open admin ports
        admin_ports = {22, 3389, 5900, 8080, 9090}
        exposed_admin = 0
        for host in hosts:
            open_ports = set(host.get("open_ports", []))
            if open_ports & admin_ports:
                exposed_admin += 1
        
        if exposed_admin > 0:
            recommendations.append(Recommendation(
                priority=2,
                title="Restrict Administrative Access",
                description=f"Found {exposed_admin} hosts with exposed admin ports. Implement network segmentation.",
                effort="high",
                impact="high",
                category="infrastructure",
            ))
        
        # Generic recommendations if few specific ones
        if len(recommendations) < 3:
            recommendations.append(Recommendation(
                priority=3,
                title="Implement Regular Vulnerability Scanning",
                description="Schedule automated vulnerability assessments on a weekly basis.",
                effort="low",
                impact="medium",
                category="process",
            ))
            
            recommendations.append(Recommendation(
                priority=4,
                title="Security Awareness Training",
                description="Conduct security awareness training for development and operations teams.",
                effort="medium",
                impact="medium",
                category="process",
            ))
        
        # Sort by priority
        recommendations.sort(key=lambda r: r.priority)
        
        return recommendations[:10]
    
    def compare(
        self,
        current: Dict[str, Any],
        previous: Dict[str, Any],
    ) -> ExecutiveSummary:
        """Generate comparative executive summary."""
        summary = self.generate(current)
        
        # Add trend data
        prev_findings = len(previous.get("findings", []))
        curr_findings = len(current.get("findings", []))
        
        if curr_findings < prev_findings:
            trend = "improving"
            change = f"{prev_findings - curr_findings} fewer findings"
        elif curr_findings > prev_findings:
            trend = "degrading"
            change = f"{curr_findings - prev_findings} new findings"
        else:
            trend = "stable"
            change = "No change in finding count"
        
        summary.risk_score.trend = trend
        summary.trend_data = {
            "previous_findings": prev_findings,
            "current_findings": curr_findings,
            "change": change,
            "trend": trend,
        }
        
        return summary
