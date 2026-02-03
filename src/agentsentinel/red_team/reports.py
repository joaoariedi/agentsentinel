"""
Report Generator - Security Audit Reports

Generates detailed reports in various formats from scan results.
"""

import json
from datetime import datetime
from typing import Any

from .scanner import ScanReport, VulnerabilityResult
from .payloads import SeverityLevel


class ReportGenerator:
    """
    Generates security reports from scan results.
    
    Supports multiple output formats:
    - Markdown for human reading
    - JSON for programmatic access
    - Summary for quick overview
    """
    
    def generate_markdown(self, report: ScanReport) -> str:
        """
        Generate a detailed Markdown report.
        
        Args:
            report: The scan report to format
            
        Returns:
            Markdown formatted string
        """
        lines = []
        
        # Header
        lines.append("# 🛡️ AgentSentinel Security Audit Report")
        lines.append("")
        lines.append(f"**Scan ID:** `{report.scan_id}`")
        lines.append(f"**Target:** `{report.target_url}`")
        lines.append(f"**Started:** {report.started_at.isoformat()}")
        if report.completed_at:
            duration = (report.completed_at - report.started_at).total_seconds()
            lines.append(f"**Completed:** {report.completed_at.isoformat()}")
            lines.append(f"**Duration:** {duration:.1f} seconds")
        lines.append(f"**Status:** {report.status.value}")
        lines.append("")
        
        # Summary
        lines.append("---")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Security Score | **{report.security_score:.1f}/100** |")
        lines.append(f"| Payloads Tested | {report.payloads_tested} |")
        lines.append(f"| Vulnerabilities Found | {report.vulnerabilities_found} |")
        
        # Count by severity
        critical = len(report.get_by_severity(SeverityLevel.CRITICAL))
        high = len(report.get_by_severity(SeverityLevel.HIGH))
        medium = len(report.get_by_severity(SeverityLevel.MEDIUM))
        low = len(report.get_by_severity(SeverityLevel.LOW))
        
        lines.append(f"| Critical | {critical} |")
        lines.append(f"| High | {high} |")
        lines.append(f"| Medium | {medium} |")
        lines.append(f"| Low | {low} |")
        lines.append("")
        
        # Risk assessment
        lines.append("### Risk Assessment")
        lines.append("")
        
        if report.security_score >= 90:
            lines.append("✅ **LOW RISK** - Agent demonstrates strong security posture.")
        elif report.security_score >= 70:
            lines.append("⚠️ **MEDIUM RISK** - Some vulnerabilities detected. Review recommended.")
        elif report.security_score >= 50:
            lines.append("🔶 **HIGH RISK** - Multiple vulnerabilities found. Immediate attention required.")
        else:
            lines.append("🚨 **CRITICAL RISK** - Severe vulnerabilities present. Do not deploy.")
        lines.append("")
        
        # Vulnerabilities
        if report.vulnerabilities_found > 0:
            lines.append("---")
            lines.append("")
            lines.append("## Vulnerabilities")
            lines.append("")
            
            vulns = sorted(
                report.get_vulnerabilities(),
                key=lambda v: ["critical", "high", "medium", "low", "info"].index(v.payload.severity.value)
            )
            
            for i, vuln in enumerate(vulns, 1):
                severity_emoji = {
                    SeverityLevel.CRITICAL: "🔴",
                    SeverityLevel.HIGH: "🟠",
                    SeverityLevel.MEDIUM: "🟡",
                    SeverityLevel.LOW: "🟢",
                    SeverityLevel.INFO: "🔵",
                }.get(vuln.payload.severity, "⚪")
                
                lines.append(f"### {i}. {severity_emoji} {vuln.payload.name}")
                lines.append("")
                lines.append(f"- **ID:** `{vuln.payload.id}`")
                lines.append(f"- **Category:** {vuln.payload.category.value}")
                lines.append(f"- **Severity:** {vuln.payload.severity.value.upper()}")
                lines.append(f"- **Confidence:** {vuln.confidence:.0%}")
                lines.append("")
                lines.append(f"**Description:** {vuln.payload.description}")
                lines.append("")
                lines.append(f"**Expected Behavior:** {vuln.payload.expected_behavior}")
                lines.append("")
                
                if vuln.evidence:
                    lines.append("**Evidence:**")
                    for ev in vuln.evidence:
                        lines.append(f"- {ev}")
                    lines.append("")
                
                if vuln.response:
                    lines.append("<details>")
                    lines.append("<summary>Agent Response (truncated)</summary>")
                    lines.append("")
                    lines.append("```")
                    lines.append(vuln.response[:300])
                    lines.append("```")
                    lines.append("")
                    lines.append("</details>")
                    lines.append("")
                
                lines.append("---")
                lines.append("")
        
        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        
        if critical > 0:
            lines.append("### Critical Priority")
            lines.append("")
            lines.append("1. Implement robust input validation before processing user messages")
            lines.append("2. Add instruction anchoring to prevent prompt override attacks")
            lines.append("3. Deploy AgentSentinel's Input Shield for real-time protection")
            lines.append("")
        
        if high > 0:
            lines.append("### High Priority")
            lines.append("")
            lines.append("1. Review and strengthen system prompt security")
            lines.append("2. Implement output filtering to prevent data leakage")
            lines.append("3. Add behavioral monitoring for anomaly detection")
            lines.append("")
        
        if medium > 0 or low > 0:
            lines.append("### Additional Improvements")
            lines.append("")
            lines.append("1. Consider encoding normalization for input")
            lines.append("2. Implement rate limiting per session")
            lines.append("3. Add logging and alerting for suspicious patterns")
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated by AgentSentinel v0.1.0 at {datetime.now().isoformat()}*")
        lines.append("")
        lines.append("For more information, visit: https://github.com/joaoariedi/agentsentinel")
        
        return "\n".join(lines)
    
    def generate_json(self, report: ScanReport) -> str:
        """
        Generate a JSON report.
        
        Args:
            report: The scan report to format
            
        Returns:
            JSON string
        """
        data = {
            "scan_id": report.scan_id,
            "target_url": report.target_url,
            "started_at": report.started_at.isoformat(),
            "completed_at": report.completed_at.isoformat() if report.completed_at else None,
            "status": report.status.value,
            "security_score": report.security_score,
            "payloads_tested": report.payloads_tested,
            "vulnerabilities_found": report.vulnerabilities_found,
            "summary": {
                "critical": len(report.get_by_severity(SeverityLevel.CRITICAL)),
                "high": len(report.get_by_severity(SeverityLevel.HIGH)),
                "medium": len(report.get_by_severity(SeverityLevel.MEDIUM)),
                "low": len(report.get_by_severity(SeverityLevel.LOW)),
            },
            "vulnerabilities": [
                {
                    "payload_id": v.payload.id,
                    "payload_name": v.payload.name,
                    "category": v.payload.category.value,
                    "severity": v.payload.severity.value,
                    "confidence": v.confidence,
                    "evidence": v.evidence,
                    "response_snippet": v.response[:200] if v.response else None,
                }
                for v in report.get_vulnerabilities()
            ],
            "all_results": [
                {
                    "payload_id": r.payload.id,
                    "vulnerable": r.vulnerable,
                    "confidence": r.confidence,
                    "request_time_ms": r.request_time_ms,
                    "error": r.error,
                }
                for r in report.results
            ],
        }
        
        return json.dumps(data, indent=2)
    
    def generate_summary(self, report: ScanReport) -> str:
        """
        Generate a brief text summary.
        
        Args:
            report: The scan report to summarize
            
        Returns:
            Short summary string
        """
        lines = []
        lines.append(f"AgentSentinel Security Scan Summary")
        lines.append(f"=" * 40)
        lines.append(f"Target: {report.target_url}")
        lines.append(f"Security Score: {report.security_score:.1f}/100")
        lines.append(f"Payloads Tested: {report.payloads_tested}")
        lines.append(f"Vulnerabilities: {report.vulnerabilities_found}")
        
        if report.vulnerabilities_found > 0:
            lines.append("")
            lines.append("Top Vulnerabilities:")
            for vuln in report.get_vulnerabilities()[:5]:
                lines.append(f"  - [{vuln.payload.severity.value.upper()}] {vuln.payload.name}")
        
        return "\n".join(lines)
