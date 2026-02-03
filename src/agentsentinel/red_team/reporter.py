
import json
from dataclasses import dataclass
from typing import List
from agentsentinel.red_team.scanner import ScanReport, VulnerabilityResult

class ReportGenerator:
    def __init__(self, scan_report: ScanReport):
        self.scan_report = scan_report

    def generate_markdown(self) -> str:
        # Implement markdown report generation logic here
        report = "# Red Team Scan Report\n\n"
        report += f"**Security Score:** {self.scan_report.security_score:.2f}\n\n"
        report += "## Scan Results\n\n"
        report += "| Payload | Category | Severity | Success | Response |\n"
        report += "|---|---|---|---|---|\n"
        for result in self.scan_report.scan_results:
            report += f"| {result.payload.text} | {result.payload.category} | {result.payload.severity} | {result.vulnerable} | {result.response} |\n"

        # Recommendations (example)
        report += "\n## Recommendations\n\n"
        if self.scan_report.security_score < 70:
            report += "- Implement stricter input validation.\n"
            report += "- Sanitize user inputs to prevent injection attacks.\n"
        else:
            report += "- The system appears to be relatively secure based on the tests conducted.\n"
        return report

    def generate_json(self) -> str:
        # Implement JSON report generation logic here
        report_data = {
            "security_score": self.scan_report.security_score,
            "scan_results": [
                {
                    "payload": result.payload.text,
                    "category": result.payload.category,
                    "severity": result.payload.severity,
                    "success": result.vulnerable,
                    "response": result.response,
                }
                for result in self.scan_report.scan_results
            ],
            "recommendations": [  # Example recommendations
                "Implement stricter input validation.",
                "Sanitize user inputs to prevent injection attacks.",
            ] if self.scan_report.security_score < 70 else ["The system appears to be relatively secure"]
        }
        return json.dumps(report_data, indent=4)
