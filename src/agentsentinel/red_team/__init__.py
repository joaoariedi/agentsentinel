"""
Red Team Suite - Automated Security Auditing

Provides automated security auditing capabilities for AI agents:
- 50+ injection payloads
- Automated scanning
- Security scoring
- Detailed vulnerability reports

Example:
    >>> from agentsentinel.red_team import AgentScanner, ReportGenerator
    >>> scanner = AgentScanner()
    >>> report = await scanner.scan("https://agent-api.example.com/chat")
    >>> print(f"Security Score: {report.security_score}/100")
"""

from . import payloads
from . import scanner
from . import reports
from .scanner import AgentScanner, ScanReport, VulnerabilityResult, ScanStatus
from .reports import ReportGenerator

__all__ = [
    # Payloads
    "payloads",
    # Scanner
    "AgentScanner",
    "ScanReport",
    "VulnerabilityResult",
    "ScanStatus",
    # Reports
    "ReportGenerator",
]
