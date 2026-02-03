"""
AgentSentinel Red Team Suite

Comprehensive security testing framework for AI agents with 50+ prompt injection payloads.

Quick Start:
    >>> from agentsentinel.red_team import AgentScanner, ReportGenerator
    >>> import asyncio
    >>>
    >>> scanner = AgentScanner()
    >>> report = asyncio.run(scanner.scan("https://api.example.com/chat"))
    >>> print(f"Security Score: {report.security_score:.1f}/100")

CLI Usage:
    $ agentsentinel-redteam scan https://api.example.com/chat --quick
    $ agentsentinel-redteam list -v
    $ agentsentinel-redteam info io-001
"""

from .payloads import (
    PAYLOAD_LIBRARY,
    Payload,
    PayloadCategory,
    Severity,
    get_all_tags,
    get_payload_by_id,
    get_payload_count_by_category,
    get_payload_count_by_severity,
    get_payloads_by_category,
    get_payloads_by_severity,
    get_payloads_by_tags,
)
from .reporter import (
    ReportGenerator,
    ReportSection,
    save_report,
)
from .scanner import (
    AgentScanner,
    ScanReport,
    ScanResult,
    ScanStatus,
)

__all__ = [
    # Payloads
    "Payload",
    "PayloadCategory",
    "Severity",
    "PAYLOAD_LIBRARY",
    "get_payloads_by_category",
    "get_payloads_by_severity",
    "get_payloads_by_tags",
    "get_payload_by_id",
    "get_all_tags",
    "get_payload_count_by_category",
    "get_payload_count_by_severity",
    # Scanner
    "AgentScanner",
    "ScanReport",
    "ScanResult",
    "ScanStatus",
    # Reporter
    "ReportGenerator",
    "ReportSection",
    "save_report",
]
