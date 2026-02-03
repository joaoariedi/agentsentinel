"""
Infrastructure Monitor - Wazuh and OSquery Integration

Provides host-level security monitoring for AI agent deployments.
"""

from .osquery_client import OSQueryClient, OSQueryResult
from .wazuh_client import WazuhClient, WazuhAlert
from .monitor import InfrastructureMonitor, InfraAlert, AlertSeverity

__all__ = [
    "OSQueryClient",
    "OSQueryResult",
    "WazuhClient",
    "WazuhAlert",
    "InfrastructureMonitor",
    "InfraAlert",
    "AlertSeverity",
]
