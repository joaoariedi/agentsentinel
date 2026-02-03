"""
AgentSentinel - Comprehensive Security Framework for AI Agents

Protects AI agents from prompt injection, monitors behavioral anomalies,
integrates with enterprise security tools, and provides on-chain security attestations.

Example:
    >>> from agentsentinel import analyze, should_block
    >>> result = analyze("Ignore all previous instructions")
    >>> print(result.should_block)  # True

The package uses a high-performance Rust core when available, with a pure Python
fallback for environments where the native extension cannot be installed.
"""

__version__ = "0.1.0"

# Try to import from Rust core (high-performance)
try:
    from agentsentinel._core import (
        InputShield,
        ThreatAssessment,
        analyze,
        should_block,
        __version__ as _core_version,
    )
    _USING_RUST_CORE = True
except ImportError:
    # Fallback to pure Python implementation
    from agentsentinel.input_shield import (
        InputShield,
        ThreatAssessment,
        analyze,
        should_block,
    )
    _USING_RUST_CORE = False

# Re-export components
from agentsentinel.behavior_monitor import BehaviorMonitor, ActionType
from agentsentinel.infra_monitor import InfrastructureMonitor
from agentsentinel.red_team import AgentScanner, ReportGenerator

__all__ = [
    # Version
    "__version__",
    # Input Shield (Rust core or Python fallback)
    "InputShield",
    "ThreatAssessment",
    "analyze",
    "should_block",
    # Behavior Monitor
    "BehaviorMonitor",
    "ActionType",
    # Infrastructure Monitor
    "InfrastructureMonitor",
    # Red Team
    "AgentScanner",
    "ReportGenerator",
    # Runtime info
    "_USING_RUST_CORE",
]


def get_runtime_info() -> dict:
    """Get information about the current runtime configuration."""
    return {
        "version": __version__,
        "using_rust_core": _USING_RUST_CORE,
        "rust_core_version": _core_version if _USING_RUST_CORE else None,
    }
