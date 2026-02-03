"""
Behavior Monitor - Action Logging & Anomaly Detection

Provides comprehensive behavioral monitoring for AI agents:
- Action logging and audit trails
- Behavioral baseline profiling
- Anomaly detection with statistical analysis
- Transaction simulation for crypto operations
- Circuit breaker protection

Example:
    >>> from agentsentinel.behavior_monitor import BehaviorMonitor, ActionType
    >>> monitor = BehaviorMonitor()
    >>> allowed, action = await monitor.pre_action_check(
    ...     action_type=ActionType.WALLET_TRANSFER,
    ...     session_id="session-123",
    ...     agent_id="my-agent",
    ...     triggered_by="user-msg-hash",
    ...     destination_address="7xKXtg...",
    ...     amount=10.5
    ... )
"""

from .models import (
    ActionType,
    RiskLevel,
    ACTION_RISK_MAP,
    AgentAction,
    ActionLog,
)
from .baseline import (
    ActionStats,
    BehaviorBaseline,
    BaselineManager,
)
from .anomaly import (
    AnomalyResult,
    AnomalyDetector,
)
from .tx_simulator import (
    SimulationResult,
    TransactionSimulator,
)
from .monitor import BehaviorMonitor

__all__ = [
    # Models
    "ActionType",
    "RiskLevel",
    "ACTION_RISK_MAP",
    "AgentAction",
    "ActionLog",
    # Baseline
    "ActionStats",
    "BehaviorBaseline",
    "BaselineManager",
    # Anomaly detection
    "AnomalyResult",
    "AnomalyDetector",
    # Transaction simulation
    "SimulationResult",
    "TransactionSimulator",
    # Main monitor
    "BehaviorMonitor",
]
