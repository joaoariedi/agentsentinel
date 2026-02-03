"""
Action Types and Data Models for Behavior Monitoring

Defines the core data structures for tracking agent actions,
including risk classifications and audit logging.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ActionType(str, Enum):
    """Types of actions an agent can perform"""

    # Read operations (low risk)
    READ_FILE = "read_file"
    WEB_FETCH = "web_fetch"
    API_QUERY = "api_query"
    DATABASE_READ = "database_read"

    # Write operations (medium risk)
    WRITE_FILE = "write_file"
    API_MUTATE = "api_mutate"
    DATABASE_WRITE = "database_write"
    SEND_MESSAGE = "send_message"

    # Crypto operations (high risk)
    WALLET_BALANCE = "wallet_balance"
    WALLET_SIGN = "wallet_sign"
    WALLET_TRANSFER = "wallet_transfer"
    CONTRACT_CALL = "contract_call"
    SWAP_EXECUTE = "swap_execute"

    # System operations (critical)
    EXEC_COMMAND = "exec_command"
    ENV_ACCESS = "env_access"
    SECRET_ACCESS = "secret_access"
    NETWORK_CONNECT = "network_connect"


class RiskLevel(str, Enum):
    """Risk classification levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Risk classification mapping
ACTION_RISK_MAP: dict[ActionType, RiskLevel] = {
    ActionType.READ_FILE: RiskLevel.LOW,
    ActionType.WEB_FETCH: RiskLevel.LOW,
    ActionType.API_QUERY: RiskLevel.LOW,
    ActionType.DATABASE_READ: RiskLevel.LOW,
    ActionType.WRITE_FILE: RiskLevel.MEDIUM,
    ActionType.API_MUTATE: RiskLevel.MEDIUM,
    ActionType.DATABASE_WRITE: RiskLevel.MEDIUM,
    ActionType.SEND_MESSAGE: RiskLevel.MEDIUM,
    ActionType.WALLET_BALANCE: RiskLevel.LOW,
    ActionType.WALLET_SIGN: RiskLevel.HIGH,
    ActionType.WALLET_TRANSFER: RiskLevel.CRITICAL,
    ActionType.CONTRACT_CALL: RiskLevel.HIGH,
    ActionType.SWAP_EXECUTE: RiskLevel.HIGH,
    ActionType.EXEC_COMMAND: RiskLevel.CRITICAL,
    ActionType.ENV_ACCESS: RiskLevel.HIGH,
    ActionType.SECRET_ACCESS: RiskLevel.CRITICAL,
    ActionType.NETWORK_CONNECT: RiskLevel.MEDIUM,
}


class AgentAction(BaseModel):
    """Record of a single agent action"""

    id: str = Field(..., description="Unique action identifier")
    timestamp: datetime = Field(..., description="When the action occurred")
    action_type: ActionType = Field(..., description="Type of action performed")
    risk_level: RiskLevel = Field(..., description="Risk classification")

    # Context
    session_id: str = Field(..., description="Session this action belongs to")
    agent_id: str = Field(..., description="Agent performing the action")
    triggered_by: str = Field(..., description="User message hash that triggered this")

    # Details
    target: Optional[str] = Field(None, description="File path, URL, address, etc.")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action parameters")

    # Crypto-specific
    wallet_address: Optional[str] = Field(None, description="Source wallet address")
    destination_address: Optional[str] = Field(None, description="Destination address")
    token: Optional[str] = Field(None, description="Token being transferred")
    amount: Optional[float] = Field(None, description="Amount in token units")
    amount_usd: Optional[float] = Field(None, description="USD equivalent value")

    # Outcome
    status: str = Field("pending", description="pending, approved, blocked, completed, failed")
    result: Optional[Any] = Field(None, description="Action result if completed")
    error: Optional[str] = Field(None, description="Error message if failed")

    # Security
    anomaly_score: float = Field(0.0, ge=0.0, le=1.0, description="Anomaly detection score")
    anomaly_reasons: list[str] = Field(default_factory=list, description="Reasons for anomaly")
    required_approval: bool = Field(False, description="Whether approval was required")
    approved_by: Optional[str] = Field(None, description="Who approved the action")

    model_config = ConfigDict(
        ser_json_timedelta="iso8601",
    )


class ActionLog:
    """Persistent log of all actions"""

    def __init__(self) -> None:
        self.actions: list[AgentAction] = []

    def add(self, action: AgentAction) -> None:
        """Add an action to the log"""
        self.actions.append(action)

    def get_by_session(self, session_id: str) -> list[AgentAction]:
        """Get all actions for a specific session"""
        return [a for a in self.actions if a.session_id == session_id]

    def get_by_type(self, action_type: ActionType) -> list[AgentAction]:
        """Get all actions of a specific type"""
        return [a for a in self.actions if a.action_type == action_type]

    def get_by_agent(self, agent_id: str) -> list[AgentAction]:
        """Get all actions for a specific agent"""
        return [a for a in self.actions if a.agent_id == agent_id]

    def get_recent(self, minutes: int = 60) -> list[AgentAction]:
        """Get actions from the last N minutes"""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return [a for a in self.actions if a.timestamp > cutoff]

    def get_by_status(self, status: str) -> list[AgentAction]:
        """Get all actions with a specific status"""
        return [a for a in self.actions if a.status == status]

    def get_high_risk(self) -> list[AgentAction]:
        """Get all high-risk and critical actions"""
        return [
            a for a in self.actions if a.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]

    def count(self) -> int:
        """Get total action count"""
        return len(self.actions)

    def clear(self) -> None:
        """Clear all actions (use with caution)"""
        self.actions.clear()
