# Phase 2: Behavior Monitor - Action Logging & Anomaly Detection

**Duration:** Days 2-4
**Goal:** Track all agent actions, establish baselines, detect anomalous behavior before damage occurs

---

## Overview

The Behavior Monitor observes what agents actually do (not just what they're asked). It logs actions, builds behavioral baselines, and flags deviations that could indicate compromise.

### Key Capabilities

1. **Action Logging** - Comprehensive audit trail of all agent operations
2. **Baseline Profiling** - Learn normal behavior patterns
3. **Anomaly Detection** - Flag statistical outliers
4. **Pre-sign Verification** - Extra scrutiny for high-risk transactions
5. **Circuit Breakers** - Automatic halt on suspicious patterns

---

## Implementation

### 2.1 Action Types & Logging

```python
# src/behavior_monitor/models.py
from enum import Enum
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any

class ActionType(str, Enum):
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
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Risk classification
ACTION_RISK_MAP = {
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
    id: str
    timestamp: datetime
    action_type: ActionType
    risk_level: RiskLevel
    
    # Context
    session_id: str
    agent_id: str
    triggered_by: str  # User message hash that triggered this
    
    # Details
    target: Optional[str] = None  # File path, URL, address, etc.
    parameters: dict[str, Any] = {}
    
    # Crypto-specific
    wallet_address: Optional[str] = None
    destination_address: Optional[str] = None
    token: Optional[str] = None
    amount: Optional[float] = None
    amount_usd: Optional[float] = None
    
    # Outcome
    status: str = "pending"  # pending, approved, blocked, completed, failed
    result: Optional[Any] = None
    error: Optional[str] = None
    
    # Security
    anomaly_score: float = 0.0
    anomaly_reasons: list[str] = []
    required_approval: bool = False
    approved_by: Optional[str] = None

class ActionLog(BaseModel):
    """Persistent log of all actions"""
    actions: list[AgentAction] = []
    
    def add(self, action: AgentAction):
        self.actions.append(action)
    
    def get_by_session(self, session_id: str) -> list[AgentAction]:
        return [a for a in self.actions if a.session_id == session_id]
    
    def get_by_type(self, action_type: ActionType) -> list[AgentAction]:
        return [a for a in self.actions if a.action_type == action_type]
    
    def get_recent(self, minutes: int = 60) -> list[AgentAction]:
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return [a for a in self.actions if a.timestamp > cutoff]
```

### 2.2 Behavioral Baseline

```python
# src/behavior_monitor/baseline.py
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
from typing import Optional
from .models import ActionType, AgentAction, RiskLevel

@dataclass
class ActionStats:
    """Statistics for a specific action type"""
    count: int = 0
    total_amount: float = 0.0
    amounts: list[float] = field(default_factory=list)
    timestamps: list[datetime] = field(default_factory=list)
    unique_targets: set[str] = field(default_factory=set)
    
    @property
    def avg_amount(self) -> float:
        return self.total_amount / self.count if self.count > 0 else 0.0
    
    @property
    def max_amount(self) -> float:
        return max(self.amounts) if self.amounts else 0.0
    
    @property
    def stddev_amount(self) -> float:
        if len(self.amounts) < 2:
            return 0.0
        return statistics.stdev(self.amounts)
    
    @property
    def actions_per_hour(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        time_span = (max(self.timestamps) - min(self.timestamps)).total_seconds() / 3600
        return self.count / time_span if time_span > 0 else 0.0

@dataclass
class BehaviorBaseline:
    """Learned baseline of normal agent behavior"""
    agent_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    observation_period_hours: float = 0.0
    total_actions: int = 0
    
    # Per-action-type statistics
    action_stats: dict[ActionType, ActionStats] = field(default_factory=dict)
    
    # Time-based patterns
    active_hours: set[int] = field(default_factory=set)  # Hours of day when active
    
    # Common targets
    known_addresses: set[str] = field(default_factory=set)
    known_domains: set[str] = field(default_factory=set)
    
    def update(self, action: AgentAction):
        """Update baseline with new action"""
        self.total_actions += 1
        self.updated_at = datetime.utcnow()
        
        # Update action-specific stats
        if action.action_type not in self.action_stats:
            self.action_stats[action.action_type] = ActionStats()
        
        stats = self.action_stats[action.action_type]
        stats.count += 1
        stats.timestamps.append(action.timestamp)
        
        if action.amount is not None:
            stats.amounts.append(action.amount)
            stats.total_amount += action.amount
        
        if action.target:
            stats.unique_targets.add(action.target)
        
        # Track active hours
        self.active_hours.add(action.timestamp.hour)
        
        # Track known targets
        if action.destination_address:
            self.known_addresses.add(action.destination_address)
        if action.target and action.action_type in [ActionType.WEB_FETCH, ActionType.API_QUERY]:
            from urllib.parse import urlparse
            try:
                domain = urlparse(action.target).netloc
                if domain:
                    self.known_domains.add(domain)
            except:
                pass

class BaselineManager:
    """Manages behavioral baselines for agents"""
    
    def __init__(self, min_observations: int = 50):
        self.baselines: dict[str, BehaviorBaseline] = {}
        self.min_observations = min_observations
    
    def get_or_create(self, agent_id: str) -> BehaviorBaseline:
        if agent_id not in self.baselines:
            self.baselines[agent_id] = BehaviorBaseline(agent_id=agent_id)
        return self.baselines[agent_id]
    
    def record_action(self, action: AgentAction):
        baseline = self.get_or_create(action.agent_id)
        baseline.update(action)
    
    def has_sufficient_data(self, agent_id: str) -> bool:
        baseline = self.baselines.get(agent_id)
        return baseline is not None and baseline.total_actions >= self.min_observations
```

### 2.3 Anomaly Detection Engine

```python
# src/behavior_monitor/anomaly.py
from dataclasses import dataclass
from typing import Optional
from .models import AgentAction, ActionType, RiskLevel, ACTION_RISK_MAP
from .baseline import BehaviorBaseline, BaselineManager

@dataclass
class AnomalyResult:
    is_anomaly: bool
    score: float  # 0.0 - 1.0
    reasons: list[str]
    require_approval: bool
    auto_block: bool

class AnomalyDetector:
    """Detects anomalous agent behavior"""
    
    def __init__(
        self,
        baseline_manager: BaselineManager,
        amount_stddev_threshold: float = 3.0,
        rate_multiplier_threshold: float = 5.0,
        new_target_on_critical: bool = True
    ):
        self.baseline_manager = baseline_manager
        self.amount_stddev_threshold = amount_stddev_threshold
        self.rate_multiplier_threshold = rate_multiplier_threshold
        self.new_target_on_critical = new_target_on_critical
    
    def analyze(self, action: AgentAction) -> AnomalyResult:
        """Analyze an action for anomalies"""
        reasons = []
        score = 0.0
        
        baseline = self.baseline_manager.baselines.get(action.agent_id)
        has_baseline = baseline and self.baseline_manager.has_sufficient_data(action.agent_id)
        
        # Check 1: Unusual action type for this agent
        if has_baseline:
            if action.action_type not in baseline.action_stats:
                reasons.append(f"First time performing {action.action_type.value}")
                score += 0.3
        
        # Check 2: Unusual amount (statistical outlier)
        if action.amount is not None and has_baseline:
            stats = baseline.action_stats.get(action.action_type)
            if stats and stats.stddev_amount > 0:
                z_score = abs(action.amount - stats.avg_amount) / stats.stddev_amount
                if z_score > self.amount_stddev_threshold:
                    reasons.append(f"Amount {action.amount} is {z_score:.1f} std devs from mean")
                    score += min(0.4, z_score * 0.1)
        
        # Check 3: New destination address on high-risk action
        if action.destination_address and has_baseline:
            if action.destination_address not in baseline.known_addresses:
                risk = ACTION_RISK_MAP.get(action.action_type, RiskLevel.MEDIUM)
                if risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    reasons.append(f"New destination address: {action.destination_address[:16]}...")
                    score += 0.4
        
        # Check 4: Unusual time of day
        if has_baseline:
            current_hour = action.timestamp.hour
            if current_hour not in baseline.active_hours:
                reasons.append(f"Action at unusual hour: {current_hour}:00")
                score += 0.2
        
        # Check 5: Rate anomaly (too many actions too fast)
        if has_baseline:
            stats = baseline.action_stats.get(action.action_type)
            if stats and stats.actions_per_hour > 0:
                recent_actions = len([
                    t for t in stats.timestamps[-20:]  # Last 20 actions
                    if (action.timestamp - t).total_seconds() < 3600
                ])
                if recent_actions > stats.actions_per_hour * self.rate_multiplier_threshold:
                    reasons.append(f"Action rate {recent_actions}/hr exceeds normal {stats.actions_per_hour:.1f}/hr")
                    score += 0.3
        
        # Check 6: Critical action without baseline
        if not has_baseline:
            risk = ACTION_RISK_MAP.get(action.action_type, RiskLevel.MEDIUM)
            if risk == RiskLevel.CRITICAL:
                reasons.append("Critical action attempted before baseline established")
                score += 0.5
        
        # Determine response
        is_anomaly = score >= 0.3
        require_approval = score >= 0.5 or ACTION_RISK_MAP.get(action.action_type) == RiskLevel.CRITICAL
        auto_block = score >= 0.8
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            score=min(1.0, score),
            reasons=reasons,
            require_approval=require_approval,
            auto_block=auto_block
        )
```

### 2.4 Transaction Simulator

```python
# src/behavior_monitor/tx_simulator.py
from dataclasses import dataclass
from typing import Optional
import httpx

@dataclass
class SimulationResult:
    success: bool
    error: Optional[str] = None
    
    # Balance changes
    sender_balance_change: float = 0.0
    receiver_balance_change: float = 0.0
    fee: float = 0.0
    
    # Token changes
    tokens_sent: list[dict] = None
    tokens_received: list[dict] = None
    
    # Risk indicators
    interacts_with_known_scam: bool = False
    drains_wallet: bool = False
    unlimited_approval: bool = False
    
    def __post_init__(self):
        self.tokens_sent = self.tokens_sent or []
        self.tokens_received = self.tokens_received or []

class TransactionSimulator:
    """Simulates Solana transactions before signing"""
    
    def __init__(self, rpc_url: str = "https://api.mainnet-beta.solana.com"):
        self.rpc_url = rpc_url
        self.known_scam_addresses = set()  # Load from threat intel
    
    async def simulate(self, transaction_base64: str, wallet_address: str) -> SimulationResult:
        """Simulate a transaction and analyze the outcome"""
        async with httpx.AsyncClient() as client:
            # Use Solana's simulateTransaction RPC
            response = await client.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "simulateTransaction",
                    "params": [
                        transaction_base64,
                        {"encoding": "base64", "commitment": "confirmed"}
                    ]
                }
            )
            
            result = response.json()
            
            if "error" in result:
                return SimulationResult(success=False, error=result["error"]["message"])
            
            sim_result = result.get("result", {}).get("value", {})
            
            if sim_result.get("err"):
                return SimulationResult(success=False, error=str(sim_result["err"]))
            
            # Analyze account changes
            # This would parse the simulation logs to extract balance changes
            # Simplified for now
            
            return SimulationResult(success=True)
    
    async def analyze_risk(
        self,
        destination: str,
        amount: float,
        wallet_balance: float
    ) -> dict:
        """Quick risk analysis without full simulation"""
        risks = []
        risk_score = 0.0
        
        # Check if destination is known scam
        if destination in self.known_scam_addresses:
            risks.append("Destination is a known scam address")
            risk_score = 1.0
        
        # Check if draining wallet
        if amount >= wallet_balance * 0.9:
            risks.append(f"Transaction would drain {amount/wallet_balance*100:.1f}% of wallet")
            risk_score = max(risk_score, 0.8)
        
        # Large transaction threshold
        if amount > 100:  # SOL
            risks.append(f"Large transaction: {amount} SOL")
            risk_score = max(risk_score, 0.5)
        
        return {
            "risks": risks,
            "risk_score": risk_score,
            "should_block": risk_score >= 0.8,
            "require_confirmation": risk_score >= 0.5
        }
```

### 2.5 Main Behavior Monitor

```python
# src/behavior_monitor/monitor.py
import uuid
from datetime import datetime
from typing import Optional, Callable, Awaitable
from .models import AgentAction, ActionType, ACTION_RISK_MAP, ActionLog
from .baseline import BaselineManager
from .anomaly import AnomalyDetector, AnomalyResult
from .tx_simulator import TransactionSimulator

class BehaviorMonitor:
    """Central behavior monitoring system"""
    
    def __init__(
        self,
        rpc_url: str = "https://api.mainnet-beta.solana.com",
        approval_callback: Optional[Callable[[AgentAction], Awaitable[bool]]] = None
    ):
        self.action_log = ActionLog()
        self.baseline_manager = BaselineManager()
        self.anomaly_detector = AnomalyDetector(self.baseline_manager)
        self.tx_simulator = TransactionSimulator(rpc_url)
        self.approval_callback = approval_callback
        
        # Circuit breaker state
        self.blocked_sessions: set[str] = set()
        self.alert_handlers: list[Callable] = []
    
    def add_alert_handler(self, handler: Callable):
        """Add a handler to receive security alerts"""
        self.alert_handlers.append(handler)
    
    async def _send_alert(self, action: AgentAction, anomaly: AnomalyResult):
        """Send alert to all registered handlers"""
        for handler in self.alert_handlers:
            try:
                await handler({
                    "type": "anomaly_detected",
                    "action": action.model_dump(),
                    "anomaly": {
                        "score": anomaly.score,
                        "reasons": anomaly.reasons,
                        "auto_blocked": anomaly.auto_block
                    },
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception as e:
                print(f"Alert handler error: {e}")
    
    async def pre_action_check(
        self,
        action_type: ActionType,
        session_id: str,
        agent_id: str,
        triggered_by: str,
        target: Optional[str] = None,
        destination_address: Optional[str] = None,
        amount: Optional[float] = None,
        parameters: dict = None
    ) -> tuple[bool, AgentAction]:
        """
        Check if an action should be allowed.
        Returns (allowed, action_record)
        """
        
        # Check circuit breaker
        if session_id in self.blocked_sessions:
            action = AgentAction(
                id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                action_type=action_type,
                risk_level=ACTION_RISK_MAP.get(action_type),
                session_id=session_id,
                agent_id=agent_id,
                triggered_by=triggered_by,
                target=target,
                destination_address=destination_address,
                amount=amount,
                parameters=parameters or {},
                status="blocked",
                anomaly_reasons=["Session blocked by circuit breaker"]
            )
            self.action_log.add(action)
            return False, action
        
        # Create action record
        action = AgentAction(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            action_type=action_type,
            risk_level=ACTION_RISK_MAP.get(action_type),
            session_id=session_id,
            agent_id=agent_id,
            triggered_by=triggered_by,
            target=target,
            destination_address=destination_address,
            amount=amount,
            parameters=parameters or {},
            status="pending"
        )
        
        # Run anomaly detection
        anomaly = self.anomaly_detector.analyze(action)
        action.anomaly_score = anomaly.score
        action.anomaly_reasons = anomaly.reasons
        
        # Auto-block if score is too high
        if anomaly.auto_block:
            action.status = "blocked"
            self.action_log.add(action)
            await self._send_alert(action, anomaly)
            
            # Trigger circuit breaker
            self.blocked_sessions.add(session_id)
            
            return False, action
        
        # Require approval for high-risk actions
        if anomaly.require_approval:
            action.required_approval = True
            
            if self.approval_callback:
                approved = await self.approval_callback(action)
                if approved:
                    action.status = "approved"
                    action.approved_by = "human"
                else:
                    action.status = "blocked"
                    self.action_log.add(action)
                    return False, action
            else:
                # No approval mechanism, block by default
                action.status = "blocked"
                action.anomaly_reasons.append("Requires approval but no approval mechanism configured")
                self.action_log.add(action)
                return False, action
        
        # Action approved
        action.status = "approved"
        self.action_log.add(action)
        
        # Update baseline
        self.baseline_manager.record_action(action)
        
        return True, action
    
    def record_completion(self, action_id: str, result: any = None, error: str = None):
        """Record the completion of an action"""
        for action in self.action_log.actions:
            if action.id == action_id:
                action.status = "completed" if not error else "failed"
                action.result = result
                action.error = error
                break
    
    def reset_circuit_breaker(self, session_id: str):
        """Manually reset circuit breaker for a session"""
        self.blocked_sessions.discard(session_id)
    
    def get_session_summary(self, session_id: str) -> dict:
        """Get summary of actions for a session"""
        actions = self.action_log.get_by_session(session_id)
        return {
            "total_actions": len(actions),
            "blocked_actions": len([a for a in actions if a.status == "blocked"]),
            "high_risk_actions": len([a for a in actions if a.risk_level in ["high", "critical"]]),
            "total_anomaly_score": sum(a.anomaly_score for a in actions),
            "is_blocked": session_id in self.blocked_sessions
        }
```

---

## Integration Example

```python
# Example usage in an agent framework
from behavior_monitor import BehaviorMonitor, ActionType

monitor = BehaviorMonitor()

# Before executing a wallet transfer
allowed, action = await monitor.pre_action_check(
    action_type=ActionType.WALLET_TRANSFER,
    session_id="session-123",
    agent_id="my-agent",
    triggered_by="user-msg-hash",
    destination_address="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    amount=10.5
)

if allowed:
    # Execute the transfer
    result = await wallet.transfer(...)
    monitor.record_completion(action.id, result=result)
else:
    # Action was blocked
    print(f"Blocked: {action.anomaly_reasons}")
```

---

## Deliverables

- [ ] `src/behavior_monitor/models.py` - Action types and data models
- [ ] `src/behavior_monitor/baseline.py` - Behavioral baseline system
- [ ] `src/behavior_monitor/anomaly.py` - Anomaly detection engine
- [ ] `src/behavior_monitor/tx_simulator.py` - Transaction simulation
- [ ] `src/behavior_monitor/monitor.py` - Main BehaviorMonitor class
- [ ] `tests/test_behavior_monitor.py` - Unit tests
- [ ] Integration with Input Shield

---

## Next Phase

Proceed to [Phase 3: Infrastructure Monitor](./04-PHASE-3-INFRA-MONITOR.md)
