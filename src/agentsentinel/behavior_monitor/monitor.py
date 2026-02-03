"""
Behavior Monitor - Central Monitoring System

Orchestrates action logging, baseline profiling, anomaly detection,
and circuit breaker protection for AI agents.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from .models import AgentAction, ActionType, ACTION_RISK_MAP, ActionLog, RiskLevel
from .baseline import BaselineManager
from .anomaly import AnomalyDetector, AnomalyResult
from .tx_simulator import TransactionSimulator


# Type alias for alert handlers
AlertHandler = Callable[[dict], Awaitable[None]]
ApprovalCallback = Callable[[AgentAction], Awaitable[bool]]


class BehaviorMonitor:
    """
    Central behavior monitoring system for AI agents.

    Provides:
    - Pre-action security checks
    - Behavioral baseline profiling
    - Anomaly detection
    - Circuit breaker protection
    - Action logging and audit trails
    """

    def __init__(
        self,
        rpc_url: str = "https://api.mainnet-beta.solana.com",
        approval_callback: Optional[ApprovalCallback] = None,
        min_baseline_observations: int = 50,
    ) -> None:
        """
        Initialize the behavior monitor.

        Args:
            rpc_url: Solana RPC endpoint for transaction simulation
            approval_callback: Async callback for requesting human approval
            min_baseline_observations: Minimum actions before baseline is trusted
        """
        self.action_log = ActionLog()
        self.baseline_manager = BaselineManager(min_observations=min_baseline_observations)
        self.anomaly_detector = AnomalyDetector(self.baseline_manager)
        self.tx_simulator = TransactionSimulator(rpc_url)
        self.approval_callback = approval_callback

        # Circuit breaker state
        self.blocked_sessions: set[str] = set()
        self.alert_handlers: list[AlertHandler] = []

    def add_alert_handler(self, handler: AlertHandler) -> None:
        """
        Add a handler to receive security alerts.

        Args:
            handler: Async function that receives alert dictionaries
        """
        self.alert_handlers.append(handler)

    def remove_alert_handler(self, handler: AlertHandler) -> None:
        """Remove an alert handler"""
        if handler in self.alert_handlers:
            self.alert_handlers.remove(handler)

    async def _send_alert(self, action: AgentAction, anomaly: AnomalyResult) -> None:
        """Send alert to all registered handlers"""
        alert_data = {
            "type": "anomaly_detected",
            "action": action.model_dump(),
            "anomaly": {
                "score": anomaly.score,
                "reasons": anomaly.reasons,
                "auto_blocked": anomaly.auto_block,
                "require_approval": anomaly.require_approval,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        for handler in self.alert_handlers:
            try:
                await handler(alert_data)
            except Exception as e:
                # Log but don't fail on alert handler errors
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
        amount_usd: Optional[float] = None,
        wallet_address: Optional[str] = None,
        token: Optional[str] = None,
        parameters: Optional[dict] = None,
    ) -> tuple[bool, AgentAction]:
        """
        Check if an action should be allowed.

        Performs:
        1. Circuit breaker check
        2. Anomaly detection
        3. Approval request if needed
        4. Action logging

        Args:
            action_type: Type of action being attempted
            session_id: Current session identifier
            agent_id: Identifier of the agent
            triggered_by: Hash of user message that triggered this
            target: Target of the action (URL, file path, etc.)
            destination_address: Destination for crypto transfers
            amount: Amount for financial operations
            amount_usd: USD equivalent of amount
            wallet_address: Source wallet address
            token: Token being transferred
            parameters: Additional action parameters

        Returns:
            Tuple of (allowed: bool, action: AgentAction)
        """
        risk_level = ACTION_RISK_MAP.get(action_type, RiskLevel.MEDIUM)

        # Check circuit breaker first
        if session_id in self.blocked_sessions:
            action = AgentAction(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                action_type=action_type,
                risk_level=risk_level,
                session_id=session_id,
                agent_id=agent_id,
                triggered_by=triggered_by,
                target=target,
                destination_address=destination_address,
                amount=amount,
                amount_usd=amount_usd,
                wallet_address=wallet_address,
                token=token,
                parameters=parameters or {},
                status="blocked",
                anomaly_reasons=["Session blocked by circuit breaker"],
            )
            self.action_log.add(action)
            return False, action

        # Create action record
        action = AgentAction(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            action_type=action_type,
            risk_level=risk_level,
            session_id=session_id,
            agent_id=agent_id,
            triggered_by=triggered_by,
            target=target,
            destination_address=destination_address,
            amount=amount,
            amount_usd=amount_usd,
            wallet_address=wallet_address,
            token=token,
            parameters=parameters or {},
            status="pending",
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
                try:
                    approved = await self.approval_callback(action)
                    if approved:
                        action.status = "approved"
                        action.approved_by = "human"
                    else:
                        action.status = "blocked"
                        action.anomaly_reasons.append("Denied by human reviewer")
                        self.action_log.add(action)
                        return False, action
                except Exception as e:
                    # Approval failed, block by default
                    action.status = "blocked"
                    action.anomaly_reasons.append(f"Approval mechanism failed: {e}")
                    self.action_log.add(action)
                    return False, action
            else:
                # No approval mechanism, block by default for safety
                action.status = "blocked"
                action.anomaly_reasons.append(
                    "Requires approval but no approval mechanism configured"
                )
                self.action_log.add(action)
                return False, action

        # Action approved
        action.status = "approved"
        self.action_log.add(action)

        # Update baseline with approved actions
        self.baseline_manager.record_action(action)

        return True, action

    def record_completion(
        self,
        action_id: str,
        result: Any = None,
        error: Optional[str] = None,
    ) -> bool:
        """
        Record the completion of an action.

        Args:
            action_id: ID of the action to update
            result: Result of the action if successful
            error: Error message if failed

        Returns:
            True if action was found and updated
        """
        for action in self.action_log.actions:
            if action.id == action_id:
                action.status = "completed" if not error else "failed"
                action.result = result
                action.error = error
                return True
        return False

    def reset_circuit_breaker(self, session_id: str) -> bool:
        """
        Manually reset circuit breaker for a session.

        Args:
            session_id: Session to unblock

        Returns:
            True if session was blocked and is now unblocked
        """
        if session_id in self.blocked_sessions:
            self.blocked_sessions.discard(session_id)
            return True
        return False

    def is_session_blocked(self, session_id: str) -> bool:
        """Check if a session is blocked by circuit breaker"""
        return session_id in self.blocked_sessions

    def block_session(self, session_id: str, reason: str = "Manual block") -> None:
        """Manually block a session"""
        self.blocked_sessions.add(session_id)

    def get_session_summary(self, session_id: str) -> dict:
        """
        Get summary of actions for a session.

        Args:
            session_id: Session to summarize

        Returns:
            Dictionary with session statistics
        """
        actions = self.action_log.get_by_session(session_id)

        return {
            "session_id": session_id,
            "total_actions": len(actions),
            "blocked_actions": len([a for a in actions if a.status == "blocked"]),
            "completed_actions": len([a for a in actions if a.status == "completed"]),
            "failed_actions": len([a for a in actions if a.status == "failed"]),
            "high_risk_actions": len(
                [a for a in actions if a.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
            ),
            "total_anomaly_score": sum(a.anomaly_score for a in actions),
            "average_anomaly_score": (
                sum(a.anomaly_score for a in actions) / len(actions) if actions else 0.0
            ),
            "is_blocked": session_id in self.blocked_sessions,
            "action_types": list(set(a.action_type.value for a in actions)),
        }

    def get_agent_summary(self, agent_id: str) -> dict:
        """
        Get summary of actions and baseline for an agent.

        Args:
            agent_id: Agent to summarize

        Returns:
            Dictionary with agent statistics and baseline info
        """
        actions = self.action_log.get_by_agent(agent_id)
        baseline = self.baseline_manager.get(agent_id)

        return {
            "agent_id": agent_id,
            "total_actions": len(actions),
            "has_baseline": self.baseline_manager.has_sufficient_data(agent_id),
            "baseline_observations": baseline.total_actions if baseline else 0,
            "baseline_period_hours": baseline.observation_period_hours if baseline else 0,
            "known_addresses": len(baseline.known_addresses) if baseline else 0,
            "known_domains": len(baseline.known_domains) if baseline else 0,
            "active_hours": sorted(baseline.active_hours) if baseline else [],
        }

    def get_action(self, action_id: str) -> Optional[AgentAction]:
        """Get a specific action by ID"""
        for action in self.action_log.actions:
            if action.id == action_id:
                return action
        return None

    def get_recent_actions(self, minutes: int = 60) -> list[AgentAction]:
        """Get actions from the last N minutes"""
        return self.action_log.get_recent(minutes)

    def get_high_risk_actions(self) -> list[AgentAction]:
        """Get all high-risk and critical actions"""
        return self.action_log.get_high_risk()

    def set_approval_callback(self, callback: Optional[ApprovalCallback]) -> None:
        """Set or update the approval callback"""
        self.approval_callback = callback

    def export_audit_log(self, session_id: Optional[str] = None) -> list[dict]:
        """
        Export action log for auditing.

        Args:
            session_id: Optional filter by session

        Returns:
            List of action records as dictionaries
        """
        if session_id:
            actions = self.action_log.get_by_session(session_id)
        else:
            actions = self.action_log.actions

        return [action.model_dump() for action in actions]
