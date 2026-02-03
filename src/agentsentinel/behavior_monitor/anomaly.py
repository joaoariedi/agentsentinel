"""
Anomaly Detection Engine

Detects anomalous agent behavior by comparing actions against
established behavioral baselines using statistical analysis.
"""

from dataclasses import dataclass, field
from typing import Optional

from .models import AgentAction, ActionType, RiskLevel, ACTION_RISK_MAP
from .baseline import BehaviorBaseline, BaselineManager


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis"""

    is_anomaly: bool
    score: float  # 0.0 - 1.0
    reasons: list[str] = field(default_factory=list)
    require_approval: bool = False
    auto_block: bool = False

    def add_reason(self, reason: str, score_delta: float) -> float:
        """Add an anomaly reason and return the new cumulative score delta"""
        self.reasons.append(reason)
        return score_delta


class AnomalyDetector:
    """Detects anomalous agent behavior through statistical analysis"""

    def __init__(
        self,
        baseline_manager: BaselineManager,
        amount_stddev_threshold: float = 3.0,
        rate_multiplier_threshold: float = 5.0,
        anomaly_threshold: float = 0.3,
        approval_threshold: float = 0.5,
        block_threshold: float = 0.8,
    ) -> None:
        """
        Initialize the anomaly detector.

        Args:
            baseline_manager: Manager containing agent baselines
            amount_stddev_threshold: Z-score threshold for amount anomalies
            rate_multiplier_threshold: Multiplier threshold for rate anomalies
            anomaly_threshold: Score threshold to flag as anomaly
            approval_threshold: Score threshold to require approval
            block_threshold: Score threshold for automatic blocking
        """
        self.baseline_manager = baseline_manager
        self.amount_stddev_threshold = amount_stddev_threshold
        self.rate_multiplier_threshold = rate_multiplier_threshold
        self.anomaly_threshold = anomaly_threshold
        self.approval_threshold = approval_threshold
        self.block_threshold = block_threshold

    def analyze(self, action: AgentAction) -> AnomalyResult:
        """
        Analyze an action for anomalies.

        Performs 6 checks:
        1. Unusual action type for this agent
        2. Unusual amount (statistical outlier)
        3. New destination on high-risk action
        4. Unusual time of day
        5. Rate anomaly (too many actions too fast)
        6. Critical action without established baseline

        Args:
            action: The action to analyze

        Returns:
            AnomalyResult with score, reasons, and recommended response
        """
        reasons: list[str] = []
        score = 0.0

        baseline = self.baseline_manager.baselines.get(action.agent_id)
        has_baseline = baseline is not None and self.baseline_manager.has_sufficient_data(
            action.agent_id
        )

        # Check 1: Unusual action type for this agent
        score += self._check_unusual_action_type(action, baseline, has_baseline, reasons)

        # Check 2: Unusual amount (statistical outlier)
        score += self._check_unusual_amount(action, baseline, has_baseline, reasons)

        # Check 3: New destination address on high-risk action
        score += self._check_new_destination(action, baseline, has_baseline, reasons)

        # Check 4: Unusual time of day
        score += self._check_unusual_time(action, baseline, has_baseline, reasons)

        # Check 5: Rate anomaly (too many actions too fast)
        score += self._check_rate_anomaly(action, baseline, has_baseline, reasons)

        # Check 6: Critical action without baseline
        score += self._check_critical_without_baseline(action, has_baseline, reasons)

        # Determine response thresholds
        is_anomaly = score >= self.anomaly_threshold
        risk_level = ACTION_RISK_MAP.get(action.action_type, RiskLevel.MEDIUM)
        require_approval = score >= self.approval_threshold or risk_level == RiskLevel.CRITICAL
        auto_block = score >= self.block_threshold

        return AnomalyResult(
            is_anomaly=is_anomaly,
            score=min(1.0, score),
            reasons=reasons,
            require_approval=require_approval,
            auto_block=auto_block,
        )

    def _check_unusual_action_type(
        self,
        action: AgentAction,
        baseline: Optional[BehaviorBaseline],
        has_baseline: bool,
        reasons: list[str],
    ) -> float:
        """Check if this action type is unusual for the agent"""
        if has_baseline and baseline is not None:
            if action.action_type not in baseline.action_stats:
                reasons.append(f"First time performing {action.action_type.value}")
                return 0.3
        return 0.0

    def _check_unusual_amount(
        self,
        action: AgentAction,
        baseline: Optional[BehaviorBaseline],
        has_baseline: bool,
        reasons: list[str],
    ) -> float:
        """Check if the amount is a statistical outlier"""
        if action.amount is None or not has_baseline or baseline is None:
            return 0.0

        stats = baseline.action_stats.get(action.action_type)
        if stats is None or stats.stddev_amount <= 0:
            return 0.0

        # Calculate z-score
        z_score = abs(action.amount - stats.avg_amount) / stats.stddev_amount

        if z_score > self.amount_stddev_threshold:
            reasons.append(
                f"Amount {action.amount} is {z_score:.1f} std devs from mean "
                f"(avg: {stats.avg_amount:.2f}, stddev: {stats.stddev_amount:.2f})"
            )
            return min(0.4, z_score * 0.1)

        return 0.0

    def _check_new_destination(
        self,
        action: AgentAction,
        baseline: Optional[BehaviorBaseline],
        has_baseline: bool,
        reasons: list[str],
    ) -> float:
        """Check if destination is new on high-risk actions"""
        if not action.destination_address or not has_baseline or baseline is None:
            return 0.0

        if action.destination_address not in baseline.known_addresses:
            risk = ACTION_RISK_MAP.get(action.action_type, RiskLevel.MEDIUM)
            if risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                truncated_addr = action.destination_address[:16]
                reasons.append(f"New destination address: {truncated_addr}...")
                return 0.4

        return 0.0

    def _check_unusual_time(
        self,
        action: AgentAction,
        baseline: Optional[BehaviorBaseline],
        has_baseline: bool,
        reasons: list[str],
    ) -> float:
        """Check if action is at an unusual time of day"""
        if not has_baseline or baseline is None:
            return 0.0

        current_hour = action.timestamp.hour
        if current_hour not in baseline.active_hours and len(baseline.active_hours) > 0:
            reasons.append(f"Action at unusual hour: {current_hour}:00")
            return 0.2

        return 0.0

    def _check_rate_anomaly(
        self,
        action: AgentAction,
        baseline: Optional[BehaviorBaseline],
        has_baseline: bool,
        reasons: list[str],
    ) -> float:
        """Check if action rate is abnormally high"""
        if not has_baseline or baseline is None:
            return 0.0

        stats = baseline.action_stats.get(action.action_type)
        if stats is None or stats.actions_per_hour <= 0:
            return 0.0

        # Count recent actions (within last hour from timestamps)
        recent_actions = sum(
            1
            for t in stats.timestamps[-20:]  # Check last 20 timestamps
            if (action.timestamp - t).total_seconds() < 3600
        )

        threshold = stats.actions_per_hour * self.rate_multiplier_threshold
        if recent_actions > threshold:
            reasons.append(
                f"Action rate {recent_actions}/hr exceeds normal "
                f"{stats.actions_per_hour:.1f}/hr by {self.rate_multiplier_threshold}x"
            )
            return 0.3

        return 0.0

    def _check_critical_without_baseline(
        self,
        action: AgentAction,
        has_baseline: bool,
        reasons: list[str],
    ) -> float:
        """Check if attempting critical action without established baseline"""
        if has_baseline:
            return 0.0

        risk = ACTION_RISK_MAP.get(action.action_type, RiskLevel.MEDIUM)
        if risk == RiskLevel.CRITICAL:
            reasons.append("Critical action attempted before baseline established")
            return 0.5

        return 0.0

    def set_thresholds(
        self,
        anomaly: Optional[float] = None,
        approval: Optional[float] = None,
        block: Optional[float] = None,
    ) -> None:
        """Update detection thresholds"""
        if anomaly is not None:
            self.anomaly_threshold = anomaly
        if approval is not None:
            self.approval_threshold = approval
        if block is not None:
            self.block_threshold = block
