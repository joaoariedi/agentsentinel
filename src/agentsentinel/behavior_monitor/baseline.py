"""
Behavioral Baseline System

Learns normal behavior patterns for agents to enable
anomaly detection through statistical analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import statistics

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
        """Average transaction amount"""
        return self.total_amount / self.count if self.count > 0 else 0.0

    @property
    def max_amount(self) -> float:
        """Maximum transaction amount"""
        return max(self.amounts) if self.amounts else 0.0

    @property
    def min_amount(self) -> float:
        """Minimum transaction amount"""
        return min(self.amounts) if self.amounts else 0.0

    @property
    def stddev_amount(self) -> float:
        """Standard deviation of amounts"""
        if len(self.amounts) < 2:
            return 0.0
        return statistics.stdev(self.amounts)

    @property
    def actions_per_hour(self) -> float:
        """Average actions per hour over observation period"""
        if len(self.timestamps) < 2:
            return 0.0
        time_span = (max(self.timestamps) - min(self.timestamps)).total_seconds() / 3600
        return self.count / time_span if time_span > 0 else 0.0

    @property
    def target_count(self) -> int:
        """Number of unique targets"""
        return len(self.unique_targets)


@dataclass
class BehaviorBaseline:
    """Learned baseline of normal agent behavior"""

    agent_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    observation_period_hours: float = 0.0
    total_actions: int = 0

    # Per-action-type statistics
    action_stats: dict[ActionType, ActionStats] = field(default_factory=dict)

    # Time-based patterns
    active_hours: set[int] = field(default_factory=set)  # Hours of day when active

    # Common targets
    known_addresses: set[str] = field(default_factory=set)
    known_domains: set[str] = field(default_factory=set)
    known_file_paths: set[str] = field(default_factory=set)

    def update(self, action: AgentAction) -> None:
        """Update baseline with a new action"""
        self.total_actions += 1
        self.updated_at = datetime.now(timezone.utc)

        # Calculate observation period
        if self.total_actions > 1:
            self.observation_period_hours = (
                self.updated_at - self.created_at
            ).total_seconds() / 3600

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

        # Track known targets by type
        if action.destination_address:
            self.known_addresses.add(action.destination_address)

        if action.target:
            # Track domains for web operations
            if action.action_type in (ActionType.WEB_FETCH, ActionType.API_QUERY, ActionType.API_MUTATE):
                try:
                    domain = urlparse(action.target).netloc
                    if domain:
                        self.known_domains.add(domain)
                except Exception:
                    pass

            # Track file paths for file operations
            if action.action_type in (ActionType.READ_FILE, ActionType.WRITE_FILE):
                self.known_file_paths.add(action.target)

    def get_stats(self, action_type: ActionType) -> Optional[ActionStats]:
        """Get statistics for a specific action type"""
        return self.action_stats.get(action_type)

    def has_seen_action_type(self, action_type: ActionType) -> bool:
        """Check if this action type has been observed before"""
        return action_type in self.action_stats

    def is_known_address(self, address: str) -> bool:
        """Check if an address is known"""
        return address in self.known_addresses

    def is_known_domain(self, domain: str) -> bool:
        """Check if a domain is known"""
        return domain in self.known_domains

    def is_active_hour(self, hour: int) -> bool:
        """Check if the given hour is within normal active hours"""
        return hour in self.active_hours


class BaselineManager:
    """Manages behavioral baselines for multiple agents"""

    def __init__(self, min_observations: int = 50) -> None:
        """
        Initialize the baseline manager.

        Args:
            min_observations: Minimum actions required before baseline is considered reliable
        """
        self.baselines: dict[str, BehaviorBaseline] = {}
        self.min_observations = min_observations

    def get_or_create(self, agent_id: str) -> BehaviorBaseline:
        """Get existing baseline or create a new one"""
        if agent_id not in self.baselines:
            self.baselines[agent_id] = BehaviorBaseline(agent_id=agent_id)
        return self.baselines[agent_id]

    def get(self, agent_id: str) -> Optional[BehaviorBaseline]:
        """Get baseline for an agent if it exists"""
        return self.baselines.get(agent_id)

    def record_action(self, action: AgentAction) -> None:
        """Record an action and update the agent's baseline"""
        baseline = self.get_or_create(action.agent_id)
        baseline.update(action)

    def has_sufficient_data(self, agent_id: str) -> bool:
        """Check if we have enough data to trust the baseline"""
        baseline = self.baselines.get(agent_id)
        return baseline is not None and baseline.total_actions >= self.min_observations

    def get_observation_count(self, agent_id: str) -> int:
        """Get the number of observations for an agent"""
        baseline = self.baselines.get(agent_id)
        return baseline.total_actions if baseline else 0

    def reset(self, agent_id: str) -> None:
        """Reset baseline for an agent"""
        if agent_id in self.baselines:
            del self.baselines[agent_id]

    def reset_all(self) -> None:
        """Reset all baselines"""
        self.baselines.clear()

    def list_agents(self) -> list[str]:
        """List all agents with baselines"""
        return list(self.baselines.keys())

    def export_baseline(self, agent_id: str) -> Optional[dict]:
        """Export baseline data for persistence"""
        baseline = self.baselines.get(agent_id)
        if not baseline:
            return None

        return {
            "agent_id": baseline.agent_id,
            "created_at": baseline.created_at.isoformat(),
            "updated_at": baseline.updated_at.isoformat(),
            "total_actions": baseline.total_actions,
            "observation_period_hours": baseline.observation_period_hours,
            "active_hours": list(baseline.active_hours),
            "known_addresses": list(baseline.known_addresses),
            "known_domains": list(baseline.known_domains),
            "action_stats": {
                action_type.value: {
                    "count": stats.count,
                    "total_amount": stats.total_amount,
                    "avg_amount": stats.avg_amount,
                    "max_amount": stats.max_amount,
                    "stddev_amount": stats.stddev_amount,
                    "actions_per_hour": stats.actions_per_hour,
                    "unique_targets_count": stats.target_count,
                }
                for action_type, stats in baseline.action_stats.items()
            },
        }
