"""
Unit Tests for Behavior Monitor

Tests for action logging, behavioral baselines, anomaly detection,
and the main behavior monitor orchestrator.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from agentsentinel.behavior_monitor import (
    ActionType,
    RiskLevel,
    ACTION_RISK_MAP,
    AgentAction,
    ActionLog,
    ActionStats,
    BehaviorBaseline,
    BaselineManager,
    AnomalyResult,
    AnomalyDetector,
    SimulationResult,
    TransactionSimulator,
    BehaviorMonitor,
)


# =============================================================================
# Models Tests
# =============================================================================


class TestActionType:
    """Tests for ActionType enum"""

    def test_all_action_types_exist(self):
        """Verify all 17 action types are defined"""
        assert len(ActionType) == 17

    def test_action_type_values(self):
        """Verify action type string values"""
        assert ActionType.READ_FILE.value == "read_file"
        assert ActionType.WALLET_TRANSFER.value == "wallet_transfer"
        assert ActionType.EXEC_COMMAND.value == "exec_command"

    def test_action_type_is_string_enum(self):
        """ActionType should be usable as string"""
        assert ActionType.READ_FILE == "read_file"


class TestRiskLevel:
    """Tests for RiskLevel enum"""

    def test_all_risk_levels_exist(self):
        """Verify all 4 risk levels are defined"""
        assert len(RiskLevel) == 4

    def test_risk_level_values(self):
        """Verify risk level string values"""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"


class TestActionRiskMap:
    """Tests for ACTION_RISK_MAP"""

    def test_all_action_types_mapped(self):
        """Every action type should have a risk mapping"""
        for action_type in ActionType:
            assert action_type in ACTION_RISK_MAP

    def test_critical_actions(self):
        """Verify critical risk classifications"""
        assert ACTION_RISK_MAP[ActionType.WALLET_TRANSFER] == RiskLevel.CRITICAL
        assert ACTION_RISK_MAP[ActionType.EXEC_COMMAND] == RiskLevel.CRITICAL
        assert ACTION_RISK_MAP[ActionType.SECRET_ACCESS] == RiskLevel.CRITICAL

    def test_low_risk_actions(self):
        """Verify low risk classifications"""
        assert ACTION_RISK_MAP[ActionType.READ_FILE] == RiskLevel.LOW
        assert ACTION_RISK_MAP[ActionType.WEB_FETCH] == RiskLevel.LOW
        assert ACTION_RISK_MAP[ActionType.WALLET_BALANCE] == RiskLevel.LOW


class TestAgentAction:
    """Tests for AgentAction model"""

    def test_create_minimal_action(self):
        """Create action with minimal required fields"""
        action = AgentAction(
            id="test-123",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
        )
        assert action.id == "test-123"
        assert action.status == "pending"
        assert action.anomaly_score == 0.0

    def test_create_full_action(self):
        """Create action with all fields"""
        action = AgentAction(
            id="test-456",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WALLET_TRANSFER,
            risk_level=RiskLevel.CRITICAL,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
            target="https://example.com",
            destination_address="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            amount=10.5,
            amount_usd=1050.0,
            wallet_address="sender-wallet",
            token="SOL",
            parameters={"memo": "test"},
            anomaly_score=0.5,
            anomaly_reasons=["Test reason"],
        )
        assert action.amount == 10.5
        assert action.destination_address == "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"

    def test_action_to_dict(self):
        """Action should serialize to dict"""
        action = AgentAction(
            id="test-123",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
        )
        data = action.model_dump()
        assert data["id"] == "test-123"
        assert data["action_type"] == "read_file"


class TestActionLog:
    """Tests for ActionLog"""

    def test_empty_log(self):
        """New log should be empty"""
        log = ActionLog()
        assert log.count() == 0

    def test_add_action(self):
        """Adding action should increase count"""
        log = ActionLog()
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg",
        )
        log.add(action)
        assert log.count() == 1

    def test_get_by_session(self):
        """Filter actions by session"""
        log = ActionLog()
        for i, session in enumerate(["s1", "s1", "s2"]):
            log.add(
                AgentAction(
                    id=f"test-{i}",
                    timestamp=datetime.now(timezone.utc),
                    action_type=ActionType.READ_FILE,
                    risk_level=RiskLevel.LOW,
                    session_id=session,
                    agent_id="agent-1",
                    triggered_by="msg",
                )
            )
        assert len(log.get_by_session("s1")) == 2
        assert len(log.get_by_session("s2")) == 1

    def test_get_by_type(self):
        """Filter actions by type"""
        log = ActionLog()
        log.add(
            AgentAction(
                id="test-1",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
        )
        log.add(
            AgentAction(
                id="test-2",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.WRITE_FILE,
                risk_level=RiskLevel.MEDIUM,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
        )
        assert len(log.get_by_type(ActionType.READ_FILE)) == 1
        assert len(log.get_by_type(ActionType.WRITE_FILE)) == 1

    def test_get_recent(self):
        """Get recent actions"""
        log = ActionLog()
        now = datetime.now(timezone.utc)
        
        # Recent action
        log.add(
            AgentAction(
                id="recent",
                timestamp=now,
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
        )
        
        # Old action
        log.add(
            AgentAction(
                id="old",
                timestamp=now - timedelta(hours=2),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
        )
        
        recent = log.get_recent(minutes=60)
        assert len(recent) == 1
        assert recent[0].id == "recent"

    def test_get_high_risk(self):
        """Get high risk actions"""
        log = ActionLog()
        log.add(
            AgentAction(
                id="low",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
        )
        log.add(
            AgentAction(
                id="critical",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.WALLET_TRANSFER,
                risk_level=RiskLevel.CRITICAL,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
        )
        
        high_risk = log.get_high_risk()
        assert len(high_risk) == 1
        assert high_risk[0].id == "critical"


# =============================================================================
# Baseline Tests
# =============================================================================


class TestActionStats:
    """Tests for ActionStats"""

    def test_empty_stats(self):
        """New stats should be zeroed"""
        stats = ActionStats()
        assert stats.count == 0
        assert stats.avg_amount == 0.0
        assert stats.max_amount == 0.0
        assert stats.stddev_amount == 0.0

    def test_stats_with_amounts(self):
        """Calculate statistics from amounts"""
        stats = ActionStats(
            count=3,
            total_amount=30.0,
            amounts=[5.0, 10.0, 15.0],
            timestamps=[
                datetime.now(timezone.utc),
                datetime.now(timezone.utc),
                datetime.now(timezone.utc),
            ],
        )
        assert stats.avg_amount == 10.0
        assert stats.max_amount == 15.0
        assert stats.min_amount == 5.0
        assert stats.stddev_amount > 0


class TestBehaviorBaseline:
    """Tests for BehaviorBaseline"""

    def test_create_baseline(self):
        """Create new baseline"""
        baseline = BehaviorBaseline(agent_id="agent-1")
        assert baseline.agent_id == "agent-1"
        assert baseline.total_actions == 0

    def test_update_baseline(self):
        """Update baseline with action"""
        baseline = BehaviorBaseline(agent_id="agent-1")
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WALLET_TRANSFER,
            risk_level=RiskLevel.CRITICAL,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            destination_address="addr-123",
            amount=10.0,
        )
        
        baseline.update(action)
        
        assert baseline.total_actions == 1
        assert ActionType.WALLET_TRANSFER in baseline.action_stats
        assert "addr-123" in baseline.known_addresses

    def test_track_active_hours(self):
        """Track active hours from actions"""
        baseline = BehaviorBaseline(agent_id="agent-1")
        
        for hour in [9, 10, 14]:
            action = AgentAction(
                id=f"test-{hour}",
                timestamp=datetime(2024, 1, 1, hour, 0, 0, tzinfo=timezone.utc),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
            baseline.update(action)
        
        assert 9 in baseline.active_hours
        assert 10 in baseline.active_hours
        assert 14 in baseline.active_hours
        assert 3 not in baseline.active_hours

    def test_track_domains(self):
        """Track known domains from web actions"""
        baseline = BehaviorBaseline(agent_id="agent-1")
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WEB_FETCH,
            risk_level=RiskLevel.LOW,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            target="https://api.example.com/endpoint",
        )
        
        baseline.update(action)
        
        assert "api.example.com" in baseline.known_domains


class TestBaselineManager:
    """Tests for BaselineManager"""

    def test_create_manager(self):
        """Create manager with defaults"""
        manager = BaselineManager()
        assert manager.min_observations == 50

    def test_get_or_create(self):
        """Get or create baseline"""
        manager = BaselineManager()
        baseline = manager.get_or_create("agent-1")
        assert baseline.agent_id == "agent-1"
        
        # Second call should return same baseline
        baseline2 = manager.get_or_create("agent-1")
        assert baseline is baseline2

    def test_has_sufficient_data(self):
        """Check sufficient data threshold"""
        manager = BaselineManager(min_observations=5)
        manager.get_or_create("agent-1")
        
        assert not manager.has_sufficient_data("agent-1")
        
        # Add enough observations
        for i in range(5):
            action = AgentAction(
                id=f"test-{i}",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
            manager.record_action(action)
        
        assert manager.has_sufficient_data("agent-1")

    def test_export_baseline(self):
        """Export baseline data"""
        manager = BaselineManager()
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
        )
        manager.record_action(action)
        
        export = manager.export_baseline("agent-1")
        assert export is not None
        assert export["agent_id"] == "agent-1"
        assert export["total_actions"] == 1


# =============================================================================
# Anomaly Detection Tests
# =============================================================================


class TestAnomalyResult:
    """Tests for AnomalyResult"""

    def test_create_result(self):
        """Create anomaly result"""
        result = AnomalyResult(
            is_anomaly=True,
            score=0.5,
            reasons=["Test reason"],
            require_approval=True,
            auto_block=False,
        )
        assert result.is_anomaly
        assert result.score == 0.5


class TestAnomalyDetector:
    """Tests for AnomalyDetector"""

    def test_create_detector(self):
        """Create detector with manager"""
        manager = BaselineManager()
        detector = AnomalyDetector(manager)
        assert detector.anomaly_threshold == 0.3

    def test_analyze_first_action(self):
        """First action without baseline should be allowed"""
        manager = BaselineManager()
        detector = AnomalyDetector(manager)
        
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
        )
        
        result = detector.analyze(action)
        assert not result.auto_block

    def test_critical_action_without_baseline(self):
        """Critical action without baseline should require approval"""
        manager = BaselineManager(min_observations=100)  # Ensure no baseline
        detector = AnomalyDetector(manager)
        
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WALLET_TRANSFER,
            risk_level=RiskLevel.CRITICAL,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            amount=100.0,
        )
        
        result = detector.analyze(action)
        assert result.require_approval
        assert "Critical action attempted before baseline established" in result.reasons

    def test_detect_unusual_action_type(self):
        """Detect first-time action type"""
        manager = BaselineManager(min_observations=3)
        
        # Build baseline with only READ_FILE actions
        for i in range(5):
            action = AgentAction(
                id=f"baseline-{i}",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
            manager.record_action(action)
        
        detector = AnomalyDetector(manager)
        
        # Try WRITE_FILE for first time
        action = AgentAction(
            id="test-new",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WRITE_FILE,
            risk_level=RiskLevel.MEDIUM,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
        )
        
        result = detector.analyze(action)
        assert "First time performing write_file" in result.reasons

    def test_detect_unusual_amount(self):
        """Detect statistical outlier amounts"""
        manager = BaselineManager(min_observations=5)
        
        # Build baseline with varying small amounts (need variance for stddev)
        amounts = [8.0, 10.0, 12.0, 9.0, 11.0, 10.5, 9.5, 11.5, 10.0, 10.0]
        for i, amount in enumerate(amounts):
            action = AgentAction(
                id=f"baseline-{i}",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.WALLET_TRANSFER,
                risk_level=RiskLevel.CRITICAL,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
                amount=amount,  # ~$10 transfers with some variance
            )
            manager.record_action(action)
        
        detector = AnomalyDetector(manager)
        
        # Try much larger amount (many standard deviations away)
        action = AgentAction(
            id="test-big",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WALLET_TRANSFER,
            risk_level=RiskLevel.CRITICAL,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            amount=10000.0,  # Way outside normal range
        )
        
        result = detector.analyze(action)
        assert result.score > 0.3
        assert any("std devs" in r for r in result.reasons)

    def test_detect_new_destination(self):
        """Detect new destination on high-risk action"""
        manager = BaselineManager(min_observations=3)
        
        # Build baseline with known destination
        for i in range(5):
            action = AgentAction(
                id=f"baseline-{i}",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.WALLET_TRANSFER,
                risk_level=RiskLevel.CRITICAL,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
                destination_address="known-addr",
            )
            manager.record_action(action)
        
        detector = AnomalyDetector(manager)
        
        # Try new destination
        action = AgentAction(
            id="test-new-dest",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.WALLET_TRANSFER,
            risk_level=RiskLevel.CRITICAL,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            destination_address="new-unknown-addr-12345",
        )
        
        result = detector.analyze(action)
        assert any("New destination" in r for r in result.reasons)

    def test_detect_unusual_time(self):
        """Detect action at unusual hour"""
        manager = BaselineManager(min_observations=3)
        
        # Build baseline with only daytime actions (9-17)
        for i in range(10):
            action = AgentAction(
                id=f"baseline-{i}",
                timestamp=datetime(2024, 1, 1, 10 + (i % 6), 0, 0, tzinfo=timezone.utc),
                action_type=ActionType.READ_FILE,
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
            )
            manager.record_action(action)
        
        detector = AnomalyDetector(manager)
        
        # Try action at 3 AM
        action = AgentAction(
            id="test-night",
            timestamp=datetime(2024, 1, 2, 3, 0, 0, tzinfo=timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
        )
        
        result = detector.analyze(action)
        assert any("unusual hour" in r for r in result.reasons)

    def test_set_thresholds(self):
        """Update detection thresholds"""
        manager = BaselineManager()
        detector = AnomalyDetector(manager)
        
        detector.set_thresholds(anomaly=0.2, approval=0.4, block=0.7)
        
        assert detector.anomaly_threshold == 0.2
        assert detector.approval_threshold == 0.4
        assert detector.block_threshold == 0.7


# =============================================================================
# Transaction Simulator Tests
# =============================================================================


class TestSimulationResult:
    """Tests for SimulationResult"""

    def test_create_success_result(self):
        """Create successful simulation result"""
        result = SimulationResult(success=True, fee=0.001)
        assert result.success
        assert not result.is_risky

    def test_create_error_result(self):
        """Create error simulation result"""
        result = SimulationResult(success=False, error="Insufficient funds")
        assert not result.success
        assert result.error == "Insufficient funds"

    def test_risky_result(self):
        """Check risk indicators"""
        result = SimulationResult(
            success=True,
            drains_wallet=True,
            interacts_with_known_scam=True,
        )
        assert result.is_risky
        assert len(result.risk_summary) == 2


class TestTransactionSimulator:
    """Tests for TransactionSimulator"""

    def test_create_simulator(self):
        """Create simulator with defaults"""
        sim = TransactionSimulator()
        assert sim.rpc_url == "https://api.mainnet-beta.solana.com"

    def test_add_scam_address(self):
        """Add scam addresses"""
        sim = TransactionSimulator()
        sim.add_scam_address("scam-addr-1")
        assert sim.is_known_scam("scam-addr-1")
        assert not sim.is_known_scam("legitimate-addr")

    def test_add_multiple_scam_addresses(self):
        """Add multiple scam addresses"""
        sim = TransactionSimulator()
        sim.add_scam_addresses(["scam-1", "scam-2", "scam-3"])
        assert sim.is_known_scam("scam-1")
        assert sim.is_known_scam("scam-2")
        assert sim.is_known_scam("scam-3")

    @pytest.mark.asyncio
    async def test_analyze_risk_scam_destination(self):
        """Detect scam destination"""
        sim = TransactionSimulator()
        sim.add_scam_address("known-scam")
        
        analysis = await sim.analyze_risk(
            destination="known-scam",
            amount=10.0,
            wallet_balance=100.0,
        )
        
        assert analysis.risk_score == 1.0
        assert analysis.should_block
        assert "known scam" in analysis.risks[0].lower()

    @pytest.mark.asyncio
    async def test_analyze_risk_wallet_drain(self):
        """Detect wallet drain"""
        sim = TransactionSimulator()
        
        analysis = await sim.analyze_risk(
            destination="some-addr",
            amount=95.0,
            wallet_balance=100.0,
        )
        
        assert analysis.risk_score >= 0.8
        assert analysis.should_block
        assert any("drain" in r.lower() for r in analysis.risks)

    @pytest.mark.asyncio
    async def test_analyze_risk_large_transaction(self):
        """Detect large transaction"""
        sim = TransactionSimulator()
        
        analysis = await sim.analyze_risk(
            destination="some-addr",
            amount=150.0,  # Over 100 SOL threshold
            wallet_balance=1000.0,
        )
        
        assert analysis.risk_score >= 0.5
        assert analysis.require_confirmation
        assert any("large" in r.lower() for r in analysis.risks)

    @pytest.mark.asyncio
    async def test_analyze_risk_safe_transaction(self):
        """Safe transaction should pass"""
        sim = TransactionSimulator()
        
        analysis = await sim.analyze_risk(
            destination="known-safe-addr",
            amount=5.0,
            wallet_balance=1000.0,
        )
        
        assert analysis.risk_score == 0.0
        assert not analysis.should_block
        assert not analysis.require_confirmation


# =============================================================================
# Behavior Monitor Tests
# =============================================================================


class TestBehaviorMonitor:
    """Tests for main BehaviorMonitor orchestrator"""

    def test_create_monitor(self):
        """Create monitor with defaults"""
        monitor = BehaviorMonitor()
        assert monitor.action_log.count() == 0
        assert len(monitor.blocked_sessions) == 0

    def test_add_alert_handler(self):
        """Add and remove alert handlers"""
        monitor = BehaviorMonitor()
        
        async def handler(alert):
            pass
        
        monitor.add_alert_handler(handler)
        assert len(monitor.alert_handlers) == 1
        
        monitor.remove_alert_handler(handler)
        assert len(monitor.alert_handlers) == 0

    @pytest.mark.asyncio
    async def test_pre_action_check_allowed(self):
        """Simple action should be allowed"""
        monitor = BehaviorMonitor()
        
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.READ_FILE,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
            target="/path/to/file",
        )
        
        assert allowed
        assert action.status == "approved"
        assert monitor.action_log.count() == 1

    @pytest.mark.asyncio
    async def test_pre_action_check_blocked_session(self):
        """Blocked session should reject actions"""
        monitor = BehaviorMonitor()
        monitor.block_session("session-1", "Testing")
        
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.READ_FILE,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
        )
        
        assert not allowed
        assert action.status == "blocked"
        assert "circuit breaker" in action.anomaly_reasons[0].lower()

    @pytest.mark.asyncio
    async def test_pre_action_critical_requires_approval(self):
        """Critical action without approval callback should be blocked"""
        monitor = BehaviorMonitor()
        
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.WALLET_TRANSFER,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
            destination_address="some-addr",
            amount=100.0,
        )
        
        assert not allowed
        assert action.status == "blocked"
        assert "approval" in " ".join(action.anomaly_reasons).lower()

    @pytest.mark.asyncio
    async def test_pre_action_with_approval_callback(self):
        """Action with approval callback should work"""
        async def approve_callback(action):
            return True
        
        monitor = BehaviorMonitor(approval_callback=approve_callback)
        
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.WALLET_TRANSFER,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
            destination_address="some-addr",
            amount=10.0,
        )
        
        assert allowed
        assert action.status == "approved"
        assert action.approved_by == "human"

    @pytest.mark.asyncio
    async def test_pre_action_denied_by_callback(self):
        """Denied by approval callback"""
        async def deny_callback(action):
            return False
        
        monitor = BehaviorMonitor(approval_callback=deny_callback)
        
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.WALLET_TRANSFER,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
            destination_address="some-addr",
            amount=10.0,
        )
        
        assert not allowed
        assert action.status == "blocked"

    def test_record_completion(self):
        """Record action completion"""
        monitor = BehaviorMonitor()
        
        # Add action directly
        action = AgentAction(
            id="test-action",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            status="approved",
        )
        monitor.action_log.add(action)
        
        # Record completion
        result = monitor.record_completion("test-action", result={"data": "test"})
        assert result
        
        # Verify updated
        updated = monitor.get_action("test-action")
        assert updated.status == "completed"
        assert updated.result == {"data": "test"}

    def test_record_completion_failure(self):
        """Record action failure"""
        monitor = BehaviorMonitor()
        
        action = AgentAction(
            id="test-action",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="s1",
            agent_id="agent-1",
            triggered_by="msg",
            status="approved",
        )
        monitor.action_log.add(action)
        
        monitor.record_completion("test-action", error="File not found")
        
        updated = monitor.get_action("test-action")
        assert updated.status == "failed"
        assert updated.error == "File not found"

    def test_circuit_breaker(self):
        """Circuit breaker operations"""
        monitor = BehaviorMonitor()
        
        assert not monitor.is_session_blocked("session-1")
        
        monitor.block_session("session-1")
        assert monitor.is_session_blocked("session-1")
        
        reset = monitor.reset_circuit_breaker("session-1")
        assert reset
        assert not monitor.is_session_blocked("session-1")
        
        # Reset non-existent should return False
        reset2 = monitor.reset_circuit_breaker("session-999")
        assert not reset2

    def test_get_session_summary(self):
        """Get session summary"""
        monitor = BehaviorMonitor()
        
        # Add some actions
        for i, (action_type, status) in enumerate([
            (ActionType.READ_FILE, "completed"),
            (ActionType.WRITE_FILE, "completed"),
            (ActionType.WALLET_TRANSFER, "blocked"),
        ]):
            action = AgentAction(
                id=f"test-{i}",
                timestamp=datetime.now(timezone.utc),
                action_type=action_type,
                risk_level=ACTION_RISK_MAP[action_type],
                session_id="session-1",
                agent_id="agent-1",
                triggered_by="msg",
                status=status,
                anomaly_score=0.3 if status == "blocked" else 0.1,
            )
            monitor.action_log.add(action)
        
        summary = monitor.get_session_summary("session-1")
        
        assert summary["total_actions"] == 3
        assert summary["blocked_actions"] == 1
        assert summary["completed_actions"] == 2
        assert summary["high_risk_actions"] == 1  # WALLET_TRANSFER is critical
        assert not summary["is_blocked"]

    def test_get_agent_summary(self):
        """Get agent summary"""
        monitor = BehaviorMonitor()
        
        # Build some baseline with WEB_FETCH actions (tracks domains)
        for i in range(10):
            action = AgentAction(
                id=f"test-{i}",
                timestamp=datetime.now(timezone.utc),
                action_type=ActionType.WEB_FETCH,  # Use WEB_FETCH for domain tracking
                risk_level=RiskLevel.LOW,
                session_id="s1",
                agent_id="agent-1",
                triggered_by="msg",
                target=f"https://example{i % 3}.com/path",
            )
            monitor.baseline_manager.record_action(action)
        
        summary = monitor.get_agent_summary("agent-1")
        
        assert summary["agent_id"] == "agent-1"
        assert summary["baseline_observations"] == 10
        assert summary["known_domains"] == 3

    def test_export_audit_log(self):
        """Export audit log"""
        monitor = BehaviorMonitor()
        
        action = AgentAction(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            action_type=ActionType.READ_FILE,
            risk_level=RiskLevel.LOW,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg",
        )
        monitor.action_log.add(action)
        
        export = monitor.export_audit_log()
        assert len(export) == 1
        assert export[0]["id"] == "test-1"
        
        # Filter by session
        export_filtered = monitor.export_audit_log(session_id="session-999")
        assert len(export_filtered) == 0

    @pytest.mark.asyncio
    async def test_alert_handler_called_on_block(self):
        """Alert handler should be called when action is auto-blocked"""
        alert_received = []
        
        async def alert_handler(alert):
            alert_received.append(alert)
        
        monitor = BehaviorMonitor()
        monitor.add_alert_handler(alert_handler)
        
        # Set very low threshold for auto-block
        monitor.anomaly_detector.block_threshold = 0.1
        
        # This should trigger auto-block due to critical + no baseline
        # We need to force a high anomaly score
        monitor.anomaly_detector.anomaly_threshold = 0.1
        monitor.anomaly_detector.approval_threshold = 0.2
        monitor.anomaly_detector.block_threshold = 0.4  # Just under critical check
        
        # Critical action without baseline should get 0.5 score
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.EXEC_COMMAND,  # Critical action
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="msg-hash",
            target="rm -rf /",
        )
        
        # Should be blocked (score >= 0.4)
        assert not allowed
        assert len(alert_received) == 1
        assert alert_received[0]["type"] == "anomaly_detected"


# =============================================================================
# Integration Tests
# =============================================================================


class TestBehaviorMonitorIntegration:
    """Integration tests for complete workflows"""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test complete action lifecycle"""
        alerts = []
        
        async def alert_handler(alert):
            alerts.append(alert)
        
        async def approval_callback(action):
            # Auto-approve amounts under 50
            return action.amount is None or action.amount < 50
        
        monitor = BehaviorMonitor(approval_callback=approval_callback)
        monitor.add_alert_handler(alert_handler)
        
        # 1. Build baseline with normal operations
        for i in range(60):
            allowed, action = await monitor.pre_action_check(
                action_type=ActionType.READ_FILE,
                session_id="session-1",
                agent_id="agent-1",
                triggered_by=f"msg-{i}",
                target=f"/path/file-{i}.txt",
            )
            assert allowed
            monitor.record_completion(action.id, result="OK")
        
        # Agent should now have baseline
        assert monitor.baseline_manager.has_sufficient_data("agent-1")
        
        # 2. Try approved transfer (under 50)
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.WALLET_TRANSFER,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="transfer-msg",
            destination_address="trusted-addr",
            amount=25.0,
        )
        assert allowed
        assert action.approved_by == "human"
        
        # 3. Try denied transfer (over 50)
        allowed, action = await monitor.pre_action_check(
            action_type=ActionType.WALLET_TRANSFER,
            session_id="session-1",
            agent_id="agent-1",
            triggered_by="big-transfer-msg",
            destination_address="trusted-addr",
            amount=100.0,
        )
        assert not allowed
        
        # 4. Check session summary
        summary = monitor.get_session_summary("session-1")
        assert summary["total_actions"] > 60
        assert summary["blocked_actions"] >= 1

    @pytest.mark.asyncio
    async def test_baseline_learning(self):
        """Test that baseline learns from approved actions"""
        monitor = BehaviorMonitor()
        
        # Do same action multiple times
        for i in range(100):
            allowed, action = await monitor.pre_action_check(
                action_type=ActionType.API_QUERY,
                session_id="session-1",
                agent_id="agent-1",
                triggered_by=f"msg-{i}",
                target="https://api.example.com/data",
            )
            assert allowed
        
        # Check baseline learned the domain
        baseline = monitor.baseline_manager.get("agent-1")
        assert "api.example.com" in baseline.known_domains
        assert ActionType.API_QUERY in baseline.action_stats
        assert baseline.action_stats[ActionType.API_QUERY].count == 100
