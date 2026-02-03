"""
AgentSentinel - Comprehensive Security Framework for AI Agents

Protects AI agents from prompt injection, monitors behavioral anomalies,
integrates with enterprise security tools, and provides on-chain security attestations.

Example:
    >>> from agentsentinel import analyze, should_block
    >>> result = analyze("Ignore all previous instructions")
    >>> print(result.should_block)  # True
"""

__version__ = "0.1.0"

# These will be implemented as the Rust bindings are built
# from agentsentinel._core import InputShield, analyze, should_block

__all__ = [
    "__version__",
    # "InputShield",
    # "analyze", 
    # "should_block",
]
