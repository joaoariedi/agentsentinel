"""
Input Shield - Python Implementation

High-performance prompt injection detection.
This is a Python implementation for when Rust bindings are not available.

Example:
    >>> from agentsentinel.input_shield import InputShield
    >>> shield = InputShield()
    >>> result = shield.analyze("Ignore all previous instructions")
    >>> print(result.should_block)  # True
"""

from .shield import (
    InputShield,
    ShieldConfig,
    ThreatAssessment,
    Threat,
    ThreatCategory,
    ThreatLevel,
    CanaryManager,
)

__all__ = [
    "InputShield",
    "ShieldConfig",
    "ThreatAssessment",
    "Threat",
    "ThreatCategory",
    "ThreatLevel",
    "CanaryManager",
]
