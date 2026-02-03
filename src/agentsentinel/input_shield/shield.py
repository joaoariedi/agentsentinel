"""
Input Shield - Python Implementation

High-performance prompt injection detection using pattern matching.
This is a pure Python implementation for when Rust bindings are not available.
"""

import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ThreatLevel(str, Enum):
    """Severity level of detected threats"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def score(self) -> int:
        """Numeric score for threat level"""
        return {
            ThreatLevel.NONE: 0,
            ThreatLevel.LOW: 20,
            ThreatLevel.MEDIUM: 40,
            ThreatLevel.HIGH: 70,
            ThreatLevel.CRITICAL: 100,
        }[self]
    
    def meets_threshold(self, threshold: "ThreatLevel") -> bool:
        """Check if this level meets or exceeds threshold"""
        return self.score() >= threshold.score()


class ThreatCategory(str, Enum):
    """Category of security threat"""
    INSTRUCTION_OVERRIDE = "instruction_override"
    PROMPT_EXTRACTION = "prompt_extraction"
    ROLE_MANIPULATION = "role_manipulation"
    CONTEXT_INJECTION = "context_injection"
    ENCODING_BYPASS = "encoding_bypass"
    DATA_EXFILTRATION = "data_exfiltration"
    CANARY_LEAK = "canary_leak"


@dataclass
class Threat:
    """A detected security threat"""
    category: ThreatCategory
    level: ThreatLevel
    description: str
    evidence: str
    confidence: float = 0.8


@dataclass
class ThreatAssessment:
    """Complete threat assessment result"""
    input_hash: str
    threats: list[Threat]
    overall_level: ThreatLevel
    risk_score: float
    should_block: bool
    analysis_time_us: int
    
    def has_threats(self) -> bool:
        """Check if any threats were detected"""
        return len(self.threats) > 0


@dataclass
class ShieldConfig:
    """Configuration for Input Shield"""
    block_threshold: ThreatLevel = ThreatLevel.HIGH
    max_input_length: int = 10_000
    enable_canary_tokens: bool = True


# Pattern definitions with threat level and category
PATTERNS: list[tuple[str, ThreatCategory, ThreatLevel, str]] = [
    # Instruction Override (Critical)
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions?", ThreatCategory.INSTRUCTION_OVERRIDE, ThreatLevel.CRITICAL, "Instruction override attempt"),
    (r"(?i)forget\s+(all\s+)?(?:previous\s+)?(?:instructions?|everything)", ThreatCategory.INSTRUCTION_OVERRIDE, ThreatLevel.CRITICAL, "Instruction reset attempt"),
    (r"(?i)disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|rules?)", ThreatCategory.INSTRUCTION_OVERRIDE, ThreatLevel.CRITICAL, "Instruction disregard attempt"),
    (r"(?i)(?:new|your)\s+(?:primary\s+)?(?:directive|instructions?|role)\s+(?:is|are)", ThreatCategory.INSTRUCTION_OVERRIDE, ThreatLevel.CRITICAL, "New directive injection"),
    (r"(?i)\[SYSTEM\]|\[ADMIN\]|<SYSTEM>|<ADMIN>", ThreatCategory.INSTRUCTION_OVERRIDE, ThreatLevel.CRITICAL, "Fake system message marker"),
    (r"(?i)(?:enter|enable)\s+(?:developer|debug|admin|sudo)\s+mode", ThreatCategory.INSTRUCTION_OVERRIDE, ThreatLevel.CRITICAL, "Debug mode activation attempt"),
    
    # Prompt Extraction (High)
    (r"(?i)(?:print|show|reveal|tell|display|output)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?prompt", ThreatCategory.PROMPT_EXTRACTION, ThreatLevel.HIGH, "System prompt extraction attempt"),
    (r"(?i)(?:repeat|recite)\s+(?:your\s+)?(?:original\s+)?(?:instructions?|prompt)", ThreatCategory.PROMPT_EXTRACTION, ThreatLevel.HIGH, "Instruction extraction attempt"),
    (r"(?i)what\s+(?:are|were)\s+(?:your\s+)?(?:initial\s+)?instructions?", ThreatCategory.PROMPT_EXTRACTION, ThreatLevel.HIGH, "Instruction query"),
    (r"(?i)(?:show|tell)\s+me\s+(?:the\s+)?(?:hidden\s+)?(?:rules|constraints)", ThreatCategory.PROMPT_EXTRACTION, ThreatLevel.MEDIUM, "Rule extraction attempt"),
    
    # Role Manipulation (High)
    (r"(?i)you\s+are\s+(?:now\s+)?(?:DAN|STAN|DUDE|ALICE)", ThreatCategory.ROLE_MANIPULATION, ThreatLevel.CRITICAL, "Known jailbreak persona"),
    (r"(?i)(?:pretend|act|behave)\s+(?:like\s+)?(?:you\s+(?:are|have)\s+)?no\s+(?:restrictions?|limits?|rules?)", ThreatCategory.ROLE_MANIPULATION, ThreatLevel.HIGH, "Restriction bypass via roleplay"),
    (r"(?i)let's\s+(?:play|do)\s+(?:a\s+)?roleplay", ThreatCategory.ROLE_MANIPULATION, ThreatLevel.MEDIUM, "Roleplay initiation"),
    (r"(?i)(?:in\s+)?(?:this\s+)?(?:hypothetical\s+)?scenario", ThreatCategory.ROLE_MANIPULATION, ThreatLevel.MEDIUM, "Hypothetical scenario bypass"),
    
    # Context Injection (Critical)
    (r"(?i)(?:admin|administrator|owner)\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized)", ThreatCategory.CONTEXT_INJECTION, ThreatLevel.CRITICAL, "False authorization claim"),
    (r"(?i)(?:previous\s+)?(?:conversation\s+)?(?:summary|context):", ThreatCategory.CONTEXT_INJECTION, ThreatLevel.HIGH, "Fake context injection"),
    (r"(?i)urgent|emergency|immediately|right\s+now", ThreatCategory.CONTEXT_INJECTION, ThreatLevel.MEDIUM, "Urgency manipulation"),
    (r"(?i)(?:the\s+)?(?:CEO|CTO|boss|manager)\s+(?:said|told|asked|wants)", ThreatCategory.CONTEXT_INJECTION, ThreatLevel.HIGH, "Authority appeal"),
    
    # Data Exfiltration (Critical)
    (r"(?i)(?:transfer|send|move)\s+(?:all\s+)?(?:my\s+)?(?:funds?|tokens?|SOL|ETH|BTC|crypto)", ThreatCategory.DATA_EXFILTRATION, ThreatLevel.CRITICAL, "Fund transfer request"),
    (r"(?i)(?:private|secret)\s*key", ThreatCategory.DATA_EXFILTRATION, ThreatLevel.CRITICAL, "Private key request"),
    (r"(?i)(?:seed|recovery)\s*phrase", ThreatCategory.DATA_EXFILTRATION, ThreatLevel.CRITICAL, "Seed phrase request"),
    (r"(?i)api[_\s]*key|access[_\s]*token|password|credential", ThreatCategory.DATA_EXFILTRATION, ThreatLevel.HIGH, "Credential request"),
    (r"(?i)(?:drain|empty|steal|take)\s+(?:the\s+)?(?:wallet|account|funds)", ThreatCategory.DATA_EXFILTRATION, ThreatLevel.CRITICAL, "Wallet drain attempt"),
    
    # Encoding Bypass (Medium)
    (r"(?i)(?:decode|decrypt|deobfuscate|unbase64)\s+(?:and\s+)?(?:execute|run|follow)", ThreatCategory.ENCODING_BYPASS, ThreatLevel.MEDIUM, "Encoded execution request"),
    (r"(?i)(?:read|execute)\s+(?:this\s+)?(?:backwards?|reversed?)", ThreatCategory.ENCODING_BYPASS, ThreatLevel.MEDIUM, "Reversed text execution"),
    (r"(?i)(?:base64|rot13|hex)\s*[:=]", ThreatCategory.ENCODING_BYPASS, ThreatLevel.LOW, "Encoded content marker"),
]


class CanaryManager:
    """Manages canary tokens for detecting prompt leakage"""
    
    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}  # token -> context
    
    def generate_token(self, context: str = "default") -> str:
        """Generate a new canary token"""
        token = f"CANARY_{secrets.token_hex(8).upper()}"
        self.tokens[token] = context
        return token
    
    def check_input(self, text: str) -> list[Threat]:
        """Check input for canary tokens (shouldn't be in user input)"""
        threats = []
        for token in self.tokens:
            if token in text:
                threats.append(Threat(
                    category=ThreatCategory.CANARY_LEAK,
                    level=ThreatLevel.HIGH,
                    description="Canary token found in input (possible prompt injection)",
                    evidence=token,
                ))
        return threats
    
    def check_output(self, text: str) -> list[Threat]:
        """Check output for leaked canary tokens"""
        threats = []
        for token, context in self.tokens.items():
            if token in text:
                threats.append(Threat(
                    category=ThreatCategory.CANARY_LEAK,
                    level=ThreatLevel.CRITICAL,
                    description=f"Canary token leaked in output (context: {context})",
                    evidence=token,
                ))
        return threats


class InputShield:
    """
    High-performance input security analyzer.
    
    Analyzes text for prompt injection and other security threats
    using pattern matching.
    """
    
    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        """
        Initialize InputShield.
        
        Args:
            config: Shield configuration (uses defaults if not provided)
        """
        self.config = config or ShieldConfig()
        self.canary_manager = CanaryManager()
        
        # Pre-compile patterns for efficiency
        self._compiled_patterns: list[tuple[re.Pattern, ThreatCategory, ThreatLevel, str]] = [
            (re.compile(pattern), category, level, desc)
            for pattern, category, level, desc in PATTERNS
        ]
    
    def analyze(self, input_text: str) -> ThreatAssessment:
        """
        Analyze input text for security threats.
        
        Args:
            input_text: Text to analyze
            
        Returns:
            ThreatAssessment with all detected threats
        """
        start_time = time.perf_counter_ns()
        threats: list[Threat] = []
        
        # Length check
        if len(input_text) > self.config.max_input_length:
            threats.append(Threat(
                category=ThreatCategory.ENCODING_BYPASS,
                level=ThreatLevel.MEDIUM,
                description="Input exceeds maximum allowed length",
                evidence=f"Length: {len(input_text)} > {self.config.max_input_length}",
            ))
        
        # Pattern matching
        for pattern, category, level, desc in self._compiled_patterns:
            match = pattern.search(input_text)
            if match:
                threats.append(Threat(
                    category=category,
                    level=level,
                    description=desc,
                    evidence=match.group()[:100],
                ))
        
        # Canary token check
        if self.config.enable_canary_tokens:
            threats.extend(self.canary_manager.check_input(input_text))
        
        # Calculate overall assessment
        overall_level = self._calculate_overall_level(threats)
        risk_score = self._calculate_risk_score(threats)
        should_block = overall_level.meets_threshold(self.config.block_threshold)
        
        # Calculate input hash
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()
        
        # Calculate analysis time in microseconds
        analysis_time_us = (time.perf_counter_ns() - start_time) // 1000
        
        return ThreatAssessment(
            input_hash=input_hash,
            threats=threats,
            overall_level=overall_level,
            risk_score=risk_score,
            should_block=should_block,
            analysis_time_us=analysis_time_us,
        )
    
    def generate_canary(self, context: str = "default") -> str:
        """
        Generate a canary token for embedding in system prompts.
        
        Args:
            context: Context identifier for the token
            
        Returns:
            Canary token string
        """
        return self.canary_manager.generate_token(context)
    
    def check_output(self, output_text: str) -> list[Threat]:
        """
        Check output for leaked canary tokens.
        
        Args:
            output_text: Output text to check
            
        Returns:
            List of leak threats
        """
        return self.canary_manager.check_output(output_text)
    
    def _calculate_overall_level(self, threats: list[Threat]) -> ThreatLevel:
        """Calculate the overall threat level"""
        if not threats:
            return ThreatLevel.NONE
        return max(threats, key=lambda t: t.level.score()).level
    
    def _calculate_risk_score(self, threats: list[Threat]) -> float:
        """Calculate the overall risk score (0-100)"""
        if not threats:
            return 0.0
        
        max_score = max(t.level.score() for t in threats)
        multi_threat_bonus = (min(len(threats), 5) - 1) * 5.0
        
        return min(100.0, max_score + multi_threat_bonus)


# Convenience functions for simple usage
_global_shield: Optional[InputShield] = None


def _get_global_shield() -> InputShield:
    """Get or create global shield instance"""
    global _global_shield
    if _global_shield is None:
        _global_shield = InputShield()
    return _global_shield


def analyze(input_text: str) -> ThreatAssessment:
    """Quick analysis using global shield instance"""
    return _get_global_shield().analyze(input_text)


def should_block(input_text: str) -> bool:
    """Quick check if input should be blocked"""
    return analyze(input_text).should_block
