//! Core type definitions for threat assessment
//!
//! These types represent the fundamental data structures used to describe
//! security threats detected by the AgentSentinel framework.

use serde::{Deserialize, Serialize};

/// Severity level of a detected threat
///
/// Threat levels are ordered from least to most severe, allowing for
/// easy comparison and threshold-based filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    /// No threat detected
    #[default]
    None,
    /// Low severity - suspicious but likely benign
    Low,
    /// Medium severity - potentially malicious
    Medium,
    /// High severity - likely malicious, should block by default
    High,
    /// Critical severity - definitely malicious, must block
    Critical,
}

impl ThreatLevel {
    /// Returns a numeric score (0-100) for this threat level
    ///
    /// Useful for calculating risk scores and thresholds.
    #[inline]
    pub fn score(&self) -> u8 {
        match self {
            ThreatLevel::None => 0,
            ThreatLevel::Low => 25,
            ThreatLevel::Medium => 50,
            ThreatLevel::High => 75,
            ThreatLevel::Critical => 100,
        }
    }

    /// Returns true if this threat level meets or exceeds the threshold
    #[inline]
    pub fn meets_threshold(&self, threshold: ThreatLevel) -> bool {
        self.score() >= threshold.score()
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatLevel::None => "none",
            ThreatLevel::Low => "low",
            ThreatLevel::Medium => "medium",
            ThreatLevel::High => "high",
            ThreatLevel::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

/// Category of detected threat
///
/// Each category represents a different type of attack vector commonly
/// used in prompt injection and LLM manipulation attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    /// Attempts to override or ignore previous instructions
    InstructionOverride,
    /// Attempts to extract system prompt or configuration
    PromptExtraction,
    /// Attempts to manipulate the AI's role or behavior
    RoleManipulation,
    /// Attempts to inject false context or authority claims
    ContextInjection,
    /// Attempts to bypass security through encoding tricks
    EncodingBypass,
    /// General jailbreak attempts
    Jailbreak,
    /// Attempts to exfiltrate sensitive data (keys, credentials, etc.)
    DataExfiltration,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatCategory::InstructionOverride => "instruction_override",
            ThreatCategory::PromptExtraction => "prompt_extraction",
            ThreatCategory::RoleManipulation => "role_manipulation",
            ThreatCategory::ContextInjection => "context_injection",
            ThreatCategory::EncodingBypass => "encoding_bypass",
            ThreatCategory::Jailbreak => "jailbreak",
            ThreatCategory::DataExfiltration => "data_exfiltration",
        };
        write!(f, "{}", s)
    }
}

/// A single detected threat
///
/// Represents one instance of a security threat found in the analyzed input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// The category of this threat
    pub category: ThreatCategory,
    /// The severity level
    pub level: ThreatLevel,
    /// Optional pattern identifier that triggered this detection
    pub pattern_id: Option<String>,
    /// Human-readable description of the threat
    pub description: String,
    /// Confidence score (0.0 - 1.0) in this detection
    pub confidence: f32,
    /// The specific text that triggered the detection
    pub evidence: String,
}

impl Threat {
    /// Creates a new Threat with the given parameters
    pub fn new(
        category: ThreatCategory,
        level: ThreatLevel,
        description: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            category,
            level,
            pattern_id: None,
            description: description.into(),
            confidence: 0.9,
            evidence: evidence.into(),
        }
    }

    /// Sets the pattern ID for this threat
    pub fn with_pattern_id(mut self, id: impl Into<String>) -> Self {
        self.pattern_id = Some(id.into());
        self
    }

    /// Sets the confidence score for this threat
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// Complete threat assessment for an input
///
/// Contains all detected threats and overall risk metrics for a single
/// input analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// SHA-256 hash of the original input (for logging without storing content)
    pub input_hash: String,
    /// All detected threats
    pub threats: Vec<Threat>,
    /// The highest threat level found
    pub overall_level: ThreatLevel,
    /// Composite risk score (0.0 - 100.0)
    pub risk_score: f32,
    /// Whether this input should be blocked based on configuration
    pub should_block: bool,
    /// Time taken for analysis in microseconds
    pub analysis_time_us: u64,
}

impl ThreatAssessment {
    /// Creates a new assessment indicating no threats
    pub fn safe(input_hash: String, analysis_time_us: u64) -> Self {
        Self {
            input_hash,
            threats: Vec::new(),
            overall_level: ThreatLevel::None,
            risk_score: 0.0,
            should_block: false,
            analysis_time_us,
        }
    }

    /// Returns true if any threats were detected
    #[inline]
    pub fn has_threats(&self) -> bool {
        !self.threats.is_empty()
    }

    /// Returns the count of threats at or above the given level
    pub fn count_threats_at_level(&self, min_level: ThreatLevel) -> usize {
        self.threats
            .iter()
            .filter(|t| t.level.meets_threshold(min_level))
            .count()
    }

    /// Returns threats filtered by category
    pub fn threats_by_category(&self, category: ThreatCategory) -> Vec<&Threat> {
        self.threats
            .iter()
            .filter(|t| t.category == category)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Medium);
        assert!(ThreatLevel::Medium > ThreatLevel::Low);
        assert!(ThreatLevel::Low > ThreatLevel::None);
    }

    #[test]
    fn test_threat_level_scores() {
        assert_eq!(ThreatLevel::None.score(), 0);
        assert_eq!(ThreatLevel::Low.score(), 25);
        assert_eq!(ThreatLevel::Medium.score(), 50);
        assert_eq!(ThreatLevel::High.score(), 75);
        assert_eq!(ThreatLevel::Critical.score(), 100);
    }

    #[test]
    fn test_threat_level_threshold() {
        assert!(ThreatLevel::Critical.meets_threshold(ThreatLevel::High));
        assert!(ThreatLevel::High.meets_threshold(ThreatLevel::High));
        assert!(!ThreatLevel::Medium.meets_threshold(ThreatLevel::High));
    }

    #[test]
    fn test_threat_creation() {
        let threat = Threat::new(
            ThreatCategory::InstructionOverride,
            ThreatLevel::Critical,
            "Test threat",
            "ignore all previous",
        )
        .with_pattern_id("PAT-0001")
        .with_confidence(0.95);

        assert_eq!(threat.category, ThreatCategory::InstructionOverride);
        assert_eq!(threat.level, ThreatLevel::Critical);
        assert_eq!(threat.pattern_id, Some("PAT-0001".to_string()));
        assert!((threat.confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_assessment_safe() {
        let assessment = ThreatAssessment::safe("abc123".to_string(), 50);
        assert!(!assessment.has_threats());
        assert_eq!(assessment.overall_level, ThreatLevel::None);
        assert!(!assessment.should_block);
    }
}
