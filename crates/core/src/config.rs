//! Configuration types for AgentSentinel
//!
//! Provides configuration structures for the Input Shield and other components.

use serde::{Deserialize, Serialize};
use crate::ThreatLevel;

/// Configuration for the Input Shield
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// Minimum threat level that triggers blocking
    pub block_threshold: ThreatLevel,
    /// Maximum allowed input length in bytes
    pub max_input_length: usize,
    /// Whether to enable canary token detection
    pub enable_canary_tokens: bool,
    /// Whether to log all analyzed inputs
    pub log_all_inputs: bool,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            block_threshold: ThreatLevel::High,
            max_input_length: 10_000,
            enable_canary_tokens: true,
            log_all_inputs: false,
        }
    }
}

impl ShieldConfig {
    /// Creates a new ShieldConfig with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the block threshold
    pub fn with_block_threshold(mut self, threshold: ThreatLevel) -> Self {
        self.block_threshold = threshold;
        self
    }

    /// Sets the maximum input length
    pub fn with_max_input_length(mut self, length: usize) -> Self {
        self.max_input_length = length;
        self
    }

    /// Enables or disables canary tokens
    pub fn with_canary_tokens(mut self, enabled: bool) -> Self {
        self.enable_canary_tokens = enabled;
        self
    }

    /// Enables or disables input logging
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_all_inputs = enabled;
        self
    }

    /// Creates a strict configuration that blocks at Medium level
    pub fn strict() -> Self {
        Self {
            block_threshold: ThreatLevel::Medium,
            max_input_length: 5_000,
            enable_canary_tokens: true,
            log_all_inputs: true,
        }
    }

    /// Creates a permissive configuration that only blocks Critical
    pub fn permissive() -> Self {
        Self {
            block_threshold: ThreatLevel::Critical,
            max_input_length: 50_000,
            enable_canary_tokens: true,
            log_all_inputs: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ShieldConfig::default();
        assert_eq!(config.block_threshold, ThreatLevel::High);
        assert_eq!(config.max_input_length, 10_000);
        assert!(config.enable_canary_tokens);
    }

    #[test]
    fn test_builder_pattern() {
        let config = ShieldConfig::new()
            .with_block_threshold(ThreatLevel::Medium)
            .with_max_input_length(5000)
            .with_canary_tokens(false);

        assert_eq!(config.block_threshold, ThreatLevel::Medium);
        assert_eq!(config.max_input_length, 5000);
        assert!(!config.enable_canary_tokens);
    }

    #[test]
    fn test_strict_config() {
        let config = ShieldConfig::strict();
        assert_eq!(config.block_threshold, ThreatLevel::Medium);
        assert!(config.log_all_inputs);
    }

    #[test]
    fn test_permissive_config() {
        let config = ShieldConfig::permissive();
        assert_eq!(config.block_threshold, ThreatLevel::Critical);
        assert_eq!(config.max_input_length, 50_000);
    }
}
