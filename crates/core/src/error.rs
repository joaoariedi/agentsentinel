//! Error types for AgentSentinel
//!
//! Provides a unified error type for all AgentSentinel operations.

use thiserror::Error;

/// Main error type for AgentSentinel operations
#[derive(Error, Debug)]
pub enum SentinelError {
    /// Input validation failed
    #[error("Input validation failed: {0}")]
    ValidationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Pattern compilation error
    #[error("Pattern compilation error: {0}")]
    PatternError(String),

    /// Canary token error
    #[error("Canary token error: {0}")]
    CanaryError(String),

    /// Analysis error
    #[error("Analysis error: {0}")]
    AnalysisError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type alias using SentinelError
pub type SentinelResult<T> = Result<T, SentinelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SentinelError::ValidationError("test error".to_string());
        assert_eq!(err.to_string(), "Input validation failed: test error");
    }
}
