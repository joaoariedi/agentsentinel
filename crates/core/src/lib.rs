//! AgentSentinel Core - Shared types and utilities
//!
//! This crate provides the foundational types used throughout the AgentSentinel
//! security framework, including threat levels, categories, and assessment structures.

pub mod types;
pub mod error;
pub mod config;

pub use types::*;
pub use error::*;
pub use config::*;

/// Re-export commonly used items at crate root
pub mod prelude {
    pub use crate::types::{Threat, ThreatAssessment, ThreatCategory, ThreatLevel};
    pub use crate::error::SentinelError;
    pub use crate::config::ShieldConfig;
}
