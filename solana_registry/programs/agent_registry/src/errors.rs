//! Error codes for the AgentSentinel Registry program
//!
//! All error codes that can be returned by the program instructions.

use anchor_lang::prelude::*;

/// Custom error codes for the Agent Registry program
#[error_code]
pub enum RegistryError {
    /// Agent ID exceeds maximum length of 64 characters
    #[msg("Agent ID exceeds maximum length of 64 characters")]
    AgentIdTooLong,

    /// Name exceeds maximum length of 128 characters
    #[msg("Name exceeds maximum length of 128 characters")]
    NameTooLong,

    /// Description exceeds maximum length of 512 characters
    #[msg("Description exceeds maximum length of 512 characters")]
    DescriptionTooLong,

    /// URL exceeds maximum length of 256 characters
    #[msg("URL exceeds maximum length of 256 characters")]
    UrlTooLong,

    /// Report hash exceeds maximum length of 64 characters
    #[msg("Report hash exceeds maximum length of 64 characters")]
    HashTooLong,

    /// Scanner version exceeds maximum length of 32 characters
    #[msg("Scanner version exceeds maximum length of 32 characters")]
    VersionTooLong,

    /// Notes exceed maximum length of 256 characters
    #[msg("Notes exceed maximum length of 256 characters")]
    NotesTooLong,

    /// Invalid score: must be between 0 and 100
    #[msg("Invalid score: must be between 0 and 100")]
    InvalidScore,

    /// Unauthorized action - caller does not have permission
    #[msg("Unauthorized action - caller does not have permission")]
    Unauthorized,

    /// An attestation from this auditor already exists for this agent
    #[msg("An attestation from this auditor already exists for this agent")]
    AttestationExists,

    /// Agent not found in the registry
    #[msg("Agent not found in the registry")]
    AgentNotFound,

    /// Auditor is not verified and cannot perform this action
    #[msg("Auditor is not verified and cannot perform this action")]
    AuditorNotVerified,

    /// Auditor not found in the registry
    #[msg("Auditor not found in the registry")]
    AuditorNotFound,

    /// Attestation not found
    #[msg("Attestation not found")]
    AttestationNotFound,

    /// Attestation has already been disputed
    #[msg("Attestation has already been disputed")]
    AttestationAlreadyDisputed,

    /// Agent is not active
    #[msg("Agent is not active")]
    AgentNotActive,

    /// Cannot dispute own attestation
    #[msg("Cannot dispute own attestation")]
    CannotDisputeOwnAttestation,

    /// Invalid PDA derivation
    #[msg("Invalid PDA derivation")]
    InvalidPDA,

    /// Arithmetic overflow occurred
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,

    /// String field is empty but required
    #[msg("Required string field is empty")]
    EmptyRequiredField,
}
