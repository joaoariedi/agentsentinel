//! Account state definitions for the AgentSentinel Registry
//!
//! This module defines all account structures stored on-chain:
//! - Agent: Registered AI agents
//! - Auditor: Security auditors who can submit attestations
//! - Attestation: Security audit results

use anchor_lang::prelude::*;

// ============================================
// Security Scores
// ============================================

/// Breakdown of security scores across different categories
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default, Debug, PartialEq)]
pub struct SecurityScores {
    /// Overall security score (0-100)
    pub overall: u8,

    /// Resistance to prompt injection attacks (0-100)
    pub injection_resistance: u8,

    /// Compliance with expected behavior (0-100)
    pub behavior_compliance: u8,

    /// Infrastructure hardening score (0-100)
    pub infra_hardening: u8,

    /// Data protection and privacy score (0-100)
    pub data_protection: u8,
}

impl SecurityScores {
    /// Size in bytes for serialization
    pub const SIZE: usize = 5; // 5 u8 fields

    /// Validate all scores are within valid range (0-100)
    pub fn is_valid(&self) -> bool {
        self.overall <= 100
            && self.injection_resistance <= 100
            && self.behavior_compliance <= 100
            && self.infra_hardening <= 100
            && self.data_protection <= 100
    }
}

// ============================================
// Attestation Status
// ============================================

/// Status of a security attestation
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Debug, Default)]
pub enum AttestationStatus {
    /// Attestation is valid and current
    #[default]
    Valid,

    /// Attestation has been superseded by a newer one from the same auditor
    Superseded,

    /// Attestation was disputed and invalidated
    Disputed,

    /// Attestation expired (older than 90 days)
    Expired,
}

impl AttestationStatus {
    /// Size in bytes for serialization (enum variant)
    pub const SIZE: usize = 1;
}

// ============================================
// Agent Account
// ============================================

/// Registered agent in the AgentSentinel system
///
/// Each agent has a unique identifier and tracks aggregate security metrics
/// from all attestations received.
#[account]
pub struct Agent {
    /// Unique identifier for the agent (e.g., "claude-assistant-v1")
    /// Used as PDA seed: ["agent", agent_id]
    pub agent_id: String,

    /// Owner wallet that can update this agent's info
    pub owner: Pubkey,

    /// Human-readable display name
    pub name: String,

    /// Description of what the agent does
    pub description: String,

    /// GitHub repository URL for the agent's source code
    pub repo_url: String,

    /// Homepage or documentation URL
    pub homepage_url: String,

    /// Unix timestamp when the agent was registered
    pub created_at: i64,

    /// Unix timestamp of last update
    pub updated_at: i64,

    /// Total number of attestations received
    pub total_attestations: u32,

    /// Average security score across all attestations (0-100)
    pub avg_security_score: u8,

    /// Total number of critical vulnerabilities ever reported
    pub total_critical_vulns: u32,

    /// Whether the agent is currently active/maintained
    pub is_active: bool,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl Agent {
    // Maximum string lengths
    pub const MAX_AGENT_ID_LEN: usize = 64;
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_DESC_LEN: usize = 512;
    pub const MAX_URL_LEN: usize = 256;

    /// Account space calculation
    pub const SPACE: usize = 8 // discriminator
        + 4 + Self::MAX_AGENT_ID_LEN // agent_id (String: 4 byte len + data)
        + 32 // owner (Pubkey)
        + 4 + Self::MAX_NAME_LEN // name
        + 4 + Self::MAX_DESC_LEN // description
        + 4 + Self::MAX_URL_LEN // repo_url
        + 4 + Self::MAX_URL_LEN // homepage_url
        + 8  // created_at
        + 8  // updated_at
        + 4  // total_attestations
        + 1  // avg_security_score
        + 4  // total_critical_vulns
        + 1  // is_active
        + 1; // bump

    /// Seeds for PDA derivation
    pub const SEED_PREFIX: &'static [u8] = b"agent";
}

// ============================================
// Attestation Account
// ============================================

/// Security attestation for an agent
///
/// Created by an auditor after performing a security audit.
/// PDA derived from: ["attestation", agent_pubkey, auditor_pubkey]
#[account]
pub struct Attestation {
    /// The agent being attested (PDA of Agent account)
    pub agent: Pubkey,

    /// The auditor who performed the audit (PDA of Auditor account)
    pub auditor: Pubkey,

    /// Authority that signed the attestation (auditor's wallet)
    pub auditor_authority: Pubkey,

    /// Unix timestamp when the audit was performed
    pub timestamp: i64,

    /// Detailed security scores
    pub scores: SecurityScores,

    /// IPFS CID/hash of the full audit report
    pub report_hash: String,

    /// Number of critical vulnerabilities found
    pub vulns_critical: u8,

    /// Number of high severity vulnerabilities found
    pub vulns_high: u8,

    /// Number of medium severity vulnerabilities found
    pub vulns_medium: u8,

    /// Number of low severity vulnerabilities found
    pub vulns_low: u8,

    /// Total number of payloads/tests executed
    pub payloads_tested: u16,

    /// Version of AgentSentinel scanner used
    pub scanner_version: String,

    /// Current status of this attestation
    pub status: AttestationStatus,

    /// Optional notes from the auditor
    pub notes: String,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl Attestation {
    // Maximum string lengths
    pub const MAX_HASH_LEN: usize = 64; // IPFS CIDv1
    pub const MAX_VERSION_LEN: usize = 32;
    pub const MAX_NOTES_LEN: usize = 256;

    /// Account space calculation
    pub const SPACE: usize = 8 // discriminator
        + 32 // agent
        + 32 // auditor
        + 32 // auditor_authority
        + 8  // timestamp
        + SecurityScores::SIZE // scores
        + 4 + Self::MAX_HASH_LEN // report_hash
        + 1  // vulns_critical
        + 1  // vulns_high
        + 1  // vulns_medium
        + 1  // vulns_low
        + 2  // payloads_tested
        + 4 + Self::MAX_VERSION_LEN // scanner_version
        + AttestationStatus::SIZE // status
        + 4 + Self::MAX_NOTES_LEN // notes
        + 1; // bump

    /// Seeds for PDA derivation
    pub const SEED_PREFIX: &'static [u8] = b"attestation";

    /// Calculate total vulnerabilities
    pub fn total_vulns(&self) -> u16 {
        self.vulns_critical as u16
            + self.vulns_high as u16
            + self.vulns_medium as u16
            + self.vulns_low as u16
    }
}

// ============================================
// Auditor Account
// ============================================

/// Registered auditor who can submit security attestations
///
/// Auditors can register freely but must be verified by admin
/// to be considered trusted. PDA: ["auditor", authority_pubkey]
#[account]
pub struct Auditor {
    /// Auditor's wallet address (signs attestations)
    pub authority: Pubkey,

    /// Auditor's display name or organization
    pub name: String,

    /// Total number of audits performed
    pub audits_performed: u32,

    /// Average score given across all audits (to detect bias)
    pub avg_score_given: u8,

    /// Whether this auditor is verified by AgentSentinel team
    pub is_verified: bool,

    /// Unix timestamp when the auditor registered
    pub created_at: i64,

    /// Auditor's website or profile URL
    pub profile_url: String,

    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl Auditor {
    // Maximum string lengths
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_URL_LEN: usize = 256;

    /// Account space calculation
    pub const SPACE: usize = 8 // discriminator
        + 32 // authority
        + 4 + Self::MAX_NAME_LEN // name
        + 4  // audits_performed
        + 1  // avg_score_given
        + 1  // is_verified
        + 8  // created_at
        + 4 + Self::MAX_URL_LEN // profile_url
        + 1; // bump

    /// Seeds for PDA derivation
    pub const SEED_PREFIX: &'static [u8] = b"auditor";
}

// ============================================
// Registry Config (Program State)
// ============================================

/// Global registry configuration
///
/// Stores admin keys and global settings.
/// Singleton PDA: ["config"]
#[account]
pub struct RegistryConfig {
    /// Primary admin who can verify auditors
    pub admin: Pubkey,

    /// Secondary admin (backup)
    pub admin_backup: Pubkey,

    /// Whether new registrations are paused
    pub registration_paused: bool,

    /// Minimum score threshold for "secure" badge
    pub min_secure_score: u8,

    /// Total agents registered
    pub total_agents: u64,

    /// Total auditors registered
    pub total_auditors: u64,

    /// Total attestations submitted
    pub total_attestations: u64,

    /// Bump seed
    pub bump: u8,
}

impl RegistryConfig {
    /// Account space calculation
    pub const SPACE: usize = 8 // discriminator
        + 32 // admin
        + 32 // admin_backup
        + 1  // registration_paused
        + 1  // min_secure_score
        + 8  // total_agents
        + 8  // total_auditors
        + 8  // total_attestations
        + 1; // bump

    /// Seeds for PDA derivation
    pub const SEED_PREFIX: &'static [u8] = b"config";
}
