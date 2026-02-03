//! AgentSentinel On-Chain Security Registry
//!
//! This Anchor program provides an immutable, transparent registry for
//! AI agent security attestations on Solana.
//!
//! # Features
//! - Agent registration with metadata
//! - Auditor registration and verification
//! - Security attestation submission
//! - Attestation dispute mechanism
//! - On-chain aggregate statistics
//!
//! # PDA Structure
//! - Agent: ["agent", agent_id]
//! - Auditor: ["auditor", authority_pubkey]
//! - Attestation: ["attestation", agent_pubkey, auditor_pubkey]
//! - Config: ["config"]

use anchor_lang::prelude::*;

// Program ID - will be updated after deployment
// This is a placeholder - run `anchor keys list` after build to get actual ID
declare_id!("11111111111111111111111111111111");

// ============================================
// Error Definitions
// ============================================

/// Custom error codes for the Agent Registry program
#[error_code]
pub enum RegistryError {
    #[msg("Agent ID exceeds maximum length of 64 characters")]
    AgentIdTooLong,

    #[msg("Name exceeds maximum length of 128 characters")]
    NameTooLong,

    #[msg("Description exceeds maximum length of 512 characters")]
    DescriptionTooLong,

    #[msg("URL exceeds maximum length of 256 characters")]
    UrlTooLong,

    #[msg("Report hash exceeds maximum length of 64 characters")]
    HashTooLong,

    #[msg("Scanner version exceeds maximum length of 32 characters")]
    VersionTooLong,

    #[msg("Notes exceed maximum length of 256 characters")]
    NotesTooLong,

    #[msg("Invalid score: must be between 0 and 100")]
    InvalidScore,

    #[msg("Unauthorized action - caller does not have permission")]
    Unauthorized,

    #[msg("An attestation from this auditor already exists for this agent")]
    AttestationExists,

    #[msg("Agent not found in the registry")]
    AgentNotFound,

    #[msg("Auditor is not verified and cannot perform this action")]
    AuditorNotVerified,

    #[msg("Auditor not found in the registry")]
    AuditorNotFound,

    #[msg("Attestation not found")]
    AttestationNotFound,

    #[msg("Attestation has already been disputed")]
    AttestationAlreadyDisputed,

    #[msg("Agent is not active")]
    AgentNotActive,

    #[msg("Cannot dispute own attestation")]
    CannotDisputeOwnAttestation,

    #[msg("Invalid PDA derivation")]
    InvalidPDA,

    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,

    #[msg("Required string field is empty")]
    EmptyRequiredField,
}

// ============================================
// State Definitions
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
    pub const SIZE: usize = 5;

    pub fn is_valid(&self) -> bool {
        self.overall <= 100
            && self.injection_resistance <= 100
            && self.behavior_compliance <= 100
            && self.infra_hardening <= 100
            && self.data_protection <= 100
    }
}

/// Status of a security attestation
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Debug, Default)]
pub enum AttestationStatus {
    #[default]
    Valid,
    Superseded,
    Disputed,
    Expired,
}

impl AttestationStatus {
    pub const SIZE: usize = 1;
}

/// Registered agent in the AgentSentinel system
#[account]
pub struct Agent {
    pub agent_id: String,
    pub owner: Pubkey,
    pub name: String,
    pub description: String,
    pub repo_url: String,
    pub homepage_url: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub total_attestations: u32,
    pub avg_security_score: u8,
    pub total_critical_vulns: u32,
    pub is_active: bool,
    pub bump: u8,
}

impl Agent {
    pub const MAX_AGENT_ID_LEN: usize = 64;
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_DESC_LEN: usize = 512;
    pub const MAX_URL_LEN: usize = 256;

    pub const SPACE: usize = 8
        + 4 + Self::MAX_AGENT_ID_LEN
        + 32
        + 4 + Self::MAX_NAME_LEN
        + 4 + Self::MAX_DESC_LEN
        + 4 + Self::MAX_URL_LEN
        + 4 + Self::MAX_URL_LEN
        + 8 + 8 + 4 + 1 + 4 + 1 + 1;

    pub const SEED_PREFIX: &'static [u8] = b"agent";
}

/// Security attestation for an agent
#[account]
pub struct Attestation {
    pub agent: Pubkey,
    pub auditor: Pubkey,
    pub auditor_authority: Pubkey,
    pub timestamp: i64,
    pub scores: SecurityScores,
    pub report_hash: String,
    pub vulns_critical: u8,
    pub vulns_high: u8,
    pub vulns_medium: u8,
    pub vulns_low: u8,
    pub payloads_tested: u16,
    pub scanner_version: String,
    pub status: AttestationStatus,
    pub notes: String,
    pub bump: u8,
}

impl Attestation {
    pub const MAX_HASH_LEN: usize = 64;
    pub const MAX_VERSION_LEN: usize = 32;
    pub const MAX_NOTES_LEN: usize = 256;

    pub const SPACE: usize = 8
        + 32 + 32 + 32 + 8
        + SecurityScores::SIZE
        + 4 + Self::MAX_HASH_LEN
        + 1 + 1 + 1 + 1 + 2
        + 4 + Self::MAX_VERSION_LEN
        + AttestationStatus::SIZE
        + 4 + Self::MAX_NOTES_LEN
        + 1;

    pub const SEED_PREFIX: &'static [u8] = b"attestation";
}

/// Registered auditor who can submit security attestations
#[account]
pub struct Auditor {
    pub authority: Pubkey,
    pub name: String,
    pub audits_performed: u32,
    pub avg_score_given: u8,
    pub is_verified: bool,
    pub created_at: i64,
    pub profile_url: String,
    pub bump: u8,
}

impl Auditor {
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_URL_LEN: usize = 256;

    pub const SPACE: usize = 8
        + 32
        + 4 + Self::MAX_NAME_LEN
        + 4 + 1 + 1 + 8
        + 4 + Self::MAX_URL_LEN
        + 1;

    pub const SEED_PREFIX: &'static [u8] = b"auditor";
}

/// Global registry configuration
#[account]
pub struct RegistryConfig {
    pub admin: Pubkey,
    pub admin_backup: Pubkey,
    pub registration_paused: bool,
    pub min_secure_score: u8,
    pub total_agents: u64,
    pub total_auditors: u64,
    pub total_attestations: u64,
    pub bump: u8,
}

impl RegistryConfig {
    pub const SPACE: usize = 8 + 32 + 32 + 1 + 1 + 8 + 8 + 8 + 1;
    pub const SEED_PREFIX: &'static [u8] = b"config";
}

// ============================================
// Program Instructions
// ============================================

#[program]
pub mod agent_registry {
    use super::*;

    /// Initialize the registry configuration
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let admin = &ctx.accounts.admin;

        config.admin = admin.key();
        config.admin_backup = admin.key();
        config.registration_paused = false;
        config.min_secure_score = 70;
        config.total_agents = 0;
        config.total_auditors = 0;
        config.total_attestations = 0;
        config.bump = ctx.bumps.config;

        emit!(RegistryInitialized {
            admin: admin.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Register a new agent in the registry
    pub fn register_agent(
        ctx: Context<RegisterAgent>,
        agent_id: String,
        name: String,
        description: String,
        repo_url: String,
        homepage_url: String,
    ) -> Result<()> {
        require!(
            agent_id.len() <= Agent::MAX_AGENT_ID_LEN,
            RegistryError::AgentIdTooLong
        );
        require!(!agent_id.is_empty(), RegistryError::EmptyRequiredField);
        require!(name.len() <= Agent::MAX_NAME_LEN, RegistryError::NameTooLong);
        require!(!name.is_empty(), RegistryError::EmptyRequiredField);
        require!(
            description.len() <= Agent::MAX_DESC_LEN,
            RegistryError::DescriptionTooLong
        );
        require!(repo_url.len() <= Agent::MAX_URL_LEN, RegistryError::UrlTooLong);
        require!(
            homepage_url.len() <= Agent::MAX_URL_LEN,
            RegistryError::UrlTooLong
        );

        let agent = &mut ctx.accounts.agent;
        let config = &mut ctx.accounts.config;
        let clock = Clock::get()?;

        agent.agent_id = agent_id.clone();
        agent.owner = ctx.accounts.owner.key();
        agent.name = name;
        agent.description = description;
        agent.repo_url = repo_url;
        agent.homepage_url = homepage_url;
        agent.created_at = clock.unix_timestamp;
        agent.updated_at = clock.unix_timestamp;
        agent.total_attestations = 0;
        agent.avg_security_score = 0;
        agent.total_critical_vulns = 0;
        agent.is_active = true;
        agent.bump = ctx.bumps.agent;

        config.total_agents = config
            .total_agents
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;

        emit!(AgentRegistered {
            agent: agent.key(),
            agent_id,
            owner: ctx.accounts.owner.key(),
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Update an existing agent's information
    pub fn update_agent(
        ctx: Context<UpdateAgent>,
        name: Option<String>,
        description: Option<String>,
        repo_url: Option<String>,
        homepage_url: Option<String>,
        is_active: Option<bool>,
    ) -> Result<()> {
        let agent = &mut ctx.accounts.agent;
        let clock = Clock::get()?;

        if let Some(n) = name {
            require!(n.len() <= Agent::MAX_NAME_LEN, RegistryError::NameTooLong);
            agent.name = n;
        }
        if let Some(d) = description {
            require!(
                d.len() <= Agent::MAX_DESC_LEN,
                RegistryError::DescriptionTooLong
            );
            agent.description = d;
        }
        if let Some(r) = repo_url {
            require!(r.len() <= Agent::MAX_URL_LEN, RegistryError::UrlTooLong);
            agent.repo_url = r;
        }
        if let Some(h) = homepage_url {
            require!(h.len() <= Agent::MAX_URL_LEN, RegistryError::UrlTooLong);
            agent.homepage_url = h;
        }
        if let Some(active) = is_active {
            agent.is_active = active;
        }

        agent.updated_at = clock.unix_timestamp;

        emit!(AgentUpdated {
            agent: agent.key(),
            updated_by: ctx.accounts.owner.key(),
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Register as an auditor
    pub fn register_auditor(
        ctx: Context<RegisterAuditor>,
        name: String,
        profile_url: String,
    ) -> Result<()> {
        require!(
            name.len() <= Auditor::MAX_NAME_LEN,
            RegistryError::NameTooLong
        );
        require!(!name.is_empty(), RegistryError::EmptyRequiredField);
        require!(
            profile_url.len() <= Auditor::MAX_URL_LEN,
            RegistryError::UrlTooLong
        );

        let auditor = &mut ctx.accounts.auditor;
        let config = &mut ctx.accounts.config;
        let clock = Clock::get()?;

        auditor.authority = ctx.accounts.authority.key();
        auditor.name = name.clone();
        auditor.audits_performed = 0;
        auditor.avg_score_given = 0;
        auditor.is_verified = false;
        auditor.created_at = clock.unix_timestamp;
        auditor.profile_url = profile_url;
        auditor.bump = ctx.bumps.auditor;

        config.total_auditors = config
            .total_auditors
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;

        emit!(AuditorRegistered {
            auditor: auditor.key(),
            authority: ctx.accounts.authority.key(),
            name,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Verify an auditor (admin only)
    pub fn verify_auditor(ctx: Context<VerifyAuditor>) -> Result<()> {
        let auditor = &mut ctx.accounts.auditor;
        auditor.is_verified = true;

        emit!(AuditorVerified {
            auditor: auditor.key(),
            verified_by: ctx.accounts.admin.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Revoke auditor verification (admin only)
    pub fn revoke_auditor_verification(ctx: Context<VerifyAuditor>) -> Result<()> {
        let auditor = &mut ctx.accounts.auditor;
        auditor.is_verified = false;

        emit!(AuditorVerificationRevoked {
            auditor: auditor.key(),
            revoked_by: ctx.accounts.admin.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Submit a security attestation for an agent
    pub fn submit_attestation(
        ctx: Context<SubmitAttestation>,
        scores: SecurityScores,
        report_hash: String,
        vulns_critical: u8,
        vulns_high: u8,
        vulns_medium: u8,
        vulns_low: u8,
        payloads_tested: u16,
        scanner_version: String,
        notes: String,
    ) -> Result<()> {
        require!(scores.is_valid(), RegistryError::InvalidScore);
        require!(
            report_hash.len() <= Attestation::MAX_HASH_LEN,
            RegistryError::HashTooLong
        );
        require!(!report_hash.is_empty(), RegistryError::EmptyRequiredField);
        require!(
            scanner_version.len() <= Attestation::MAX_VERSION_LEN,
            RegistryError::VersionTooLong
        );
        require!(
            notes.len() <= Attestation::MAX_NOTES_LEN,
            RegistryError::NotesTooLong
        );

        let attestation = &mut ctx.accounts.attestation;
        let agent = &mut ctx.accounts.agent;
        let auditor = &mut ctx.accounts.auditor;
        let config = &mut ctx.accounts.config;
        let clock = Clock::get()?;

        require!(agent.is_active, RegistryError::AgentNotActive);

        attestation.agent = agent.key();
        attestation.auditor = auditor.key();
        attestation.auditor_authority = ctx.accounts.authority.key();
        attestation.timestamp = clock.unix_timestamp;
        attestation.scores = scores.clone();
        attestation.report_hash = report_hash;
        attestation.vulns_critical = vulns_critical;
        attestation.vulns_high = vulns_high;
        attestation.vulns_medium = vulns_medium;
        attestation.vulns_low = vulns_low;
        attestation.payloads_tested = payloads_tested;
        attestation.scanner_version = scanner_version;
        attestation.status = AttestationStatus::Valid;
        attestation.notes = notes;
        attestation.bump = ctx.bumps.attestation;

        // Update agent stats
        let old_total = agent.total_attestations as u64;
        let old_avg = agent.avg_security_score as u64;
        agent.total_attestations = agent
            .total_attestations
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;

        let new_total = agent.total_attestations as u64;
        let new_avg = old_avg
            .checked_mul(old_total)
            .and_then(|x| x.checked_add(scores.overall as u64))
            .and_then(|x| x.checked_div(new_total))
            .ok_or(RegistryError::ArithmeticOverflow)? as u8;
        agent.avg_security_score = new_avg;
        agent.total_critical_vulns = agent
            .total_critical_vulns
            .checked_add(vulns_critical as u32)
            .ok_or(RegistryError::ArithmeticOverflow)?;
        agent.updated_at = clock.unix_timestamp;

        // Update auditor stats
        let auditor_old_total = auditor.audits_performed as u64;
        let auditor_old_avg = auditor.avg_score_given as u64;
        auditor.audits_performed = auditor
            .audits_performed
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;

        let auditor_new_total = auditor.audits_performed as u64;
        let auditor_new_avg = auditor_old_avg
            .checked_mul(auditor_old_total)
            .and_then(|x| x.checked_add(scores.overall as u64))
            .and_then(|x| x.checked_div(auditor_new_total))
            .ok_or(RegistryError::ArithmeticOverflow)? as u8;
        auditor.avg_score_given = auditor_new_avg;

        config.total_attestations = config
            .total_attestations
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;

        emit!(AttestationSubmitted {
            attestation: attestation.key(),
            agent: agent.key(),
            auditor: auditor.key(),
            score: scores.overall,
            vulns_critical,
            vulns_high,
            vulns_medium,
            vulns_low,
            is_verified_auditor: auditor.is_verified,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Dispute an attestation
    pub fn dispute_attestation(ctx: Context<DisputeAttestation>, reason: String) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;

        require!(
            attestation.status != AttestationStatus::Disputed,
            RegistryError::AttestationAlreadyDisputed
        );

        require!(
            ctx.accounts.disputer.key() != attestation.auditor_authority,
            RegistryError::CannotDisputeOwnAttestation
        );

        attestation.status = AttestationStatus::Disputed;

        emit!(AttestationDisputed {
            attestation: attestation.key(),
            disputed_by: ctx.accounts.disputer.key(),
            reason,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Update the admin (admin only)
    pub fn update_admin(ctx: Context<UpdateConfig>, new_admin: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let old_admin = config.admin;

        config.admin = new_admin;

        emit!(AdminUpdated {
            old_admin,
            new_admin,
            updated_by: ctx.accounts.admin.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Pause or unpause registrations (admin only)
    pub fn set_registration_paused(ctx: Context<UpdateConfig>, paused: bool) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.registration_paused = paused;

        emit!(RegistrationPauseToggled {
            paused,
            toggled_by: ctx.accounts.admin.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }
}

// ============================================
// Account Contexts
// ============================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = RegistryConfig::SPACE,
        seeds = [RegistryConfig::SEED_PREFIX],
        bump
    )]
    pub config: Account<'info, RegistryConfig>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(agent_id: String)]
pub struct RegisterAgent<'info> {
    #[account(
        init,
        payer = owner,
        space = Agent::SPACE,
        seeds = [Agent::SEED_PREFIX, agent_id.as_bytes()],
        bump
    )]
    pub agent: Account<'info, Agent>,

    #[account(
        mut,
        seeds = [RegistryConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = !config.registration_paused @ RegistryError::Unauthorized
    )]
    pub config: Account<'info, RegistryConfig>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAgent<'info> {
    #[account(
        mut,
        has_one = owner @ RegistryError::Unauthorized
    )]
    pub agent: Account<'info, Agent>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct RegisterAuditor<'info> {
    #[account(
        init,
        payer = authority,
        space = Auditor::SPACE,
        seeds = [Auditor::SEED_PREFIX, authority.key().as_ref()],
        bump
    )]
    pub auditor: Account<'info, Auditor>,

    #[account(
        mut,
        seeds = [RegistryConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = !config.registration_paused @ RegistryError::Unauthorized
    )]
    pub config: Account<'info, RegistryConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyAuditor<'info> {
    #[account(mut)]
    pub auditor: Account<'info, Auditor>,

    #[account(
        seeds = [RegistryConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = admin.key() == config.admin @ RegistryError::Unauthorized
    )]
    pub config: Account<'info, RegistryConfig>,

    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SubmitAttestation<'info> {
    #[account(
        init,
        payer = authority,
        space = Attestation::SPACE,
        seeds = [Attestation::SEED_PREFIX, agent.key().as_ref(), auditor.key().as_ref()],
        bump
    )]
    pub attestation: Account<'info, Attestation>,

    #[account(mut)]
    pub agent: Account<'info, Agent>,

    #[account(
        mut,
        has_one = authority @ RegistryError::Unauthorized
    )]
    pub auditor: Account<'info, Auditor>,

    #[account(
        mut,
        seeds = [RegistryConfig::SEED_PREFIX],
        bump = config.bump
    )]
    pub config: Account<'info, RegistryConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DisputeAttestation<'info> {
    #[account(mut)]
    pub attestation: Account<'info, Attestation>,

    pub disputer: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(
        mut,
        seeds = [RegistryConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = admin.key() == config.admin @ RegistryError::Unauthorized
    )]
    pub config: Account<'info, RegistryConfig>,

    pub admin: Signer<'info>,
}

// ============================================
// Events
// ============================================

#[event]
pub struct RegistryInitialized {
    pub admin: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AgentRegistered {
    pub agent: Pubkey,
    pub agent_id: String,
    pub owner: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AgentUpdated {
    pub agent: Pubkey,
    pub updated_by: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AuditorRegistered {
    pub auditor: Pubkey,
    pub authority: Pubkey,
    pub name: String,
    pub timestamp: i64,
}

#[event]
pub struct AuditorVerified {
    pub auditor: Pubkey,
    pub verified_by: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AuditorVerificationRevoked {
    pub auditor: Pubkey,
    pub revoked_by: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AttestationSubmitted {
    pub attestation: Pubkey,
    pub agent: Pubkey,
    pub auditor: Pubkey,
    pub score: u8,
    pub vulns_critical: u8,
    pub vulns_high: u8,
    pub vulns_medium: u8,
    pub vulns_low: u8,
    pub is_verified_auditor: bool,
    pub timestamp: i64,
}

#[event]
pub struct AttestationDisputed {
    pub attestation: Pubkey,
    pub disputed_by: Pubkey,
    pub reason: String,
    pub timestamp: i64,
}

#[event]
pub struct AdminUpdated {
    pub old_admin: Pubkey,
    pub new_admin: Pubkey,
    pub updated_by: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct RegistrationPauseToggled {
    pub paused: bool,
    pub toggled_by: Pubkey,
    pub timestamp: i64,
}
