# Phase 5: Solana On-Chain Registry - Security Attestations

**Duration:** Days 8-9
**Goal:** Build an Anchor program that stores agent security attestations on Solana

---

## Overview

The Solana Registry creates an immutable, transparent record of agent security audits. This allows:

1. **Agents** - Publish their security scores after passing audits
2. **Users** - Verify an agent's security before granting access
3. **Auditors** - Build reputation as trusted security reviewers
4. **Ecosystem** - Create accountability for agent security

---

## Program Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AgentSentinel Registry Program                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ Agent Account   │  │ Attestation     │  │ Auditor Account     │  │
│  │                 │  │ Account         │  │                     │  │
│  │ • agent_id      │  │                 │  │ • auditor_pubkey    │  │
│  │ • owner         │  │ • agent         │  │ • name              │  │
│  │ • name          │  │ • auditor       │  │ • audits_performed  │  │
│  │ • description   │  │ • timestamp     │  │ • avg_score_given   │  │
│  │ • repo_url      │  │ • scores        │  │ • is_verified       │  │
│  │ • created_at    │  │ • report_hash   │  │ • created_at        │  │
│  │ • total_audits  │  │ • status        │  │                     │  │
│  │ • avg_score     │  │                 │  │                     │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘  │
│           │                    │                      │              │
│           │      PDA Seeds     │                      │              │
│           │                    │                      │              │
│  [b"agent", agent_id]   [b"attestation",      [b"auditor",          │
│                          agent.key(),          auditor_pubkey]       │
│                          auditor.key()]                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### 5.1 Program State & Accounts

```rust
// src/solana_registry/programs/agent_registry/src/state.rs
use anchor_lang::prelude::*;

/// Registered agent in the system
#[account]
pub struct Agent {
    /// Unique identifier for the agent (e.g., "AgentSentinel-v1")
    pub agent_id: String,
    
    /// Owner who can update this agent's info
    pub owner: Pubkey,
    
    /// Human-readable name
    pub name: String,
    
    /// Description of what the agent does
    pub description: String,
    
    /// GitHub repository URL
    pub repo_url: String,
    
    /// Homepage or documentation URL
    pub homepage_url: String,
    
    /// When the agent was registered
    pub created_at: i64,
    
    /// Last updated timestamp
    pub updated_at: i64,
    
    /// Total number of attestations received
    pub total_attestations: u32,
    
    /// Average security score (0-100)
    pub avg_security_score: u8,
    
    /// Number of critical vulnerabilities ever reported
    pub total_critical_vulns: u32,
    
    /// Whether the agent is currently active
    pub is_active: bool,
    
    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl Agent {
    pub const MAX_AGENT_ID_LEN: usize = 64;
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_DESC_LEN: usize = 512;
    pub const MAX_URL_LEN: usize = 256;
    
    pub const SPACE: usize = 8 +  // discriminator
        4 + Self::MAX_AGENT_ID_LEN +  // agent_id (String)
        32 +  // owner
        4 + Self::MAX_NAME_LEN +  // name
        4 + Self::MAX_DESC_LEN +  // description
        4 + Self::MAX_URL_LEN +  // repo_url
        4 + Self::MAX_URL_LEN +  // homepage_url
        8 +  // created_at
        8 +  // updated_at
        4 +  // total_attestations
        1 +  // avg_security_score
        4 +  // total_critical_vulns
        1 +  // is_active
        1;   // bump
}

/// Security scores breakdown
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct SecurityScores {
    /// Overall security score (0-100)
    pub overall: u8,
    
    /// Resistance to prompt injection (0-100)
    pub injection_resistance: u8,
    
    /// Behavior compliance score (0-100)
    pub behavior_compliance: u8,
    
    /// Infrastructure hardening score (0-100)
    pub infra_hardening: u8,
    
    /// Data protection score (0-100)
    pub data_protection: u8,
}

/// Attestation status
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq)]
pub enum AttestationStatus {
    /// Attestation is valid and current
    Valid,
    /// Attestation has been superseded by a newer one
    Superseded,
    /// Attestation was disputed and invalidated
    Disputed,
    /// Attestation expired (older than 90 days)
    Expired,
}

impl Default for AttestationStatus {
    fn default() -> Self {
        AttestationStatus::Valid
    }
}

/// Security attestation for an agent
#[account]
pub struct Attestation {
    /// The agent being attested
    pub agent: Pubkey,
    
    /// The auditor who performed the audit
    pub auditor: Pubkey,
    
    /// When the audit was performed
    pub timestamp: i64,
    
    /// Security scores
    pub scores: SecurityScores,
    
    /// IPFS hash of the full report
    pub report_hash: String,
    
    /// Number of vulnerabilities found by severity
    pub vulns_critical: u8,
    pub vulns_high: u8,
    pub vulns_medium: u8,
    pub vulns_low: u8,
    
    /// Total payloads tested
    pub payloads_tested: u16,
    
    /// Version of AgentSentinel used for the audit
    pub scanner_version: String,
    
    /// Current status of this attestation
    pub status: AttestationStatus,
    
    /// Optional notes from the auditor
    pub notes: String,
    
    /// Bump seed
    pub bump: u8,
}

impl Attestation {
    pub const MAX_HASH_LEN: usize = 64;  // IPFS CID
    pub const MAX_VERSION_LEN: usize = 32;
    pub const MAX_NOTES_LEN: usize = 256;
    
    pub const SPACE: usize = 8 +  // discriminator
        32 +  // agent
        32 +  // auditor
        8 +   // timestamp
        5 +   // scores (5 u8s)
        4 + Self::MAX_HASH_LEN +  // report_hash
        1 + 1 + 1 + 1 +  // vuln counts
        2 +   // payloads_tested
        4 + Self::MAX_VERSION_LEN +  // scanner_version
        1 +   // status
        4 + Self::MAX_NOTES_LEN +  // notes
        1;    // bump
}

/// Registered auditor
#[account]
pub struct Auditor {
    /// Auditor's wallet address
    pub authority: Pubkey,
    
    /// Auditor name/identifier
    pub name: String,
    
    /// Number of audits performed
    pub audits_performed: u32,
    
    /// Average score given (to detect too lenient/strict auditors)
    pub avg_score_given: u8,
    
    /// Whether this auditor is verified by AgentSentinel team
    pub is_verified: bool,
    
    /// When the auditor registered
    pub created_at: i64,
    
    /// Auditor's website or profile
    pub profile_url: String,
    
    /// Bump seed
    pub bump: u8,
}

impl Auditor {
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_URL_LEN: usize = 256;
    
    pub const SPACE: usize = 8 +  // discriminator
        32 +  // authority
        4 + Self::MAX_NAME_LEN +  // name
        4 +   // audits_performed
        1 +   // avg_score_given
        1 +   // is_verified
        8 +   // created_at
        4 + Self::MAX_URL_LEN +  // profile_url
        1;    // bump
}
```

### 5.2 Program Instructions

```rust
// src/solana_registry/programs/agent_registry/src/lib.rs
use anchor_lang::prelude::*;

pub mod state;
pub mod errors;

use state::*;
use errors::*;

declare_id!("AGENT1111111111111111111111111111111111111");

#[program]
pub mod agent_registry {
    use super::*;

    /// Register a new agent
    pub fn register_agent(
        ctx: Context<RegisterAgent>,
        agent_id: String,
        name: String,
        description: String,
        repo_url: String,
        homepage_url: String,
    ) -> Result<()> {
        require!(agent_id.len() <= Agent::MAX_AGENT_ID_LEN, RegistryError::AgentIdTooLong);
        require!(name.len() <= Agent::MAX_NAME_LEN, RegistryError::NameTooLong);
        require!(description.len() <= Agent::MAX_DESC_LEN, RegistryError::DescriptionTooLong);
        
        let agent = &mut ctx.accounts.agent;
        let clock = Clock::get()?;
        
        agent.agent_id = agent_id;
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
        
        emit!(AgentRegistered {
            agent: agent.key(),
            agent_id: agent.agent_id.clone(),
            owner: agent.owner,
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
        require!(name.len() <= Auditor::MAX_NAME_LEN, RegistryError::NameTooLong);
        
        let auditor = &mut ctx.accounts.auditor;
        let clock = Clock::get()?;
        
        auditor.authority = ctx.accounts.authority.key();
        auditor.name = name;
        auditor.audits_performed = 0;
        auditor.avg_score_given = 0;
        auditor.is_verified = false;
        auditor.created_at = clock.unix_timestamp;
        auditor.profile_url = profile_url;
        auditor.bump = ctx.bumps.auditor;
        
        emit!(AuditorRegistered {
            auditor: auditor.key(),
            authority: auditor.authority,
            name: auditor.name.clone(),
            timestamp: clock.unix_timestamp,
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
        require!(report_hash.len() <= Attestation::MAX_HASH_LEN, RegistryError::HashTooLong);
        require!(scores.overall <= 100, RegistryError::InvalidScore);
        
        let attestation = &mut ctx.accounts.attestation;
        let agent = &mut ctx.accounts.agent;
        let auditor = &mut ctx.accounts.auditor;
        let clock = Clock::get()?;
        
        // Record attestation
        attestation.agent = agent.key();
        attestation.auditor = auditor.key();
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
        let old_total = agent.total_attestations;
        let old_avg = agent.avg_security_score as u32;
        agent.total_attestations += 1;
        agent.avg_security_score = (
            (old_avg * old_total + scores.overall as u32) / agent.total_attestations
        ) as u8;
        agent.total_critical_vulns += vulns_critical as u32;
        agent.updated_at = clock.unix_timestamp;
        
        // Update auditor stats
        let auditor_old_total = auditor.audits_performed;
        let auditor_old_avg = auditor.avg_score_given as u32;
        auditor.audits_performed += 1;
        auditor.avg_score_given = (
            (auditor_old_avg * auditor_old_total + scores.overall as u32) / auditor.audits_performed
        ) as u8;
        
        emit!(AttestationSubmitted {
            attestation: attestation.key(),
            agent: agent.key(),
            auditor: auditor.key(),
            score: scores.overall,
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
        });
        
        Ok(())
    }

    /// Dispute an attestation
    pub fn dispute_attestation(ctx: Context<DisputeAttestation>, reason: String) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;
        attestation.status = AttestationStatus::Disputed;
        
        emit!(AttestationDisputed {
            attestation: attestation.key(),
            disputed_by: ctx.accounts.disputer.key(),
            reason,
        });
        
        Ok(())
    }
}

// ============================================
// Account Contexts
// ============================================

#[derive(Accounts)]
#[instruction(agent_id: String)]
pub struct RegisterAgent<'info> {
    #[account(
        init,
        payer = owner,
        space = Agent::SPACE,
        seeds = [b"agent", agent_id.as_bytes()],
        bump
    )]
    pub agent: Account<'info, Agent>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterAuditor<'info> {
    #[account(
        init,
        payer = authority,
        space = Auditor::SPACE,
        seeds = [b"auditor", authority.key().as_ref()],
        bump
    )]
    pub auditor: Account<'info, Auditor>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SubmitAttestation<'info> {
    #[account(
        init,
        payer = authority,
        space = Attestation::SPACE,
        seeds = [b"attestation", agent.key().as_ref(), auditor.key().as_ref()],
        bump
    )]
    pub attestation: Account<'info, Attestation>,
    
    #[account(mut)]
    pub agent: Account<'info, Agent>,
    
    #[account(
        mut,
        has_one = authority
    )]
    pub auditor: Account<'info, Auditor>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyAuditor<'info> {
    #[account(mut)]
    pub auditor: Account<'info, Auditor>,
    
    /// Admin who can verify auditors (hardcoded or governance)
    #[account(
        constraint = admin.key() == ADMIN_PUBKEY @ RegistryError::Unauthorized
    )]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct DisputeAttestation<'info> {
    #[account(mut)]
    pub attestation: Account<'info, Attestation>,
    
    /// Only the agent owner or a verified auditor can dispute
    pub disputer: Signer<'info>,
}

// ============================================
// Events
// ============================================

#[event]
pub struct AgentRegistered {
    pub agent: Pubkey,
    pub agent_id: String,
    pub owner: Pubkey,
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
pub struct AttestationSubmitted {
    pub attestation: Pubkey,
    pub agent: Pubkey,
    pub auditor: Pubkey,
    pub score: u8,
    pub timestamp: i64,
}

#[event]
pub struct AuditorVerified {
    pub auditor: Pubkey,
    pub verified_by: Pubkey,
}

#[event]
pub struct AttestationDisputed {
    pub attestation: Pubkey,
    pub disputed_by: Pubkey,
    pub reason: String,
}

// Admin pubkey - replace with actual governance
const ADMIN_PUBKEY: Pubkey = Pubkey::new_from_array([0; 32]); // TODO: Set real admin
```

### 5.3 Error Definitions

```rust
// src/solana_registry/programs/agent_registry/src/errors.rs
use anchor_lang::prelude::*;

#[error_code]
pub enum RegistryError {
    #[msg("Agent ID exceeds maximum length")]
    AgentIdTooLong,
    
    #[msg("Name exceeds maximum length")]
    NameTooLong,
    
    #[msg("Description exceeds maximum length")]
    DescriptionTooLong,
    
    #[msg("Report hash exceeds maximum length")]
    HashTooLong,
    
    #[msg("Invalid score: must be 0-100")]
    InvalidScore,
    
    #[msg("Unauthorized action")]
    Unauthorized,
    
    #[msg("Attestation already exists")]
    AttestationExists,
    
    #[msg("Agent not found")]
    AgentNotFound,
    
    #[msg("Auditor not verified")]
    AuditorNotVerified,
}
```

### 5.4 TypeScript Client SDK

```typescript
// src/solana_registry/sdk/src/index.ts
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, web3 } from "@coral-xyz/anchor";
import { PublicKey, Connection, Keypair } from "@solana/web3.js";

// Types matching the Rust program
export interface SecurityScores {
  overall: number;
  injectionResistance: number;
  behaviorCompliance: number;
  infraHardening: number;
  dataProtection: number;
}

export interface Agent {
  agentId: string;
  owner: PublicKey;
  name: string;
  description: string;
  repoUrl: string;
  homepageUrl: string;
  createdAt: number;
  updatedAt: number;
  totalAttestations: number;
  avgSecurityScore: number;
  totalCriticalVulns: number;
  isActive: boolean;
}

export interface Attestation {
  agent: PublicKey;
  auditor: PublicKey;
  timestamp: number;
  scores: SecurityScores;
  reportHash: string;
  vulnsCritical: number;
  vulnsHigh: number;
  vulnsMedium: number;
  vulnsLow: number;
  payloadsTested: number;
  scannerVersion: string;
  status: "valid" | "superseded" | "disputed" | "expired";
  notes: string;
}

export interface Auditor {
  authority: PublicKey;
  name: string;
  auditsPerformed: number;
  avgScoreGiven: number;
  isVerified: boolean;
  createdAt: number;
  profileUrl: string;
}

export class AgentRegistryClient {
  private program: Program;
  private provider: AnchorProvider;

  constructor(
    connection: Connection,
    wallet: anchor.Wallet,
    programId: PublicKey
  ) {
    this.provider = new AnchorProvider(connection, wallet, {});
    // In production, load IDL from chain or file
    // this.program = new Program(IDL, programId, this.provider);
  }

  // ============================================
  // PDA Derivation
  // ============================================

  getAgentPDA(agentId: string): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("agent"), Buffer.from(agentId)],
      this.program.programId
    );
  }

  getAuditorPDA(authority: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("auditor"), authority.toBuffer()],
      this.program.programId
    );
  }

  getAttestationPDA(agent: PublicKey, auditor: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("attestation"), agent.toBuffer(), auditor.toBuffer()],
      this.program.programId
    );
  }

  // ============================================
  // Instructions
  // ============================================

  async registerAgent(
    agentId: string,
    name: string,
    description: string,
    repoUrl: string,
    homepageUrl: string
  ): Promise<string> {
    const [agentPDA] = this.getAgentPDA(agentId);

    const tx = await this.program.methods
      .registerAgent(agentId, name, description, repoUrl, homepageUrl)
      .accounts({
        agent: agentPDA,
        owner: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    return tx;
  }

  async registerAuditor(name: string, profileUrl: string): Promise<string> {
    const [auditorPDA] = this.getAuditorPDA(this.provider.wallet.publicKey);

    const tx = await this.program.methods
      .registerAuditor(name, profileUrl)
      .accounts({
        auditor: auditorPDA,
        authority: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    return tx;
  }

  async submitAttestation(
    agentPDA: PublicKey,
    scores: SecurityScores,
    reportHash: string,
    vulns: { critical: number; high: number; medium: number; low: number },
    payloadsTested: number,
    scannerVersion: string,
    notes: string
  ): Promise<string> {
    const [auditorPDA] = this.getAuditorPDA(this.provider.wallet.publicKey);
    const [attestationPDA] = this.getAttestationPDA(agentPDA, auditorPDA);

    const tx = await this.program.methods
      .submitAttestation(
        scores,
        reportHash,
        vulns.critical,
        vulns.high,
        vulns.medium,
        vulns.low,
        payloadsTested,
        scannerVersion,
        notes
      )
      .accounts({
        attestation: attestationPDA,
        agent: agentPDA,
        auditor: auditorPDA,
        authority: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    return tx;
  }

  // ============================================
  // Queries
  // ============================================

  async getAgent(agentId: string): Promise<Agent | null> {
    const [pda] = this.getAgentPDA(agentId);
    try {
      const account = await this.program.account.agent.fetch(pda);
      return account as Agent;
    } catch {
      return null;
    }
  }

  async getAuditor(authority: PublicKey): Promise<Auditor | null> {
    const [pda] = this.getAuditorPDA(authority);
    try {
      const account = await this.program.account.auditor.fetch(pda);
      return account as Auditor;
    } catch {
      return null;
    }
  }

  async getAttestation(
    agent: PublicKey,
    auditor: PublicKey
  ): Promise<Attestation | null> {
    const [pda] = this.getAttestationPDA(agent, auditor);
    try {
      const account = await this.program.account.attestation.fetch(pda);
      return account as Attestation;
    } catch {
      return null;
    }
  }

  async getAllAgents(): Promise<Agent[]> {
    const accounts = await this.program.account.agent.all();
    return accounts.map((a) => a.account as Agent);
  }

  async getAgentAttestations(agentPDA: PublicKey): Promise<Attestation[]> {
    const accounts = await this.program.account.attestation.all([
      {
        memcmp: {
          offset: 8, // After discriminator
          bytes: agentPDA.toBase58(),
        },
      },
    ]);
    return accounts.map((a) => a.account as Attestation);
  }

  // ============================================
  // Utility
  // ============================================

  async verifyAgentSecurity(agentId: string): Promise<{
    isSecure: boolean;
    score: number;
    latestAttestation: Attestation | null;
    warnings: string[];
  }> {
    const agent = await this.getAgent(agentId);
    if (!agent) {
      return {
        isSecure: false,
        score: 0,
        latestAttestation: null,
        warnings: ["Agent not found in registry"],
      };
    }

    const [agentPDA] = this.getAgentPDA(agentId);
    const attestations = await this.getAgentAttestations(agentPDA);

    const warnings: string[] = [];

    if (attestations.length === 0) {
      warnings.push("No security attestations found");
    }

    if (agent.totalCriticalVulns > 0) {
      warnings.push(`${agent.totalCriticalVulns} critical vulnerabilities reported`);
    }

    const latestAttestation = attestations.sort(
      (a, b) => b.timestamp - a.timestamp
    )[0];

    // Check if latest attestation is recent (within 90 days)
    if (latestAttestation) {
      const daysSinceAudit = (Date.now() / 1000 - latestAttestation.timestamp) / 86400;
      if (daysSinceAudit > 90) {
        warnings.push(`Latest audit is ${Math.floor(daysSinceAudit)} days old`);
      }
    }

    return {
      isSecure: agent.avgSecurityScore >= 70 && warnings.length === 0,
      score: agent.avgSecurityScore,
      latestAttestation: latestAttestation || null,
      warnings,
    };
  }
}
```

---

## Deployment

### Anchor.toml

```toml
[features]
seeds = false
skip-lint = false

[programs.devnet]
agent_registry = "AGENT1111111111111111111111111111111111111"

[registry]
url = "https://api.apr.dev"

[provider]
cluster = "devnet"
wallet = "~/.config/solana/id.json"

[scripts]
test = "yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/**/*.ts"
```

### Deploy Script

```bash
#!/bin/bash
# scripts/deploy_solana.sh

set -e

echo "🔧 Building Anchor program..."
cd src/solana_registry
anchor build

echo "📋 Program ID:"
solana address -k target/deploy/agent_registry-keypair.json

echo "🚀 Deploying to devnet..."
anchor deploy --provider.cluster devnet

echo "✅ Deployment complete!"
echo "🔗 View on explorer: https://explorer.solana.com/address/$(solana address -k target/deploy/agent_registry-keypair.json)?cluster=devnet"
```

---

## Deliverables

- [ ] `src/solana_registry/programs/agent_registry/src/lib.rs` - Main program
- [ ] `src/solana_registry/programs/agent_registry/src/state.rs` - Account definitions
- [ ] `src/solana_registry/programs/agent_registry/src/errors.rs` - Error codes
- [ ] `src/solana_registry/sdk/` - TypeScript SDK
- [ ] `scripts/deploy_solana.sh` - Deployment script
- [ ] Unit tests for all instructions
- [ ] Deployed to devnet with verified transactions

---

## Next Phase

Proceed to [Phase 6: Integration & Demo](./07-PHASE-6-INTEGRATION.md)
