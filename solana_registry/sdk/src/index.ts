/**
 * AgentSentinel Solana Registry SDK
 *
 * TypeScript client for interacting with the on-chain security registry.
 *
 * @example
 * ```typescript
 * import { AgentRegistryClient, SecurityScores } from '@agentsentinel/solana-registry-sdk';
 *
 * const client = new AgentRegistryClient(connection, wallet, programId);
 *
 * // Register an agent
 * await client.registerAgent('my-agent-v1', 'My Agent', 'A helpful AI assistant', 'https://github.com/...', 'https://...');
 *
 * // Check security status
 * const status = await client.verifyAgentSecurity('my-agent-v1');
 * console.log(`Score: ${status.score}, Secure: ${status.isSecure}`);
 * ```
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, BN, web3, Idl } from "@coral-xyz/anchor";
import { PublicKey, Connection, Commitment, TransactionSignature } from "@solana/web3.js";

// ============================================
// Types
// ============================================

/**
 * Security scores breakdown across different categories
 */
export interface SecurityScores {
  /** Overall security score (0-100) */
  overall: number;
  /** Resistance to prompt injection attacks (0-100) */
  injectionResistance: number;
  /** Compliance with expected behavior (0-100) */
  behaviorCompliance: number;
  /** Infrastructure hardening score (0-100) */
  infraHardening: number;
  /** Data protection and privacy score (0-100) */
  dataProtection: number;
}

/**
 * Status of an attestation
 */
export type AttestationStatus = "valid" | "superseded" | "disputed" | "expired";

/**
 * Registered agent account data
 */
export interface Agent {
  /** PDA address of this account */
  address: PublicKey;
  /** Unique identifier */
  agentId: string;
  /** Owner wallet */
  owner: PublicKey;
  /** Display name */
  name: string;
  /** Description of the agent */
  description: string;
  /** GitHub repository URL */
  repoUrl: string;
  /** Homepage URL */
  homepageUrl: string;
  /** Unix timestamp of registration */
  createdAt: number;
  /** Unix timestamp of last update */
  updatedAt: number;
  /** Total attestations received */
  totalAttestations: number;
  /** Average security score */
  avgSecurityScore: number;
  /** Total critical vulnerabilities reported */
  totalCriticalVulns: number;
  /** Whether the agent is active */
  isActive: boolean;
}

/**
 * Security attestation account data
 */
export interface Attestation {
  /** PDA address of this account */
  address: PublicKey;
  /** Agent being attested */
  agent: PublicKey;
  /** Auditor who created this */
  auditor: PublicKey;
  /** Auditor's signing authority */
  auditorAuthority: PublicKey;
  /** Unix timestamp of attestation */
  timestamp: number;
  /** Security scores */
  scores: SecurityScores;
  /** IPFS hash of full report */
  reportHash: string;
  /** Vulnerability counts */
  vulnsCritical: number;
  vulnsHigh: number;
  vulnsMedium: number;
  vulnsLow: number;
  /** Number of payloads tested */
  payloadsTested: number;
  /** Scanner version used */
  scannerVersion: string;
  /** Current status */
  status: AttestationStatus;
  /** Auditor notes */
  notes: string;
}

/**
 * Registered auditor account data
 */
export interface Auditor {
  /** PDA address of this account */
  address: PublicKey;
  /** Signing authority */
  authority: PublicKey;
  /** Display name */
  name: string;
  /** Total audits performed */
  auditsPerformed: number;
  /** Average score given */
  avgScoreGiven: number;
  /** Whether verified by admin */
  isVerified: boolean;
  /** Unix timestamp of registration */
  createdAt: number;
  /** Profile URL */
  profileUrl: string;
}

/**
 * Registry configuration account data
 */
export interface RegistryConfig {
  /** Admin wallet */
  admin: PublicKey;
  /** Backup admin wallet */
  adminBackup: PublicKey;
  /** Whether registrations are paused */
  registrationPaused: boolean;
  /** Minimum score for "secure" badge */
  minSecureScore: number;
  /** Total agents registered */
  totalAgents: number;
  /** Total auditors registered */
  totalAuditors: number;
  /** Total attestations submitted */
  totalAttestations: number;
}

/**
 * Security verification result
 */
export interface SecurityVerification {
  /** Whether the agent meets security requirements */
  isSecure: boolean;
  /** Overall security score */
  score: number;
  /** Latest attestation if any */
  latestAttestation: Attestation | null;
  /** Any warnings or concerns */
  warnings: string[];
  /** Days since last audit */
  daysSinceAudit: number | null;
  /** Number of verified auditor attestations */
  verifiedAttestations: number;
}

/**
 * Vulnerability summary
 */
export interface VulnerabilitySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

// ============================================
// Client
// ============================================

/**
 * Client for interacting with the AgentSentinel on-chain registry
 */
export class AgentRegistryClient {
  private provider: AnchorProvider;
  private programId: PublicKey;

  // IDL would be loaded from the deployed program
  // For now we use a placeholder - in production this comes from anchor build
  private program: Program | null = null;

  /**
   * Create a new registry client
   *
   * @param connection - Solana RPC connection
   * @param wallet - Wallet for signing transactions
   * @param programId - Program ID of the deployed registry
   */
  constructor(
    connection: Connection,
    wallet: anchor.Wallet,
    programId: PublicKey
  ) {
    this.provider = new AnchorProvider(
      connection,
      wallet,
      { commitment: "confirmed" as Commitment }
    );
    this.programId = programId;
  }

  /**
   * Initialize with the program IDL
   * Call this after fetching the IDL from the deployed program
   */
  async initializeWithIdl(idl: Idl): Promise<void> {
    this.program = new Program(idl, this.provider);
  }

  // ============================================
  // PDA Derivation
  // ============================================

  /**
   * Derive the config PDA
   */
  getConfigPDA(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      this.programId
    );
  }

  /**
   * Derive an agent PDA from its ID
   */
  getAgentPDA(agentId: string): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("agent"), Buffer.from(agentId)],
      this.programId
    );
  }

  /**
   * Derive an auditor PDA from authority pubkey
   */
  getAuditorPDA(authority: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("auditor"), authority.toBuffer()],
      this.programId
    );
  }

  /**
   * Derive an attestation PDA from agent and auditor PDAs
   */
  getAttestationPDA(agent: PublicKey, auditor: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("attestation"), agent.toBuffer(), auditor.toBuffer()],
      this.programId
    );
  }

  // ============================================
  // Instructions
  // ============================================

  /**
   * Initialize the registry (admin only, once)
   */
  async initialize(): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [configPDA] = this.getConfigPDA();

    return await this.program.methods
      .initialize()
      .accounts({
        config: configPDA,
        admin: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
  }

  /**
   * Register a new agent
   */
  async registerAgent(
    agentId: string,
    name: string,
    description: string,
    repoUrl: string,
    homepageUrl: string
  ): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [agentPDA] = this.getAgentPDA(agentId);
    const [configPDA] = this.getConfigPDA();

    return await this.program.methods
      .registerAgent(agentId, name, description, repoUrl, homepageUrl)
      .accounts({
        agent: agentPDA,
        config: configPDA,
        owner: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
  }

  /**
   * Update an existing agent
   */
  async updateAgent(
    agentId: string,
    updates: {
      name?: string;
      description?: string;
      repoUrl?: string;
      homepageUrl?: string;
      isActive?: boolean;
    }
  ): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [agentPDA] = this.getAgentPDA(agentId);

    return await this.program.methods
      .updateAgent(
        updates.name ?? null,
        updates.description ?? null,
        updates.repoUrl ?? null,
        updates.homepageUrl ?? null,
        updates.isActive ?? null
      )
      .accounts({
        agent: agentPDA,
        owner: this.provider.wallet.publicKey,
      })
      .rpc();
  }

  /**
   * Register as an auditor
   */
  async registerAuditor(
    name: string,
    profileUrl: string
  ): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [auditorPDA] = this.getAuditorPDA(this.provider.wallet.publicKey);
    const [configPDA] = this.getConfigPDA();

    return await this.program.methods
      .registerAuditor(name, profileUrl)
      .accounts({
        auditor: auditorPDA,
        config: configPDA,
        authority: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
  }

  /**
   * Submit a security attestation
   */
  async submitAttestation(
    agentId: string,
    scores: SecurityScores,
    reportHash: string,
    vulns: VulnerabilitySummary,
    payloadsTested: number,
    scannerVersion: string,
    notes: string = ""
  ): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [agentPDA] = this.getAgentPDA(agentId);
    const [auditorPDA] = this.getAuditorPDA(this.provider.wallet.publicKey);
    const [attestationPDA] = this.getAttestationPDA(agentPDA, auditorPDA);
    const [configPDA] = this.getConfigPDA();

    // Convert scores to on-chain format
    const scoresOnChain = {
      overall: scores.overall,
      injectionResistance: scores.injectionResistance,
      behaviorCompliance: scores.behaviorCompliance,
      infraHardening: scores.infraHardening,
      dataProtection: scores.dataProtection,
    };

    return await this.program.methods
      .submitAttestation(
        scoresOnChain,
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
        config: configPDA,
        authority: this.provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
  }

  /**
   * Dispute an attestation
   */
  async disputeAttestation(
    agentId: string,
    auditorAuthority: PublicKey,
    reason: string
  ): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [agentPDA] = this.getAgentPDA(agentId);
    const [auditorPDA] = this.getAuditorPDA(auditorAuthority);
    const [attestationPDA] = this.getAttestationPDA(agentPDA, auditorPDA);

    return await this.program.methods
      .disputeAttestation(reason)
      .accounts({
        attestation: attestationPDA,
        disputer: this.provider.wallet.publicKey,
      })
      .rpc();
  }

  /**
   * Verify an auditor (admin only)
   */
  async verifyAuditor(auditorAuthority: PublicKey): Promise<TransactionSignature> {
    if (!this.program) throw new Error("Program not initialized");

    const [auditorPDA] = this.getAuditorPDA(auditorAuthority);
    const [configPDA] = this.getConfigPDA();

    return await this.program.methods
      .verifyAuditor()
      .accounts({
        auditor: auditorPDA,
        config: configPDA,
        admin: this.provider.wallet.publicKey,
      })
      .rpc();
  }

  // ============================================
  // Queries
  // ============================================

  /**
   * Get registry configuration
   */
  async getConfig(): Promise<RegistryConfig | null> {
    if (!this.program) throw new Error("Program not initialized");

    const [pda] = this.getConfigPDA();
    try {
      const account = await this.program.account.registryConfig.fetch(pda);
      return {
        admin: account.admin,
        adminBackup: account.adminBackup,
        registrationPaused: account.registrationPaused,
        minSecureScore: account.minSecureScore,
        totalAgents: (account.totalAgents as BN).toNumber(),
        totalAuditors: (account.totalAuditors as BN).toNumber(),
        totalAttestations: (account.totalAttestations as BN).toNumber(),
      };
    } catch {
      return null;
    }
  }

  /**
   * Get an agent by ID
   */
  async getAgent(agentId: string): Promise<Agent | null> {
    if (!this.program) throw new Error("Program not initialized");

    const [pda] = this.getAgentPDA(agentId);
    try {
      const account = await this.program.account.agent.fetch(pda);
      return {
        address: pda,
        agentId: account.agentId,
        owner: account.owner,
        name: account.name,
        description: account.description,
        repoUrl: account.repoUrl,
        homepageUrl: account.homepageUrl,
        createdAt: (account.createdAt as BN).toNumber(),
        updatedAt: (account.updatedAt as BN).toNumber(),
        totalAttestations: account.totalAttestations,
        avgSecurityScore: account.avgSecurityScore,
        totalCriticalVulns: account.totalCriticalVulns,
        isActive: account.isActive,
      };
    } catch {
      return null;
    }
  }

  /**
   * Get an auditor by authority
   */
  async getAuditor(authority: PublicKey): Promise<Auditor | null> {
    if (!this.program) throw new Error("Program not initialized");

    const [pda] = this.getAuditorPDA(authority);
    try {
      const account = await this.program.account.auditor.fetch(pda);
      return {
        address: pda,
        authority: account.authority,
        name: account.name,
        auditsPerformed: account.auditsPerformed,
        avgScoreGiven: account.avgScoreGiven,
        isVerified: account.isVerified,
        createdAt: (account.createdAt as BN).toNumber(),
        profileUrl: account.profileUrl,
      };
    } catch {
      return null;
    }
  }

  /**
   * Get an attestation
   */
  async getAttestation(
    agentId: string,
    auditorAuthority: PublicKey
  ): Promise<Attestation | null> {
    if (!this.program) throw new Error("Program not initialized");

    const [agentPDA] = this.getAgentPDA(agentId);
    const [auditorPDA] = this.getAuditorPDA(auditorAuthority);
    const [pda] = this.getAttestationPDA(agentPDA, auditorPDA);

    try {
      const account = await this.program.account.attestation.fetch(pda);
      return this.parseAttestation(pda, account);
    } catch {
      return null;
    }
  }

  /**
   * Get all agents
   */
  async getAllAgents(): Promise<Agent[]> {
    if (!this.program) throw new Error("Program not initialized");

    const accounts = await this.program.account.agent.all();
    return accounts.map((a) => ({
      address: a.publicKey,
      agentId: a.account.agentId,
      owner: a.account.owner,
      name: a.account.name,
      description: a.account.description,
      repoUrl: a.account.repoUrl,
      homepageUrl: a.account.homepageUrl,
      createdAt: (a.account.createdAt as BN).toNumber(),
      updatedAt: (a.account.updatedAt as BN).toNumber(),
      totalAttestations: a.account.totalAttestations,
      avgSecurityScore: a.account.avgSecurityScore,
      totalCriticalVulns: a.account.totalCriticalVulns,
      isActive: a.account.isActive,
    }));
  }

  /**
   * Get all attestations for an agent
   */
  async getAgentAttestations(agentId: string): Promise<Attestation[]> {
    if (!this.program) throw new Error("Program not initialized");

    const [agentPDA] = this.getAgentPDA(agentId);

    // Filter by agent field (offset 8 is after discriminator)
    const accounts = await this.program.account.attestation.all([
      {
        memcmp: {
          offset: 8,
          bytes: agentPDA.toBase58(),
        },
      },
    ]);

    return accounts.map((a) => this.parseAttestation(a.publicKey, a.account));
  }

  /**
   * Get all verified auditors
   */
  async getVerifiedAuditors(): Promise<Auditor[]> {
    if (!this.program) throw new Error("Program not initialized");

    const accounts = await this.program.account.auditor.all();
    return accounts
      .filter((a) => a.account.isVerified)
      .map((a) => ({
        address: a.publicKey,
        authority: a.account.authority,
        name: a.account.name,
        auditsPerformed: a.account.auditsPerformed,
        avgScoreGiven: a.account.avgScoreGiven,
        isVerified: a.account.isVerified,
        createdAt: (a.account.createdAt as BN).toNumber(),
        profileUrl: a.account.profileUrl,
      }));
  }

  // ============================================
  // High-Level Verification
  // ============================================

  /**
   * Verify an agent's security status
   *
   * Returns a comprehensive security assessment including:
   * - Whether the agent is considered secure
   * - Latest attestation details
   * - Any warnings or concerns
   */
  async verifyAgentSecurity(agentId: string): Promise<SecurityVerification> {
    const agent = await this.getAgent(agentId);

    if (!agent) {
      return {
        isSecure: false,
        score: 0,
        latestAttestation: null,
        warnings: ["Agent not found in registry"],
        daysSinceAudit: null,
        verifiedAttestations: 0,
      };
    }

    const attestations = await this.getAgentAttestations(agentId);
    const config = await this.getConfig();
    const minSecureScore = config?.minSecureScore ?? 70;

    const warnings: string[] = [];

    // Check for no attestations
    if (attestations.length === 0) {
      warnings.push("No security attestations found");
    }

    // Check for critical vulnerabilities
    if (agent.totalCriticalVulns > 0) {
      warnings.push(
        `${agent.totalCriticalVulns} critical vulnerabilities reported across all audits`
      );
    }

    // Check if agent is inactive
    if (!agent.isActive) {
      warnings.push("Agent is marked as inactive");
    }

    // Get latest valid attestation
    const validAttestations = attestations.filter((a) => a.status === "valid");
    const latestAttestation = validAttestations.sort(
      (a, b) => b.timestamp - a.timestamp
    )[0] ?? null;

    // Count verified auditor attestations
    const verifiedAttestations = validAttestations.length; // Would need to cross-reference with auditors

    // Check attestation age
    let daysSinceAudit: number | null = null;
    if (latestAttestation) {
      daysSinceAudit = Math.floor(
        (Date.now() / 1000 - latestAttestation.timestamp) / 86400
      );
      if (daysSinceAudit > 90) {
        warnings.push(`Latest audit is ${daysSinceAudit} days old (>90 days)`);
      }
    }

    // Check latest attestation for recent critical vulns
    if (latestAttestation && latestAttestation.vulnsCritical > 0) {
      warnings.push(
        `Latest audit found ${latestAttestation.vulnsCritical} critical vulnerabilities`
      );
    }

    // Determine if secure
    const isSecure =
      agent.avgSecurityScore >= minSecureScore &&
      agent.isActive &&
      attestations.length > 0 &&
      (latestAttestation?.vulnsCritical ?? 0) === 0 &&
      (daysSinceAudit === null || daysSinceAudit <= 90);

    return {
      isSecure,
      score: agent.avgSecurityScore,
      latestAttestation,
      warnings,
      daysSinceAudit,
      verifiedAttestations,
    };
  }

  // ============================================
  // Helpers
  // ============================================

  private parseAttestation(address: PublicKey, account: any): Attestation {
    // Map on-chain status enum to string
    let status: AttestationStatus = "valid";
    if (account.status.superseded) status = "superseded";
    else if (account.status.disputed) status = "disputed";
    else if (account.status.expired) status = "expired";

    return {
      address,
      agent: account.agent,
      auditor: account.auditor,
      auditorAuthority: account.auditorAuthority,
      timestamp: (account.timestamp as BN).toNumber(),
      scores: {
        overall: account.scores.overall,
        injectionResistance: account.scores.injectionResistance,
        behaviorCompliance: account.scores.behaviorCompliance,
        infraHardening: account.scores.infraHardening,
        dataProtection: account.scores.dataProtection,
      },
      reportHash: account.reportHash,
      vulnsCritical: account.vulnsCritical,
      vulnsHigh: account.vulnsHigh,
      vulnsMedium: account.vulnsMedium,
      vulnsLow: account.vulnsLow,
      payloadsTested: account.payloadsTested,
      scannerVersion: account.scannerVersion,
      status,
      notes: account.notes,
    };
  }
}

// ============================================
// Exports
// ============================================

export default AgentRegistryClient;
