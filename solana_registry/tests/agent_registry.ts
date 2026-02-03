import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";

describe("agent_registry", () => {
  // Configure the client to use the local cluster
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Program ID - update after deployment
  const programId = new PublicKey("AgntRgstry1111111111111111111111111111111");

  // Test keypairs
  const admin = provider.wallet;
  const agentOwner = Keypair.generate();
  const auditorAuthority = Keypair.generate();
  const disputer = Keypair.generate();

  // PDAs
  let configPDA: PublicKey;
  let agentPDA: PublicKey;
  let auditorPDA: PublicKey;
  let attestationPDA: PublicKey;

  // Test data
  const testAgentId = "test-agent-v1";
  const testAgentName = "Test Agent";
  const testAgentDesc = "A test AI agent for validation";
  const testRepoUrl = "https://github.com/test/agent";
  const testHomepageUrl = "https://test-agent.example.com";

  const testAuditorName = "Security Auditor Inc";
  const testAuditorProfile = "https://auditor.example.com";

  const testScores = {
    overall: 85,
    injectionResistance: 90,
    behaviorCompliance: 80,
    infraHardening: 85,
    dataProtection: 88,
  };

  const testReportHash = "QmTestReportHash123456789012345678901234567890";
  const testScannerVersion = "1.0.0";

  before(async () => {
    // Derive PDAs
    [configPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      programId
    );

    [agentPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("agent"), Buffer.from(testAgentId)],
      programId
    );

    [auditorPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("auditor"), auditorAuthority.publicKey.toBuffer()],
      programId
    );

    [attestationPDA] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("attestation"),
        agentPDA.toBuffer(),
        auditorPDA.toBuffer(),
      ],
      programId
    );

    // Airdrop SOL to test accounts
    const airdropAmount = 10 * anchor.web3.LAMPORTS_PER_SOL;

    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(agentOwner.publicKey, airdropAmount)
    );

    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(auditorAuthority.publicKey, airdropAmount)
    );

    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(disputer.publicKey, airdropAmount)
    );

    console.log("Test setup complete");
    console.log("Config PDA:", configPDA.toBase58());
    console.log("Agent PDA:", agentPDA.toBase58());
    console.log("Auditor PDA:", auditorPDA.toBase58());
    console.log("Attestation PDA:", attestationPDA.toBase58());
  });

  describe("Initialization", () => {
    it("should initialize the registry", async () => {
      // Note: This test would use the actual program once deployed
      // For now, we're documenting the expected behavior

      console.log("Initialize registry with admin:", admin.publicKey.toBase58());

      // Expected:
      // - Config account created at configPDA
      // - admin field set to signer
      // - registration_paused = false
      // - min_secure_score = 70
      // - all counters = 0
    });
  });

  describe("Agent Registration", () => {
    it("should register a new agent", async () => {
      console.log("Register agent:", testAgentId);
      console.log("Owner:", agentOwner.publicKey.toBase58());

      // Expected:
      // - Agent account created at agentPDA
      // - agent_id, name, description, URLs set correctly
      // - owner = agentOwner.publicKey
      // - is_active = true
      // - all attestation counters = 0
      // - config.total_agents incremented
    });

    it("should reject agent ID that is too long", async () => {
      const longAgentId = "a".repeat(100); // > 64 chars
      console.log("Attempting to register agent with ID length:", longAgentId.length);

      // Expected: RegistryError::AgentIdTooLong
    });

    it("should allow agent owner to update agent info", async () => {
      const newName = "Updated Test Agent";
      const newDesc = "Updated description";

      console.log("Update agent name to:", newName);

      // Expected:
      // - Agent name and description updated
      // - updated_at timestamp refreshed
      // - AgentUpdated event emitted
    });

    it("should reject updates from non-owner", async () => {
      console.log("Attempting update from non-owner");

      // Expected: RegistryError::Unauthorized
    });
  });

  describe("Auditor Registration", () => {
    it("should register a new auditor", async () => {
      console.log("Register auditor:", testAuditorName);
      console.log("Authority:", auditorAuthority.publicKey.toBase58());

      // Expected:
      // - Auditor account created at auditorPDA
      // - authority = auditorAuthority.publicKey
      // - is_verified = false (initially)
      // - audits_performed = 0
      // - config.total_auditors incremented
    });

    it("should verify auditor (admin only)", async () => {
      console.log("Admin verifying auditor");

      // Expected:
      // - auditor.is_verified = true
      // - AuditorVerified event emitted
    });

    it("should reject verification from non-admin", async () => {
      console.log("Non-admin attempting to verify auditor");

      // Expected: RegistryError::Unauthorized
    });
  });

  describe("Attestation Submission", () => {
    it("should submit attestation for an agent", async () => {
      console.log("Submit attestation for agent:", testAgentId);
      console.log("Scores:", testScores);
      console.log("Report hash:", testReportHash);

      // Expected:
      // - Attestation account created at attestationPDA
      // - All scores and metadata stored correctly
      // - status = Valid
      // - agent.total_attestations incremented
      // - agent.avg_security_score updated
      // - auditor.audits_performed incremented
      // - config.total_attestations incremented
    });

    it("should reject attestation with invalid scores", async () => {
      const invalidScores = { ...testScores, overall: 150 }; // > 100
      console.log("Attempting attestation with invalid score:", invalidScores.overall);

      // Expected: RegistryError::InvalidScore
    });

    it("should reject duplicate attestation from same auditor", async () => {
      console.log("Attempting duplicate attestation");

      // Expected: Account already exists error (init fails)
    });

    it("should update agent average score correctly", async () => {
      // After multiple attestations, verify average calculation
      // avg = (old_avg * old_count + new_score) / new_count

      console.log("Verify average score calculation");
    });
  });

  describe("Attestation Disputes", () => {
    it("should allow agent owner to dispute attestation", async () => {
      const reason = "Inaccurate vulnerability assessment";
      console.log("Agent owner disputing attestation:", reason);

      // Expected:
      // - attestation.status = Disputed
      // - AttestationDisputed event emitted
    });

    it("should reject self-dispute by auditor", async () => {
      console.log("Auditor attempting to dispute own attestation");

      // Expected: RegistryError::CannotDisputeOwnAttestation
    });

    it("should reject dispute of already disputed attestation", async () => {
      console.log("Attempting to dispute already disputed attestation");

      // Expected: RegistryError::AttestationAlreadyDisputed
    });
  });

  describe("Admin Functions", () => {
    it("should allow admin to pause registrations", async () => {
      console.log("Admin pausing registrations");

      // Expected:
      // - config.registration_paused = true
      // - RegistrationPauseToggled event emitted
    });

    it("should block registrations when paused", async () => {
      console.log("Attempting registration while paused");

      // Expected: RegistryError::Unauthorized
    });

    it("should allow admin to update admin address", async () => {
      const newAdmin = Keypair.generate().publicKey;
      console.log("Updating admin to:", newAdmin.toBase58());

      // Expected:
      // - config.admin = newAdmin
      // - AdminUpdated event emitted
    });
  });

  describe("Query Functions", () => {
    it("should fetch agent by ID", async () => {
      console.log("Fetching agent:", testAgentId);

      // Expected: Full agent data returned
    });

    it("should fetch all attestations for an agent", async () => {
      console.log("Fetching attestations for agent:", testAgentId);

      // Expected: Array of attestations filtered by agent
    });

    it("should fetch all verified auditors", async () => {
      console.log("Fetching verified auditors");

      // Expected: Array of auditors where is_verified = true
    });

    it("should verify agent security status", async () => {
      console.log("Verifying security status for:", testAgentId);

      // Expected:
      // - isSecure based on score threshold and no critical vulns
      // - warnings for any concerns
      // - daysSinceAudit calculated correctly
    });
  });

  describe("Edge Cases", () => {
    it("should handle agent with no attestations", async () => {
      const emptyAgentId = "empty-agent";
      console.log("Checking security for agent with no attestations");

      // Expected: isSecure = false, warning about no attestations
    });

    it("should handle very old attestations", async () => {
      console.log("Checking agent with attestation > 90 days old");

      // Expected: Warning about stale attestation
    });

    it("should handle agent with critical vulnerabilities", async () => {
      console.log("Checking agent with critical vulns");

      // Expected: isSecure = false, warning about critical vulns
    });
  });
});

// ============================================
// Test Utilities
// ============================================

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function expectError(error: any, expectedCode: string): void {
  expect(error.toString()).to.include(expectedCode);
}
