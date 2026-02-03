# AgentSentinel Solana Registry

On-chain security attestation registry for AI agents on Solana.

## Overview

The AgentSentinel Registry creates an immutable, transparent record of AI agent security audits on the Solana blockchain. This enables:

- **Agents** to publish their security scores after passing audits
- **Users** to verify an agent's security before granting access
- **Auditors** to build reputation as trusted security reviewers
- **Ecosystem** to create accountability for agent security

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AgentSentinel Registry Program                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ Agent Account   │  │ Attestation     │  │ Auditor Account     │  │
│  │                 │  │ Account         │  │                     │  │
│  │ • agent_id      │  │                 │  │ • authority         │  │
│  │ • owner         │  │ • agent         │  │ • name              │  │
│  │ • name          │  │ • auditor       │  │ • audits_performed  │  │
│  │ • description   │  │ • timestamp     │  │ • avg_score_given   │  │
│  │ • repo_url      │  │ • scores        │  │ • is_verified       │  │
│  │ • created_at    │  │ • report_hash   │  │ • created_at        │  │
│  │ • avg_score     │  │ • vulns         │  │                     │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘  │
│           │                    │                      │              │
│           └────────────────────┴──────────────────────┘              │
│                           PDA Seeds                                  │
│     [b"agent", agent_id]    [b"attestation",     [b"auditor",       │
│                              agent, auditor]      authority]         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) (v1.18+)
- [Anchor](https://www.anchor-lang.com/docs/installation) (v0.30+)
- Node.js 18+ and Yarn

## Installation

```bash
# Install dependencies
yarn install

# Build the program
anchor build

# Run tests
anchor test
```

## Deployment

### Devnet

```bash
# Configure for devnet
solana config set --url devnet

# Airdrop SOL for deployment
solana airdrop 2

# Deploy
./scripts/deploy_solana.sh devnet
```

### Mainnet

```bash
./scripts/deploy_solana.sh mainnet-beta
```

## Program Instructions

### Initialize Registry

One-time initialization by the deployer:

```typescript
await program.methods.initialize().accounts({
  config: configPDA,
  admin: wallet.publicKey,
  systemProgram: SystemProgram.programId,
}).rpc();
```

### Register Agent

```typescript
await program.methods
  .registerAgent(
    "my-agent-v1",           // agent_id
    "My AI Agent",           // name
    "A helpful assistant",   // description
    "https://github.com/...", // repo_url
    "https://myagent.com"    // homepage_url
  )
  .accounts({
    agent: agentPDA,
    config: configPDA,
    owner: wallet.publicKey,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
```

### Register Auditor

```typescript
await program.methods
  .registerAuditor(
    "Security Auditor Inc",      // name
    "https://auditor.example.com" // profile_url
  )
  .accounts({
    auditor: auditorPDA,
    config: configPDA,
    authority: wallet.publicKey,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
```

### Submit Attestation

```typescript
await program.methods
  .submitAttestation(
    {
      overall: 85,
      injectionResistance: 90,
      behaviorCompliance: 80,
      infraHardening: 85,
      dataProtection: 88,
    },
    "QmReportHash...",    // IPFS hash
    0,                    // vulns_critical
    1,                    // vulns_high
    3,                    // vulns_medium
    5,                    // vulns_low
    1000,                 // payloads_tested
    "1.0.0",              // scanner_version
    "Audit notes..."      // notes
  )
  .accounts({
    attestation: attestationPDA,
    agent: agentPDA,
    auditor: auditorPDA,
    config: configPDA,
    authority: wallet.publicKey,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
```

### Verify Auditor (Admin Only)

```typescript
await program.methods
  .verifyAuditor()
  .accounts({
    auditor: auditorPDA,
    config: configPDA,
    admin: adminWallet.publicKey,
  })
  .rpc();
```

### Dispute Attestation

```typescript
await program.methods
  .disputeAttestation("Inaccurate vulnerability count")
  .accounts({
    attestation: attestationPDA,
    disputer: wallet.publicKey,
  })
  .rpc();
```

## TypeScript SDK

The SDK provides a high-level interface for interacting with the registry:

```typescript
import { AgentRegistryClient } from '@agentsentinel/solana-registry-sdk';

const client = new AgentRegistryClient(connection, wallet, programId);

// Register an agent
await client.registerAgent(
  'my-agent-v1',
  'My Agent',
  'Description',
  'https://github.com/...',
  'https://...'
);

// Check security status
const status = await client.verifyAgentSecurity('my-agent-v1');
console.log(`Score: ${status.score}`);
console.log(`Secure: ${status.isSecure}`);
console.log(`Warnings: ${status.warnings}`);
```

## Account Sizes

| Account | Size (bytes) |
|---------|-------------|
| RegistryConfig | 99 |
| Agent | ~1,300 |
| Auditor | ~440 |
| Attestation | ~500 |

## Events

The program emits events for all state changes:

- `RegistryInitialized` - Registry setup complete
- `AgentRegistered` - New agent added
- `AgentUpdated` - Agent info modified
- `AuditorRegistered` - New auditor added
- `AuditorVerified` - Auditor verified by admin
- `AttestationSubmitted` - New security attestation
- `AttestationDisputed` - Attestation challenged
- `AdminUpdated` - Admin changed
- `RegistrationPauseToggled` - Registration paused/unpaused

## Security Considerations

1. **Auditor Verification**: Only verified auditors should be fully trusted
2. **Attestation Freshness**: Attestations older than 90 days are considered stale
3. **Critical Vulnerabilities**: Any critical vulns should be a red flag
4. **Admin Key Security**: Admin key controls auditor verification

## License

MIT
