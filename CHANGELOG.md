# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure and documentation
- Development plan for Colosseum Agent Hackathon
- MIT License
- Contributing guidelines
- Open source strategy

### Phase 1: Rust Core & Input Shield ✅
- `agentsentinel-core` crate with shared types:
  - `ThreatLevel` enum (None, Low, Medium, High, Critical)
  - `ThreatCategory` enum (7 categories)
  - `Threat` struct with builder pattern
  - `ThreatAssessment` struct
  - `ShieldConfig` configuration
  - Comprehensive error types
- `agentsentinel-input-shield` crate:
  - Aho-Corasick pattern matcher (O(n) complexity)
  - 90+ injection patterns across all threat categories
  - Canary token system for prompt leak detection
  - `InputShield` main API
  - Global `analyze()` and `should_block()` functions
- 32 unit tests, all passing
- Doc tests for public APIs

---

## [0.1.0] - 2026-02-XX (Target: Hackathon Submission)

### Added

#### Core (Rust)
- `agentsentinel-core`: Shared types and error definitions
- `agentsentinel-input-shield`: High-performance prompt injection detection
  - Aho-Corasick pattern matching (O(n) complexity)
  - 50+ injection patterns across 7 threat categories
  - Canary token system for prompt leak detection
  - Sub-100μs analysis time
- `agentsentinel-red-team`: Automated security testing suite
  - 50+ injection payloads
  - Automated scanner with progress tracking
  - Security scoring engine
  - Markdown and JSON report generation

#### Python SDK
- PyO3-based bindings to Rust core
- `InputShield` class with full API
- `@protect` decorator for easy integration
- `Shield` class for high-level usage
- Async support

#### Node.js SDK  
- NAPI-RS bindings to Rust core
- TypeScript type definitions
- Express.js middleware
- `@protect` decorator for TypeScript

#### Behavior Monitor (Python)
- Action logging system
- Behavioral baseline learning
- Statistical anomaly detection
- Pre-sign transaction verification
- Circuit breaker for compromised sessions

#### Infrastructure Monitor (Python)
- Wazuh integration with custom rules
- OSquery integration with agent-specific queries
- Unified alert aggregation
- Real-time infrastructure scanning

#### Solana Registry (Anchor)
- Agent registration program
- Auditor registration and verification
- Security attestation submission
- On-chain trust verification
- TypeScript SDK for registry interaction

#### API Server
- FastAPI-based unified API
- `/api/v1/analyze` - Input analysis
- `/api/v1/protect` - Unified protection
- `/api/v1/behavior/*` - Behavior monitoring
- `/api/v1/redteam/*` - Security scanning
- `/api/v1/registry/*` - Solana registry

#### Documentation
- Comprehensive development plan (9 phases)
- Architecture documentation
- API reference
- SDK usage guides
- Demo scenarios and video script

### Security
- Initial payload library with 50+ injection patterns
- Coverage for all major attack categories:
  - Instruction Override
  - Prompt Extraction
  - Role Manipulation
  - Context Injection
  - Encoding Bypass
  - Jailbreak
  - Data Exfiltration

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | TBD | Initial release for Colosseum Hackathon |

---

## Contributors

Thanks to everyone who contributed to this release:

- Initial development team

### Payload Contributors

*Your name here! Submit new injection patterns to be credited.*

---

## Links

- [GitHub Repository](https://github.com/agentsentinel/agentsentinel)
- [Documentation](https://docs.agentsentinel.dev)
- [PyPI Package](https://pypi.org/project/agentsentinel/)
- [npm Package](https://www.npmjs.com/package/@agentsentinel/sdk)

[Unreleased]: https://github.com/agentsentinel/agentsentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentsentinel/agentsentinel/releases/tag/v0.1.0
