# 🛡️ AgentSentinel

> **Comprehensive Security Framework for AI Agents in Crypto**

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Solana](https://img.shields.io/badge/Solana-9945FF?style=flat&logo=solana&logoColor=white)](https://solana.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

AI agents are gaining access to wallets and executing real transactions. A single prompt injection could drain everything.

**Who protects the protectors?**

## The Solution

AgentSentinel provides comprehensive, multi-layered security for AI agents:

```
User Input → [Input Shield] → [Behavior Monitor] → [Agent Action]
                   ↓                    ↓
            [Infra Monitor] ←──── [Alert Engine] ────→ [Solana Registry]
                   ↓
            [Wazuh + OSquery]
```

---

## 🚀 Quick Start

### Python

```bash
pip install agentsentinel
```

```python
import agentsentinel

# Quick check
result = agentsentinel.analyze("Ignore all previous instructions")
print(result.should_block)  # True
print(result.risk_score)    # 100.0

# Protect your agent with a decorator
@agentsentinel.protect
def my_agent_handler(user_input: str) -> str:
    return llm.generate(user_input)
```

### Node.js

```bash
npm install @agentsentinel/sdk
```

```typescript
import { InputShield, expressMiddleware } from '@agentsentinel/sdk';

// Express middleware (one line protection)
app.use(expressMiddleware({ blockThreshold: 'high' }));

// Or manual checking
const shield = new InputShield();
const result = shield.analyze(userInput);

if (result.shouldBlock) {
  throw new Error(`Threat detected: ${result.overallLevel}`);
}
```

---

## 🏗️ Architecture

### 1. Input Shield (Rust Core)
High-performance prompt injection detection using Aho-Corasick algorithm.

- **O(n) pattern matching** - Scans against 50+ patterns in single pass
- **<100μs response time** - Sub-millisecond protection
- **Canary tokens** - Detect system prompt leakage
- **Semantic analysis** - LLM-as-judge for sophisticated attacks

### 2. Behavior Monitor (Python)
Learns normal agent behavior and detects anomalies.

- **Baseline profiling** - Automatically learns expected patterns
- **Statistical anomaly detection** - Flags unusual actions
- **Pre-sign verification** - Extra scrutiny for high-risk transactions
- **Circuit breakers** - Automatic halt on suspicious patterns

### 3. Infrastructure Monitor
Enterprise-grade visibility using Wazuh and OSquery.

- **File integrity monitoring** - Detect config tampering
- **Process monitoring** - Track agent execution
- **Network analysis** - Identify suspicious connections
- **Custom alerting rules** - Agent-specific security events

### 4. Red Team Suite (Rust)
Automated security auditing with 50+ injection payloads.

- **Comprehensive payload library** - All major attack categories
- **Automated scanning** - Test agents systematically
- **Security scoring** - Quantified security posture
- **Detailed reporting** - Markdown and JSON reports

### 5. Solana Registry
On-chain security attestations for verifiable trust.

- **Agent registration** - Immutable identity records
- **Security attestations** - Publish audit results
- **Trust verification** - Check agent security before granting access
- **Auditor reputation** - Track auditor credibility

---

## 📊 Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Pattern matching | <50μs | 50+ patterns, O(n) |
| Full analysis | <100μs | Including all checks |
| Behavioral check | <1ms | With baseline lookup |
| Red team payload | ~500ms | Network round-trip |

Benchmarked on Apple M1. Rust core ensures consistent performance.

---

## 🔧 Components

```
agentsentinel/
├── crates/
│   ├── core/           # Shared types (Rust)
│   ├── input-shield/   # Prompt injection detection (Rust)
│   ├── red-team/       # Security testing suite (Rust)
│   ├── python/         # Python bindings (PyO3)
│   ├── nodejs/         # Node.js bindings (NAPI-RS)
│   └── wasm/           # Browser support (wasm-bindgen)
├── src/
│   ├── behavior_monitor/   # Anomaly detection (Python)
│   ├── infra_monitor/      # Wazuh/OSquery (Python)
│   └── api/                # FastAPI server
├── programs/
│   └── agent_registry/     # Solana program (Anchor)
├── configs/
│   ├── wazuh/              # Wazuh rules & decoders
│   └── osquery/            # OSquery queries
└── docs/
    └── planning/           # Development phases
```

---

## 🛡️ Threat Categories

| Category | Description | Severity |
|----------|-------------|----------|
| Instruction Override | Attempts to replace system instructions | Critical |
| Prompt Extraction | Tries to leak system prompt | High |
| Role Manipulation | Changes agent's behavior/persona | High |
| Context Injection | Injects false context/authority | Critical |
| Encoding Bypass | Uses encoding to evade detection | Medium |
| Data Exfiltration | Extracts keys, credentials, funds | Critical |

---

## 📖 Documentation

- [Development Plan](./docs/planning/00-OVERVIEW.md)
- [Input Shield](./docs/planning/02-PHASE-1-INPUT-SHIELD.md)
- [Behavior Monitor](./docs/planning/03-PHASE-2-BEHAVIOR-MONITOR.md)
- [Infrastructure Monitor](./docs/planning/04-PHASE-3-INFRA-MONITOR.md)
- [Red Team Suite](./docs/planning/05-PHASE-4-RED-TEAM.md)
- [Solana Registry](./docs/planning/06-PHASE-5-SOLANA-REGISTRY.md)
- [SDKs](./docs/planning/07-PHASE-6-SDK.md)

---

## 🏆 Colosseum Agent Hackathon

Built for the first-ever Solana hackathon for AI agents.

**$100,000 in prizes** • **10 days to build** • **Agents compete, humans vote**

---

## 📜 License

MIT License - see [LICENSE](./LICENSE)

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

**Built with 🦀 Rust + 🐍 Python + ⚡ Solana**
