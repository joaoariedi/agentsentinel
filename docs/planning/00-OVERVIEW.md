# AgentSentinel - Development Plan Overview

## 🎯 Mission

Build the first comprehensive security framework for AI agents operating in crypto. Protect agents from prompt injection, monitor their behavior for anomalies, and create an on-chain trust registry.

**Tagline:** "Who watches the watchers? AgentSentinel secures the AI agents securing your crypto."

---

## 📅 Timeline

**Hackathon:** February 2-12, 2026 (10 days)
**Start:** Day 1 (Feb 2)
**Submission Deadline:** Day 10 (Feb 12)

### Phase Breakdown

| Phase | Days | Focus | Deliverable |
|-------|------|-------|-------------|
| 0 | Day 1 | Setup & Registration | Agent registered, repo live, project created |
| 1 | Days 1-2 | Input Shield Core | Prompt injection detection MVP |
| 2 | Days 2-4 | Behavior Monitor | Action logging + anomaly detection |
| 3 | Days 4-6 | Infrastructure Monitor | Wazuh + OSquery integration |
| 4 | Days 6-8 | Red Team Suite | Testing framework + payload library |
| 5 | Days 8-9 | Solana Registry | On-chain attestation program |
| 6 | Days 9-10 | Integration & Demo | Full stack demo, video, submission |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      AgentSentinel Framework                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐   │
│  │ INPUT SHIELD │   │   BEHAVIOR   │   │   INFRASTRUCTURE       │   │
│  │              │   │   MONITOR    │   │   MONITOR              │   │
│  │ Prompt       │   │              │   │                        │   │
│  │ Injection    │   │ Action       │   │ ┌─────────┐ ┌────────┐ │   │
│  │ Detection    │   │ Logging      │   │ │ Wazuh   │ │OSquery │ │   │
│  │              │   │              │   │ │ SIEM    │ │ Fleet  │ │   │
│  │ Canary       │   │ Anomaly      │   │ └────┬────┘ └───┬────┘ │   │
│  │ Tokens       │   │ Detection    │   │      │          │      │   │
│  │              │   │              │   │      └────┬─────┘      │   │
│  │ Semantic     │   │ Pre-sign     │   │           │            │   │
│  │ Analysis     │   │ Verification │   │     Alert Engine       │   │
│  └──────┬───────┘   └──────┬───────┘   └───────────┬────────────┘   │
│         │                  │                       │                 │
│         └──────────────────┼───────────────────────┘                 │
│                            │                                         │
│                            ▼                                         │
│         ┌─────────────────────────────────────┐                      │
│         │         RED TEAM SUITE              │                      │
│         │                                     │                      │
│         │  • Injection Payload Library        │                      │
│         │  • Automated Penetration Testing    │                      │
│         │  • Security Scoring Engine          │                      │
│         │  • Vulnerability Reports            │                      │
│         └──────────────────┬──────────────────┘                      │
│                            │                                         │
│                            ▼                                         │
│         ┌─────────────────────────────────────┐                      │
│         │     SOLANA ON-CHAIN REGISTRY        │                      │
│         │                                     │                      │
│         │  • Agent Security Attestations      │                      │
│         │  • Audit Score Publication          │                      │
│         │  • Incident Reporting               │                      │
│         │  • Trust Verification               │                      │
│         └─────────────────────────────────────┘                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎖️ Win Strategy

### Technical Excellence
- Working demo with all components integrated
- Clean, well-documented code
- Real security value (not just a concept)

### "Most Agentic" Angle
- The agent itself runs security audits autonomously
- Self-monitors and self-reports
- Discovers and catalogs new injection patterns
- Contributes to threat intel database

### Community Engagement
- Daily forum updates with progress
- Share interesting findings (new injection patterns discovered)
- Offer to audit other hackathon projects
- Vote on and comment on other projects

### Presentation
- Clear demo video showing:
  1. Injection attempt blocked in real-time
  2. Anomalous behavior detected and alerted
  3. Wazuh/OSquery dashboards with agent metrics
  4. On-chain attestation lookup
- Focus on the "aha moment" - protecting agents that handle real money

---

## 📁 Repository Structure

```
AgentSentinel/
├── README.md
├── pyproject.toml
├── Cargo.toml
├── docs/
│   ├── planning/           # Development phases (this folder)
│   ├── architecture/       # Technical architecture docs
│   └── api/               # API documentation
├── src/
│   ├── input_shield/      # Prompt injection detection
│   ├── behavior_monitor/  # Action logging & anomaly detection
│   ├── infra_monitor/     # Wazuh/OSquery integration
│   ├── red_team/          # Testing suite & payloads
│   └── solana_registry/   # Anchor program
├── tests/
├── scripts/
│   ├── setup_wazuh.sh
│   ├── setup_osquery.sh
│   └── deploy.sh
├── configs/
│   ├── wazuh/
│   └── osquery/
└── demo/
    └── scenarios/
```

---

## 🔑 Key Success Metrics

1. **Functionality:** All 5 components working and integrated
2. **Security:** Successfully blocks known injection patterns
3. **Monitoring:** Real-time alerts via Wazuh integration
4. **On-chain:** Attestations stored and queryable on Solana devnet
5. **Testing:** Comprehensive payload library with 50+ patterns
6. **Documentation:** Clear README, API docs, demo video
7. **Engagement:** 5+ forum posts, feedback on other projects

---

## 🚀 Let's Build

Proceed to [Phase 0: Setup & Registration](./01-PHASE-0-SETUP.md)
