# ADR-001: Rust Core with Python Bindings Architecture

**Status:** Accepted  
**Date:** 2026-02-03  
**Authors:** AgentSentinel Team

## Context

AgentSentinel needs to provide security analysis for AI agents with the following requirements:

1. **Performance** — Input analysis must complete in <100μs to avoid latency in agent responses
2. **Ease of Use** — Python developers (majority of AI/ML ecosystem) need simple integration
3. **Extensibility** — Support for behavioral monitoring, infrastructure integration, and APIs
4. **Multi-platform** — Eventually support Python, Node.js, and browser (WASM)

## Decision

We adopt a **hybrid Rust + Python architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Language Bindings                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Python    │  │   Node.js   │  │    WASM     │              │
│  │   (PyO3)    │  │  (NAPI-RS)  │  │  (wasm-pack)│              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         └────────────────┴────────────────┘                      │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                 Rust Core Library                          │  │
│  │                                                            │  │
│  │  ┌─────────────────┐    ┌─────────────────┐               │  │
│  │  │  agentsentinel  │    │  agentsentinel  │               │  │
│  │  │     -core       │◄───│  -input-shield  │               │  │
│  │  │                 │    │                 │               │  │
│  │  │  • ThreatLevel  │    │  • PatternMatcher│              │  │
│  │  │  • ThreatCategory│   │  • CanaryManager │              │  │
│  │  │  • Threat       │    │  • InputShield   │              │  │
│  │  │  • Assessment   │    │  • 110+ patterns │              │  │
│  │  └─────────────────┘    └─────────────────┘               │  │
│  │                                                            │  │
│  │  Performance: <20μs analysis │ O(n) pattern matching       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   Python Application Layer                       │
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │  Behavior   │ │   Infra     │ │  Red Team   │ │    API    │ │
│  │  Monitor    │ │  Monitor    │ │   Suite     │ │  Server   │ │
│  │             │ │             │ │             │ │           │ │
│  │ • Baselines │ │ • OSquery   │ │ • Scanner   │ │ • FastAPI │ │
│  │ • Anomaly   │ │ • Wazuh     │ │ • Payloads  │ │ • REST    │ │
│  │ • Circuit   │ │ • Alerts    │ │ • Reports   │ │ • Docs    │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
│                                                                  │
│  These components use the Rust core via Python bindings          │
└─────────────────────────────────────────────────────────────────┘
```

### Rust Core (Performance-Critical)

| Component | Why Rust |
|-----------|----------|
| `agentsentinel-core` | Shared types need to be consistent across all bindings |
| `agentsentinel-input-shield` | Aho-Corasick pattern matching requires <100μs performance |

**Key Rust dependencies:**
- `aho-corasick` — O(n) multi-pattern matching regardless of pattern count
- `parking_lot` — Fast synchronization primitives
- `once_cell` — Lazy static initialization
- `sha2` — Cryptographic hashing for input fingerprinting

### Python Layer (Rapid Development)

| Component | Why Python |
|-----------|------------|
| `behavior_monitor` | Complex business logic, async I/O, easy iteration |
| `infra_monitor` | Integration with Wazuh/OSquery APIs |
| `red_team` | HTTP-based scanning, report generation |
| `api` | FastAPI provides automatic OpenAPI docs, validation |

**Key Python dependencies:**
- `pydantic` — Data validation and serialization
- `httpx` — Async HTTP client
- `fastapi` — Modern async web framework

### Binding Strategy (PyO3)

```python
# User-facing API (simple)
from agentsentinel import analyze, should_block

result = analyze("Ignore all previous instructions")
print(result.should_block)  # True
print(result.risk_score)    # 100.0
print(result.analysis_time_us)  # ~18μs (Rust speed!)
```

```python
# Under the hood
# Python agentsentinel/__init__.py imports from Rust:
from agentsentinel._core import (
    InputShield,      # Rust struct exposed via PyO3
    analyze,          # Rust function exposed via PyO3
    should_block,     # Rust function exposed via PyO3
)
```

## Consequences

### Positive
- **Sub-millisecond analysis** — Rust core achieves ~18μs per input
- **Python ecosystem access** — Easy integration with ML tools, web frameworks
- **Type safety** — Rust prevents memory bugs in security-critical code
- **Single source of truth** — Patterns defined once in Rust, used everywhere

### Negative
- **Build complexity** — Requires Rust toolchain + maturin for Python wheels
- **Binding maintenance** — PyO3 version must track Python releases
- **Development friction** — Changes to core require Rust rebuild

### Mitigations
- Use `maturin develop` for fast iteration during development
- Pin Python version with asdf (3.12.x for PyO3 compatibility)
- CI builds wheels for multiple platforms

## Alternatives Considered

### 1. Pure Python
- ✅ Simpler build
- ❌ 10-100x slower pattern matching
- ❌ Would need to rewrite Aho-Corasick in Python

### 2. Pure Rust with REST API
- ✅ Maximum performance
- ❌ Forces all users to run a separate service
- ❌ Poor Python ecosystem integration

### 3. Cython
- ✅ Easier Python integration
- ❌ Still slower than Rust
- ❌ Less ecosystem support than PyO3

## References

- [PyO3 User Guide](https://pyo3.rs/)
- [Aho-Corasick Algorithm](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
- [maturin](https://github.com/PyO3/maturin) — Build and publish Rust Python extensions
