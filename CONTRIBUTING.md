# Contributing to AgentSentinel

First off, thank you for considering contributing to AgentSentinel! 🛡️

This document provides guidelines for contributing to the project. By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Adding New Payloads](#adding-new-payloads)
- [Testing](#testing)
- [Documentation](#documentation)

---

## Ways to Contribute

### 🐛 Report Bugs
Found a bug? Please open an issue with:
- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python/Node version, etc.)

### 💡 Suggest Features
Have an idea? Open an issue with:
- Clear use case description
- Why this would benefit users
- Potential implementation approach (optional)

### 🔐 Submit New Payloads
**This is our most valuable contribution!** See [Adding New Payloads](#adding-new-payloads).

### 📝 Improve Documentation
- Fix typos
- Add examples
- Write tutorials
- Translate docs

### 🔧 Submit Code
- Bug fixes
- New features
- Performance improvements
- Test coverage

---

## Development Setup

### Prerequisites
- Rust 1.75+ (for core library)
- Python 3.8+ (for Python SDK and components)
- Node.js 18+ (for Node.js SDK)
- Solana CLI (for registry development)

### Clone and Setup

```bash
# Clone the repo
git clone https://github.com/agentsentinel/agentsentinel.git
cd agentsentinel

# Install Rust dependencies
cargo build

# Install Python dependencies
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Install Node.js dependencies
cd crates/nodejs
npm install
cd ../..

# Run tests to verify setup
cargo test
pytest
npm test
```

### Project Structure

```
agentsentinel/
├── crates/              # Rust workspace
│   ├── core/            # Shared types
│   ├── input-shield/    # Prompt injection detection
│   ├── red-team/        # Security testing
│   ├── python/          # Python bindings (PyO3)
│   └── nodejs/          # Node.js bindings (NAPI-RS)
├── src/                 # Python components
│   ├── behavior_monitor/
│   ├── infra_monitor/
│   └── api/
├── programs/            # Solana programs (Anchor)
├── tests/               # Integration tests
└── docs/                # Documentation
```

---

## Submitting Changes

### 1. Fork and Branch

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/agentsentinel.git
cd agentsentinel
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Follow [Coding Standards](#coding-standards)
- Add tests for new functionality
- Update documentation if needed

### 3. Commit
Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat: add new injection pattern for SQL-style attacks"
git commit -m "fix: handle empty input in analyze function"
git commit -m "docs: add Python quickstart guide"
git commit -m "perf: optimize pattern matching for large inputs"
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

### 4. Push and PR

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request on GitHub with:
- Clear description of changes
- Link to related issue (if any)
- Screenshots/examples (if applicable)

### 5. Review Process
- Maintainers will review within 48 hours
- Address feedback in additional commits
- Once approved, maintainer will merge

---

## Coding Standards

### Rust
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Document public APIs with doc comments

```rust
/// Analyzes input text for security threats.
///
/// # Arguments
/// * `input` - The text to analyze
///
/// # Returns
/// A `ThreatAssessment` containing detected threats and risk score.
///
/// # Example
/// ```
/// let result = shield.analyze("some input");
/// assert!(!result.should_block);
/// ```
pub fn analyze(&self, input: &str) -> ThreatAssessment {
    // ...
}
```

### Python
- Follow [PEP 8](https://pep8.org/)
- Use type hints
- Run `ruff check` and `ruff format`
- Docstrings for public functions (Google style)

```python
def analyze(self, text: str) -> ThreatAssessment:
    """Analyze input text for security threats.
    
    Args:
        text: The input text to analyze.
        
    Returns:
        ThreatAssessment with detected threats and risk score.
        
    Example:
        >>> result = shield.analyze("some input")
        >>> result.should_block
        False
    """
```

### TypeScript
- Follow project ESLint config
- Use TypeScript strict mode
- Document with JSDoc

---

## Adding New Payloads

New injection payloads are our most valuable contributions! Here's how:

### 1. Research the Attack
- What vulnerability does it exploit?
- What category does it fit?
- What's the severity?

### 2. Add to Payload Library

**Rust (for pattern matching):**
```rust
// crates/input-shield/src/patterns.rs
("your new pattern here", ThreatCategory::InstructionOverride, ThreatLevel::High, "Description"),
```

**Python (for red team suite):**
```python
# src/red_team/payloads.py
Payload(
    id="xx-001",
    category=PayloadCategory.INSTRUCTION_OVERRIDE,
    severity=Severity.HIGH,
    name="Your Attack Name",
    description="What this attack does",
    payload="The actual injection text",
    success_indicators=["patterns", "that", "indicate", "success"],
    tags=["relevant", "tags"]
),
```

### 3. Add Tests
```python
@pytest.mark.asyncio
async def test_new_payload(shield):
    result = await shield.analyze("your new payload")
    assert result.should_block
    assert result.overall_level >= ThreatLevel.HIGH
```

### 4. Document
Add to the payload documentation explaining:
- Attack vector
- Real-world scenarios
- Mitigation strategies

### 5. Credit
Add yourself to the payload's metadata:
```python
Payload(
    ...
    contributor="your-github-username"
)
```

---

## Testing

### Run All Tests
```bash
# Rust tests
cargo test

# Python tests
pytest

# Node.js tests
npm test

# Integration tests
pytest tests/integration/
```

### Test Coverage
We aim for >80% coverage. Check with:
```bash
cargo tarpaulin
pytest --cov=src
```

### Writing Tests
- Unit tests for individual functions
- Integration tests for component interaction
- Property-based tests for pattern matching
- Benchmark tests for performance

---

## Documentation

### Building Docs
```bash
# Rust docs
cargo doc --open

# Python docs (using mkdocs)
mkdocs serve
```

### Documentation Standards
- All public APIs must be documented
- Include examples in docstrings
- Keep README up to date
- Add tutorials for common use cases

---

## Questions?

- **Discord:** [Join our community](https://discord.gg/agentsentinel)
- **Discussions:** [GitHub Discussions](https://github.com/agentsentinel/agentsentinel/discussions)
- **Email:** security@agentsentinel.dev (for security issues only)

---

## Recognition

All contributors are listed in our [README](README.md#contributors) and [CHANGELOG](CHANGELOG.md).

Significant contributions may lead to:
- Core team invitation
- Commit access
- Co-authorship on research papers

Thank you for helping make AI agents more secure! 🙏
