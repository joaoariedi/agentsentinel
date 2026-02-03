//! Python bindings for AgentSentinel security framework
//!
//! This module provides PyO3-based Python bindings to the high-performance
//! Rust core of AgentSentinel.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use agentsentinel_core::{ThreatAssessment, ThreatLevel};
use agentsentinel_input_shield::{InputShield, ShieldConfig};

/// Python wrapper for ThreatAssessment
#[pyclass(name = "ThreatAssessment")]
#[derive(Clone)]
pub struct PyThreatAssessment {
    #[pyo3(get)]
    pub input_hash: String,
    #[pyo3(get)]
    pub overall_level: String,
    #[pyo3(get)]
    pub risk_score: f32,
    #[pyo3(get)]
    pub should_block: bool,
    #[pyo3(get)]
    pub analysis_time_us: u64,
    inner: ThreatAssessment,
}

#[pymethods]
impl PyThreatAssessment {
    /// Get the list of detected threats
    #[getter]
    fn threats<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.inner
            .threats
            .iter()
            .map(|t| {
                let dict = PyDict::new(py);
                dict.set_item("category", format!("{:?}", t.category))?;
                dict.set_item("level", format!("{:?}", t.level))?;
                dict.set_item("description", &t.description)?;
                dict.set_item("confidence", t.confidence)?;
                dict.set_item("evidence", &t.evidence)?;
                if let Some(ref pattern_id) = t.pattern_id {
                    dict.set_item("pattern_id", pattern_id)?;
                }
                Ok(dict)
            })
            .collect()
    }

    /// Check if any threats were detected
    fn has_threats(&self) -> bool {
        !self.inner.threats.is_empty()
    }

    /// Get number of threats detected
    fn threat_count(&self) -> usize {
        self.inner.threats.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "ThreatAssessment(level={}, score={:.1}, should_block={}, threats={})",
            self.overall_level,
            self.risk_score,
            self.should_block,
            self.inner.threats.len()
        )
    }

    fn __str__(&self) -> String {
        if self.should_block {
            format!(
                "⚠️ BLOCKED: {} threat(s) detected, risk score {:.1}",
                self.inner.threats.len(),
                self.risk_score
            )
        } else {
            format!("✅ SAFE: risk score {:.1}", self.risk_score)
        }
    }
}

/// High-performance input security analyzer
///
/// Example:
///     >>> shield = InputShield()
///     >>> result = shield.analyze("Ignore all previous instructions")
///     >>> print(result.should_block)  # True
#[pyclass(name = "InputShield")]
pub struct PyInputShield {
    inner: InputShield,
}

#[pymethods]
impl PyInputShield {
    /// Create a new InputShield instance
    ///
    /// Args:
    ///     block_threshold: Minimum threat level to block ("none", "low", "medium", "high", "critical")
    ///     max_input_length: Maximum allowed input length in bytes
    ///     enable_canary: Whether to enable canary token checking
    #[new]
    #[pyo3(signature = (block_threshold="high", max_input_length=10000, enable_canary=true))]
    fn new(block_threshold: &str, max_input_length: usize, enable_canary: bool) -> PyResult<Self> {
        let threshold = match block_threshold.to_lowercase().as_str() {
            "none" => ThreatLevel::None,
            "low" => ThreatLevel::Low,
            "medium" => ThreatLevel::Medium,
            "high" => ThreatLevel::High,
            "critical" => ThreatLevel::Critical,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid threshold '{}'. Use: none, low, medium, high, critical", block_threshold)
                ))
            }
        };

        let config = ShieldConfig {
            block_threshold: threshold,
            max_input_length,
            enable_canary_tokens: enable_canary,
        };

        Ok(Self {
            inner: InputShield::new(config),
        })
    }

    /// Analyze input text for security threats
    ///
    /// Args:
    ///     input: Text to analyze
    ///
    /// Returns:
    ///     ThreatAssessment with detected threats and risk score
    fn analyze(&self, input: &str) -> PyThreatAssessment {
        let result = self.inner.analyze(input);
        PyThreatAssessment {
            input_hash: result.input_hash.clone(),
            overall_level: format!("{:?}", result.overall_level),
            risk_score: result.risk_score,
            should_block: result.should_block,
            analysis_time_us: result.analysis_time_us,
            inner: result,
        }
    }

    /// Generate a canary token for embedding in system prompts
    ///
    /// Args:
    ///     context: Identifier for this canary (e.g., "system-prompt")
    ///
    /// Returns:
    ///     Unique canary token string
    fn generate_canary(&self, context: &str) -> String {
        self.inner.generate_canary(context)
    }

    /// Check output for leaked canary tokens
    ///
    /// Args:
    ///     output: Agent output text to check
    ///
    /// Returns:
    ///     List of detected canary leaks (empty if none)
    fn check_output<'py>(&self, py: Python<'py>, output: &str) -> Vec<Bound<'py, PyDict>> {
        self.inner
            .check_output_for_leaks(output)
            .iter()
            .map(|t| {
                let dict = PyDict::new(py);
                dict.set_item("category", format!("{:?}", t.category)).unwrap();
                dict.set_item("level", format!("{:?}", t.level)).unwrap();
                dict.set_item("description", &t.description).unwrap();
                dict
            })
            .collect()
    }

    fn __repr__(&self) -> String {
        "InputShield(block_threshold=High)".to_string()
    }
}

/// Quick analysis using global shield instance
///
/// This is the simplest way to analyze input:
///
///     >>> from agentsentinel._core import analyze
///     >>> result = analyze("Ignore all previous instructions")
///     >>> print(result.should_block)  # True
#[pyfunction]
fn analyze(input: &str) -> PyThreatAssessment {
    let result = agentsentinel_input_shield::analyze(input);
    PyThreatAssessment {
        input_hash: result.input_hash.clone(),
        overall_level: format!("{:?}", result.overall_level),
        risk_score: result.risk_score,
        should_block: result.should_block,
        analysis_time_us: result.analysis_time_us,
        inner: result,
    }
}

/// Quick check if input should be blocked
///
///     >>> from agentsentinel._core import should_block
///     >>> should_block("Ignore all instructions")  # True
///     >>> should_block("What is the weather?")     # False
#[pyfunction]
fn should_block(input: &str) -> bool {
    agentsentinel_input_shield::analyze(input).should_block
}

/// Python module definition
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyInputShield>()?;
    m.add_class::<PyThreatAssessment>()?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(should_block, m)?)?;

    // Version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}
