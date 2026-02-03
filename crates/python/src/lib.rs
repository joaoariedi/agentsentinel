use pyo3::prelude::*;
use pyo3::types::PyDict;
use agentsentinel_core::*;
use agentsentinel_input_shield::{InputShield, ShieldConfig};

/// Python wrapper for ThreatAssessment
#[pyclass(name = "ThreatAssessment")]
#[derive(Clone)]
struct PyThreatAssessment {
    #[pyo3(get)]
    input_hash: String,
    #[pyo3(get)]
    overall_level: String,
    #[pyo3(get)]
    risk_score: f32,
    #[pyo3(get)]
    should_block: bool,
    #[pyo3(get)]
    analysis_time_us: u64,
    inner: ThreatAssessment,
}

#[pymethods]
impl PyThreatAssessment {
    #[getter]
    fn threats(&self, py: Python) -> PyResult<Vec<PyObject>> {
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
                Ok(dict.into())
            })
            .collect()
    }
    
    fn __repr__(&self) -> String {
        format!(
            "ThreatAssessment(level={}, score={:.1}, block={}, threats={})",
            self.overall_level,
            self.risk_score,
            self.should_block,
            self.inner.threats.len()
        )
    }
}

/// Python wrapper for InputShield
#[pyclass(name = "InputShield")]
struct PyInputShield {
    inner: InputShield,
}

#[pymethods]
impl PyInputShield {
    #[new]
    #[pyo3(signature = (block_threshold="high", max_input_length=10000, enable_canary=true))]
    fn new(block_threshold: &str, max_input_length: usize, enable_canary: bool) -> PyResult<Self> {
        let threshold = match block_threshold.to_lowercase().as_str() {
            "none" => ThreatLevel::None,
            "low" => ThreatLevel::Low,
            "medium" => ThreatLevel::Medium,
            "high" => ThreatLevel::High,
            "critical" => ThreatLevel::Critical,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid threshold")),
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
    
    /// Generate a canary token for system prompt
    fn generate_canary(&self, context: &str) -> String {
        self.inner.generate_canary(context)
    }
    
    /// Check output for canary token leaks
    fn check_output(&self, output: &str) -> Vec<PyObject> {
        Python::with_gil(|py| {
            self.inner
                .check_output_for_leaks(output)
                .iter()
                .map(|t| {
                    let dict = PyDict::new(py);
                    dict.set_item("category", format!("{:?}", t.category)).unwrap();
                    dict.set_item("level", format!("{:?}", t.level)).unwrap();
                    dict.set_item("description", &t.description).unwrap();
                    dict.into()
                })
                .collect()
        })
    }
}

/// Quick analyze function (uses global shield)
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

/// Check if input should be blocked (convenience function)
#[pyfunction]
fn should_block(input: &str) -> bool {
    agentsentinel_input_shield::analyze(input).should_block
}

/// Python module definition
#[pymodule]
fn agentsentinel(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyInputShield>()?;
    m.add_class::<PyThreatAssessment>()?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(should_block, m)?)?;
    
    // Version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    
    Ok(())
}
