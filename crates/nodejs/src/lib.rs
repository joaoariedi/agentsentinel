use napi::bindgen_prelude::*;
use napi_derive::napi;
use agentsentinel_core::*;
use agentsentinel_input_shield::{InputShield, ShieldConfig};

#[napi(object)]
pub struct JsThreat {
    pub category: String,
    pub level: String,
    pub description: String,
    pub confidence: f64,
    pub evidence: String,
}

#[napi(object)]
pub struct JsThreatAssessment {
    pub input_hash: String,
    pub threats: Vec<JsThreat>,
    pub overall_level: String,
    pub risk_score: f64,
    pub should_block: bool,
    pub analysis_time_us: u32,
}

impl From<ThreatAssessment> for JsThreatAssessment {
    fn from(assessment: ThreatAssessment) -> Self {
        Self {
            input_hash: assessment.input_hash,
            threats: assessment
                .threats
                .into_iter()
                .map(|t| JsThreat {
                    category: format!("{:?}", t.category),
                    level: format!("{:?}", t.level),
                    description: t.description,
                    confidence: t.confidence as f64,
                    evidence: t.evidence,
                })
                .collect(),
            overall_level: format!("{:?}", assessment.overall_level),
            risk_score: assessment.risk_score as f64,
            should_block: assessment.should_block,
            analysis_time_us: assessment.analysis_time_us as u32,
        }
    }
}

#[napi]
pub struct JsInputShield {
    inner: InputShield,
}

#[napi]
impl JsInputShield {
    #[napi(constructor)]
    pub fn new(config: Option<JsShieldConfig>) -> Self {
        let config = config.map(|c| c.into()).unwrap_or_default();
        Self {
            inner: InputShield::new(config),
        }
    }
    
    #[napi]
    pub fn analyze(&self, input: String) -> JsThreatAssessment {
        self.inner.analyze(&input).into()
    }
    
    #[napi]
    pub fn generate_canary(&self, context: String) -> String {
        self.inner.generate_canary(&context)
    }
    
    #[napi]
    pub fn check_output(&self, output: String) -> Vec<JsThreat> {
        self.inner
            .check_output_for_leaks(&output)
            .into_iter()
            .map(|t| JsThreat {
                category: format!("{:?}", t.category),
                level: format!("{:?}", t.level),
                description: t.description,
                confidence: t.confidence as f64,
                evidence: t.evidence,
            })
            .collect()
    }
}

#[napi(object)]
pub struct JsShieldConfig {
    pub block_threshold: Option<String>,
    pub max_input_length: Option<u32>,
    pub enable_canary_tokens: Option<bool>,
}

impl From<JsShieldConfig> for ShieldConfig {
    fn from(config: JsShieldConfig) -> Self {
        let threshold = config
            .block_threshold
            .map(|s| match s.to_lowercase().as_str() {
                "none" => ThreatLevel::None,
                "low" => ThreatLevel::Low,
                "medium" => ThreatLevel::Medium,
                "critical" => ThreatLevel::Critical,
                _ => ThreatLevel::High,
            })
            .unwrap_or(ThreatLevel::High);
        
        Self {
            block_threshold: threshold,
            max_input_length: config.max_input_length.unwrap_or(10_000) as usize,
            enable_canary_tokens: config.enable_canary_tokens.unwrap_or(true),
        }
    }
}

/// Quick analyze using global shield
#[napi]
pub fn analyze(input: String) -> JsThreatAssessment {
    agentsentinel_input_shield::analyze(&input).into()
}

/// Quick check if should block
#[napi]
pub fn should_block(input: String) -> bool {
    agentsentinel_input_shield::analyze(&input).should_block
}
