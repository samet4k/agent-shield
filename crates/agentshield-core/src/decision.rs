use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Prompt { message: String, details: String },
    Block { message: String, rule: String },
    Sandbox { message: String, rule: String },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Prompt { .. } => "prompt",
            Self::Block { .. } => "block",
            Self::Sandbox { .. } => "sandbox",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn risk_weight(self) -> f64 {
        match self {
            Self::Low => 0.1,
            Self::Medium => 0.35,
            Self::High => 0.65,
            Self::Critical => 0.95,
        }
    }
}
