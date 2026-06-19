use serde::{Deserialize, Serialize};

use crate::decision::Severity;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: Option<String>,
    pub trust_level: Option<TrustLevel>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub session: SessionPolicy,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Minimal,
    #[default]
    Standard,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub r#match: RuleMatch,
    pub action: RuleAction,
    pub severity: Severity,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMatch {
    pub command: Option<String>,
    pub pattern: Option<String>,
    pub ast_pattern: Option<String>,
    pub flags_include: Option<Vec<String>>,
    pub target_outside: Option<Vec<String>>,
    pub pipe_to_shell: Option<bool>,
    pub obfuscation: Option<bool>,
    pub indirect_exec: Option<bool>,
    pub context: Option<String>,
    /// At least one of these substrings must appear in the command.
    pub requires_any: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Prompt,
    Block,
    Sandbox,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allow_write: Vec<String>,
    #[serde(default)]
    pub deny_read: Vec<String>,
    #[serde(default)]
    pub deny_write: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub block_unknown: bool,
    pub alert_on_large_upload: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionPolicy {
    pub threat_chain_window: Option<usize>,
    pub cumulative_risk_threshold: Option<f64>,
}

impl PolicyDocument {
    pub fn builtin_default() -> Self {
        serde_yaml::from_str(include_str!("../../../../policies/default.yml")).unwrap_or_else(
            |_| Self {
                version: Some("1.0".into()),
                trust_level: Some(TrustLevel::Standard),
                rules: vec![],
                filesystem: FilesystemPolicy::default(),
                network: NetworkPolicy::default(),
                session: SessionPolicy {
                    threat_chain_window: Some(20),
                    cumulative_risk_threshold: Some(0.8),
                },
            },
        )
    }
}
