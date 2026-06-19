use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("no webhook configured")]
    NotConfigured,
}

/// Notification configuration stored in user config dir.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    pub webhooks: Vec<WebhookTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookTarget {
    pub url: String,
    pub events: Vec<String>,
}

/// Payload sent to Slack/Discord-compatible webhooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub text: String,
    pub severity: String,
    pub decision: String,
    pub command: String,
    pub rule: Option<String>,
    pub risk_score: f64,
    pub timestamp: String,
}

pub fn config_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("agentshield")
        .join("notify.yml")
}

pub fn load_config() -> NotifyConfig {
    let path = config_path();
    if !path.exists() {
        return NotifyConfig::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_yaml::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config(config: &NotifyConfig) -> std::io::Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_yaml::to_string(config).unwrap_or_default())
}

pub async fn send_alert(
    config: &NotifyConfig,
    payload: &WebhookPayload,
) -> Result<(), NotifyError> {
    if config.webhooks.is_empty() {
        return Err(NotifyError::NotConfigured);
    }

    let client = reqwest::Client::new();
    for hook in &config.webhooks {
        if !hook.events.is_empty() && !hook.events.iter().any(|e| e == &payload.decision) {
            continue;
        }
        client
            .post(&hook.url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?;
    }
    Ok(())
}

pub async fn notify_if_critical(
    decision: &crate::decision::Decision,
    command: &str,
    rule: Option<&str>,
    risk_score: f64,
) {
    let config = load_config();
    let (decision_str, severity) = match decision {
        crate::decision::Decision::Block { .. } => ("block", "critical"),
        crate::decision::Decision::Prompt { .. } => ("prompt", "high"),
        crate::decision::Decision::Sandbox { .. } => ("sandbox", "medium"),
        crate::decision::Decision::Allow => return,
    };

    let payload = WebhookPayload {
        text: format!("AgentShield {decision_str}: {command}"),
        severity: severity.into(),
        decision: decision_str.into(),
        command: command.into(),
        rule: rule.map(str::to_string),
        risk_score,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let _ = send_alert(&config, &payload).await;
}
