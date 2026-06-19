use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use serde::Serialize;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::pipeline::AnalysisResult;

/// Structured JSON log entry for a single command analysis.
#[derive(Debug, Serialize)]
pub struct CommandLogEntry {
    pub timestamp: String,
    pub session_id: String,
    pub agent: Option<String>,
    pub command_raw: String,
    pub command_normalized: String,
    pub ast_analysis: AstLogSummary,
    pub risk_score: f64,
    pub cumulative_session_risk: f64,
    pub decision: String,
    pub rule_triggered: Option<String>,
    pub execution_time_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct AstLogSummary {
    pub patterns_matched: Vec<String>,
    pub obfuscation_detected: bool,
}

/// Initialize tracing and return the log directory path.
pub fn init_logging() -> PathBuf {
    let log_dir = log_directory();
    fs::create_dir_all(&log_dir).ok();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false))
        .init();

    log_dir
}

pub fn log_directory() -> PathBuf {
    if cfg!(windows) {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("agentshield")
            .join("logs")
    } else {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from(".local/share"))
            .join("agentshield")
            .join("logs")
    }
}

/// Append a structured JSON log line for the given analysis result.
pub fn write_command_log(result: &AnalysisResult) -> std::io::Result<()> {
    let log_dir = log_directory();
    fs::create_dir_all(&log_dir)?;

    let date = Utc::now().format("%Y-%m-%d");
    let path = log_dir.join(format!("agentshield-{date}.jsonl"));

    let entry = CommandLogEntry {
        timestamp: result.event.timestamp.to_rfc3339(),
        session_id: result.event.session_id.to_string(),
        agent: result.event.agent_id.clone(),
        command_raw: result.event.command_raw.clone(),
        command_normalized: result.event.command_normalized.clone(),
        ast_analysis: AstLogSummary {
            patterns_matched: result.patterns_matched.clone(),
            obfuscation_detected: result.obfuscation_detected,
        },
        risk_score: result.risk_score,
        cumulative_session_risk: result.cumulative_session_risk,
        decision: result.decision.label().to_string(),
        rule_triggered: result.rule_triggered.clone(),
        execution_time_ms: result.execution_time_ms,
    };

    let line = serde_json::to_string(&entry)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}
