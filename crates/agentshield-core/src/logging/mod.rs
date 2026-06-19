use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
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

const COMPRESS_AFTER_DAYS: i64 = 7;
const RETAIN_DAYS: i64 = 30;

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

/// Spawn a background task that compresses and prunes old log files.
pub fn spawn_log_maintenance() {
    std::thread::spawn(|| {
        loop {
            if let Err(e) = maintain_logs() {
                tracing::warn!("log maintenance failed: {e}");
            }
            std::thread::sleep(Duration::from_secs(3600));
        }
    });
}

fn maintain_logs() -> std::io::Result<()> {
    let log_dir = log_directory();
    if !log_dir.exists() {
        return Ok(());
    }

    let now = Utc::now();
    for entry in fs::read_dir(&log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.starts_with("agentshield-") {
            continue;
        }

        let modified = entry
            .metadata()?
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let modified_dt: DateTime<Utc> = modified.into();

        let age_days = now.signed_duration_since(modified_dt).num_days();

        if age_days > RETAIN_DAYS {
            fs::remove_file(&path)?;
            continue;
        }

        if age_days > COMPRESS_AFTER_DAYS && path.extension().and_then(|e| e.to_str()) == Some("jsonl")
        {
            compress_log_file(&path)?;
        }
    }
    Ok(())
}

fn compress_log_file(path: &Path) -> std::io::Result<()> {
    let gz_path = path.with_extension("jsonl.gz");
    if gz_path.exists() {
        return Ok(());
    }

    let mut input = File::open(path)?;
    let mut contents = Vec::new();
    input.read_to_end(&mut contents)?;

    let output = File::create(&gz_path)?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    encoder.write_all(&contents)?;
    encoder.finish()?;
    fs::remove_file(path)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_directory_is_platform_aware() {
        let dir = log_directory();
        assert!(dir.to_string_lossy().contains("agentshield"));
    }
}