use std::path::{Path, PathBuf};

use agentshield_core::ipc::client as ipc_client;
use agentshield_core::ipc::AnalyzeParams;
use agentshield_core::{notify, AnalysisPipeline, Decision, PipelineError};
use serde::Serialize;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Serialize)]
struct AnalyzeJson {
    decision: Decision,
    risk_score: f64,
    cumulative_session_risk: f64,
    rule_triggered: Option<String>,
    patterns_matched: Vec<String>,
    obfuscation_detected: bool,
    execution_time_ms: f64,
}

pub async fn run(command: &str, format: OutputFormat) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let result = if ipc_client::daemon_available().await {
        match ipc_client::analyze_via_daemon(AnalyzeParams {
            command: command.to_string(),
            cwd: Some(cwd.display().to_string()),
            agent_id: None,
            source: None,
            event_kind: None,
        })
        .await
        {
            Ok(daemon) => AnalyzeJson {
                decision: daemon.decision,
                risk_score: daemon.risk_score,
                cumulative_session_risk: daemon.cumulative_session_risk,
                rule_triggered: daemon.rule_triggered,
                patterns_matched: daemon.patterns_matched,
                obfuscation_detected: daemon.obfuscation_detected,
                execution_time_ms: daemon.execution_time_ms,
            },
            Err(e) => {
                eprintln!("daemon unavailable ({e}), analyzing locally");
                analyze_local(command, &cwd)?
            }
        }
    } else {
        analyze_local(command, &cwd)?
    };

    notify::notify_if_critical(
        &result.decision,
        command,
        result.rule_triggered.as_deref(),
        result.risk_score,
    )
    .await;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(&result)?);
        }
        OutputFormat::Text => print_text(&result),
    }
    Ok(())
}

fn analyze_local(command: &str, cwd: &Path) -> anyhow::Result<AnalyzeJson> {
    let mut pipeline = AnalysisPipeline::from_project(Some(cwd), None)
        .map_err(|e: PipelineError| anyhow::anyhow!("{e}"))?;
    let result = pipeline.analyze_command(command, cwd)?;
    agentshield_core::write_command_log(&result).ok();
    Ok(AnalyzeJson {
        decision: result.decision,
        risk_score: result.risk_score,
        cumulative_session_risk: result.cumulative_session_risk,
        rule_triggered: result.rule_triggered,
        patterns_matched: result.patterns_matched,
        obfuscation_detected: result.obfuscation_detected,
        execution_time_ms: result.execution_time_ms,
    })
}

fn print_text(result: &AnalyzeJson) {
    println!("Decision:      {}", result.decision.label());
    println!("Risk score:    {:.2}", result.risk_score);
    println!("Cumulative:    {:.2}", result.cumulative_session_risk);
    if let Some(rule) = &result.rule_triggered {
        println!("Rule:          {rule}");
    }
    if !result.patterns_matched.is_empty() {
        println!("Patterns:      {}", result.patterns_matched.join(", "));
    }
    println!("Obfuscation:   {}", result.obfuscation_detected);
    println!("Latency:       {:.2}ms", result.execution_time_ms);
}
