use std::path::PathBuf;
use std::sync::Arc;

use agentshield_core::{
    ipc::{AnalyzeParams, AnalyzeResult, ExecEvent},
    notify, write_command_log, ConnectionId, EventKind,
};
use anyhow::Result;

use crate::state::SharedState;

pub async fn analyze_command(
    state: &Arc<SharedState>,
    params: AnalyzeParams,
    connection_id: Option<ConnectionId>,
) -> Result<AnalyzeResult> {
    let cwd = params
        .cwd
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let session_id = state
        .sessions
        .resolve_session(params.session_id, connection_id, params.agent_id.clone())
        .await?;

    let result = state
        .sessions
        .analyze(session_id, &params.command, &cwd)
        .await?;

    write_command_log(&result).ok();
    state.record_decision(result.decision.label());

    notify::notify_if_critical(
        &result.decision,
        &params.command,
        result.rule_triggered.as_deref(),
        result.risk_score,
    )
    .await;

    Ok(AnalyzeResult {
        session_id: result.event.session_id,
        decision: result.decision,
        risk_score: result.risk_score,
        cumulative_session_risk: result.cumulative_session_risk,
        rule_triggered: result.rule_triggered,
        patterns_matched: result.patterns_matched,
        obfuscation_detected: result.obfuscation_detected,
        execution_time_ms: result.execution_time_ms,
    })
}

pub async fn handle_exec_event(
    state: &Arc<SharedState>,
    event: ExecEvent,
    connection_id: Option<ConnectionId>,
) -> Result<AnalyzeResult> {
    let command = event.to_command_line();
    analyze_command(
        state,
        AnalyzeParams {
            command,
            cwd: event.cwd,
            session_id: None,
            agent_id: None,
            source: Some(event.source),
            event_kind: Some(EventKind::Command),
        },
        connection_id,
    )
    .await
}
