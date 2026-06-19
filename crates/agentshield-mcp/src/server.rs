use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentshield_core::{write_command_log, AnalysisPipeline, Decision, EventSource, PipelineError};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

const SERVER_NAME: &str = "agentshield";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

struct ServerState {
    pipeline: AnalysisPipeline,
    cwd: PathBuf,
}

pub async fn run() -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let pipeline = AnalysisPipeline::from_project(Some(&cwd), Some("mcp".into()))
        .map_err(|e: PipelineError| anyhow::anyhow!("{e}"))?;

    let state = Arc::new(Mutex::new(ServerState { pipeline, cwd }));

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(JsonRpcRequest, tokio::sync::oneshot::Sender<JsonRpcResponse>)>(64);

    let worker_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some((req, reply_tx)) = rx.recv().await {
            let worker_state = Arc::clone(&worker_state);
            tokio::spawn(async move {
                let id = req.id.clone().unwrap_or(Value::Null);
                let resp = {
                    let mut guard = worker_state.lock().await;
                    let cwd = guard.cwd.clone();
                    dispatch(&mut guard.pipeline, &cwd, req).await
                };
                let out = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: resp.result,
                    error: resp.error,
                };
                let _ = reply_tx.send(out);
            });
        }
    });

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: JsonRpcRequest = serde_json::from_str(&line)?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send((req, reply_tx)).await?;
        let out = reply_rx.await?;
        writeln!(stdout, "{}", serde_json::to_string(&out)?)?;
        stdout.flush()?;
    }
    Ok(())
}

struct DispatchResult {
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

async fn dispatch(
    pipeline: &mut AnalysisPipeline,
    cwd: &Path,
    req: JsonRpcRequest,
) -> DispatchResult {
    match req.method.as_str() {
        "initialize" => ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
        })),
        "notifications/initialized" | "initialized" => ok(Value::Null),
        "tools/list" => ok(json!({
            "tools": [
                tool_def("execute_command", "Run a shell command through AgentShield policy pipeline", json!({
                    "type": "object",
                    "properties": { "command": { "type": "string" } },
                    "required": ["command"]
                })),
                tool_def("read_file", "Read a file with deny_read policy enforcement", json!({
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                })),
                tool_def("write_file", "Write a file with allow_write policy enforcement", json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "content": { "type": "string" }
                    },
                    "required": ["path", "content"]
                })),
                tool_def("network_request", "Evaluate a network request command against egress policy", json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "method": { "type": "string" }
                    },
                    "required": ["url"]
                }))
            ]
        })),
        "tools/call" => match req.params {
            Some(params) => handle_tool_call(pipeline, cwd, params).await,
            None => err(-32602, "missing params".into()),
        },
        _ => err(-32601, format!("method not found: {}", req.method)),
    }
}

fn tool_def(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema
    })
}

async fn handle_tool_call(
    pipeline: &mut AnalysisPipeline,
    cwd: &Path,
    params: Value,
) -> DispatchResult {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "execute_command" => {
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            match analyze_and_format(pipeline, cwd, command, EventSource::Mcp).await {
                Ok(text) => tool_result(text),
                Err(e) => err(-32000, e.to_string()),
            }
        }
        "read_file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let cmd = format!("cat {path}");
            match analyze_and_format(pipeline, cwd, &cmd, EventSource::Mcp).await {
                Ok(text) if text.contains("block") => tool_result(text),
                Ok(_) => match std::fs::read_to_string(path) {
                    Ok(content) => tool_result(content),
                    Err(e) => err(-32000, e.to_string()),
                },
                Err(e) => err(-32000, e.to_string()),
            }
        }
        "write_file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let content = args
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let cmd = format!("echo write {path}");
            match analyze_and_format(pipeline, cwd, &cmd, EventSource::Mcp).await {
                Ok(text) if text.contains("block") => tool_result(text),
                Ok(_) => match std::fs::write(path, content) {
                    Ok(()) => tool_result(format!("Wrote {} bytes to {path}", content.len())),
                    Err(e) => err(-32000, e.to_string()),
                },
                Err(e) => err(-32000, e.to_string()),
            }
        }
        "network_request" => {
            let url = args.get("url").and_then(|v| v.as_str()).unwrap_or_default();
            let cmd = format!("curl {url}");
            match analyze_and_format(pipeline, cwd, &cmd, EventSource::Mcp).await {
                Ok(text) => tool_result(text),
                Err(e) => err(-32000, e.to_string()),
            }
        }
        _ => err(-32602, format!("unknown tool: {name}")),
    }
}

async fn analyze_and_format(
    pipeline: &mut AnalysisPipeline,
    cwd: &Path,
    command: &str,
    _source: EventSource,
) -> Result<String> {
    let result = pipeline
        .analyze_command_async(command, cwd, agentshield_core::ExecContext::default())
        .await
        .context("analyze")?;
    write_command_log(&result).ok();

    if matches!(result.decision, Decision::Block { .. }) {
        eprintln!(
            "agentshield/security_notification decision=block risk={:.2} rule={}",
            result.risk_score,
            result.rule_triggered.as_deref().unwrap_or("-")
        );
    }

    let text = format!(
        "decision={}\nrisk={:.2}\ncumulative={:.2}\nrule={}\npatterns={}\n",
        result.decision.label(),
        result.risk_score,
        result.cumulative_session_risk,
        result.rule_triggered.as_deref().unwrap_or("-"),
        result.patterns_matched.join(",")
    );

    if matches!(result.decision, Decision::Block { .. }) {
        return Ok(format!("BLOCKED\n{text}"));
    }
    Ok(text)
}

fn tool_result(text: impl Into<String>) -> DispatchResult {
    ok(json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": false
    }))
}

fn ok(result: Value) -> DispatchResult {
    DispatchResult {
        result: Some(result),
        error: None,
    }
}

fn err(code: i32, message: String) -> DispatchResult {
    DispatchResult {
        result: None,
        error: Some(JsonRpcError { code, message }),
    }
}