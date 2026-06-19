pub mod client;
pub mod transport;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::decision::Decision;
use crate::session::{EventKind, EventSource};

/// JSON-RPC request from CLI/SDK to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

/// JSON-RPC response from daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    pub code: i32,
    pub message: String,
}

/// Analyze a command via daemon IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeParams {
    pub command: String,
    pub cwd: Option<String>,
    pub session_id: Option<Uuid>,
    pub agent_id: Option<String>,
    pub source: Option<EventSource>,
    pub event_kind: Option<EventKind>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
}

/// Analyze response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeResult {
    pub session_id: Uuid,
    pub decision: Decision,
    pub risk_score: f64,
    pub cumulative_session_risk: f64,
    pub rule_triggered: Option<String>,
    pub patterns_matched: Vec<String>,
    pub obfuscation_detected: bool,
    pub execution_time_ms: f64,
}

/// Daemon health and stats for VS Code status bar.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub active: bool,
    pub version: String,
    pub total_commands: u64,
    pub blocked_count: u64,
    pub prompt_count: u64,
    pub sandbox_count: u64,
    pub collectors: Vec<String>,
}

/// Platform exec event forwarded to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEvent {
    pub executable: String,
    pub args: Vec<String>,
    pub pid: u32,
    pub ppid: u32,
    pub source: EventSource,
    pub cwd: Option<String>,
}

impl ExecEvent {
    pub fn to_command_line(&self) -> String {
        if self.args.is_empty() {
            self.executable.clone()
        } else {
            format!("{} {}", self.executable, self.args.join(" "))
        }
    }
}

pub fn ipc_socket_path() -> std::path::PathBuf {
    if cfg!(windows) {
        std::path::PathBuf::from(
            std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| ".".into())
                .to_string()
                + r"\agentshield\daemon.sock",
        )
    } else {
        dirs::runtime_dir()
            .or_else(dirs::data_local_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("agentshield")
            .join("daemon.sock")
    }
}
