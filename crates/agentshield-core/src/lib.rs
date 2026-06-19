#![warn(clippy::all)]

//! AgentShield core analysis pipeline, policy engine, and decision runtime.

pub mod ast;
pub mod decision;
pub mod filesystem;
pub mod ipc;
pub mod logging;
pub mod network;
pub mod notify;
pub mod obfuscation;
pub mod pipeline;
pub mod plugins;
pub mod policy;
pub mod session;
pub mod threat;

pub use decision::{Decision, Severity};
pub use ipc::{AnalyzeParams, AnalyzeResult, DaemonStatus, ExecEvent, IpcRequest, IpcResponse};
pub use logging::{init_logging, log_directory, write_command_log, CommandLogEntry};
pub use notify::{NotifyConfig, WebhookPayload};
pub use pipeline::{AnalysisPipeline, AnalysisResult, PipelineError};
pub use policy::{PolicyDocument, PolicyEngine, PolicyError, PolicyMatch};
pub use session::{
    ConnectionId, EventKind, EventSource, SecurityEvent, SessionManager, SessionState,
};
pub use threat::{ThreatChainAnalyzer, ThreatChainResult};
